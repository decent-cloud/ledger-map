#[cfg(target_arch = "wasm32")]
use ic_cdk::println;

use crate::platform_specific::{
    persistent_storage_grow64, persistent_storage_read64, persistent_storage_size_bytes,
    persistent_storage_write64, PERSISTENT_STORAGE_PAGE_SIZE,
};
use crate::{debug, info, warn};
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

pub const PARTITION_TABLE_START_OFFSET: u64 = 0; // Partition table may not start at an arbitrary offset of the persistent storage.
pub const PARTITION_TABLE_MAX_ENTRIES: usize = 128;
const EXPECTED_MAGIC_BYTES: [u8; 8] = [0x4c, 0x65, 0x64, 0x67, 0x50, 0x61, 0x72, 0x74]; // "LedgPart"

fn calc_needed_pages(current_bytes: u64, target_bytes: u64) -> u64 {
    if current_bytes < target_bytes {
        (target_bytes - current_bytes) / PERSISTENT_STORAGE_PAGE_SIZE + 1
    } else {
        0
    }
}

#[derive(Serialize, Clone)]
pub struct PartitionTableHeader {
    pub magic_bytes: [u8; 8],
}

impl Default for PartitionTableHeader {
    fn default() -> Self {
        PartitionTableHeader::new()
    }
}

impl PartitionTableHeader {
    pub fn new() -> PartitionTableHeader {
        PartitionTableHeader {
            magic_bytes: EXPECTED_MAGIC_BYTES,
        }
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Result<PartitionTableHeader, String> {
        if bytes.len() != 8 {
            return Err(format!(
                "Partition table header size mismatch: expected {}, got {}",
                Self::size(),
                bytes.len()
            ));
        }
        let mut header = PartitionTableHeader::default();
        header.magic_bytes.copy_from_slice(&bytes[0..8]);
        header.check_magic_bytes()?;
        Ok(header)
    }

    pub fn size() -> usize {
        std::mem::size_of::<PartitionTableHeader>()
    }

    /// Check if the magic bytes match the expected value.
    pub fn check_magic_bytes(&self) -> Result<(), String> {
        if self.magic_bytes != EXPECTED_MAGIC_BYTES {
            return Err(format!(
                "Partition table header magic bytes mismatch: got {:?}, expected {:?}.",
                self.magic_bytes, EXPECTED_MAGIC_BYTES
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct PartitionTableEntry {
    pub name: [u8; 16], // Partition name, zero-terminated
    pub start_lba: u64, // LBA of the byte of the partition
    pub end_lba: u64,   // zero means unused
}

impl PartitionTableEntry {
    pub fn new(name: [u8; 16], start_lba: u64, end_lba: u64) -> PartitionTableEntry {
        PartitionTableEntry {
            name,
            start_lba,
            end_lba,
        }
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Result<PartitionTableEntry, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "Partition table entry size mismatch: expected {}, got {}",
                Self::size(),
                bytes.len()
            ));
        }

        Ok(PartitionTableEntry {
            name: bytes[0..16]
                .try_into()
                .map_err(|_| "Slice to array conversion failed for bytes 0..16")?,
            start_lba: u64::from_le_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| "Slice to array conversion failed for bytes 16..24")?,
            ),
            end_lba: u64::from_le_bytes(
                bytes[24..32]
                    .try_into()
                    .map_err(|_| "Slice to array conversion failed for bytes 16..24")?,
            ),
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&self.name);
        bytes[16..24].copy_from_slice(&self.start_lba.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.end_lba.to_le_bytes());
        bytes
    }

    pub fn size() -> usize {
        std::mem::size_of::<PartitionTableEntry>()
    }

    pub fn is_used(&self) -> bool {
        self.end_lba != 0
    }
}

impl std::fmt::Display for PartitionTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "name: {}, start_lba: {}, end_lba: {}",
            String::from_utf8_lossy(&self.name),
            self.start_lba,
            self.end_lba
        )
    }
}

#[derive(Clone)]
pub struct PartitionTable {
    pub num_entries: u16,
    pub header: PartitionTableHeader,
    pub entries: [PartitionTableEntry; PARTITION_TABLE_MAX_ENTRIES],
}

impl Serialize for PartitionTable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PartitionTable", 3)?;

        state.serialize_field("num_entries", &self.num_entries)?;
        state.serialize_field("header", &self.header)?;

        // Automatic derive might not work for large arrays due to trait
        // implementations for arrays being limited to certain sizes.
        let mut entries = Vec::new();
        for entry in &self.entries {
            if entry.is_used() {
                entries.push(entry);
            } else {
                break;
            }
        }
        state.serialize_field("entries", &entries)?;

        state.end()
    }
}

impl Default for PartitionTable {
    fn default() -> Self {
        PartitionTable {
            num_entries: 0,
            header: PartitionTableHeader::default(),
            entries: [PartitionTableEntry::default(); PARTITION_TABLE_MAX_ENTRIES],
        }
    }
}

impl PartitionTable {
    pub fn new() -> PartitionTable {
        PartitionTable::default()
    }

    pub fn size() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Read data from persistent storage and check if it matches the expected magic bytes.
    pub fn read_from_persistent_storage(mut self) -> anyhow::Result<PartitionTable> {
        let persistent_storage_bytes = persistent_storage_size_bytes();
        if persistent_storage_bytes < PARTITION_TABLE_START_OFFSET + Self::size() as u64 {
            return Err(anyhow::format_err!(
                "Not enough persistent storage allocated"
            ));
        }
        debug!(
            "Reading from persistent storage of size {} bytes",
            persistent_storage_bytes
        );

        let mut buf = vec![0; Self::size()];

        persistent_storage_read64(PARTITION_TABLE_START_OFFSET, buf.as_mut_slice())?;
        debug!(
            "Read {} bytes of partition table from persistent storage @ {}",
            buf.len(),
            PARTITION_TABLE_START_OFFSET
        );

        self.header =
            PartitionTableHeader::new_from_bytes(&buf.as_slice()[..PartitionTableHeader::size()])
                .map_err(|e| anyhow::format_err!("{}", e))?;

        for i in 0..self.entries.len() {
            let entry_offset = PartitionTableHeader::size() + i * PartitionTableEntry::size();
            let entry = PartitionTableEntry::new_from_bytes(
                &buf.as_slice()[entry_offset..entry_offset + PartitionTableEntry::size()],
            )
            .map_err(|e| anyhow::format_err!("{}", e))?;
            if entry.is_used() {
                self.entries[i] = entry;
                self.num_entries += 1;
            } else {
                break;
            }
        }
        debug!("Loaded Partition Table: {}", self);

        Ok(self)
    }

    /// Write the partition table to persistent storage.
    pub fn persist(&self) -> Result<(), String> {
        if self.num_entries == 0 {
            return Err("Partition table empty".to_string());
        }
        self.ensure_enough_persistent_storage_allocated()?;

        let mut buf = vec![0; Self::size()];
        buf.as_mut_slice()[..PartitionTableHeader::size()]
            .copy_from_slice(&self.header.magic_bytes);
        for i in 0..self.entries.len() {
            let offset = PartitionTableHeader::size() + i * PartitionTableEntry::size();
            let entry_slice = &mut buf.as_mut_slice()[offset..offset + PartitionTableEntry::size()];
            entry_slice.copy_from_slice(&self.entries[i].to_bytes());
        }

        persistent_storage_write64(PARTITION_TABLE_START_OFFSET, buf.as_slice());
        info!(
            "Wrote {} bytes of partition table to persistent storage at LBA {}",
            buf.len(),
            PARTITION_TABLE_START_OFFSET
        );
        Ok(())
    }

    pub fn add_new_entry(&mut self, entry: PartitionTableEntry) -> Result<(), String> {
        if self.num_entries + 1 >= self.entries.len() as u16 {
            return Err(format!("Partition table full: {}", self.num_entries));
        }
        self.entries[self.num_entries as usize] = entry;
        self.num_entries += 1;
        Ok(())
    }

    pub fn ensure_enough_persistent_storage_allocated(&self) -> Result<(), String> {
        let persistent_storage_bytes_before = persistent_storage_size_bytes();
        info!(
            "current persistent storage size in bytes: {}",
            persistent_storage_bytes_before
        );
        let new_pages = calc_needed_pages(
            persistent_storage_bytes_before,
            PARTITION_TABLE_START_OFFSET + Self::size() as u64,
        );
        if new_pages > 0 {
            persistent_storage_grow64(new_pages)?;
            let persistent_storage_bytes_after = persistent_storage_size_bytes();
            info!(
                "persistent storage resized to bytes: {}",
                persistent_storage_bytes_after
            );
        } else {
            info!("persistent storage is sufficiently large");
        }
        Ok(())
    }
}

impl std::fmt::Display for PartitionTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Partition table: num_entries: {}, header: {}",
            self.num_entries,
            if self.header.magic_bytes == EXPECTED_MAGIC_BYTES {
                "VALID"
            } else {
                "INVALID"
            }
        )?;
        for entry in self.entries.iter() {
            if !entry.is_used() {
                break;
            }
            write!(f, "\n\t{}", entry)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! default_partition_table {
    ( $( $name:ident => $size:expr ),* ) => {
        lazy_static::lazy_static! {
            pub static ref PARTITIONS: $crate::partition_table::PartitionTable =
                match $crate::partition_table::PartitionTable::new().read_from_persistent_storage() {
                    Ok(partition_table) => {
                        partition_table
                    }
                    Err(err) => {
                        warn!("Failed to read partition table: {}", err);
                        let mut _start_lba = PARTITION_TABLE_START_OFFSET;
                        let mut table = $crate::partition_table::PartitionTable::new();
                        $(
                            let mut buffer = [0u8; 16];
                            let bytes = stringify!($name).as_bytes();

                            // Copy the bytes from the string slice to the buffer
                            // It copies either the whole string if it's shorter than 16 bytes,
                            // or the first 16 bytes if it's longer.
                            buffer[..bytes.len().min(16)].copy_from_slice(&bytes[..16.min(bytes.len())]);
                            table.add_new_entry($crate::partition_table::PartitionTableEntry::new(buffer, _start_lba, _start_lba + $size)).expect("Failed to add a PartitionTableEntry");
                            _start_lba += $size;
                        )*
                        table.persist().expect("Failed to persist partition table");
                        table
                    }
                };
        }
    };
}

default_partition_table![
    RESERVED => 64 * 1024,
    METADATA => 256 * 1024,
    DATA => 100 * 1024 * 1024
];

pub const PART_RESERVED: usize = 0;
pub const PART_METADATA: usize = 1;
pub const PART_DATA: usize = 2;

fn get_partition_by_num(partnum: usize) -> PartitionTableEntry {
    PARTITIONS.entries[partnum]
}

pub fn get_metadata_partition() -> PartitionTableEntry {
    get_partition_by_num(PART_METADATA)
}

pub fn get_data_partition() -> PartitionTableEntry {
    get_partition_by_num(PART_DATA)
}

pub fn get_partition_table() -> PartitionTable {
    PARTITIONS.clone()
}

pub fn persist() {
    PARTITIONS.persist().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_needed_pages() {
        assert_eq!(calc_needed_pages(0, 1000), 1);
        assert_eq!(calc_needed_pages(500, 1000), 1);
        assert_eq!(calc_needed_pages(1000, 1000), 0);
    }

    #[test]
    fn test_partition_table_header_default() {
        let header = PartitionTableHeader::default();
        assert_eq!(header.magic_bytes, EXPECTED_MAGIC_BYTES);
    }
}
