use crate::LedgerError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};
use flate2::write::ZlibEncoder;
use flate2::{read::ZlibDecoder, Compression};
use std::io;

/// Enum defining the different operations that can be performed on entries.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Operation {
    Upsert,
    Delete,
}

pub type EntryKey = Vec<u8>;
pub type EntryValue = Vec<u8>;

/// Struct representing an entry stored for a particular key in the key-value store.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerEntryV1 {
    label: String,
    key: EntryKey,
    value: EntryValue,
    operation: Operation,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum LedgerEntry {
    V1(LedgerEntryV1),
}

impl LedgerEntry {
    pub fn new<S: AsRef<str>, K: AsRef<[u8]>, V: AsRef<[u8]>>(
        label: S,
        key: K,
        value: V,
        operation: Operation,
    ) -> Self {
        LedgerEntry::V1(LedgerEntryV1 {
            label: label.as_ref().to_string(),
            key: key.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
            operation,
        })
    }

    pub fn label(&self) -> &str {
        match self {
            LedgerEntry::V1(entry) => &entry.label,
        }
    }

    pub fn key(&self) -> &[u8] {
        match self {
            LedgerEntry::V1(entry) => &entry.key,
        }
    }

    pub fn value(&self) -> &[u8] {
        match self {
            LedgerEntry::V1(entry) => &entry.value,
        }
    }

    pub fn operation(&self) -> Operation {
        match self {
            LedgerEntry::V1(entry) => entry.operation,
        }
    }
}

impl std::fmt::Display for LedgerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let key = match String::try_from_slice(self.key()) {
            Ok(v) => v,
            Err(_) => BASE64.encode(self.key()),
        };
        let value = match String::try_from_slice(self.value()) {
            Ok(v) => v,
            Err(_) => BASE64.encode(self.value()),
        };
        write!(f, "[{}] Key: {}, Value: {}", self.label(), key, value)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LedgerBlockHeaderV1 {
    block_version: u32,
    jump_bytes_prev: i32,
    jump_bytes_next: u32,
    reserved: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LedgerBlockHeader {
    V1(LedgerBlockHeaderV1),
}

impl LedgerBlockHeader {
    pub fn new(jump_bytes_prev: i32, jump_bytes_next: u32) -> Self {
        LedgerBlockHeader::V1(LedgerBlockHeaderV1 {
            block_version: 1,
            jump_bytes_prev,
            jump_bytes_next,
            reserved: 0,
        })
    }

    pub const fn sizeof() -> usize {
        size_of::<LedgerBlockHeaderV1>()
    }

    pub fn jump_bytes_prev_block(&self) -> i32 {
        match self {
            LedgerBlockHeader::V1(header) => header.jump_bytes_prev,
        }
    }

    pub fn jump_bytes_next_block(&self) -> u32 {
        match self {
            LedgerBlockHeader::V1(header) => header.jump_bytes_next,
        }
    }

    /// Block header is always serialized to 4x 32-bit integers
    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            LedgerBlockHeader::V1(header) => {
                let mut bytes = [0u8; 16];
                // Copy each field to the "bytes" array, using LE byte order
                bytes[0..4].copy_from_slice(&header.block_version.to_le_bytes());
                bytes[4..8].copy_from_slice(&header.jump_bytes_prev.to_le_bytes());
                bytes[8..12].copy_from_slice(&header.jump_bytes_next.to_le_bytes());
                bytes[12..16].copy_from_slice(&header.reserved.to_le_bytes());
                Ok(bytes.to_vec())
            }
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, LedgerError> {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(data);
        let block_version = u32::from_le_bytes(bytes[0..4].try_into()?);
        match block_version {
            0 => Err(LedgerError::BlockEmpty),
            1 => Ok(LedgerBlockHeader::V1(LedgerBlockHeaderV1 {
                block_version,
                jump_bytes_prev: i32::from_le_bytes(bytes[4..8].try_into()?),
                jump_bytes_next: u32::from_le_bytes(bytes[8..12].try_into()?),
                reserved: u32::from_le_bytes(bytes[12..16].try_into()?),
            })),
            _ => Err(LedgerError::BlockCorrupted(format!(
                "Unsupported block version: {}",
                block_version
            ))),
        }
    }
}

impl std::fmt::Display for LedgerBlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LedgerBlockHeader::V1(header) => write!(f, "{}", header),
        }
    }
}

impl std::fmt::Display for LedgerBlockHeaderV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "block_version: {}, jump_bytes_prev: {}, jump_bytes_next: {}",
            self.block_version, self.jump_bytes_prev, self.jump_bytes_next
        )
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerBlockV1 {
    entries: Vec<LedgerEntry>,
    timestamp: u64,
    parent_hash: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum LedgerBlock {
    V1(LedgerBlockV1),
}

impl LedgerBlock {
    pub fn new(entries: Vec<LedgerEntry>, timestamp: u64, parent_hash: Vec<u8>) -> Self {
        LedgerBlock::V1(LedgerBlockV1 {
            entries,
            timestamp,
            parent_hash,
        })
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        borsh::to_writer(&mut e, self)?;
        e.finish()
    }

    pub fn deserialize(data: &[u8]) -> anyhow::Result<Self> {
        let mut e = ZlibDecoder::new(data);
        let v = borsh::de::from_reader(&mut e)?;
        Ok(v)
    }

    pub fn entries(&self) -> &[LedgerEntry] {
        match self {
            LedgerBlock::V1(block) => &block.entries,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            LedgerBlock::V1(block) => block.timestamp,
        }
    }

    pub fn parent_hash(&self) -> &[u8] {
        match self {
            LedgerBlock::V1(block) => &block.parent_hash,
        }
    }
}

impl std::fmt::Display for LedgerBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "~-=-~-=-~-=-~ Ledger block with timestamp [{}] parent_hash {}  ~-=-~-=-~-=-~",
            self.timestamp(),
            hex::encode(self.parent_hash())
        )?;
        for entry in self.entries() {
            writeln!(f, "{}", entry)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn create_dummy_ledger_entry(seed: u64) -> LedgerEntry {
        let key = seed.to_le_bytes().to_vec();
        let value = (seed + 1).to_le_bytes().to_vec();
        LedgerEntry::new("test_label", key, value, Operation::Upsert)
    }

    #[test]
    fn test_ledger_entry_new() {
        let seed = 42u64;
        let entry = create_dummy_ledger_entry(seed);

        assert_eq!(entry.label(), "test_label");
        assert_eq!(entry.key(), seed.to_le_bytes().to_vec());
        assert_eq!(entry.value(), (seed + 1).to_le_bytes().to_vec());
        assert_eq!(entry.operation(), Operation::Upsert);
    }

    #[test]
    fn test_operation_enum() {
        assert_eq!(Operation::Upsert as u8, 0);
        assert_eq!(Operation::Delete as u8, 1);
    }
}
