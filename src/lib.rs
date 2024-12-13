//! This module implements a key-value storage system called LedgerMap.
//!
//! The LedgerMap struct provides methods for inserting, deleting, and retrieving key-value entries.
//! It journals the entries in a binary file on x86-64 systems or in stable memory in the
//! Internet Computer canister. Each entry is appended to the file along with its length,
//! allowing efficient retrieval and updates.
//!
//! The LedgerMap struct maintains an in-memory index of the entries for quick lookups. It uses a HashMap (IndexMap)
//! to store the entries, where the key is an enum value representing the label of the entry, and the value
//! is an IndexMap of key-value pairs.
//!
//! The LedgerMap struct also maintains metadata to keep track of the number of entries, the last offset
//! in the persistent storage, and the chain (a.k.a root) hash of the ledger.
//!
//! The LedgerMap struct provides methods for inserting and deleting entries, as well as iterating over the entries
//! by label or in raw form. It also supports re-reading the in-memory index and metadata from the binary file.
//!
//! Entries of LedgerMap are stored in blocks. Each block contains a vector of entries, and the block is committed
//! to the binary file when the user calls the commit_block method. A block also contains metadata such as the
//! offset of block in the persistent storage, the timestamp, and the parent hash.
//!
//! Example usage:
//!
//! ```rust
//! use ledger_map::{LedgerMap};
//! use env_logger::Env;
//!
//! // Set log level to info by default
//! env_logger::try_init_from_env(Env::default().default_filter_or("info")).unwrap();
//!
//! // Optional: Use custom file path for the persistent storage
//! let ledger_path = None;
//! // let ledger_path = Some(std::path::PathBuf::from("/tmp/ledger_map/test_data.bin"));
//!
//! // Create a new LedgerMap instance
//! let mut ledger_map = LedgerMap::new_with_path(None, ledger_path).expect("Failed to create LedgerMap");
//!
//! // Insert a few new entries, each with a separate label
//! ledger_map.upsert("Label1", b"key1".to_vec(), b"value1".to_vec()).unwrap();
//! ledger_map.upsert("Label2", b"key2".to_vec(), b"value2".to_vec()).unwrap();
//! ledger_map.commit_block().unwrap();
//!
//! // Retrieve all entries
//! let entries = ledger_map.iter(None).collect::<Vec<_>>();
//! println!("All entries: {:?}", entries);
//! // Only entries with the Label1 label
//! let entries = ledger_map.iter(Some("Label1")).collect::<Vec<_>>();
//! println!("Label1 entries: {:?}", entries);
//! // Only entries with the Label2 label
//! let entries = ledger_map.iter(Some("Label2")).collect::<Vec<_>>();
//! println!("Label2 entries: {:?}", entries);
//!
//! // Delete an entry
//! ledger_map.delete("Label1", b"key1".to_vec()).unwrap();
//! ledger_map.commit_block().unwrap();
//! // Label1 entries are now empty
//! assert_eq!(ledger_map.iter(Some("Label1")).count(), 0);
//! // Label2 entries still exist
//! assert_eq!(ledger_map.iter(Some("Label2")).count(), 1);
//! ```

#[cfg(target_arch = "wasm32")]
pub mod platform_specific_wasm32;
#[cfg(target_arch = "wasm32")]
use ic_cdk::println;
use ledger_entry::LedgerBlockHeader;
#[cfg(target_arch = "wasm32")]
pub use platform_specific_wasm32 as platform_specific;

#[cfg(target_arch = "x86_64")]
pub mod platform_specific_x86_64;
#[cfg(target_arch = "x86_64")]
pub use platform_specific::{debug, error, info, warn};
#[cfg(target_arch = "x86_64")]
pub use platform_specific_x86_64 as platform_specific;

pub mod ledger_entry;
pub mod partition_table;

use crate::platform_specific::{
    persistent_storage_read, persistent_storage_size_bytes, persistent_storage_write,
};
pub use platform_specific::{export_debug, export_error, export_info, export_warn};

use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use indexmap::IndexMap;
pub use ledger_entry::{EntryKey, EntryValue, LedgerBlock, LedgerEntry, Operation};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, fmt::Debug};
use std::{collections::HashSet, hash::BuildHasherDefault};

pub type AHashSet<K> = HashSet<K, BuildHasherDefault<ahash::AHasher>>;

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MetadataV1 {
    /// The number of blocks in the ledger so far.
    num_blocks: usize,
    /// The offset in the persistent storage where the previous-to-tip block was written.
    prev_block_start_pos: Option<u64>,
    /// The chain hash of the entire ledger.
    tip_block_chain_hash: Vec<u8>,
    /// The timestamp of the last block
    tip_block_timestamp_ns: u64,
    /// The offset in the persistent storage where the tip (last completed) block is written.
    tip_block_start_pos: Option<u64>,
    /// The offset in the persistent storage where the next block will be written.
    next_block_start_pos: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Metadata {
    V1(MetadataV1),
}

impl Default for Metadata {
    fn default() -> Self {
        let next_block_start_pos = partition_table::get_data_partition().start_lba;
        debug!("next_block_start_pos: 0x{:0x}", next_block_start_pos);
        Metadata::V1(MetadataV1 {
            num_blocks: 0,
            prev_block_start_pos: None,
            tip_block_chain_hash: Vec::new(),
            tip_block_timestamp_ns: 0,
            tip_block_start_pos: Some(next_block_start_pos),
            next_block_start_pos,
        })
    }
}

impl Metadata {
    pub fn new() -> Self {
        Metadata::default()
    }

    pub fn clear(&mut self) {
        *self = Metadata::default();
    }

    pub fn num_blocks(&self) -> usize {
        match self {
            Metadata::V1(metadata) => metadata.num_blocks,
        }
    }

    pub fn prev_block_start_pos(&self) -> Option<u64> {
        match self {
            Metadata::V1(metadata) => metadata.prev_block_start_pos,
        }
    }

    pub fn tip_block_chain_hash(&self) -> &[u8] {
        match self {
            Metadata::V1(metadata) => metadata.tip_block_chain_hash.as_slice(),
        }
    }

    pub fn tip_block_timestamp_ns(&self) -> u64 {
        match self {
            Metadata::V1(metadata) => metadata.tip_block_timestamp_ns,
        }
    }

    pub fn tip_block_start_pos(&self) -> Option<u64> {
        match self {
            Metadata::V1(metadata) => metadata.tip_block_start_pos,
        }
    }

    pub fn next_block_start_pos(&self) -> u64 {
        match self {
            Metadata::V1(metadata) => metadata.next_block_start_pos,
        }
    }

    pub fn update_from_appended_block(
        &mut self,
        new_chain_hash: &[u8],
        block_timestamp_ns: u64,
        next_block_start_pos: u64,
    ) {
        match self {
            Metadata::V1(metadata) => {
                metadata.num_blocks += 1;
                metadata.prev_block_start_pos = metadata.tip_block_start_pos;
                metadata.tip_block_chain_hash = new_chain_hash.to_vec();
                metadata.tip_block_timestamp_ns = block_timestamp_ns;
                metadata.tip_block_start_pos = Some(metadata.next_block_start_pos);
                metadata.next_block_start_pos = next_block_start_pos;
            }
        }
    }

    fn get_last_block_chain_hash(&self) -> &[u8] {
        match self {
            Metadata::V1(metadata) => metadata.tip_block_chain_hash.as_slice(),
        }
    }

    fn get_last_block_timestamp_ns(&self) -> u64 {
        match self {
            Metadata::V1(metadata) => metadata.tip_block_timestamp_ns,
        }
    }
}

#[derive(Debug)]
pub struct LedgerMap {
    metadata: RefCell<Metadata>,
    labels_to_index: Option<AHashSet<String>>,
    entries: IndexMap<String, IndexMap<EntryKey, LedgerEntry>>,
    next_block_entries: IndexMap<String, IndexMap<EntryKey, LedgerEntry>>,
    current_timestamp_nanos: fn() -> u64,
}

impl LedgerMap {
    /// Create a new LedgerMap instance.
    /// If `labels_to_index` is `None`, then all labels will be indexed.
    /// Note that iterating over non-indexed labels will not be possible through .iter()
    pub fn new(labels_to_index: Option<Vec<String>>) -> anyhow::Result<Self> {
        let mut result = LedgerMap {
            metadata: RefCell::new(Metadata::new()),
            labels_to_index: labels_to_index.map(AHashSet::from_iter),
            entries: IndexMap::new(),
            next_block_entries: IndexMap::new(),
            current_timestamp_nanos: platform_specific::get_timestamp_nanos,
        };
        result.refresh_ledger()?;
        Ok(result)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn new_with_path(
        labels_to_index: Option<Vec<String>>,
        path: Option<std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        platform_specific::set_backing_file(path).map_err(|e| anyhow::format_err!("{:?}", e))?;
        Self::new(labels_to_index)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_file_path(&self) -> Option<std::path::PathBuf> {
        platform_specific::get_backing_file_path()
    }

    #[cfg(test)]
    fn with_timestamp_fn(self, get_timestamp_nanos: fn() -> u64) -> Self {
        LedgerMap {
            current_timestamp_nanos: get_timestamp_nanos,
            ..self
        }
    }

    pub fn begin_block(&mut self) -> anyhow::Result<()> {
        if !&self.next_block_entries.is_empty() {
            return Err(anyhow::format_err!("There is already an open transaction."));
        } else {
            self.next_block_entries.clear();
        }
        Ok(())
    }

    pub fn commit_block(&mut self) -> anyhow::Result<()> {
        if self.next_block_entries.is_empty() {
            // debug!("Commit of empty block invoked, skipping");
        } else {
            info!(
                "Commit non-empty block, with {} entries",
                self.next_block_entries.len()
            );
            let mut block_entries = Vec::new();
            for (label, values) in self.next_block_entries.iter() {
                if match &self.labels_to_index {
                    Some(labels_to_index) => labels_to_index.contains(label),
                    None => true,
                } {
                    self.entries
                        .entry(label.clone())
                        .or_default()
                        .extend(values.clone())
                };
                for (_key, entry) in values.iter() {
                    block_entries.push(entry.clone());
                }
            }
            let block_timestamp = (self.current_timestamp_nanos)();
            let parent_hash = self.metadata.borrow().get_last_block_chain_hash().to_vec();
            let block = LedgerBlock::new(block_entries, block_timestamp, parent_hash);
            self._persist_block(block)?;
            self.next_block_entries.clear();
        }
        Ok(())
    }

    pub fn get<S: AsRef<str>>(&self, label: S, key: &[u8]) -> Result<EntryValue, LedgerError> {
        fn lookup<'a>(
            map: &'a IndexMap<String, IndexMap<EntryKey, LedgerEntry>>,
            label: &String,
            key: &[u8],
        ) -> Option<&'a LedgerEntry> {
            match map.get(label) {
                Some(entries) => entries.get(key),
                None => None,
            }
        }

        let label = label.as_ref().to_string();
        for map in [&self.next_block_entries, &self.entries] {
            if let Some(entry) = lookup(map, &label, key) {
                match entry.operation() {
                    Operation::Upsert => {
                        return Ok(entry.value().to_vec());
                    }
                    Operation::Delete => {
                        return Err(LedgerError::EntryNotFound);
                    }
                }
            }
        }

        Err(LedgerError::EntryNotFound)
    }

    pub fn upsert<S: AsRef<str>, K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        label: S,
        key: K,
        value: V,
    ) -> Result<(), LedgerError> {
        self._insert_entry_into_next_block(label, key, value, Operation::Upsert)
    }

    pub fn delete<S: AsRef<str>, K: AsRef<[u8]>>(
        &mut self,
        label: S,
        key: K,
    ) -> Result<(), LedgerError> {
        self._insert_entry_into_next_block(label, key, Vec::new(), Operation::Delete)
    }

    pub fn refresh_ledger(&mut self) -> anyhow::Result<()> {
        self.metadata.borrow_mut().clear();
        self.entries.clear();
        self.next_block_entries.clear();

        // If the backend is empty or non-existing, just return
        if persistent_storage_size_bytes() == 0 {
            warn!("Persistent storage is empty");
            return Ok(());
        }

        let data_part_entry = partition_table::get_data_partition();
        if persistent_storage_size_bytes() < data_part_entry.start_lba {
            warn!("No data found in persistent storage");
            return Ok(());
        }

        let mut expected_parent_hash = Vec::new();
        let mut updates = Vec::new();
        // Step 1: Read all Ledger Blocks
        for entry in self.iter_raw() {
            let (block_header, ledger_block) = entry?;

            if ledger_block.parent_hash() != expected_parent_hash {
                return Err(anyhow::format_err!(
                    "Hash mismatch: expected parent hash {:?}, got {:?}",
                    expected_parent_hash,
                    ledger_block.parent_hash()
                ));
            };

            let new_chain_hash = Self::_compute_block_chain_hash(
                ledger_block.parent_hash(),
                ledger_block.entries(),
                ledger_block.timestamp(),
            )?;

            let next_block_start_pos = self.metadata.borrow().next_block_start_pos()
                + block_header.jump_bytes_next_block() as u64;
            self.metadata.borrow_mut().update_from_appended_block(
                &new_chain_hash,
                ledger_block.timestamp(),
                next_block_start_pos,
            );
            expected_parent_hash = new_chain_hash;

            updates.push(ledger_block);
        }

        // Step 2: Add ledger entries into the index (self.entries) for quick search
        for ledger_block in updates.into_iter() {
            for ledger_entry in ledger_block.entries() {
                // Skip entries that are not in the labels_to_index
                if !match &self.labels_to_index {
                    Some(labels_to_index) => labels_to_index.contains(ledger_entry.label()),
                    None => true,
                } {
                    continue;
                }
                let entries = match self.entries.get_mut(ledger_entry.label()) {
                    Some(entries) => entries,
                    None => {
                        let new_map = IndexMap::new();
                        self.entries
                            .insert(ledger_entry.label().to_string(), new_map);
                        self.entries
                            .get_mut(ledger_entry.label())
                            .ok_or(anyhow::format_err!(
                                "Entry label {:?} not found",
                                ledger_entry.label()
                            ))?
                    }
                };

                match &ledger_entry.operation() {
                    Operation::Upsert => {
                        entries.insert(ledger_entry.key().to_vec(), ledger_entry.clone());
                    }
                    Operation::Delete => {
                        entries.swap_remove(&ledger_entry.key().to_vec());
                    }
                }
            }
        }
        info!("Ledger refreshed successfully");

        Ok(())
    }

    pub fn next_block_iter(&self, label: Option<&str>) -> impl Iterator<Item = &LedgerEntry> {
        match label {
            Some(label) => self
                .next_block_entries
                .get(label)
                .map(|entries| entries.values())
                .unwrap_or_default()
                .filter(|entry| entry.operation() == Operation::Upsert)
                .collect::<Vec<_>>()
                .into_iter(),
            None => self
                .next_block_entries
                .values()
                .flat_map(|entries| entries.values())
                .filter(|entry| entry.operation() == Operation::Upsert)
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    pub fn iter(&self, label: Option<&str>) -> impl Iterator<Item = &LedgerEntry> {
        match label {
            Some(label) => self
                .entries
                .get(label)
                .map(|entries| entries.values())
                .unwrap_or_default()
                .filter(|entry| entry.operation() == Operation::Upsert)
                .collect::<Vec<_>>()
                .into_iter(),
            None => self
                .entries
                .values()
                .flat_map(|entries| entries.values())
                .filter(|entry| entry.operation() == Operation::Upsert)
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    pub fn iter_raw(
        &self,
    ) -> impl Iterator<Item = anyhow::Result<(LedgerBlockHeader, LedgerBlock)>> + '_ {
        let data_start = partition_table::get_data_partition().start_lba;
        (0..).scan(data_start, |state, _| {
            let (block_header, ledger_block) = match self._persisted_block_read(*state) {
                Ok(decoded) => decoded,
                Err(LedgerError::BlockEmpty) => return None,
                Err(LedgerError::BlockCorrupted(err)) => {
                    return Some(Err(anyhow::format_err!(
                        "Failed to read Ledger block: {}",
                        err
                    )))
                }
                Err(err) => {
                    return Some(Err(anyhow::format_err!(
                        "Failed to read Ledger block: {}",
                        err
                    )))
                }
            };
            *state += block_header.jump_bytes_next_block() as u64;
            Some(Ok((block_header, ledger_block)))
        })
    }

    pub fn get_blocks_count(&self) -> usize {
        self.metadata.borrow().num_blocks()
    }

    pub fn get_latest_block_hash(&self) -> Vec<u8> {
        self.metadata.borrow().get_last_block_chain_hash().to_vec()
    }

    pub fn get_latest_block_timestamp_ns(&self) -> u64 {
        self.metadata.borrow().get_last_block_timestamp_ns()
    }

    pub fn get_next_block_start_pos(&self) -> u64 {
        self.metadata.borrow().next_block_start_pos()
    }

    pub fn get_next_block_entries_count(&self, label: Option<&str>) -> usize {
        self.next_block_iter(label).count()
    }

    fn _compute_block_chain_hash(
        parent_block_hash: &[u8],
        block_entries: &[LedgerEntry],
        block_timestamp: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(parent_block_hash);
        for entry in block_entries.iter() {
            hasher.update(to_vec(entry)?);
        }
        hasher.update(block_timestamp.to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }

    fn _persist_block(&self, ledger_block: LedgerBlock) -> anyhow::Result<()> {
        let block_serialized_data = ledger_block.serialize()?;
        info!(
            "Appending block @timestamp {} with {} bytes data: {}",
            ledger_block.timestamp(),
            block_serialized_data.len(),
            ledger_block
        );
        // Prepare block header
        let jump_bytes_prev_block = (self
            .metadata
            .borrow()
            .tip_block_start_pos()
            .unwrap_or_default() as i64
            - self.metadata.borrow().next_block_start_pos() as i64)
            as i32;
        let jump_bytes_next_block =
            (block_serialized_data.len() + LedgerBlockHeader::sizeof()) as u32;
        let serialized_block_header =
            LedgerBlockHeader::new(jump_bytes_prev_block, jump_bytes_next_block).serialize()?;

        // First persist block header
        persistent_storage_write(
            self.metadata.borrow().next_block_start_pos(),
            &serialized_block_header,
        );

        // Then persist block data
        persistent_storage_write(
            self.metadata.borrow().next_block_start_pos() + LedgerBlockHeader::sizeof() as u64,
            &block_serialized_data,
        );

        let new_chain_hash = Self::_compute_block_chain_hash(
            ledger_block.parent_hash(),
            ledger_block.entries(),
            ledger_block.timestamp(),
        )?;
        let next_block_start_pos =
            self.metadata.borrow().next_block_start_pos() + jump_bytes_next_block as u64;
        self.metadata.borrow_mut().update_from_appended_block(
            &new_chain_hash,
            ledger_block.timestamp(),
            next_block_start_pos,
        );

        // Finally, persist 0u32 to mark the end of the block chain
        persistent_storage_write(
            self.metadata.borrow().next_block_start_pos() + jump_bytes_next_block as u64,
            &[0u8; size_of::<u32>()],
        );
        Ok(())
    }

    fn _persisted_block_read(
        &self,
        offset: u64,
    ) -> Result<(LedgerBlockHeader, LedgerBlock), LedgerError> {
        // Find out how many bytes we need to read ==> block len in bytes
        let mut buf = [0u8; size_of::<LedgerBlockHeader>()];
        persistent_storage_read(offset, &mut buf)
            .map_err(|e| LedgerError::BlockCorrupted(e.to_string()))?;

        let block_header = LedgerBlockHeader::deserialize(buf.as_ref())?;
        let block_len_bytes = block_header.jump_bytes_next_block();

        debug!(
            "Reading persisted block of {} bytes at offset 0x{:0x}",
            block_len_bytes, offset
        );

        // Read the block as raw bytes
        let mut buf = vec![0u8; block_len_bytes as usize];
        persistent_storage_read(offset + LedgerBlockHeader::sizeof() as u64, &mut buf)
            .map_err(|e| LedgerError::Other(e.to_string()))?;

        let block = LedgerBlock::deserialize(buf.as_ref(), block_header.block_version())
            .map_err(|err| LedgerError::BlockCorrupted(err.to_string()))?;

        Ok((block_header, block))
    }

    fn _insert_entry_into_next_block<S: AsRef<str>, K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        label: S,
        key: K,
        value: V,
        operation: Operation,
    ) -> Result<(), LedgerError> {
        let entry = LedgerEntry::new(label.as_ref(), key, value, operation);
        match self.next_block_entries.get_mut(entry.label()) {
            Some(entries) => {
                entries.insert(entry.key().to_vec(), entry);
            }
            None => {
                let mut new_map = IndexMap::new();
                new_map.insert(entry.key().to_vec(), entry);
                self.next_block_entries
                    .insert(label.as_ref().to_string(), new_map);
            }
        };

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum LedgerError {
    EntryNotFound,
    BlockEmpty,
    BlockCorrupted(String),
    Other(String),
}

impl<E: std::error::Error> From<E> for LedgerError {
    fn from(error: E) -> Self {
        LedgerError::Other(error.to_string())
    }
}

impl From<LedgerError> for anyhow::Error {
    fn from(error: LedgerError) -> Self {
        anyhow::anyhow!(error)
    }
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::EntryNotFound => write!(f, "Entry not found"),
            LedgerError::BlockEmpty => write!(f, "Block is empty"),
            LedgerError::BlockCorrupted(err) => write!(f, "Block corrupted: {}", err),
            LedgerError::Other(err) => write!(f, "Other error: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    fn log_init() {
        // Set log level to info by default
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "info");
        }
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn new_temp_ledger(labels_to_index: Option<Vec<String>>) -> LedgerMap {
        log_init();
        info!("Create temp ledger");
        // Create a temporary directory for the test
        let file_path = tempfile::tempdir()
            .unwrap()
            .into_path()
            .join("test_ledger_store.bin");

        fn mock_get_timestamp_nanos() -> u64 {
            0
        }

        LedgerMap::new_with_path(labels_to_index, Some(file_path))
            .expect("Failed to create a temp ledger for the test")
            .with_timestamp_fn(mock_get_timestamp_nanos)
    }

    #[test]
    fn test_compute_cumulative_hash() {
        let parent_hash = vec![0, 1, 2, 3];
        let key = vec![4, 5, 6, 7];
        let value = vec![8, 9, 10, 11];
        let ledger_block = LedgerBlock::new(
            vec![LedgerEntry::new(
                "Label2",
                key.clone(),
                value.clone(),
                Operation::Upsert,
            )],
            0,
            vec![],
        );
        let cumulative_hash = LedgerMap::_compute_block_chain_hash(
            &parent_hash,
            ledger_block.entries(),
            ledger_block.timestamp(),
        )
        .unwrap();

        // Cumulative hash is a sha256 hash of the parent hash, key, and value
        // Obtained from a reference run
        assert_eq!(
            cumulative_hash,
            vec![
                21, 5, 93, 78, 94, 126, 142, 35, 221, 131, 204, 67, 57, 54, 102, 107, 225, 68, 197,
                244, 204, 60, 238, 250, 126, 8, 240, 137, 84, 55, 3, 91
            ]
        );
    }

    #[test]
    fn test_upsert() {
        let mut ledger_map = new_temp_ledger(None);

        // Test upsert
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label2", key.clone(), value.clone())
            .unwrap();
        println!("partition table {}", partition_table::get_partition_table());
        assert_eq!(ledger_map.get("Label2", &key).unwrap(), value);
        assert!(ledger_map.commit_block().is_ok());
        assert_eq!(ledger_map.get("Label2", &key).unwrap(), value);
        let entries = ledger_map.entries.get("Label2").unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&LedgerEntry::new("Label2", key, value, Operation::Upsert,))
        );
        assert_eq!(ledger_map.metadata.borrow().num_blocks(), 1);
        assert!(ledger_map.next_block_entries.is_empty());
    }

    #[test]
    fn test_upsert_with_matching_entry_label() {
        let mut ledger_map = new_temp_ledger(None);

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label1", key.clone(), value.clone())
            .unwrap();
        assert_eq!(ledger_map.entries.get("Label1"), None); // value not committed yet
        assert_eq!(ledger_map.get("Label1", &key).unwrap(), value);
        ledger_map.commit_block().unwrap();
        let entries = ledger_map.entries.get("Label1").unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&LedgerEntry::new(
                "Label1",
                key.clone(),
                value.clone(),
                Operation::Upsert,
            ))
        );
    }

    #[test]
    fn test_upsert_with_mismatched_entry_label() {
        let mut ledger_map = new_temp_ledger(None);

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label2", key.clone(), value.clone())
            .unwrap();

        // Ensure that the entry is not added to the NodeProvider ledger since the label doesn't match
        assert_eq!(ledger_map.entries.get("Label1"), None);
    }

    #[test]
    fn test_delete_with_matching_entry_label() {
        let mut ledger_map = new_temp_ledger(None);

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label1", key.clone(), value.clone())
            .unwrap();
        assert_eq!(ledger_map.get("Label1", &key).unwrap(), value); // Before delete: the value is there
        ledger_map.delete("Label1", key.clone()).unwrap();
        let expected_tombstone = Some(LedgerEntry::new(
            "Label1",
            key.clone(),
            vec![],
            Operation::Delete,
        ));
        assert_eq!(
            ledger_map.get("Label1", &key).unwrap_err(),
            LedgerError::EntryNotFound
        ); // After delete: the value is gone in the public interface
        assert_eq!(
            ledger_map
                .next_block_entries
                .get("Label1")
                .unwrap()
                .get(&key),
            expected_tombstone.as_ref()
        );
        assert_eq!(ledger_map.entries.get("Label1"), None); // (not yet committed)

        // Now commit the block
        assert!(ledger_map.commit_block().is_ok());

        // And recheck: the value is gone in the public interface and deletion is in the ledger
        assert_eq!(
            ledger_map.entries.get("Label1").unwrap().get(&key),
            expected_tombstone.as_ref()
        );
        assert_eq!(ledger_map.next_block_entries.get("Label1"), None);
        assert_eq!(
            ledger_map.get("Label1", &key).unwrap_err(),
            LedgerError::EntryNotFound
        );
    }

    #[test]
    fn test_delete_with_mismatched_entry_label() {
        let mut ledger_map = new_temp_ledger(None);

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label1", key.clone(), value.clone())
            .unwrap();
        ledger_map.get("Label1", &key).unwrap();
        assert!(ledger_map.entries.get("Label1").is_none()); // the value is not yet committed
        ledger_map.commit_block().unwrap();
        ledger_map.entries.get("Label1").unwrap();
        ledger_map.delete("Label2", key.clone()).unwrap();

        // Ensure that the entry is not deleted from the ledger since the label doesn't match
        let entries_np = ledger_map.entries.get("Label1").unwrap();
        assert_eq!(
            entries_np.get(&key),
            Some(&LedgerEntry::new(
                "Label1",
                key.clone(),
                value.clone(),
                Operation::Upsert,
            ))
        );
        assert_eq!(ledger_map.entries.get("Label2"), None);
    }

    #[test]
    fn test_labels_to_index() {
        let mut ledger_map = new_temp_ledger(Some(vec!["Label1".to_string()]));

        let key = b"test_key".to_vec();
        let value1 = b"test_value1".to_vec();
        let value2 = b"test_value2".to_vec();
        ledger_map
            .upsert("Label1", key.clone(), value1.clone())
            .unwrap();
        ledger_map
            .upsert("Label2", key.clone(), value2.clone())
            .unwrap();
        assert!(ledger_map.entries.get("Label1").is_none()); // the value is not yet committed
        assert!(ledger_map.entries.get("Label2").is_none()); // the value is not yet committed
        ledger_map.commit_block().unwrap();
        assert_eq!(ledger_map.get("Label1", &key).unwrap(), value1);
        assert_eq!(
            ledger_map.get("Label2", &key).unwrap_err(),
            LedgerError::EntryNotFound
        );
        // Delete the non-indexed entry, ensure that the indexed entry is still there
        ledger_map.delete("Label2", key.clone()).unwrap();
        assert_eq!(ledger_map.get("Label1", &key).unwrap(), value1);
        assert_eq!(
            ledger_map.get("Label2", &key).unwrap_err(),
            LedgerError::EntryNotFound
        );
        // Delete the indexed entry, ensure that it's gone
        ledger_map.delete("Label1", key.clone()).unwrap();
        assert_eq!(
            ledger_map.get("Label1", &key).unwrap_err(),
            LedgerError::EntryNotFound
        );
        assert_eq!(
            ledger_map.get("Label2", &key).unwrap_err(),
            LedgerError::EntryNotFound
        );
    }

    #[test]
    fn test_delete() {
        let mut ledger_map = new_temp_ledger(None);

        // Test delete
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label2", key.clone(), value.clone())
            .unwrap();
        ledger_map.delete("Label2", key.clone()).unwrap();
        assert!(ledger_map.commit_block().is_ok());
        let entries = ledger_map.entries.get("Label2").unwrap();
        assert_eq!(
            entries.get(&key),
            Some(LedgerEntry::new(
                "Label2",
                key.clone(),
                vec![],
                Operation::Delete
            ))
            .as_ref()
        );
        assert_eq!(ledger_map.entries.get("Label1"), None);
        assert_eq!(
            ledger_map.get("Label2", &key).unwrap_err(),
            LedgerError::EntryNotFound
        );
    }

    #[test]
    fn test_refresh_ledger() {
        let mut ledger_map = new_temp_ledger(None);

        info!("New temp ledger created");
        info!("ledger: {:?}", ledger_map);

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_map
            .upsert("Label2", key.clone(), value.clone())
            .unwrap();
        assert!(ledger_map.commit_block().is_ok());
        ledger_map.refresh_ledger().unwrap();

        let entry = ledger_map
            .entries
            .get("Label2")
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            entry,
            LedgerEntry::new("Label2", key.clone(), value.clone(), Operation::Upsert)
        );
        let expected_chain_hash = vec![
            245, 142, 15, 179, 87, 133, 107, 164, 123, 16, 145, 52, 243, 153, 170, 45, 177, 243,
            61, 37, 162, 237, 226, 100, 94, 136, 159, 73, 117, 58, 222, 153,
        ];
        assert_eq!(
            ledger_map.metadata.borrow().tip_block_chain_hash(),
            expected_chain_hash
        );
        assert_eq!(ledger_map.get_latest_block_hash(), expected_chain_hash);
    }

    #[test]
    fn test_ledger_block_offsets() {
        // Create a new ledger
        let mut ledger_map = new_temp_ledger(None);

        // Create some dummy entries
        ledger_map.upsert("label1", b"key1", b"value1").unwrap();
        ledger_map.commit_block().unwrap();
        ledger_map.upsert("label1a", b"key2a", b"value2aa").unwrap();
        ledger_map.commit_block().unwrap();
        ledger_map
            .upsert("label1bb", b"key3bbb", b"value3bbbb")
            .unwrap();
        ledger_map.commit_block().unwrap();

        let (headers, blocks): (Vec<_>, Vec<_>) = ledger_map.iter_raw().map(|x| x.unwrap()).unzip();

        let header_len_bytes = headers
            .iter()
            .map(|x| x.serialize().unwrap().len() as u32)
            .collect::<Vec<_>>();
        let blocks_len_bytes = blocks
            .iter()
            .map(|x| x.serialize().unwrap().len() as u32)
            .collect::<Vec<_>>();
        let blk0_bytes = (header_len_bytes[0] + blocks_len_bytes[0]) as u64;
        let blk1_bytes = (header_len_bytes[1] + blocks_len_bytes[1]) as u64;
        let blk2_bytes = (header_len_bytes[2] + blocks_len_bytes[2]) as u64;
        assert_eq!(headers[0].jump_bytes_prev_block(), 0);
        assert_eq!(headers[0].jump_bytes_next_block(), blk0_bytes as u32);

        assert_eq!(headers[1].jump_bytes_prev_block(), -(blk0_bytes as i32));
        assert_eq!(headers[1].jump_bytes_next_block(), blk1_bytes as u32);
        assert_eq!(headers[2].jump_bytes_prev_block(), -(blk1_bytes as i32));
        assert_eq!(headers[2].jump_bytes_next_block(), blk2_bytes as u32);
    }
}
