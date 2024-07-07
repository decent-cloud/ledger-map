use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};

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

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerBlockV1 {
    entries: Vec<LedgerEntry>,
    offset: u64,
    offset_next: Option<u64>,
    timestamp: u64,
    hash: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum LedgerBlock {
    V1(LedgerBlockV1),
}

impl LedgerBlock {
    pub fn new(
        entries: Vec<LedgerEntry>,
        offset: u64,
        offset_next: Option<u64>,
        timestamp: u64,
        hash: Vec<u8>,
    ) -> Self {
        LedgerBlock::V1(LedgerBlockV1 {
            entries,
            offset,
            offset_next,
            timestamp,
            hash,
        })
    }

    pub fn entries(&self) -> &[LedgerEntry] {
        match self {
            LedgerBlock::V1(block) => &block.entries,
        }
    }

    pub fn offset(&self) -> u64 {
        match self {
            LedgerBlock::V1(block) => block.offset,
        }
    }

    pub fn offset_next(&self) -> Option<u64> {
        match self {
            LedgerBlock::V1(block) => block.offset_next,
        }
    }

    pub fn offset_next_set(&mut self, value: Option<u64>) {
        match self {
            LedgerBlock::V1(block) => block.offset_next = value,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            LedgerBlock::V1(block) => block.timestamp,
        }
    }

    pub fn hash(&self) -> &[u8] {
        match self {
            LedgerBlock::V1(block) => &block.hash,
        }
    }
}

impl std::fmt::Display for LedgerBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[{}] ~-=-~-=-~-=-~ Ledger block at offsets 0x{:x} .. {:x?} hash {}",
            self.timestamp(),
            self.offset(),
            self.offset_next(),
            hex::encode(self.hash())
        )?;
        for entry in self.entries() {
            write!(f, "\n[{}] {}", self.timestamp(), entry)?
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
        LedgerEntry::new("test_label", &key, value, Operation::Upsert)
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
