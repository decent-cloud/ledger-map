/// This module contains functionalities specific to the WebAssembly (WASM) 32-bit platform.
/// It provides implementations and abstractions that are unique to this environment,
/// enabling LedgerMap to run on the Internet Computer Platform, which uses wasm32 for canisters.
///
pub use crate::{debug, error, info, warn}; // created in the crate root by macro_export
pub use ic_canister_log::log;
use ic_canister_log::{declare_log_buffer, export, LogEntry};
use ic_cdk::println;

// Keep up to "capacity" last messages.
declare_log_buffer!(name = DEBUG, capacity = 10000);
declare_log_buffer!(name = INFO, capacity = 10000);
declare_log_buffer!(name = WARN, capacity = 10000);
declare_log_buffer!(name = ERROR, capacity = 10000);

#[macro_export]
macro_rules! debug {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        $crate::platform_specific_wasm32::log!($crate::platform_specific_wasm32::DEBUG, $message $(,$args)*);
    }}
}

#[macro_export]
macro_rules! info {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        $crate::platform_specific_wasm32::log!($crate::platform_specific_wasm32::INFO, $message $(,$args)*);
    }}
}

#[macro_export]
macro_rules! warn {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        $crate::platform_specific_wasm32::log!($crate::platform_specific_wasm32::WARN, $message $(,$args)*);
    }}
}

#[macro_export]
macro_rules! error {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        $crate::platform_specific_wasm32::log!($crate::platform_specific_wasm32::ERROR, $message $(,$args)*);
    }}
}

pub fn export_debug() -> Vec<LogEntry> {
    export(&DEBUG)
}

pub fn export_info() -> Vec<LogEntry> {
    export(&INFO)
}

pub fn export_warn() -> Vec<LogEntry> {
    export(&WARN)
}

pub fn export_error() -> Vec<LogEntry> {
    export(&ERROR)
}

pub const PERSISTENT_STORAGE_PAGE_SIZE: u64 = 64 * 1024;

pub fn persistent_storage_size_bytes() -> u64 {
    ic_cdk::api::stable::stable64_size() * PERSISTENT_STORAGE_PAGE_SIZE
}

pub fn persistent_storage_read64(offset: u64, buf: &mut [u8]) -> anyhow::Result<()> {
    ic_cdk::api::stable::stable64_read(offset, buf);
    Ok(())
}

pub fn persistent_storage_write64(offset: u64, buf: &[u8]) {
    let stable_memory_size_bytes = persistent_storage_size_bytes();
    if stable_memory_size_bytes < offset + buf.len() as u64 {
        let stable_memory_bytes_new = offset + (buf.len() as u64).max(PERSISTENT_STORAGE_PAGE_SIZE);
        persistent_storage_grow64(
            (stable_memory_bytes_new - stable_memory_size_bytes) / PERSISTENT_STORAGE_PAGE_SIZE + 1,
        )
        .unwrap();
    }
    ic_cdk::api::stable::stable64_write(offset, buf)
}

pub fn persistent_storage_grow64(additional_pages: u64) -> Result<u64, String> {
    info!(
        "persistent_storage_grow64: {} additional_pages.",
        additional_pages
    );
    ic_cdk::api::stable::stable64_grow(additional_pages).map_err(|err| format!("{:?}", err))
}

pub(crate) fn get_timestamp_nanos() -> u64 {
    ic_cdk::api::time()
}
