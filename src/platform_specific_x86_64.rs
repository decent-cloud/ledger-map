/// This module contains functionalities specific to the x86_64 architecture.
/// It includes implementations and optimizations tailored for this 64-bit environment,
/// allowing LedgerMap to run on x86_64 platforms and share most of the code with
/// the wasm32 platform.
///
use std::io::{Read as _, Seek as _, Write as _};
use std::path::PathBuf;

use fs_err as fs;
use fs_err::{File, OpenOptions};
pub use log::{debug, error, info, warn};

#[derive(Default)]
struct BackingFile {
    file: Option<File>,
    file_path: PathBuf,
}

impl BackingFile {
    pub fn new(file_path: Option<PathBuf>) -> Self {
        let mut backing_file = BackingFile::default();
        backing_file.change_backing_file(file_path);
        backing_file
    }

    pub fn change_backing_file(&mut self, file_path: Option<PathBuf>) {
        let file_path = file_path.unwrap_or_else(|| match dirs::data_local_dir() {
            Some(path) => path.join("ledger-map").join("data.bin"),
            None => PathBuf::from("data.bin"),
        });
        info!("Using persistent storage: {:?}", file_path);
        fs::create_dir_all(file_path.parent().expect("Could not find parent directory")).unwrap();
        self.file = Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&file_path)
                .expect("failed to open a backing file"),
        );
        self.file_path = file_path;
    }
}

thread_local! {
    pub static BACKING_FILE: std::cell::RefCell<BackingFile> =
        std::cell::RefCell::new(BackingFile::new(None));
}

pub fn override_backing_file(file_path: Option<PathBuf>) {
    BACKING_FILE.with(|backing_file| backing_file.borrow_mut().change_backing_file(file_path));
}

pub fn persistent_storage_size_bytes() -> u64 {
    BACKING_FILE.with(|backing_file| match backing_file.borrow().file.as_ref() {
        Some(file) => match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                error!("Failed to get metadata: {}", err);
                0
            }
        },
        None => 0,
    })
}

pub fn persistent_storage_read64(offset: u64, buf: &mut [u8]) -> anyhow::Result<()> {
    BACKING_FILE.with(
        |backing_file| match backing_file.borrow_mut().file.as_mut() {
            Some(file) => {
                let file_size_bytes = file.metadata().unwrap().len();
                debug!(
                    "Reading from persistent storage {:?} @ 0x{:0x} .. 0x{:0x}",
                    file.path(),
                    offset,
                    offset + buf.len() as u64
                );
                if offset + buf.len() as u64 > file_size_bytes {
                    return Err(anyhow::format_err!(
                        "Failed to read from persistent storage: read beyond end of file."
                    ));
                }
                file.seek(std::io::SeekFrom::Start(offset)).unwrap();
                file.read_exact(buf).unwrap();
                debug!("Read bytes: {:?}", buf);
                Ok(())
            }
            None => Err(anyhow::format_err!(
                "Failed to read from persistent storage: file not open."
            )),
        },
    )
}

pub fn persistent_storage_write64(offset: u64, buf: &[u8]) {
    BACKING_FILE.with(
        |backing_file| match backing_file.borrow_mut().file.as_mut() {
            Some(file) => {
                // Grow the file if necessary
                let file_size_bytes = file.metadata().unwrap().len();
                if file_size_bytes < offset + (buf.len() as u64).max(PERSISTENT_STORAGE_PAGE_SIZE) {
                    let file_size_bytes_new =
                        offset + (buf.len() as u64).max(PERSISTENT_STORAGE_PAGE_SIZE);
                    file.set_len(file_size_bytes_new).unwrap();
                    // fill new file space with zeros
                    file.seek(std::io::SeekFrom::Start(file_size_bytes))
                        .unwrap();
                    file.write_all(&vec![0; (file_size_bytes_new - file_size_bytes) as usize])
                        .unwrap();
                    info!(
                        "Growing persistent storage to {} bytes.",
                        file_size_bytes_new
                    );
                }
                debug!(
                    "Writing {} bytes to persistent storage @offset 0x{:0x}",
                    buf.len(),
                    offset
                );
                file.seek(std::io::SeekFrom::Start(offset)).unwrap();
                file.write_all(buf)
                    .expect("Failed to write to persistent storage.");
            }
            None => {
                warn!("Failed to write to persistent storage: file not open.");
            }
        },
    )
}

pub fn persistent_storage_grow64(additional_pages: u64) -> Result<u64, String> {
    BACKING_FILE.with(|backing_file| match &backing_file.borrow_mut().file {
        Some(file) => {
            let previous_size_bytes = file.metadata().map_err(|err| err.to_string())?.len();
            let new_size_bytes =
                previous_size_bytes + (additional_pages * PERSISTENT_STORAGE_PAGE_SIZE);
            info!("Growing persistent storage to {} bytes.", new_size_bytes);
            file.set_len(new_size_bytes)
                .map_err(|err| err.to_string())?;
            Ok(previous_size_bytes * PERSISTENT_STORAGE_PAGE_SIZE)
        }
        None => Ok(0),
    })
}

pub const PERSISTENT_STORAGE_PAGE_SIZE: u64 = 64 * 1024;

// These functions exist only for compatibility with the wasm32 implementation.
pub fn export_debug() -> Vec<String> {
    Vec::new()
}

pub fn export_info() -> Vec<String> {
    Vec::new()
}

pub fn export_warn() -> Vec<String> {
    Vec::new()
}

pub fn export_error() -> Vec<String> {
    Vec::new()
}

pub(crate) fn get_timestamp_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
