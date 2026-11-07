//! File-backed key provider for the gateway binary.
//!
//! The `KeyProvider` trait will be defined in `tirbase-core/src/traits.rs`
//! (task 5.2 — CLAIM-5.2).  This module provides the concrete
//! `FileKeyProvider` struct that will implement that trait once it lands.

use std::path::PathBuf;

/// Key provider that loads a device Ed25519 key from a file on disk.
///
/// The private key material is held only in memory after the initial load;
/// it is never written back to configuration files (CLAIM-6.1).
pub struct FileKeyProvider {
    /// Filesystem path to the device key file (PEM or raw bytes).
    pub key_path: PathBuf,
}

impl FileKeyProvider {
    /// Construct a new `FileKeyProvider` for the given key file path.
    pub fn new(key_path: PathBuf) -> Self {
        FileKeyProvider { key_path }
    }
}
