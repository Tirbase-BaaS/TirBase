//! DID generation, persistence, and resolution.
//!
//! Each TirBase device has a DID of the form `did:key:z6Mk…` derived from
//! its Ed25519 public key (Req 7.1).

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// A `did:key:` DID string.
pub type Did = String;

/// Derive a `did:key:` DID from a raw Ed25519 public key (32 bytes).
///
/// The DID is the multibase-encoded (base58btc) multicodec-prefixed public key:
///   `did:key:z` + base58btc(0xed01 || public_key_bytes)
pub fn derive_did(public_key: &[u8; 32]) -> Did {
    todo!("Task 4: implement did:key derivation")
}

/// Resolve a `did:key:` DID to its Ed25519 public key bytes.
///
/// Returns `DidResolutionFailed` if the DID is malformed or uses an
/// unsupported method.
pub fn resolve_did(did: &Did) -> Result<[u8; 32], TirBaseError> {
    todo!("Task 4: implement did:key resolution")
}

/// Persist the device DID and private key to durable storage (Req 7.1).
pub fn persist_identity(did: &Did, keypair_bytes: &[u8]) -> Result<(), TirBaseError> {
    todo!("Task 4: implement durable storage via LocalStore")
}

/// Load the device DID and private key from durable storage (Req 7.1).
/// Returns `None` if no identity has been persisted yet.
pub fn load_identity() -> Result<Option<(Did, Vec<u8>)>, TirBaseError> {
    todo!("Task 4: implement identity load")
}
