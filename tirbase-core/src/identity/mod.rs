//! IdentityManager — Ed25519 keypair generation, DID derivation, and persistence (Req 7.1).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod did;
pub mod keypair;

use crate::errors::TirBaseError;

/// Manages the local device's Ed25519 identity and DID (Req 7.1).
pub struct IdentityManager {
    /// `did:key:z6Mk…` DID for this device.
    pub did: String,
    // TODO(task-4): hold ed25519-dalek SigningKey
}

impl IdentityManager {
    /// Initialise the identity: load from storage or generate a new keypair (Req 7.1).
    pub fn init() -> Result<Self, TirBaseError> {
        todo!("Task 4: load or generate Ed25519 keypair and persist DID")
    }

    /// Sign a payload with this device's Ed25519 private key (Req 7.2).
    pub fn sign(&self, payload: &[u8]) -> Result<[u8; 64], TirBaseError> {
        todo!("Task 4: implement signing")
    }

    /// Verify a Delta's signature against a peer's DID-resolved public key (Req 7.3).
    pub fn verify_delta_signature(
        &self,
        sender_did: &str,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), TirBaseError> {
        todo!("Task 4: implement DID resolution + signature verification")
    }
}
