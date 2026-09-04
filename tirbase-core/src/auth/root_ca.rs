//! Root CA public key registry (Req 8.1).
//!
//! Read-only in v1. Issuance, rotation, and recovery are deferred to post-v1 ops tasks.

#![allow(dead_code)]

use crate::errors::TirBaseError;

/// The root CA public key registry.
///
/// In v1 this is a static, read-only list loaded from deployment configuration.
/// Key rotation and recovery are out of scope for v1.
pub struct RootCaRegistry {
    /// Ed25519 public keys of registered root CAs.
    keys: Vec<[u8; 32]>,
}

impl RootCaRegistry {
    /// Create a registry from a list of root CA public key bytes.
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        Self { keys }
    }

    /// Register an additional root CA public key at runtime.
    ///
    /// Idempotent: registering a key that is already present is a no-op.
    pub(crate) fn register(&mut self, key: [u8; 32]) {
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
    }

    /// Return all registered root CA public keys.
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    /// Check if a given Ed25519 public key belongs to a registered root CA.
    pub fn is_registered(&self, key: &[u8; 32]) -> bool {
        self.keys.contains(key)
    }

    /// Return the first registered CA public key, if any.
    pub fn primary_key(&self) -> Option<&[u8; 32]> {
        self.keys.first()
    }
}
