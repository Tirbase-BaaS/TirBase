//! IdentityManager — Ed25519 keypair generation, DID derivation, and persistence (Req 7.1).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod did;
pub mod keypair;

use crate::crdt::delta::{Delta, Ed25519Signature};
use crate::errors::TirBaseError;
use ed25519_dalek::SigningKey;

/// Manages the local device's Ed25519 identity and DID (Req 7.1).
pub struct IdentityManager {
    /// `did:key:z6Mk…` DID for this device.
    pub did: String,
    /// Ed25519 signing key (32-byte seed internally).
    signing_key: SigningKey,
    /// Path used for persistence (None = in-memory only).
    identity_path: Option<String>,
}

impl IdentityManager {
    /// Initialise the identity: load from the default storage path or generate a new keypair.
    ///
    /// Uses `./tirbase-identity.json` as default path on native builds.
    pub fn init() -> Result<Self, TirBaseError> {
        Self::init_with_path(Some("./tirbase-identity.json"))
    }

    /// Initialise with a specific storage path.
    /// Pass `None` for `path` to operate in-memory without persistence.
    pub fn init_with_path(path: Option<&str>) -> Result<Self, TirBaseError> {
        // Try loading an existing identity first
        if let Some(p) = path {
            if let Some((loaded_did, keypair_bytes)) = did::load_identity_from(p)? {
                if keypair_bytes.len() >= 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&keypair_bytes[..32]);
                    let signing_key = SigningKey::from_bytes(&seed);
                    return Ok(Self {
                        did: loaded_did,
                        signing_key,
                        identity_path: Some(p.to_string()),
                    });
                }
            }
        }

        // Generate new keypair
        let (secret_bytes, public_bytes) = keypair::generate_keypair()?;
        let derived_did = did::derive_did(&public_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // Persist if path is given
        if let Some(p) = path {
            let mut keypair_bytes = secret_bytes.to_vec();
            keypair_bytes.extend_from_slice(&public_bytes);
            did::persist_identity_to(&derived_did, &keypair_bytes, p)?;
        }

        Ok(Self {
            did: derived_did,
            signing_key,
            identity_path: path.map(|s| s.to_string()),
        })
    }

    /// Initialise an in-memory-only identity (no persistence). Useful for WASM and testing.
    pub fn init_in_memory() -> Result<Self, TirBaseError> {
        Self::init_with_path(None)
    }

    /// Return the DID string for this device.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Return the 32-byte Ed25519 public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a payload with this device's Ed25519 private key (Req 7.2).
    ///
    /// Returns the 64-byte signature.
    pub fn sign(&self, payload: &[u8]) -> Result<[u8; 64], TirBaseError> {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(payload);
        Ok(sig.to_bytes())
    }

    /// Sign a Delta: set `delta.signature`, `delta.author_did`, and `delta.id` (Req 7.2).
    ///
    /// The signature covers `canonical_bytes()` which excludes the signature and id fields.
    pub fn sign_delta(&self, delta: &mut Delta) -> Result<(), TirBaseError> {
        // Set the author DID
        delta.author_did = self.did.clone();

        // Compute canonical bytes (excludes signature and id)
        let canonical = delta.canonical_bytes();

        // Sign
        let sig_bytes = self.sign(&canonical)?;
        delta.signature = Ed25519Signature::from_bytes(sig_bytes);

        // Compute and set the id
        delta.id = Delta::compute_id(&canonical);

        Ok(())
    }

    /// Verify a Delta's signature against a peer's DID-resolved public key (Req 7.3).
    ///
    /// Returns `Ok(())` if valid. Returns `DidResolutionFailed` or
    /// `SignatureVerificationFailed` on failure (Req 7.4–7.5).
    pub fn verify_delta_signature(
        &self,
        sender_did: &str,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), TirBaseError> {
        // Resolve sender's DID to public key
        let sender_did_str = sender_did.to_string();
        let public_key = did::resolve_did(&sender_did_str)?;

        // Reconstruct Ed25519Signature and verify
        let ed_sig = Ed25519Signature::from_bytes(*signature);
        keypair::verify(&public_key, payload, &ed_sig)
    }

    /// Verify a Delta's embedded signature (convenience wrapper).
    pub fn verify_delta(&self, delta: &Delta) -> Result<(), TirBaseError> {
        let canonical = delta.canonical_bytes();
        let sig_bytes = delta.signature.as_bytes().ok_or_else(|| {
            TirBaseError::SignatureVerificationFailed {
                reason: "delta signature is not 64 bytes".to_string(),
            }
        })?;
        self.verify_delta_signature(&delta.author_did, &canonical, &sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};

    fn make_test_delta() -> Delta {
        Delta {
            id: [0u8; 32],
            author_did: String::new(),
            signature: Ed25519Signature::default(),
            schema_hash: [1u8; 32],
            automerge_bytes: b"test-delta-data".to_vec(),
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 1_720_000_000_000_000,
        }
    }

    #[test]
    fn test_identity_manager_init_generates_did() {
        let mgr = IdentityManager::init_in_memory().expect("init should succeed");
        let did = mgr.did();
        assert!(
            did.starts_with("did:key:z6Mk"),
            "DID should start with 'did:key:z6Mk', got: {did}"
        );
    }

    #[test]
    fn test_identity_manager_sign_delta_and_verify() {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let mut delta = make_test_delta();

        mgr.sign_delta(&mut delta).expect("sign_delta should succeed");

        assert_eq!(
            delta.author_did,
            mgr.did(),
            "author_did should be set to manager's DID"
        );
        assert!(!delta.signature.0.is_empty(), "signature should be set");
        assert_ne!(delta.id, [0u8; 32], "delta id should be computed");

        // Verify the signature
        mgr.verify_delta(&delta).expect("delta signature should be valid");
    }

    #[test]
    fn test_tampered_delta_rejected() {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let mut delta = make_test_delta();
        mgr.sign_delta(&mut delta).unwrap();

        // Tamper with the payload after signing
        delta.automerge_bytes = b"tampered-data".to_vec();

        let result = mgr.verify_delta(&delta);
        assert!(result.is_err(), "tampered delta should fail verification");
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_identity_manager_persistence_and_restore() {
        use std::env;
        let tmp = env::temp_dir().join("tirbase_test_idmgr.json");
        let path = tmp.to_str().unwrap();

        // Remove leftover from prior run
        let _ = std::fs::remove_file(path);

        // Create new identity with persistence
        let mgr = IdentityManager::init_with_path(Some(path))
            .expect("init with path should succeed");
        let original_did = mgr.did().to_string();
        let original_pk = mgr.public_key_bytes();

        // Load it back
        let mgr2 = IdentityManager::init_with_path(Some(path))
            .expect("reload from path should succeed");
        assert_eq!(mgr2.did(), &original_did, "DID should be restored");
        assert_eq!(
            mgr2.public_key_bytes(),
            original_pk,
            "public key should be restored"
        );

        // Verify that a delta signed by the first can be verified by the second
        let mut delta = make_test_delta();
        mgr.sign_delta(&mut delta).unwrap();
        mgr2.verify_delta(&delta)
            .expect("cross-instance verification should succeed after restore");

        // Clean up
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_sign_and_verify_raw_payload() {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let payload = b"raw signing test";
        let sig_bytes = mgr.sign(payload).unwrap();
        let sig = Ed25519Signature::from_bytes(sig_bytes);
        let pk = mgr.public_key_bytes();
        keypair::verify(&pk, payload, &sig).expect("raw sign/verify should succeed");
    }

    #[test]
    fn test_verify_delta_signature_wrong_did_fails() {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let mut delta = make_test_delta();
        mgr.sign_delta(&mut delta).unwrap();

        let other_mgr = IdentityManager::init_in_memory().unwrap();
        let canonical = delta.canonical_bytes();
        let sig_bytes = delta.signature.as_bytes().unwrap();

        // Try to verify the signature using the other manager's DID
        let result = mgr.verify_delta_signature(other_mgr.did(), &canonical, &sig_bytes);
        assert!(
            result.is_err(),
            "verification with wrong DID/key should fail"
        );
    }
}
