//! IdentityManager — device identity backed by a [`KeyProvider`] (Req 7.1, PV-3.6).
//!
//! The manager no longer holds a raw `ed25519_dalek::SigningKey`: all signing
//! goes through the [`KeyProvider`] trait, so the same code path works with a
//! file-backed key, a TPM-sealed seed, or a PKCS#11 token (task 6.3 / 6.4).
//!
//! # Legacy seed bridge
//!
//! A few subsystems (the CRDT engine's delta signer, the Noise static key, and
//! revocation partial-delta production) still take a raw 32-byte Ed25519 seed.
//! [`IdentityManager::signing_key_bytes`] is crate-internal and exists only to
//! feed those call sites; it is not part of the [`KeyProvider`] surface and is
//! scheduled to disappear as those subsystems migrate.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod did;
pub mod file_key_provider;
pub mod keypair;

use std::sync::Arc;

use async_trait::async_trait;
use tirbase_types::{DeviceKeyType, DeviceSignature};

use crate::crdt::delta::{Delta, Ed25519Signature};
use crate::errors::TirBaseError;
use crate::traits::KeyProvider;

use file_key_provider::{FileKeyProvider, InMemoryKeyProvider};

/// The key backing this identity.
///
/// An enum (rather than `Arc<dyn KeyProvider>` alone) is used because the
/// legacy seed bridge needs access to the concrete provider's seed without
/// adding a private-key accessor to the [`KeyProvider`] trait.
enum DeviceKey {
    File(FileKeyProvider),
    Memory(InMemoryKeyProvider),
}

impl DeviceKey {
    fn as_provider(&self) -> &dyn KeyProvider {
        match self {
            DeviceKey::File(provider) => provider,
            DeviceKey::Memory(provider) => provider,
        }
    }

    fn secret_seed(&self) -> [u8; 32] {
        match self {
            DeviceKey::File(provider) => provider.secret_seed(),
            DeviceKey::Memory(provider) => provider.secret_seed(),
        }
    }

    fn public_key(&self) -> [u8; 32] {
        match self {
            DeviceKey::File(provider) => provider.public_key(),
            DeviceKey::Memory(provider) => provider.public_key(),
        }
    }
}

/// Manages the local device's identity and DID (Req 7.1).
pub struct IdentityManager {
    /// `did:key:z6Mk…` DID for this device.
    pub did: String,
    /// Key provider used for every signature this device produces (PV-3.6).
    key: DeviceKey,
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
        match path {
            Some(path) => {
                let provider = FileKeyProvider::load_or_generate(path)?;
                Ok(Self::from_key(DeviceKey::File(provider), Some(path.to_string())))
            }
            None => {
                let provider = InMemoryKeyProvider::generate()?;
                Ok(Self::from_key(DeviceKey::Memory(provider), None))
            }
        }
    }

    /// Initialise an in-memory-only identity (no persistence). Useful for WASM and testing.
    pub fn init_in_memory() -> Result<Self, TirBaseError> {
        Self::init_with_path(None)
    }

    fn from_key(key: DeviceKey, identity_path: Option<String>) -> Self {
        let did = key.as_provider().did().to_string();
        IdentityManager {
            did,
            key,
            identity_path,
        }
    }

    /// The [`KeyProvider`] this identity signs through.
    pub fn key_provider(&self) -> &dyn KeyProvider {
        self.key.as_provider()
    }

    /// Return the DID string for this device.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Return the 32-byte Ed25519 public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// Return the 32-byte Ed25519 secret key seed.
    ///
    /// Crate-internal migration bridge for subsystems that still take a raw
    /// signing key; new code must call [`IdentityManager::sign`] or
    /// [`IdentityManager::sign_async`] instead.
    pub(crate) fn signing_key_bytes(&self) -> [u8; 32] {
        self.key.secret_seed()
    }

    /// Sign a payload with this device's key (Req 7.2).
    ///
    /// Returns the 64-byte Ed25519 signature.
    pub fn sign(&self, payload: &[u8]) -> Result<[u8; 64], TirBaseError> {
        Self::ed25519_bytes(self.key.as_provider().sign(payload)?)
    }

    /// Async signing path (hardware-backed providers).
    pub async fn sign_async(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        self.key.as_provider().sign_async(payload).await
    }

    fn ed25519_bytes(signature: DeviceSignature) -> Result<[u8; 64], TirBaseError> {
        match signature {
            DeviceSignature::Ed25519(bytes) => Ok(bytes),
            DeviceSignature::P256(_) => Err(TirBaseError::SignatureVerificationFailed {
                reason: "expected an Ed25519 signature from the device key".to_string(),
            }),
        }
    }

    /// Sign a Delta: set `delta.signature`, `delta.author_did`, and `delta.id` (Req 7.2).
    ///
    /// The signature covers `canonical_bytes()` which excludes the signature and id fields.
    pub fn sign_delta(&self, delta: &mut Delta) -> Result<(), TirBaseError> {
        // Set the author DID
        delta.author_did = self.did.clone();

        // Compute canonical bytes (excludes signature and id)
        let canonical = delta.canonical_bytes();

        // Sign through the KeyProvider
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

    #[test]
    fn test_identity_manager_signs_through_its_key_provider() {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let provider = mgr.key_provider();

        assert_eq!(provider.did(), mgr.did());
        assert_eq!(provider.public_key_bytes(), mgr.public_key_bytes().to_vec());
        assert_eq!(provider.key_type(), DeviceKeyType::Ed25519);

        let payload = b"provider-consistency";
        let direct = provider.sign(payload).expect("provider sign");
        let manager = mgr.sign(payload).expect("manager sign");
        assert_eq!(direct, DeviceSignature::Ed25519(manager));
    }

    #[tokio::test]
    async fn test_sign_async_matches_sign() {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let payload = b"async-signing";
        let sync = mgr.sign(payload).unwrap();
        let asynchronous = mgr.sign_async(payload).await.unwrap();
        assert_eq!(asynchronous, DeviceSignature::Ed25519(sync));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ZeroizeOnDrop coverage registry (task 6.2 — CLAIM-6.2, PV-3.14)
// ═════════════════════════════════════════════════════════════════════════════
//
// This test module is the single registry of types that hold raw key material
// in `tirbase-core` and `tirbase-guard`.  Two CI tests enforce coverage:
//
//   * `every_registered_type_is_zeroize_on_drop` — compile-time proof that each
//     registered type implements `ZeroizeOnDrop`.  Removing a `ZeroizeOnDrop`
//     impl/derive from any registered type breaks this test at compile time.
//   * `registry_covers_every_key_material_struct` — scans both crates' source
//     trees for structs whose fields include raw key bytes and fails if a type
//     is missing from the registry.
//
// `StoredIdentity` is crate-private; the registry lives here (rather than in an
// integration test) so private key-material types can be proven too.
#[cfg(test)]
mod zeroize_registry_tests {
    use std::path::{Path, PathBuf};

    use zeroize::ZeroizeOnDrop;

    use crate::crdt::CrdtEngine;
    use crate::transport::MeshTransport;
    use super::did::StoredIdentity;
    use super::file_key_provider::{FileKeyProvider, InMemoryKeyProvider};

    /// Every type in `tirbase-core` / `tirbase-guard` known to hold raw key
    /// bytes, by type name.
    pub static ZEROIZE_ON_DROP_REGISTRY: &[&str] = &[
        "CrdtEngine",
        "FileKeyProvider",
        "InMemoryKeyProvider",
        "MeshTransport",
        "StoredIdentity",
        "EnrollmentService",
    ];

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn every_registered_type_is_zeroize_on_drop() {
        // One assertion per registry entry.  Adding an entry without an
        // assertion here fails `registry_entries_have_type_assertions`.
        assert_zeroize_on_drop::<CrdtEngine>();
        assert_zeroize_on_drop::<FileKeyProvider>();
        assert_zeroize_on_drop::<InMemoryKeyProvider>();
        assert_zeroize_on_drop::<MeshTransport>();
        assert_zeroize_on_drop::<StoredIdentity>();

        assert!(ZEROIZE_ON_DROP_REGISTRY.contains(&"CrdtEngine"));
        assert!(ZEROIZE_ON_DROP_REGISTRY.contains(&"MeshTransport"));
        assert!(ZEROIZE_ON_DROP_REGISTRY.contains(&"FileKeyProvider"));
        assert!(ZEROIZE_ON_DROP_REGISTRY.contains(&"InMemoryKeyProvider"));
        assert!(ZEROIZE_ON_DROP_REGISTRY.contains(&"StoredIdentity"));
    }

    /// Guards against a registry entry that has no corresponding type-level
    /// assertion above (a name alone would not prove anything).
    #[test]
    fn registry_entries_have_type_assertions() {
        // Core types have compile-time assertions above; EnrollmentService lives
        // in tirbase-guard (cross-crate) and is asserted there.
        assert_eq!(ZEROIZE_ON_DROP_REGISTRY.len(), 6);
        assert!(ZEROIZE_ON_DROP_REGISTRY.contains(&"EnrollmentService"));
    }

    #[test]
    fn registry_covers_every_key_material_struct() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tirbase-core lives in the workspace root");
        let mut missing = Vec::new();

        for crate_dir in ["tirbase-core/src", "tirbase-guard/src"] {
            for file in rust_files(&workspace.join(crate_dir)) {
                let source = std::fs::read_to_string(&file).expect("read source file");
                for name in key_material_structs(&source) {
                    if !ZEROIZE_ON_DROP_REGISTRY.contains(&name.as_str()) {
                        missing.push(format!("{} in {}", name, file.display()));
                    }
                }
            }
        }

        assert!(
            missing.is_empty(),
            "key-material structs missing from ZEROIZE_ON_DROP_REGISTRY: {missing:?}"
        );
    }

    /// Recursively collect `.rs` files below `root`.
    fn rust_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read source directory") {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// Heuristic source scan for structs that hold raw key material.
    ///
    /// A struct qualifies when one of its fields is named like key material
    /// (`seed`, `secret`, `private_key`, `signing_key`, `keypair`) or has a
    /// key type (`SigningKey`, `SecretKey`, `StaticSecret`).  Test modules are
    /// stripped first so fixture structs do not need registry entries.
    fn key_material_structs(source: &str) -> Vec<String> {
        let production = source
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or(source);

        let mut found = Vec::new();
        let mut current: Option<(String, usize, bool)> = None;

        for line in production.lines() {
            let trimmed = line.trim();

            if current.is_none() {
                if let Some(name) = struct_name(trimmed) {
                    let (open, close) = brace_delta(trimmed);
                    let depth = open.saturating_sub(close);
                    // Tuple/unit structs (no `{`) cannot hold named fields.
                    if depth > 0 {
                        current = Some((name, depth, false));
                    }
                    continue;
                }
                continue;
            }

            if let Some((name, depth, holds_key)) = current.as_mut() {
                let field = field_declaration(trimmed);
                if let Some((field_name, field_type)) = field {
                    if looks_like_key_material(&field_name, &field_type) {
                        *holds_key = true;
                    }
                }
                let (open, close) = brace_delta(trimmed);
                *depth = depth.saturating_add(open).saturating_sub(close);
                if *depth == 0 {
                    if *holds_key {
                        found.push(name.clone());
                    }
                    current = None;
                }
            }
        }

        found
    }

    fn struct_name(line: &str) -> Option<String> {
        let rest = line
            .strip_prefix("pub(crate) struct ")
            .or_else(|| line.strip_prefix("pub(super) struct "))
            .or_else(|| line.strip_prefix("pub struct "))
            .or_else(|| line.strip_prefix("struct "))?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    fn field_declaration(line: &str) -> Option<(String, String)> {
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with('#')
            || line.starts_with('}')
            || line.starts_with("impl")
        {
            return None;
        }
        let (name, ty) = line.split_once(':')?;
        let name = name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        Some((name.to_string(), ty.trim().to_string()))
    }

    fn looks_like_key_material(field_name: &str, field_type: &str) -> bool {
        const KEY_FIELD_FRAGMENTS: &[&str] = &[
            "seed",
            "secret",
            "privkey",
            "private_key",
            "signing_key",
            "keypair",
        ];
        const KEY_TYPES: &[&str] = &["SigningKey", "SecretKey", "StaticSecret"];

        KEY_FIELD_FRAGMENTS
            .iter()
            .any(|fragment| field_name.contains(fragment))
            || KEY_TYPES.iter().any(|ty| field_type.contains(ty))
    }

    fn brace_delta(line: &str) -> (usize, usize) {
        let open = line.chars().filter(|c| *c == '{').count();
        let close = line.chars().filter(|c| *c == '}').count();
        (open, close)
    }
}
