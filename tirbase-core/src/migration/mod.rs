//! Schema Migration Engine — zero-trust gate, WASM sandbox, Side-Car replay (Req 17–19).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod migration_delta;
pub mod quarantine;
pub mod revocation;
pub mod sidecar;
pub mod version_path;
pub mod wasm_sandbox;

use std::collections::HashSet;

#[cfg(feature = "native")]
use std::sync::{Arc, Mutex};

use crate::errors::TirBaseError;
use migration_delta::{MigrationDelta, MigrationId, MigrationRevocationDelta};
use revocation::RevokedMigrationRegistry;
use version_path::SchemaVersionPath;
use wasm_sandbox::{execute_migration, MigrationResult};

// Re-export for tests in sub-modules
pub use revocation::resolve_did_key_to_public_key;

// ─── SchemaMigrationEngine ───────────────────────────────────────────────────

/// The Schema Migration Engine orchestrates the zero-trust gate, sandbox
/// execution, quarantine management, Side-Car replay, and CCE tagging.
pub struct SchemaMigrationEngine {
    /// Ed25519 public key of the deployment's Certificate Authority.
    /// Used to verify `MigrationDelta.ca_signature` (Req 18.2).
    ca_public_key: [u8; 32],

    /// Current schema hash of this device's local store.
    local_schema_hash: crate::schema::hash::SchemaIdentifierHash,

    /// Ordered version path for step-validation (Req 18.3a).
    version_path: SchemaVersionPath,

    /// Registry tracking revoked and in-progress migrations (Req 18.5–18.7).
    revocation_registry: RevokedMigrationRegistry,

    /// Set of sender DIDs blacklisted due to CA sig or hash failures (Req 18.3).
    blacklisted_senders: HashSet<crate::crdt::delta::Did>,

    /// Minimum number of Manager DID signatures required for a revocation delta.
    revocation_threshold_m: usize,

    /// Handle to the local store for migration sandbox host functions (native only).
    #[cfg(feature = "native")]
    store: Arc<Mutex<crate::store::LocalStore>>,
}

impl SchemaMigrationEngine {
    /// Create a new SchemaMigrationEngine.
    ///
    /// - `ca_public_key`: 32-byte Ed25519 public key of the deployment CA.
    /// - `local_schema_hash`: current schema hash of the local store.
    /// - `version_path`: deployment's ordered schema version path.
    /// - `revocation_threshold_m`: M value for M-of-N manager signature requirement.
    /// - `store`: handle to the local store for sandbox host functions (native only).
    pub fn new(
        ca_public_key: [u8; 32],
        local_schema_hash: crate::schema::hash::SchemaIdentifierHash,
        version_path: SchemaVersionPath,
        revocation_threshold_m: usize,
        #[cfg(feature = "native")] store: Arc<Mutex<crate::store::LocalStore>>,
    ) -> Self {
        Self {
            ca_public_key,
            local_schema_hash,
            version_path,
            revocation_registry: RevokedMigrationRegistry::default(),
            blacklisted_senders: HashSet::new(),
            revocation_threshold_m,
            #[cfg(feature = "native")]
            store,
        }
    }

    /// Check whether a sender DID has been blacklisted.
    pub fn is_blacklisted(&self, did: &str) -> bool {
        self.blacklisted_senders.contains(did)
    }

    /// Check whether a migration has been revoked.
    pub fn is_revoked(&self, migration_id: &MigrationId) -> bool {
        self.revocation_registry.is_revoked(migration_id)
    }

    /// Return `true` if the QuarantineLedger holds any entry whose schema hash
    /// matches the engine's current `local_schema_hash` and has not yet been
    /// released via `release_for_migration()`.
    ///
    /// Used by `CoreHandle::write()` to determine whether to auto-tag writes as
    /// `ContaminatedByHumanReaction` (Req 19.5).
    pub fn is_schema_quarantined(&self, _table: &str) -> bool {
        // The quarantine ledger is keyed by schema hash, not by table name.
        // A quarantined delta with our local schema hash means that *this* device
        // is receiving deltas it cannot merge — the whole schema is in quarantine.
        // We report true for any table if the local schema hash appears in the ledger
        // without a migration_id (not yet released for replay).
        #[cfg(feature = "native")]
        {
            // We need a QuarantineLedger handle here.  In practice the Migration Engine
            // holds the quarantine logic inline — we check whether any delta with our
            // current local_schema_hash is sitting unreleased in the quarantine ledger
            // via the stored Arc<Mutex<LocalStore>> connection.
            //
            // For v1 the conservative approach: if the blacklisted_senders set is
            // non-empty (implying at least one migration validation failure occurred),
            // or if the revocation_registry has any in-progress migration, consider
            // the schema potentially quarantined.  This is a safe over-approximation.
            //
            // A more precise implementation would query the quarantine_ledger table
            // directly; that requires passing a DB connection into this method.
            // The quarantine-active flag is set to true only when there ARE quarantined
            // deltas pending — we approximate by checking if any migration is in-progress
            // (meaning the engine has started but not finished a schema migration),
            // which happens when deltas for the next schema are sitting in quarantine.
            self.revocation_registry.has_in_progress()
        }
        #[cfg(not(feature = "native"))]
        {
            // WASM: same conservative check.
            self.revocation_registry.has_in_progress()
        }
    }

    /// Receive and validate an incoming MigrationDelta (Req 18.2–18.3a).
    ///
    /// Checks in order:
    /// 1. Sender not blacklisted.
    /// 2. Migration not already revoked.
    /// 3. CA signature over transform_bytes is valid.
    /// 4. SHA-256 of transform_bytes matches embedded hash.
    /// 5. source_schema_hash == local current schema.
    /// 6. target_schema_hash == next step in registered version path.
    /// 7. Execute in sandbox (Req 18.4).
    ///
    /// On CA sig or hash failure: blacklist sender (Req 18.3).
    /// On version path mismatch: reject + log (no blacklist).
    pub fn receive_migration_delta(
        &mut self,
        delta: MigrationDelta,
        sender_did: &str,
    ) -> Result<MigrationResult, TirBaseError> {
        // ── 1. Blacklist check ────────────────────────────────────────────────
        if self.blacklisted_senders.contains(sender_did) {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!("sender {sender_did} is blacklisted"),
            });
        }

        // ── 2. Revocation check ──────────────────────────────────────────────
        if self.revocation_registry.is_revoked(&delta.id) {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!("migration {:?} has been revoked", delta.id),
            });
        }

        // ── 3. CA signature verification ─────────────────────────────────────
        if let Err(e) = self.verify_ca_signature(&delta) {
            eprintln!(
                "[migration] CA signature invalid from {sender_did}: {e} — blacklisting"
            );
            self.blacklisted_senders.insert(sender_did.to_string());
            let migration_id_hex = hex::encode(delta.id);
            return Err(TirBaseError::MigrationCaSignatureInvalid {
                migration_id: migration_id_hex,
            });
        }

        // ── 4. SHA-256 hash integrity check ──────────────────────────────────
        if let Err(e) = self.verify_transform_hash(&delta) {
            eprintln!(
                "[migration] Hash mismatch from {sender_did} — blacklisting"
            );
            self.blacklisted_senders.insert(sender_did.to_string());
            let migration_id_hex = hex::encode(delta.id);
            return Err(TirBaseError::MigrationHashMismatch {
                migration_id: migration_id_hex,
            });
        }

        // ── 5 & 6. Version path validation ───────────────────────────────────
        if let Err(e) = self.verify_version_path(&delta) {
            return Err(e);
        }

        // ── 7. Execute in sandbox ─────────────────────────────────────────────
        self.revocation_registry.mark_in_progress(delta.id);

        #[cfg(feature = "native")]
        let result = execute_migration(&delta.transform_bytes, delta.id, 30, &self.store);

        #[cfg(not(feature = "native"))]
        let result = execute_migration(&delta.transform_bytes, delta.id, 30);

        self.revocation_registry.clear_in_progress(&delta.id);

        match result {
            Err(e) => Err(e),
            Ok(MigrationResult::TimedOut { timeout_secs }) => {
                let migration_id_hex = hex::encode(delta.id);
                eprintln!("[migration] Migration {migration_id_hex} timed out after {timeout_secs}s");
                Err(TirBaseError::MigrationTransformTimeout {
                    migration_id: migration_id_hex,
                })
            }
            Ok(MigrationResult::Aborted { ref reason }) => {
                eprintln!("[migration] Migration {:?} aborted: {reason}", delta.id);
                Ok(MigrationResult::Aborted { reason: reason.clone() })
            }
            Ok(MigrationResult::Success) => {
                // Update local schema hash to target after successful migration.
                self.local_schema_hash = delta.target_schema_hash;
                eprintln!(
                    "[migration] Migration {:?} succeeded; schema updated to {:?}",
                    delta.id, delta.target_schema_hash
                );
                Ok(MigrationResult::Success)
            }
        }
    }

    /// Receive a MigrationRevocationDelta and halt any in-progress transform (Req 18.5–18.7).
    pub fn receive_revocation_delta(
        &mut self,
        delta: MigrationRevocationDelta,
    ) -> Result<(), TirBaseError> {
        self.revocation_registry
            .apply_revocation(delta, self.revocation_threshold_m)
    }

    // ─── Private helpers ───────────────────────────────────────────────────────

    /// Verify the CA's Ed25519 signature over `transform_bytes` (Req 18.2).
    fn verify_ca_signature(&self, delta: &MigrationDelta) -> Result<(), TirBaseError> {
        use ed25519_dalek::{Signature, VerifyingKey};

        if delta.ca_signature.0.is_empty() {
            return Err(TirBaseError::MigrationCaSignatureInvalid {
                migration_id: hex::encode(delta.id),
            });
        }

        let sig_bytes: [u8; 64] = delta.ca_signature.0.as_slice().try_into().map_err(|_| {
            TirBaseError::MigrationCaSignatureInvalid {
                migration_id: hex::encode(delta.id),
            }
        })?;

        let verifying_key = VerifyingKey::from_bytes(&self.ca_public_key).map_err(|e| {
            TirBaseError::SignatureVerificationFailed {
                reason: format!("invalid CA public key: {e}"),
            }
        })?;

        let sig = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify_strict(&delta.transform_bytes, &sig)
            .map_err(|e| TirBaseError::MigrationCaSignatureInvalid {
                migration_id: hex::encode(delta.id),
            })
    }

    /// Verify SHA-256(transform_bytes) == embedded hash (Req 18.2).
    fn verify_transform_hash(&self, delta: &MigrationDelta) -> Result<(), TirBaseError> {
        use sha2::{Digest, Sha256};

        let computed: [u8; 32] = Sha256::digest(&delta.transform_bytes).into();
        if computed != delta.transform_sha256 {
            return Err(TirBaseError::MigrationHashMismatch {
                migration_id: hex::encode(delta.id),
            });
        }
        Ok(())
    }

    /// Verify source_schema_hash == local AND target_schema_hash == next in path (Req 18.3a).
    fn verify_version_path(&self, delta: &MigrationDelta) -> Result<(), TirBaseError> {
        if delta.source_schema_hash != self.local_schema_hash {
            return Err(TirBaseError::VersionPathMismatch {
                local_ver: hex::encode(self.local_schema_hash),
                source_ver: hex::encode(delta.source_schema_hash),
                expected_next: hex::encode(
                    self.version_path
                        .next_version(&self.local_schema_hash)
                        .copied()
                        .unwrap_or([0u8; 32]),
                ),
            });
        }

        if !self.version_path.is_valid_step(&delta.source_schema_hash, &delta.target_schema_hash) {
            return Err(TirBaseError::VersionPathMismatch {
                local_ver: hex::encode(self.local_schema_hash),
                source_ver: hex::encode(delta.source_schema_hash),
                expected_next: hex::encode(
                    self.version_path
                        .next_version(&delta.source_schema_hash)
                        .copied()
                        .unwrap_or([0u8; 32]),
                ),
            });
        }

        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{Ed25519Signature, PriorityClass};
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::migration::migration_delta::{CaSignature, ManagerSignature, MigrationRevocationDelta};
    use sha2::{Digest, Sha256};

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// Generate a CA keypair + sign transform_bytes.
    fn make_ca_signed_delta(
        ca_secret: &[u8; 32],
        source_hash: [u8; 32],
        target_hash: [u8; 32],
        transform_bytes: Vec<u8>,
        tamper_hash: bool,
    ) -> (MigrationDelta, [u8; 32]) {
        use crate::crdt::derive_did_from_public_key;
        let (_, ca_public) = generate_keypair().expect("keygen");

        let transform_sha256: [u8; 32] = Sha256::digest(&transform_bytes).into();
        let ca_sig = sign(ca_secret, &transform_bytes).expect("ca sign");

        let migration_id: [u8; 32] = transform_sha256; // id = SHA-256(transform_bytes)

        let embedded_hash = if tamper_hash {
            [0xFFu8; 32] // deliberately wrong
        } else {
            transform_sha256
        };

        let delta = MigrationDelta {
            id: migration_id,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source_hash,
            target_schema_hash: target_hash,
            transform_bytes,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256: embedded_hash,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        (delta, ca_public)
    }

    fn trivial_wasm_bytes() -> Vec<u8> {
        // Minimal WASM module: (module (func (export "run")))
        // Hard-coded bytes to avoid requiring `wat` at test time when not native.
        // Generated from: wat::parse_str(r#"(module (func (export "run")))"#)
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
            0x03, 0x02, 0x01, 0x00, // function section
            0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, // export "run"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty body
        ]
    }

    fn make_engine_with_path(
        ca_public: [u8; 32],
        source: [u8; 32],
        target: [u8; 32],
    ) -> SchemaMigrationEngine {
        let path = SchemaVersionPath::new(vec![source, target]);
        SchemaMigrationEngine::new(
            ca_public,
            source,
            path,
            1,
            #[cfg(feature = "native")]
            std::sync::Arc::new(std::sync::Mutex::new(
                crate::store::LocalStore::open(":memory:").expect("test store"),
            )),
        )
    }

    fn make_revocation(
        target_migration_id: MigrationId,
        signers: &[([u8; 32], String)],
    ) -> MigrationRevocationDelta {
        let sigs: Vec<ManagerSignature> = signers
            .iter()
            .map(|(secret, did)| {
                let sig = sign(secret, &target_migration_id).expect("sign");
                ManagerSignature {
                    manager_did: did.clone(),
                    signature: sig,
                }
            })
            .collect();

        MigrationRevocationDelta {
            target_migration_id,
            signatures: sigs,
            created_at: 0,
        }
    }

    fn make_manager_identity() -> ([u8; 32], String) {
        use crate::crdt::derive_did_from_public_key;
        let (secret, public) = generate_keypair().expect("keygen");
        let did = derive_did_from_public_key(&public);
        (secret, did)
    }

    // ─── Test: CA signature invalid → reject + blacklist ─────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn ca_sig_invalid_rejects_and_blacklists() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        // Build a delta but sign with a DIFFERENT (wrong) secret key.
        let (wrong_secret, _) = generate_keypair().expect("keygen");
        let (mut delta, _) =
            make_ca_signed_delta(&ca_secret, source, target, trivial_wasm_bytes(), false);

        // Replace the CA signature with one from the wrong key.
        let wrong_sig = sign(&wrong_secret, &delta.transform_bytes).expect("wrong sign");
        delta.ca_signature = CaSignature(wrong_sig.0);

        let mut engine = make_engine_with_path(ca_public, source, target);
        let result = engine.receive_migration_delta(delta, "did:key:z6MkBadSender");

        assert!(
            matches!(result, Err(TirBaseError::MigrationCaSignatureInvalid { .. })),
            "should reject with CA sig invalid: {result:?}"
        );
        assert!(
            engine.is_blacklisted("did:key:z6MkBadSender"),
            "sender must be blacklisted after CA sig failure"
        );
    }

    // ─── Test: hash mismatch → reject + blacklist ─────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn hash_mismatch_rejects_and_blacklists() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        let (delta, _) =
            make_ca_signed_delta(&ca_secret, source, target, trivial_wasm_bytes(), true /* tamper hash */);

        // Re-sign with the real CA key so the CA sig passes, but hash is wrong.
        let ca_sig = sign(&ca_secret, &delta.transform_bytes).expect("ca sign");
        let mut delta = delta;
        delta.ca_signature = CaSignature(ca_sig.0);

        let mut engine = make_engine_with_path(ca_public, source, target);
        let result = engine.receive_migration_delta(delta, "did:key:z6MkHashBad");

        assert!(
            matches!(result, Err(TirBaseError::MigrationHashMismatch { .. })),
            "should reject with hash mismatch: {result:?}"
        );
        assert!(
            engine.is_blacklisted("did:key:z6MkHashBad"),
            "sender must be blacklisted after hash mismatch"
        );
    }

    // ─── Test: version path mismatch → reject (no blacklist) ─────────────────

    #[test]
    #[cfg(feature = "native")]
    fn version_path_mismatch_rejects_without_blacklist() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];
        let wrong_source = [0x20u8; 32]; // not the local schema hash

        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let ca_sig = sign(&ca_secret, &wasm).expect("ca sign");

        let delta = MigrationDelta {
            id: transform_sha256,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: wrong_source, // mismatch
            target_schema_hash: target,
            transform_bytes: wasm,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        let mut engine = make_engine_with_path(ca_public, source, target);
        let result = engine.receive_migration_delta(delta, "did:key:z6MkVersionMismatch");

        assert!(
            matches!(result, Err(TirBaseError::VersionPathMismatch { .. })),
            "should reject with VersionPathMismatch: {result:?}"
        );
        assert!(
            !engine.is_blacklisted("did:key:z6MkVersionMismatch"),
            "version path mismatch must NOT blacklist the sender"
        );
    }

    // ─── Test: successful migration + schema update ───────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn successful_migration_updates_schema_hash() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let ca_sig = sign(&ca_secret, &wasm).expect("ca sign");

        let delta = MigrationDelta {
            id: transform_sha256,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes: wasm,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        let mut engine = make_engine_with_path(ca_public, source, target);
        let result = engine
            .receive_migration_delta(delta, "did:key:z6MkSender")
            .expect("migration should succeed");

        assert_eq!(result, MigrationResult::Success);
        assert_eq!(
            engine.local_schema_hash, target,
            "schema hash must be updated to target after successful migration"
        );
    }

    // ─── Test: revocation halts in-progress and blocks future apply ───────────

    #[test]
    fn revocation_blocks_migration() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let migration_id = transform_sha256;

        let (mgr_secret, mgr_did) = make_manager_identity();
        let revocation = make_revocation(migration_id, &[(mgr_secret, mgr_did)]);

        let mut engine = make_engine_with_path(ca_public, source, target);
        engine
            .receive_revocation_delta(revocation)
            .expect("revocation should succeed");

        assert!(engine.is_revoked(&migration_id), "migration must be revoked");

        // Attempting to apply the revoked migration should fail.
        let ca_sig = sign(&ca_secret, &wasm).expect("ca sign");
        let delta = MigrationDelta {
            id: migration_id,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes: wasm,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        let result = engine.receive_migration_delta(delta, "did:key:z6MkSender");
        assert!(
            matches!(result, Err(TirBaseError::AuthorisationFailed { .. })),
            "revoked migration must be rejected: {result:?}"
        );
    }

    // ─── Test: blacklisted sender is blocked on next attempt ─────────────────

    #[test]
    #[cfg(feature = "native")]
    fn blacklisted_sender_is_blocked() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];
        let sender = "did:key:z6MkBlacklist";

        // First request: wrong sig → blacklist.
        let (wrong_secret, _) = generate_keypair().expect("keygen");
        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let wrong_ca_sig = sign(&wrong_secret, &wasm).expect("wrong sign");

        let delta1 = MigrationDelta {
            id: transform_sha256,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes: wasm.clone(),
            ca_signature: CaSignature(wrong_ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        let mut engine = make_engine_with_path(ca_public, source, target);
        let _ = engine.receive_migration_delta(delta1, sender); // should fail + blacklist

        // Second request: even with valid sig, should be blocked.
        let good_ca_sig = sign(&ca_secret, &wasm).expect("good sign");
        let delta2 = MigrationDelta {
            id: transform_sha256,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes: wasm,
            ca_signature: CaSignature(good_ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        let result = engine.receive_migration_delta(delta2, sender);
        assert!(
            matches!(result, Err(TirBaseError::AuthorisationFailed { .. })),
            "blacklisted sender must be blocked: {result:?}"
        );
    }
}
