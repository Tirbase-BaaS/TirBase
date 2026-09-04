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
use quarantine::{QuarantineEntry, QuarantineLedger, QuarantineReason};
use revocation::RevokedMigrationRegistry;
use version_path::SchemaVersionPath;
use wasm_sandbox::{execute_migration, MigrationResult};

// Re-export for tests in sub-modules
pub use revocation::resolve_did_key_to_public_key;

/// A migration that passed every pre-flight gate (Req 18.2–18.3a) and is
/// ready to execute.
///
/// Carries everything the sandbox needs as owned data so the transform can
/// execute OFF the engine lock (Req 18.6): the caller runs the WASM sandbox
/// and reports the outcome back through [`SchemaMigrationEngine::finish_migration`].
/// Keeping execution off-lock is what lets a concurrently-arriving
/// `MigrationRevocationDelta` acquire the engine (to permanently revoke) and
/// epoch-interrupt the running transform instead of queueing behind it under
/// the shared mutex.
pub(crate) struct PreparedMigration {
    /// SHA-256(transform_bytes) — the migration's identifier.
    pub(crate) migration_id: MigrationId,
    /// Schema hash the device must advance to on a clean, non-revoked run.
    pub(crate) target_schema_hash: crate::schema::hash::SchemaIdentifierHash,
    /// CA-validated WASM bytecode to hand to the sandbox.
    pub(crate) transform_bytes: Vec<u8>,
    /// Epoch-interrupt timeout in seconds (Req 18.4 default: 30).
    pub(crate) timeout_secs: u64,
}

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

    /// Quarantine ledger for schema-incompatible Deltas (Req 17.4–17.6).
    ///
    /// Native: SQLite-backed via a dedicated connection.
    /// WASM: in-memory Vec.
    #[cfg(feature = "native")]
    quarantine_ledger: QuarantineLedger,

    #[cfg(not(feature = "native"))]
    quarantine_ledger: QuarantineLedger,
}

impl SchemaMigrationEngine {
    /// Create a new SchemaMigrationEngine.
    ///
    /// - `ca_public_key`: 32-byte Ed25519 public key of the deployment CA.
    /// - `local_schema_hash`: current schema hash of the local store.
    /// - `version_path`: deployment's ordered schema version path.
    /// - `revocation_threshold_m`: M value for M-of-N manager signature requirement.
    /// - `store`: handle to the local store for sandbox host functions (native only).
    /// - `migration_conn`: dedicated SQLite connection for the quarantine ledger (native only).
    pub fn new(
        ca_public_key: [u8; 32],
        local_schema_hash: crate::schema::hash::SchemaIdentifierHash,
        version_path: SchemaVersionPath,
        revocation_threshold_m: usize,
        #[cfg(feature = "native")] store: Arc<Mutex<crate::store::LocalStore>>,
        #[cfg(feature = "native")] migration_conn: Arc<Mutex<rusqlite::Connection>>,
    ) -> Self {
        #[cfg(feature = "native")]
        let quarantine_ledger = QuarantineLedger::new(migration_conn);

        #[cfg(not(feature = "native"))]
        let quarantine_ledger = QuarantineLedger::new();

        Self {
            ca_public_key,
            local_schema_hash,
            version_path,
            revocation_registry: RevokedMigrationRegistry::default(),
            blacklisted_senders: HashSet::new(),
            revocation_threshold_m,
            #[cfg(feature = "native")]
            store,
            quarantine_ledger,
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

    /// Register the deployment's Migration CA Ed25519 public key at runtime
    /// (Req 18.2).
    ///
    /// Takes effect immediately: subsequent [`receive_migration_delta`]
    /// calls verify `ca_signature` against this key.  Replaces any key
    /// registered at construction (deployment config).
    ///
    /// Production caller: [`crate::api::CoreHandle::register_migration_ca_key`],
    /// which is reachable from native host applications and the
    /// `core_register_migration_ca_key` WASM export.
    pub(crate) fn register_ca_public_key(&mut self, key: [u8; 32]) {
        self.ca_public_key = key;
    }

    /// The device's current (deployed) schema hash — starts at the first
    /// version of the registered path and advances as migrations apply.
    ///
    /// CoreHandle mirrors this into the CRDT engine's current schema after a
    /// successful inbound migration so that locally produced Deltas stamp the
    /// new hash (Req 4.6) and the data-Delta gate classifies against the new
    /// schema (Subphase 5.3, Req 17.3/17.4).
    pub(crate) fn current_schema_hash(&self) -> crate::schema::hash::SchemaIdentifierHash {
        self.local_schema_hash
    }

    /// Return `true` if the QuarantineLedger holds any unreleased entry whose
    /// schema hash matches the engine's current `local_schema_hash`.
    ///
    /// The quarantine is keyed by schema hash, not by table name. The `table`
    /// parameter is accepted for call-site compatibility but the check applies
    /// schema-wide.
    ///
    /// Used by `CoreHandle::write()` to determine whether to auto-tag writes as
    /// `ContaminatedByHumanReaction` (Req 19.5).
    pub fn is_schema_quarantined(&self, table: &str) -> bool {
        #[cfg(feature = "native")]
        {
            // Query all quarantined entries and check if any match our local schema
            // hash without having been released for migration.
            match self.quarantine_ledger.get_all() {
                Ok(entries) => entries.iter().any(|e| {
                    e.schema_hash == Some(self.local_schema_hash) && e.migration_id.is_none()
                }),
                Err(_) => false,
            }
        }
        #[cfg(not(feature = "native"))]
        {
            // WASM: use the in-memory get_by_schema_hash.
            match self.quarantine_ledger.get_by_schema_hash(&self.local_schema_hash) {
                Ok(entries) => entries.iter().any(|e| e.migration_id.is_none()),
                Err(_) => false,
            }
        }
    }

    /// Validate an incoming MigrationDelta and prepare it for execution
    /// (Req 18.2–18.3a).
    ///
    /// Checks in order:
    /// 1. Sender not blacklisted.
    /// 2. Migration not already revoked.
    /// 3. CA signature over transform_bytes is valid.
    /// 4. SHA-256 of transform_bytes matches embedded hash.
    /// 5. source_schema_hash == local current schema.
    /// 6. target_schema_hash == next step in registered version path.
    /// 7. No other transform is currently executing (migrations are strictly
    ///    serialised — each step validates against the device's current
    ///    schema hash, which only advances when the previous step commits).
    ///
    /// On success the migration is marked in-progress and a
    /// [`PreparedMigration`] is returned.  The caller then executes the
    /// transform OFF this engine's lock and reports the outcome through
    /// [`SchemaMigrationEngine::finish_migration`]; the synchronous
    /// [`SchemaMigrationEngine::receive_migration_delta`] convenience wrapper
    /// does exactly that without releasing the lock (direct-call path).
    ///
    /// On CA sig or hash failure: blacklist sender (Req 18.3).
    /// On version path mismatch: reject + log (no blacklist).
    pub(crate) fn prepare_migration(
        &mut self,
        delta: MigrationDelta,
        sender_did: &str,
    ) -> Result<PreparedMigration, TirBaseError> {
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

        // ── 7. Serialisation gate ────────────────────────────────────────────
        // At most one transform may execute at a time: schema steps are
        // ordered, and a second migration can only validate once the first
        // has committed (or been revoked) and the local schema hash reflects
        // it.  The CoreHandle inbound pipeline retries on this error instead
        // of dropping the delta.
        if self.revocation_registry.has_in_progress() {
            return Err(TirBaseError::MigrationInProgress {
                migration_id: hex::encode(delta.id),
            });
        }

        // ── 8. Mark in-progress and hand execution to the caller ────────────
        self.revocation_registry.mark_in_progress(delta.id);

        Ok(PreparedMigration {
            migration_id: delta.id,
            target_schema_hash: delta.target_schema_hash,
            transform_bytes: delta.transform_bytes,
            timeout_secs: 30, // Req 18.4: default 30s epoch-interrupt timeout
        })
    }

    /// Report the outcome of a prepared transform back to the engine.
    ///
    /// - Clears the in-progress marker unconditionally (the migration is no
    ///   longer executing regardless of how it ended).
    /// - **Re-checks revocation before committing**: if the migration was
    ///   revoked while the transform ran (or between sandbox exit and this
    ///   call), the local schema hash must NOT advance to the target — the
    ///   outcome is returned as [`MigrationResult::Revoked`] instead of
    ///   `Success` (Req 18.6).  This is the authoritative commit gate for the
    ///   off-lock execution path.
    pub(crate) fn finish_migration(
        &mut self,
        migration_id: &MigrationId,
        target_schema_hash: &crate::schema::hash::SchemaIdentifierHash,
        result: Result<MigrationResult, TirBaseError>,
    ) -> Result<MigrationResult, TirBaseError> {
        self.revocation_registry.clear_in_progress(migration_id);

        if self.revocation_registry.is_revoked(migration_id) {
            let migration_id_hex = hex::encode(migration_id);
            eprintln!(
                "[migration] Migration {migration_id_hex} revoked before commit — \
                 transform outcome discarded, schema NOT advanced"
            );
            return Ok(MigrationResult::Revoked {
                reason: format!("migration {migration_id_hex} revoked while in progress"),
            });
        }

        match result {
            Ok(MigrationResult::Success) => {
                self.local_schema_hash = *target_schema_hash;
                Ok(MigrationResult::Success)
            }
            Ok(other) => Ok(other),
            Err(e) => Err(e),
        }
    }

    /// Whether a migration transform is currently executing (prepared but not
    /// yet finished).  At most one may run at a time.
    pub(crate) fn any_migration_in_progress(&self) -> bool {
        self.revocation_registry.has_in_progress()
    }

    /// Whether the given migration id is currently executing.
    pub(crate) fn is_migration_in_progress(&self, migration_id: &MigrationId) -> bool {
        self.revocation_registry.is_in_progress(migration_id)
    }

    /// Receive and validate an incoming MigrationDelta, execute it in the
    /// sandbox, and commit the schema-hash advance (Req 18.2–18.4).
    ///
    /// This is the synchronous convenience path: the transform runs while the
    /// caller holds the engine lock, so a concurrently arriving revocation
    /// cannot interrupt it mid-flight (it will be processed after this call
    /// returns and only block *future* applies).  Production inbound traffic
    /// that must satisfy Req 18.6 goes through [`SchemaMigrationEngine::prepare_migration`]
    /// → off-lock sandbox execution → [`SchemaMigrationEngine::finish_migration`]
    /// (see the CoreHandle inbound pipeline).  Regardless of path, the
    /// post-run revocation re-check in `finish_migration` protects the commit.
    pub fn receive_migration_delta(
        &mut self,
        delta: MigrationDelta,
        sender_did: &str,
    ) -> Result<MigrationResult, TirBaseError> {
        let prepared = self.prepare_migration(delta, sender_did)?;

        #[cfg(feature = "native")]
        let result = execute_migration(
            &prepared.transform_bytes,
            prepared.migration_id,
            prepared.timeout_secs,
            &self.store,
        );

        #[cfg(not(feature = "native"))]
        let result = execute_migration(
            &prepared.transform_bytes,
            prepared.migration_id,
            prepared.timeout_secs,
        );

        let outcome = self.finish_migration(
            &prepared.migration_id,
            &prepared.target_schema_hash,
            result,
        );

        match outcome {
            Ok(MigrationResult::Success) => {
                eprintln!(
                    "[migration] Migration {:?} succeeded; schema updated to {:?}",
                    prepared.migration_id, prepared.target_schema_hash
                );
                Ok(MigrationResult::Success)
            }
            Ok(MigrationResult::TimedOut { timeout_secs }) => {
                let migration_id_hex = hex::encode(prepared.migration_id);
                eprintln!(
                    "[migration] Migration {migration_id_hex} timed out after {timeout_secs}s"
                );
                Err(TirBaseError::MigrationTransformTimeout {
                    migration_id: migration_id_hex,
                })
            }
            Ok(MigrationResult::Aborted { ref reason }) => {
                eprintln!(
                    "[migration] Migration {:?} aborted: {reason}",
                    prepared.migration_id
                );
                Ok(MigrationResult::Aborted { reason: reason.clone() })
            }
            Ok(MigrationResult::Revoked { ref reason }) => {
                eprintln!(
                    "[migration] Migration {:?} revoked: {reason}",
                    prepared.migration_id
                );
                Ok(MigrationResult::Revoked { reason: reason.clone() })
            }
            Err(e) => Err(e),
        }
    }

    /// Receive a MigrationRevocationDelta (Req 18.5–18.7).
    ///
    /// Verifies the M-of-N Manager signature threshold, permanently blocks the
    /// target migration id, and halts any in-progress transform for it.
    ///
    /// Returns `Ok(true)` when a transform for the target was executing and
    /// has been halted.  The caller must then epoch-interrupt the running
    /// sandbox via the execution registry so it actually stops (Req 18.6) —
    /// the engine merely clears the in-progress marker here; the CoreHandle
    /// inbound pipeline performs the wasmtime interrupt.
    pub fn receive_revocation_delta(
        &mut self,
        delta: MigrationRevocationDelta,
    ) -> Result<bool, TirBaseError> {
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

// ─── Public quarantine helper ─────────────────────────────────────────────────

impl SchemaMigrationEngine {
    /// Quarantine a raw incoming Delta that is incompatible with the current schema.
    ///
    /// This is called by the inbound pipeline (e.g. `CoreHandle::receive_inbound`)
    /// when a Delta's schema hash does not match the local schema hash. The Delta
    /// is stored byte-for-byte in the quarantine ledger without modification (Req 17.5).
    ///
    /// Returns the quarantine entry ID (SHA-256 of `raw_bytes`).
    pub fn quarantine_incoming(
        &mut self,
        sender_did: &str,
        raw_bytes: Vec<u8>,
        schema_hash: Option<crate::schema::hash::SchemaIdentifierHash>,
        reason: QuarantineReason,
        received_at: i64,
    ) -> Result<[u8; 32], TirBaseError> {
        self.quarantine_ledger.quarantine(
            sender_did.to_string(),
            raw_bytes,
            schema_hash,
            reason,
            received_at,
        )
    }

    /// Return all entries currently held in the quarantine ledger.
    ///
    /// Used by the inbound integration tests to assert that a quarantined
    /// Delta's raw bytes were persisted byte-for-byte (Subphase 5.2); also the
    /// inspection entry point for quarantine replay tooling (Req 17.4–17.6).
    pub(crate) fn quarantined_entries(&self) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        self.quarantine_ledger.get_all()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{Ed25519Signature, PriorityClass};
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::migration::migration_delta::{CaSignature, ManagerSignature, MigrationRevocationDelta};
    use crate::migration::quarantine::QuarantineReason;
    #[cfg(feature = "native")]
    use crate::store::sqlite::CREATE_SCHEMA_SQL;
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
            #[cfg(feature = "native")]
            {
                let conn = rusqlite::Connection::open_in_memory().expect("open in-memory migration conn");
                conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL).expect("create schema");
                std::sync::Arc::new(std::sync::Mutex::new(conn))
            },
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

    // ─── Test: a revocation landing between prepare and finish blocks the ────
    //
    // ── schema-hash commit (Req 18.6 commit gate) ───────────────────────────
    //
    // The off-lock execution path prepares a migration, runs the transform
    // without the engine lock, and finishes afterwards.  If a revocation is
    // applied while the transform runs, `finish_migration` must NOT advance
    // the local schema hash even though the transform itself succeeded.
    #[test]
    #[cfg(feature = "native")]
    fn revocation_between_prepare_and_finish_blocks_schema_commit() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let migration_id = transform_sha256;
        let ca_sig = sign(&ca_secret, &wasm).expect("ca sign");

        let delta = MigrationDelta {
            id: migration_id,
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes: wasm,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: crate::crdt::delta::PriorityClass::Medium,
            created_at: 0,
        };

        let mut engine = make_engine_with_path(ca_public, source, target);

        // Prepare (validates + marks in-progress) but do NOT run yet — this
        // models the off-lock window in which the CoreHandle pipeline runs the
        // sandbox while the engine lock is free.
        let prepared = engine
            .prepare_migration(delta, "did:key:z6MkSender")
            .expect("prepare must succeed");
        assert!(engine.is_migration_in_progress(&migration_id));

        // A revocation arrives and halts the in-progress transform.
        let (mgr_secret, mgr_did) = make_manager_identity();
        let revocation = make_revocation(migration_id, &[(mgr_secret, mgr_did)]);
        let halted = engine
            .receive_revocation_delta(revocation)
            .expect("revocation must succeed");
        assert!(halted, "revocation must report that it halted the in-progress run");

        // The transform (which "succeeded") reports back: the commit gate must
        // convert it to Revoked and leave the schema at the source hash.
        let outcome = engine
            .finish_migration(
                &prepared.migration_id,
                &prepared.target_schema_hash,
                Ok(MigrationResult::Success),
            )
            .expect("finish must succeed");
        assert!(
            matches!(outcome, MigrationResult::Revoked { .. }),
            "a revoked migration must never commit as Success: {outcome:?}"
        );
        assert_eq!(
            engine.local_schema_hash, source,
            "schema hash must NOT advance for a revoked migration"
        );
        assert!(
            !engine.is_migration_in_progress(&migration_id),
            "in-progress marker must be cleared after finish"
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

    // ─── Test: quarantine entry → is_schema_quarantined returns true ──────────

    #[test]
    fn quarantine_entry_causes_is_schema_quarantined_to_return_true() {
        let (_, ca_public) = generate_keypair().expect("keygen");
        let source = [0x42u8; 32];
        let target = [0x43u8; 32];

        let mut engine = make_engine_with_path(ca_public, source, target);

        // Initially no quarantined entries → should be false.
        assert!(
            !engine.is_schema_quarantined("any_table"),
            "is_schema_quarantined must be false when ledger is empty"
        );

        // Add a raw delta to the quarantine ledger matching the engine's local schema hash.
        let raw_bytes = b"fake-raw-delta-bytes".to_vec();
        engine
            .quarantine_incoming(
                "did:key:z6MkSender",
                raw_bytes,
                Some(source), // schema_hash == local_schema_hash
                QuarantineReason::UnknownSchemaHash,
                1_720_000_000_000_000,
            )
            .expect("quarantine_incoming must succeed");

        // Now should be true.
        assert!(
            engine.is_schema_quarantined("any_table"),
            "is_schema_quarantined must be true after adding an unreleased quarantine entry"
        );
    }

    // ─── Test: after release_for_migration → is_schema_quarantined returns false ──

    #[test]
    #[cfg(feature = "native")]
    fn is_schema_quarantined_false_after_release_for_migration() {
        let (_, ca_public) = generate_keypair().expect("keygen");
        let source = [0x44u8; 32];
        let target = [0x45u8; 32];

        let mut engine = make_engine_with_path(ca_public, source, target);

        // Quarantine an entry.
        let raw_bytes = b"raw-delta-to-release".to_vec();
        engine
            .quarantine_incoming(
                "did:key:z6MkPeer",
                raw_bytes,
                Some(source),
                QuarantineReason::BreakingSchemaChange,
                0,
            )
            .expect("quarantine_incoming must succeed");

        assert!(
            engine.is_schema_quarantined("tbl"),
            "must be quarantined before release"
        );

        // Release via quarantine_ledger directly.
        let migration_id = [0xCCu8; 32];
        engine
            .quarantine_ledger
            .release_for_migration(&source, migration_id)
            .expect("release_for_migration must succeed");

        // After release (migration_id is now set) → should be false.
        assert!(
            !engine.is_schema_quarantined("tbl"),
            "is_schema_quarantined must be false after entry is released for migration"
        );
    }

    // ─── Test: in-progress sandbox (no quarantine entries) → is_schema_quarantined false ──

    #[test]
    fn no_quarantine_entries_means_not_quarantined_even_if_migration_in_progress() {
        let (_, ca_public) = generate_keypair().expect("keygen");
        let source = [0x46u8; 32];
        let target = [0x47u8; 32];

        let mut engine = make_engine_with_path(ca_public, source, target);

        // Simulate a migration that is "in progress" via the revocation registry.
        let migration_id: [u8; 32] = [0xABu8; 32];
        engine.revocation_registry.mark_in_progress(migration_id);

        // No quarantine entries have been added.
        assert!(
            !engine.is_schema_quarantined("any_table"),
            "is_schema_quarantined must be false when ledger is empty, even if a migration is in-progress"
        );
    }
}
