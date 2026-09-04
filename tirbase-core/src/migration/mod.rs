//! Schema Migration Engine — zero-trust gate, WASM sandbox, Side-Car replay (Req 17–19).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod migration_delta;
pub mod quarantine;
pub mod revocation;
pub mod sidecar;
pub mod version_path;
pub mod wasm_sandbox;

use std::collections::{HashMap, HashSet};

#[cfg(feature = "native")]
use std::sync::{Arc, Mutex};

use crate::crdt::delta::DeltaId;
use crate::errors::TirBaseError;
use migration_delta::{MigrationDelta, MigrationId, MigrationRevocationDelta};
use quarantine::{QuarantineEntry, QuarantineLedger, QuarantineReason};
use revocation::RevokedMigrationRegistry;
use sidecar::{ReplaySummary, SideCarEntry, SideCarLedger};
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

    /// Side-Car Ledger — non-destructive preservation of writes made against
    /// a corrupted schema, for replay when a corrected migration arrives
    /// (Req 19.1–19.6).
    ///
    /// Native: SQLite-backed via the migration's dedicated connection.
    /// WASM: in-memory Vec.
    sidecar_ledger: SideCarLedger,

    /// Migration hash → target schema hash, recorded at prepare time so a
    /// revocation can identify which schema a corrupted migration produced
    /// (Req 19.1/19.2 corruption-window scoping).
    migration_targets: HashMap<MigrationId, crate::schema::hash::SchemaIdentifierHash>,

    /// Schema hashes currently under a corruption window → the migration IDs
    /// whose revocations opened them (Req 19.1/19.2).  A window opens when a
    /// revoked migration's target schema is the device's current schema;
    /// while it is open, writes stamped with that schema are captured in the
    /// Side-Car Ledger and the window's entries are replayed onto the
    /// corrected projection when a migration off that schema commits (Req
    /// 19.3).
    corrupted_schema_windows:
        HashMap<crate::schema::hash::SchemaIdentifierHash, Vec<MigrationId>>,
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
        let quarantine_ledger = QuarantineLedger::new(migration_conn.clone());

        #[cfg(not(feature = "native"))]
        let quarantine_ledger = QuarantineLedger::new();

        // The Side-Car Ledger shares the migration's dedicated connection
        // (native) or uses the in-memory stub (WASM).  Both the quarantine
        // and side-car ledgers live on the same per-migration connection so
        // they are created by `CREATE_SCHEMA_SQL` at store open.
        #[cfg(feature = "native")]
        let sidecar_ledger = SideCarLedger::new(migration_conn);

        #[cfg(not(feature = "native"))]
        let sidecar_ledger = SideCarLedger::new();

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
            sidecar_ledger,
            migration_targets: HashMap::new(),
            corrupted_schema_windows: HashMap::new(),
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
    /// 4a. Record the migration hash as **known / previously-seen** (Req 18.7)
    ///     — once the CA signature and hash integrity cleared, this is a real
    ///     migration this device has seen, and the only kind a manager-signed
    ///     `MigrationRevocationDelta` may target.  Recorded even when a later
    ///     gate below rejects the delta (e.g. version-path mismatch), so a
    ///     corrupt-but-CA-signed migration can be revoked before it becomes
    ///     applicable.
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
    /// On CA sig or hash failure: blacklist sender (Req 18.3) and the hash is
    /// NOT recorded as known (an unauthenticated hash must not become
    /// revocable).
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

        // ── 4a. Known-hash recording (Req 18.7) ──────────────────────────────
        // The CA signature (3) and embedded SHA-256 (4) both verified, so this
        // hash is a genuine migration this device has now seen.  Record it:
        // `apply_revocation` only accepts a MigrationRevocationDelta whose
        // target is in this known set, so an arbitrary-hash revocation is
        // rejected rather than silently poisoning the registry.  Recorded
        // before the version-path gate on purpose: a corrupt-but-CA-signed
        // migration for a *future* schema step is still a real hash managers
        // may legitimately revoke before it becomes applicable.
        self.revocation_registry.record_known_migration(delta.id);

        // Remember the migration's target schema hash so a later revocation
        // can open the corruption window on the exact schema this migration
        // produces (Req 19.1/19.2).
        self.migration_targets
            .insert(delta.id, delta.target_schema_hash);

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
    /// Rejects with [`TirBaseError::UnknownMigrationHash`] unless the target
    /// is a known, previously-seen migration hash (Req 18.7) — one this
    /// engine recorded in [`Self::prepare_migration`] after its CA signature
    /// cleared.  Then verifies the M-of-N Manager signature threshold,
    /// permanently blocks the target migration id, and halts any in-progress
    /// transform for it.
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
        let revoked_id = delta.target_migration_id;
        let halted = self
            .revocation_registry
            .apply_revocation(delta, self.revocation_threshold_m)?;

        // ── Req 19.1/19.2: corruption window ────────────────────────────────
        // The revoked migration is now flagged corrupted.  If it produced the
        // schema this device is currently on, open a corruption window so
        // every subsequent write stamped with that schema is preserved in the
        // Side-Car Ledger (scoped to this migration id) instead of being
        // silently trusted.  A migration revoked before it was ever applied
        // (local schema != its target) opens nothing — the device never moved
        // onto the corrupted schema, so there is nothing to capture.
        if let Some(target) = self.migration_targets.get(&revoked_id).copied() {
            if target == self.local_schema_hash {
                self.corrupted_schema_windows
                    .entry(target)
                    .or_default()
                    .push(revoked_id);
                eprintln!(
                    "[migration] Corruption window opened for schema {} \
                     (migration {:?}) — writes are now Side-Car captured (Req 19.2)",
                    hex::encode(target),
                    revoked_id
                );
            }
        }

        Ok(halted)
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

// ─── Corruption-window + Side-Car capture/replay (Req 19.1–19.6) ───────────────

impl SchemaMigrationEngine {
    /// If the device's current schema is under an active corruption window — a
    /// revoked (corrupted) migration produced it — return the migration ID
    /// that opened the window: the scope under which writes against the
    /// corrupted schema are preserved in the Side-Car Ledger (Req 19.2).
    ///
    /// Returns `None` when the current schema is not corrupted.
    pub(crate) fn active_corruption_migration(&self) -> Option<MigrationId> {
        self.corrupted_schema_windows
            .get(&self.local_schema_hash)
            .and_then(|ids| ids.first().copied())
    }

    /// Record a write made against the corrupted schema in the Side-Car
    /// Ledger, byte-for-byte and scoped to the corrupting migration's ID
    /// (Req 19.2).
    ///
    /// Returns `Ok(None)` when no corruption window is active for the current
    /// schema (nothing to capture); `Ok(Some(entry_id))` when the write was
    /// preserved.  The caller (the production write path) treats capture as
    /// best-effort: a capture failure must not fail the write itself.
    pub(crate) fn record_corrupted_window_write(
        &mut self,
        table: &str,
        delta_bytes: Vec<u8>,
        recorded_ts: i64,
    ) -> Result<Option<DeltaId>, TirBaseError> {
        let Some(migration_id) = self.active_corruption_migration() else {
            return Ok(None);
        };
        let entry_id = self
            .sidecar_ledger
            .record(migration_id, table.to_string(), delta_bytes, recorded_ts)?;
        Ok(Some(entry_id))
    }

    /// Replay every Side-Car entry captured while `pre_migration_schema` was
    /// under a corruption window against the corrected projection (Req 19.3).
    ///
    /// Called by the inbound migration success path once a corrected
    /// migration has committed and the CRDT engine has advanced to
    /// `corrected_schema_hash`.  Entries are replayed in recorded-timestamp
    /// order; replay conflicts are flagged, never aborting the pass or the
    /// already-committed migration (Req 19.4).  The corruption window is
    /// closed once replayed — the device has left the corrupted schema.
    pub(crate) fn replay_corrupted_windows(
        &mut self,
        pre_migration_schema: &crate::schema::hash::SchemaIdentifierHash,
        corrected_schema_hash: crate::schema::hash::SchemaIdentifierHash,
        engine: &mut crate::crdt::CrdtEngine,
    ) -> Result<(), TirBaseError> {
        let Some(migration_ids) = self.corrupted_schema_windows.remove(pre_migration_schema) else {
            return Ok(());
        };

        for migration_id in &migration_ids {
            match self
                .sidecar_ledger
                .replay_sidecar(*migration_id, corrected_schema_hash, engine)
            {
                Ok(summary) => {
                    eprintln!(
                        "[migration] Side-Car replay for corrupted migration {:?}: \
                         {}/{} entries replayed, {} conflicts, complete={} (Req 19.3)",
                        migration_id,
                        summary.replayed,
                        summary.total_entries,
                        summary.conflicts,
                        summary.complete,
                    );
                }
                Err(e) => {
                    // Best-effort: the migration has already committed and the
                    // entries stay PENDING in the ledger for a later retry.
                    eprintln!(
                        "[migration] Side-Car replay for corrupted migration {:?} failed: {e}",
                        migration_id
                    );
                }
            }
        }

        Ok(())
    }

    /// All Side-Car entries scoped to `migration_id`, in recorded-timestamp
    /// order — the replay-order view used by the corruption-recovery
    /// integration test to assert capture and replay status transitions.
    pub(crate) fn sidecar_entries(
        &self,
        migration_id: &MigrationId,
    ) -> Result<Vec<SideCarEntry>, TirBaseError> {
        self.sidecar_ledger.load_entries_ordered(*migration_id)
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

    // ─── Test: revocation blocks future apply of a seen migration hash ────────
    //
    // The migration delta is received first — that is what makes its
    // CA-validated hash a known, previously-seen migration hash (Req 18.7) —
    // then a manager-signed revocation permanently blocks it, and a later
    // re-delivery of the same migration is rejected at the revocation gate.

    #[test]
    fn revocation_blocks_migration() {
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
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes: wasm,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        };

        let (mgr_secret, mgr_did) = make_manager_identity();
        let revocation = make_revocation(migration_id, &[(mgr_secret, mgr_did)]);

        let mut engine = make_engine_with_path(ca_public, source, target);

        // 1. Deliver the migration: prepare validates it (CA sig + hash) and
        // records the hash as known (Req 18.7).  In production the transform
        // runs off-lock after this; here we hold the prepared run.
        let prepared = engine
            .prepare_migration(delta.clone(), "did:key:z6MkSender")
            .expect("prepare must succeed");
        assert!(!engine.is_revoked(&migration_id), "not revoked yet");

        // 2. A manager-signed revocation for the seen hash is accepted and
        // halts the in-progress run.
        let halted = engine
            .receive_revocation_delta(revocation)
            .expect("revocation should succeed");
        assert!(halted, "revocation must report halting the in-progress run");
        assert!(engine.is_revoked(&migration_id), "migration must be revoked");

        // 3. The sandbox job exits: the commit gate converts the run to
        // Revoked — the schema never advances for a revoked migration.
        let outcome = engine
            .finish_migration(
                &prepared.migration_id,
                &prepared.target_schema_hash,
                Ok(MigrationResult::Success),
            )
            .expect("finish must succeed");
        assert!(
            matches!(outcome, MigrationResult::Revoked { .. }),
            "revoked run must not commit as Success: {outcome:?}"
        );

        // 4. Attempting to apply the revoked migration again must fail.
        let result = engine.receive_migration_delta(delta, "did:key:z6MkSender");
        assert!(
            matches!(result, Err(TirBaseError::AuthorisationFailed { .. })),
            "revoked migration must be rejected: {result:?}"
        );
    }

    // ─── Test: a revocation for a never-seen (arbitrary) hash is rejected ────
    //
    // Req 18.7: even a revocation carrying a threshold-valid Manager
    // signature is rejected when the target hash was never received as a
    // CA-validated MigrationDelta — arbitrary hashes are no longer accepted.

    #[test]
    fn revocation_for_never_seen_hash_is_rejected() {
        let (_, ca_public) = generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        // A hash this engine has never seen: nothing was ever prepared or
        // delivered for it.
        let arbitrary: MigrationId = [0xEEu8; 32];
        let (mgr_secret, mgr_did) = make_manager_identity();
        let revocation = make_revocation(arbitrary, &[(mgr_secret, mgr_did)]);

        let mut engine = make_engine_with_path(ca_public, source, target);
        let result = engine.receive_revocation_delta(revocation);

        assert!(
            matches!(result, Err(TirBaseError::UnknownMigrationHash { .. })),
            "arbitrary-hash revocation must be rejected: {result:?}"
        );
        assert!(
            !engine.is_revoked(&arbitrary),
            "registry must stay un-poisoned by an arbitrary-hash revocation"
        );
        assert_eq!(
            engine.revocation_registry.revocation_log().len(),
            0,
            "no audit entry may be appended for a rejected revocation"
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

    // ─── Test: revoking an *applied* migration opens the corruption window ──
    //
    // Req 19.1/19.2: once a migration that produced the device's current
    // schema is flagged corrupted (revoked), writes against that schema must
    // be captured in the Side-Car Ledger scoped to the corrupting migration.

    #[test]
    #[cfg(feature = "native")]
    fn revoked_applied_migration_opens_corruption_window_and_captures_writes() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x50u8; 32];
        let target = [0x51u8; 32];
        let corrected = [0x52u8; 32];

        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let migration_id = transform_sha256;
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

        let mut engine = make_engine_with_path(ca_public, source, target);

        // 1. Apply the migration: the device now runs schema `target`.
        let prepared = engine
            .prepare_migration(delta, "did:key:z6MkSender")
            .expect("prepare must succeed");
        let outcome = engine
            .finish_migration(
                &prepared.migration_id,
                &prepared.target_schema_hash,
                Ok(MigrationResult::Success),
            )
            .expect("finish must succeed");
        assert_eq!(outcome, MigrationResult::Success);
        assert_eq!(engine.local_schema_hash, target);

        // 2. Revoke the applied migration → the corruption window opens.
        let (mgr_secret, mgr_did) = make_manager_identity();
        let revocation = make_revocation(migration_id, &[(mgr_secret, mgr_did)]);
        engine
            .receive_revocation_delta(revocation)
            .expect("revocation of the applied migration must succeed");
        assert!(
            engine.active_corruption_migration() == Some(migration_id),
            "corruption window must open on the revoked migration's target schema"
        );

        // 3. Writes during the corrupted window are Side-Car captured, scoped
        // to the corrupting migration (Req 19.2), byte-for-byte.
        let raw = b"user-write-during-corrupted-window".to_vec();
        let entry = engine
            .record_corrupted_window_write("reports", raw.clone(), 1234)
            .expect("capture must succeed")
            .expect("a capture id must be returned while the window is open");
        let entries = engine
            .sidecar_entries(&migration_id)
            .expect("read sidecar entries");
        assert_eq!(entries.len(), 1, "exactly one captured write");
        assert_eq!(entries[0].id, entry);
        assert_eq!(entries[0].migration_id, migration_id);
        assert_eq!(entries[0].table_name, "reports");
        assert_eq!(entries[0].delta_bytes, raw, "Req 19.2: no modification");
        assert_eq!(entries[0].recorded_ts, 1234);

        // 4. A corrected migration commits → replay runs against the corrected
        // projection (Req 19.3).  The captured entry is garbage JSON here, so
        // it flags CONFLICT rather than aborting the pass (Req 19.4) — the
        // window is still closed afterwards, so capture stops.
        let (secret, public) = generate_keypair().expect("keygen");
        let did = crate::crdt::derive_did_from_public_key(&public);
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
            .expect("create schema");
        let mut crdt = crate::crdt::CrdtEngine::new(
            secret,
            public,
            did,
            corrected,
            std::sync::Arc::new(std::sync::Mutex::new(conn)),
        );
        engine
            .replay_corrupted_windows(&target, corrected, &mut crdt)
            .expect("replay must not error");

        assert!(
            engine.active_corruption_migration().is_none(),
            "the corruption window must close once replayed"
        );
        let entries = engine
            .sidecar_entries(&migration_id)
            .expect("read sidecar entries after replay");
        assert_eq!(entries.len(), 1);
        assert!(
            matches!(
                entries[0].replay_status,
                crate::migration::sidecar::ReplayStatus::Conflict { .. }
            ),
            "the replay pass must have touched the entry (garbage bytes → CONFLICT, Req 19.4): {:?}",
            entries[0].replay_status
        );
        let captured_after = engine
            .record_corrupted_window_write("reports", b"post-replay".to_vec(), 9999)
            .expect("capture call must not error");
        assert!(
            captured_after.is_none(),
            "no capture after the window closed (device has left the corrupted schema)"
        );
    }

    // ─── Test: revoking a *never-applied* migration opens no window ─────────
    //
    // If the revoked migration never moved the device onto its target schema
    // (revoked before apply), the device has no corrupted-window writes to
    // preserve — capture must stay off.

    #[test]
    #[cfg(feature = "native")]
    fn revoked_unapplied_migration_does_not_open_corruption_window() {
        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let source = [0x53u8; 32];
        let target = [0x54u8; 32];

        let wasm = trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&wasm).into();
        let migration_id = transform_sha256;
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

        let mut engine = make_engine_with_path(ca_public, source, target);

        // Prepare records the migration as known (Req 18.7) and remembers its
        // target, but the transform never commits — the device stays on
        // `source`.
        let _prepared = engine
            .prepare_migration(delta, "did:key:z6MkSender")
            .expect("prepare must succeed");

        let (mgr_secret, mgr_did) = make_manager_identity();
        let revocation = make_revocation(migration_id, &[(mgr_secret, mgr_did)]);
        engine
            .receive_revocation_delta(revocation)
            .expect("revocation must succeed");

        assert!(
            engine.active_corruption_migration().is_none(),
            "no corruption window when the revoked migration was never applied"
        );
        let captured = engine
            .record_corrupted_window_write("reports", b"not-captured".to_vec(), 1)
            .expect("capture call must not error");
        assert!(
            captured.is_none(),
            "writes must not be captured when no corruption window is active"
        );
    }
}
