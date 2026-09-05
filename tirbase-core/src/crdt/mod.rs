//! CRDT Engine — wrapper around automerge::AutoCommit (Req 4.1).
//!
//! The CrdtEngine converts writes into Automerge 3.0 changesets (Deltas) and
//! merges incoming Deltas from peers. It maintains the ChangesetDag and drives
//! the LWW and RGA merge paths via the schema-hash gate.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod dag;
pub mod delta;
pub mod merge;
pub mod schema_hash;

pub(crate) mod failure;
mod verify;

use std::collections::{HashMap, HashSet, VecDeque};

use failure::{
    notify_delta_rejection, DeltaRejectionCode, DeltaRejectionListener, DeltaRejectionRecord,
};

use crate::errors::TirBaseError;
use crate::identity::keypair;
use crate::schema::diff::{diff_schemas, SchemaDiff};
use crate::schema::Schema;
use delta::{Delta, DeltaId, DeltaTag, Did, Ed25519Signature, PriorityClass};
use merge::{MergeOutcome, QuarantineReason};
use schema_hash::SchemaIdentifierHash;

#[cfg(feature = "native")]
use dag::{ChangesetDag, DagNode};

// ─── DID resolution helpers ──────────────────────────────────────────────────

/// Decode a `did:key:z6Mk…` DID to its 32-byte Ed25519 public key.
///
/// Delegates to the canonical [`crate::identity::did::resolve_did`].  (This
/// helper previously re-implemented resolution but forgot the multibase `z`
/// marker, so real device DIDs — which are always `did:key:z6Mk…` — could
/// never be resolved and every peer Delta was rejected at signature
/// verification.  A real-mesh round-trip test — Phase 0.3(b) — surfaced it.)
fn resolve_did_key_to_public_key(did: &str) -> Result<[u8; 32], TirBaseError> {
    crate::identity::did::resolve_did(&did.to_string())
}

/// Derive a `did:key:` DID from a 32-byte Ed25519 public key.
///
/// Delegates to the canonical [`crate::identity::did::derive_did`] so every
/// DID in the system uses the multibase `z` marker (`did:key:z6Mk…`).
pub fn derive_did_from_public_key(public_key: &[u8; 32]) -> Did {
    crate::identity::did::derive_did(public_key)
}

// ─── CrdtEngine ──────────────────────────────────────────────────────────────

/// The CRDT Engine wraps `automerge::AutoCommit` and adds TirBase-specific
/// routing, signing, and DAG management.
pub struct CrdtEngine {
    /// One Automerge doc per engine instance (the CRDT engine is table-scoped at the
    /// `CoreHandle` level; each table gets its own `CrdtEngine`).
    doc: automerge::AutoCommit,

    /// Monotonically increasing Lamport clock.
    lamport: u64,

    /// The schema hash of the device's current (deployed) schema.  Set at
    /// construction; advanced to the deployment's next version when an
    /// over-the-mesh migration applies ([`CrdtEngine::set_current_schema`]).
    /// Deltas produced locally carry this hash (Req 4.6).
    known_schema_hash: SchemaIdentifierHash,

    /// All schema hashes accepted by this engine.
    /// Grows as additive schema migrations are applied and when additive
    /// peer Deltas are merged (Req 17.3).
    known_schemas: HashSet<SchemaIdentifierHash>,

    /// Full schema definitions the deployment registered, keyed by their
    /// canonical SchemaIdentifierHash (Subphase 5.3).  Present only for
    /// schemas the device can reason about at the field level; a hash with no
    /// definition here cannot be classified as additive vs breaking and falls
    /// back to the legacy unknown-hash quarantine.
    schema_definitions: HashMap<SchemaIdentifierHash, Schema>,

    /// DID of the local device's identity (used in `produce_delta`).
    author_did: Did,

    /// Ed25519 secret key seed (32 bytes) for signing produced Deltas.
    secret_key: [u8; 32],

    /// DIDs whose devices are REVOKED (Req 8.6).
    ///
    /// Inbound Deltas authored by any DID in this set are rejected by
    /// [`CrdtEngine::apply`] before schema/signature checks — a revoked
    /// author's Deltas must never enter the merged state, even if they
    /// are well-formed and correctly signed.
    revoked_dids: HashSet<Did>,

    /// Structured rejection failure records emitted by [`Self::apply`]
    /// (Subphase 6.2 — Req 7.4/7.5).
    ///
    /// Every rejected inbound Delta appends one record carrying the sender
    /// DID and a UTC timestamp; the buffer is bounded (oldest dropped) so a
    /// hostile peer that floods the gate with invalid Deltas cannot grow
    /// engine memory without bound.  Retained on the engine for introspection
    /// ([`Self::rejection_records`]) and relayed to the host listener
    /// ([`Self::set_rejection_listener`]).
    rejection_records: VecDeque<DeltaRejectionRecord>,

    /// Optional host listener invoked for every rejection record the engine
    /// emits (Subphase 6.2).
    ///
    /// Registered by [`crate::api::CoreHandle::init`], which forwards each
    /// record onto a non-blocking broadcast channel for host subscribers.  The
    /// listener runs while the engine is locked (inside [`Self::apply`]), so
    /// it must never re-enter the engine.
    rejection_listener: Option<DeltaRejectionListener>,

    /// SQLite-backed Changeset DAG (native build only).
    #[cfg(feature = "native")]
    dag: ChangesetDag,
}

/// Result of the schema-hash gate's additive-vs-breaking classification
/// (Subphase 5.3 — Req 17.2–17.4).
enum IncomingSchemaClass {
    /// Hash is already accepted; merge without further checks (Req 17.2).
    Known,
    /// Registered schema definition differs from the local schema only by
    /// added tables/fields (Req 17.3).
    Additive { diff: SchemaDiff },
    /// Registered schema definition removes/renames/retypes an existing field
    /// or drops a table (Req 17.4).
    Breaking { diff: SchemaDiff },
    /// No definition registered for the local or incoming hash — cannot
    /// classify; legacy unknown-hash quarantine applies.
    Unknown,
}

impl CrdtEngine {
    /// Create a new CrdtEngine.
    ///
    /// `secret_key` is the 32-byte Ed25519 seed; `public_key` is the
    /// corresponding 32-byte Ed25519 public key (used as the Automerge actor
    /// ID so that LWW/RGA tiebreaks are driven by DID-derived bytes per
    /// Req 4.5 / 4.5a); `author_did` is the `did:key:` DID; `schema_hash` is
    /// the initial known schema.
    ///
    /// On native builds the caller must supply a live SQLite connection so the
    /// DAG can persist nodes.
    #[cfg(feature = "native")]
    pub fn new(
        secret_key: [u8; 32],
        public_key: [u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
        conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        let mut known_schemas = HashSet::new();
        known_schemas.insert(schema_hash);

        // Set the Automerge actor ID to the Ed25519 public key bytes so that
        // Automerge's internal LWW / RGA tiebreaks use the DID-derived bytes
        // (Req 4.5, 4.5a).
        let actor_id = automerge::ActorId::from(&public_key[..]);

        CrdtEngine {
            doc: automerge::AutoCommit::new().with_actor(actor_id),
            lamport: 0,
            known_schema_hash: schema_hash,
            known_schemas,
            schema_definitions: HashMap::new(),
            author_did,
            secret_key,
            revoked_dids: HashSet::new(),
            rejection_records: VecDeque::new(),
            rejection_listener: None,
            dag: ChangesetDag::new(conn),
        }
    }

    /// WASM / test constructor (no SQLite connection required).
    #[cfg(not(feature = "native"))]
    pub fn new(
        secret_key: [u8; 32],
        public_key: [u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
    ) -> Self {
        let mut known_schemas = HashSet::new();
        known_schemas.insert(schema_hash);

        // Set the Automerge actor ID to the Ed25519 public key bytes so that
        // Automerge's internal LWW / RGA tiebreaks use the DID-derived bytes
        // (Req 4.5, 4.5a).
        let actor_id = automerge::ActorId::from(&public_key[..]);

        CrdtEngine {
            doc: automerge::AutoCommit::new().with_actor(actor_id),
            lamport: 0,
            known_schema_hash: schema_hash,
            known_schemas,
            schema_definitions: HashMap::new(),
            author_did,
            secret_key,
            revoked_dids: HashSet::new(),
            rejection_records: VecDeque::new(),
            rejection_listener: None,
        }
    }

    /// Register an additional known schema hash (called during additive migration).
    pub fn add_known_schema(&mut self, hash: SchemaIdentifierHash) {
        self.known_schemas.insert(hash);
    }

    /// Register the full definition of a schema version this deployment
    /// recognises, keyed by its canonical hash (Subphase 5.3).
    ///
    /// The computed `schema.identifier_hash()` must equal `expected_hash`,
    /// otherwise the registration is rejected with a
    /// [`TirBaseError::SchemaRegistrationFailed`] — a deployment may not attach
    /// a definition to a hash it does not actually hash to, because the CRDT
    /// gate then could not trust its field-level diff.
    ///
    /// Registration is **not** an acceptance: the hash is only added to
    /// [`CrdtEngine::known_schemas`] once it is the device's current schema
    /// (`set_current_schema`) or an additive Delta under it has merged.
    pub(crate) fn register_schema_definition(
        &mut self,
        expected_hash: SchemaIdentifierHash,
        schema: Schema,
    ) -> Result<(), TirBaseError> {
        let computed = schema.identifier_hash();
        if computed != expected_hash {
            return Err(TirBaseError::SchemaRegistrationFailed {
                reason: format!(
                    "schema definition hashes to {}, not the registered version hash {}",
                    hex::encode(computed),
                    hex::encode(expected_hash),
                ),
            });
        }
        self.schema_definitions.insert(computed, schema);
        Ok(())
    }

    /// Declare `hash` the device's current (deployed) schema.
    ///
    /// Makes locally produced Deltas carry `hash` (Req 4.6) and accepts
    /// inbound Deltas stamped with it (Req 17.2).  Called by
    /// [`crate::api::CoreHandle::init`] with the first version of a configured
    /// schema-version path and after every successfully applied
    /// over-the-mesh migration (Req 17.2 / Req 18).
    pub(crate) fn set_current_schema(&mut self, hash: SchemaIdentifierHash) {
        self.known_schema_hash = hash;
        self.known_schemas.insert(hash);
    }

    /// Classify an inbound Delta's schema hash at the field level (Subphase 5.3).
    ///
    /// Pure read: never mutates engine state, so a Delta that later fails
    /// signature verification cannot leave an adopted schema behind.
    fn classify_incoming_schema(&self, hash: &SchemaIdentifierHash) -> IncomingSchemaClass {
        if self.known_schemas.contains(hash) {
            return IncomingSchemaClass::Known;
        }

        // Both the device's own schema definition and the sender's must be
        // registered before a field-level diff is possible.
        let local = match self.schema_definitions.get(&self.known_schema_hash) {
            Some(def) => def,
            None => return IncomingSchemaClass::Unknown,
        };
        let incoming = match self.schema_definitions.get(hash) {
            Some(def) => def,
            None => return IncomingSchemaClass::Unknown,
        };

        let diff = diff_schemas(local, incoming);
        if diff.is_additive() {
            IncomingSchemaClass::Additive { diff }
        } else if diff.is_breaking() {
            IncomingSchemaClass::Breaking { diff }
        } else {
            // Structurally identical yet not "known" is impossible when every
            // registered definition was stored under its own computed hash
            // (`register_schema_definition` enforces this) — identical
            // structure means identical hash, which is already in
            // `known_schemas`.  Defensive fallback.
            IncomingSchemaClass::Unknown
        }
    }

    /// Set of schema hashes currently accepted by the gate (test introspection).
    #[cfg(test)]
    pub(crate) fn known_schema_hashes(&self) -> Vec<SchemaIdentifierHash> {
        let mut hashes: Vec<SchemaIdentifierHash> = self.known_schemas.iter().copied().collect();
        hashes.sort();
        hashes
    }

    /// Hash of the device's current (deployed) schema.
    #[cfg(test)]
    pub(crate) fn current_schema_hash(&self) -> SchemaIdentifierHash {
        self.known_schema_hash
    }

    /// Record `did` as REVOKED (Req 8.6) so all future inbound Deltas authored
    /// by it are rejected by [`CrdtEngine::apply`].
    ///
    /// Idempotent. Called by the inbound revocation pipeline when a validated
    /// `RevocationDelta` crosses its M-of-N threshold
    /// (`CoreHandle::receive_inbound` / `receive_inbound_wasm`).
    pub(crate) fn mark_did_revoked(&mut self, did: &Did) {
        self.revoked_dids.insert(did.clone());
    }

    /// Force the engine's Lamport clock to `value` — test-only simulation of
    /// clock skew.
    ///
    /// In production the Lamport clock only advances through `produce_delta`
    /// (local writes) and `apply` (incoming Deltas — `max(local, incoming) + 1`).
    /// There is no natural path that jumps the clock forward to an arbitrary
    /// value, but a long network partition lets each device's clock diverge
    /// arbitrarily from every other device's.  The merge path's
    /// `max(local, incoming) + 1` reconciliation is correct *regardless* of the
    /// absolute skew, but nothing in the existing test harness could exercise
    /// significant skew — the audit (Report 5, Scenario 10) explicitly noted
    /// "no clock-skew harness."  This setter lets integration tests inject the
    /// skew a partition would have produced.
    ///
    /// `pub(crate)`: only reachable from in-crate test code; not exported on
    /// either build target.  Gated on `#[cfg(test)]` so it can never be called
    /// in a non-test build.
    #[cfg(test)]
    pub(crate) fn set_lamport_for_test(&mut self, value: u64) {
        self.lamport = value;
    }

    /// Emit a structured rejection failure record for an inbound Delta the
    /// merge gate is about to discard (Subphase 6.2 — Req 7.4/7.5).
    ///
    /// 1. Appends a [`DeltaRejectionRecord`] (sender DID + UTC timestamp) to
    ///    the engine's bounded rejection-record buffer;
    /// 2. Relays it to the host listener registered by
    ///    [`crate::api::CoreHandle::init`];
    /// 3. Notifies the v1 observability channel (native stderr rendering).
    ///
    /// Called from every `MergeOutcome::Rejected` path in [`Self::apply`]
    /// — the revocation gate, the malformed-signature guard, DID-resolution
    /// failure (Req 7.5), and signature-verification failure (Req 7.4) — so
    /// a rejected Delta always leaves a structured record behind and never
    /// merges any data.
    fn record_rejection(&mut self, code: DeltaRejectionCode, delta: &Delta, reason: String) {
        let record = DeltaRejectionRecord {
            code,
            author_did: delta.author_did.clone(),
            delta_id: delta.id,
            reason,
            occurred_at_utc: current_timestamp_micros(),
        };

        self.rejection_records.push_back(record.clone());
        if self.rejection_records.len() > MAX_REJECTION_RECORDS {
            self.rejection_records.pop_front();
        }

        // Host listener (registered by CoreHandle::init).  Invoked while the
        // engine is locked, so the listener must only forward onto a
        // non-blocking channel.
        if let Some(listener) = self.rejection_listener.as_mut() {
            listener(&record);
        }

        // v1 observability channel: stderr on native, silent no-op on WASM.
        notify_delta_rejection(&record);
    }

    /// Register the host listener invoked for every rejection record the
    /// engine emits (Subphase 6.2).
    ///
    /// Production caller: [`crate::api::CoreHandle::init`], which attaches a
    /// listener forwarding each record onto the handle's rejection-record
    /// broadcast channel so host applications and integration tests can
    /// subscribe.  The listener is invoked while the engine mutex is held
    /// (inside [`Self::apply`]) and must not re-enter the engine.
    pub(crate) fn set_rejection_listener(&mut self, listener: DeltaRejectionListener) {
        self.rejection_listener = Some(listener);
    }

    /// Structured rejection records currently retained on the engine
    /// (oldest-first, bounded to [`MAX_REJECTION_RECORDS`]).
    ///
    /// `pub(crate)`: introspection for in-crate callers/tests; rejection
    /// records are internal diagnostics, not external API surface.
    pub(crate) fn rejection_records(&self) -> &VecDeque<DeltaRejectionRecord> {
        &self.rejection_records
    }

    /// Current Lamport clock value.
    pub fn lamport(&self) -> u64 {
        self.lamport
    }

    /// Look up a persisted DagNode by Delta ID (native only).
    ///
    /// Crate-internal observability: lets callers (mesh integration tests,
    /// diagnostics) assert that a specific inbound Delta — identified by the
    /// Delta ID its author produced — actually landed in this engine's DAG
    /// after a merge.
    #[cfg(feature = "native")]
    pub(crate) fn dag_node(&self, delta_id: &DeltaId) -> Result<Option<DagNode>, TirBaseError> {
        self.dag.get(delta_id)
    }

    /// Produce a Delta for a local write that has already been committed to the
    /// Local Store (Req 4.2, 4.6). Called after `LocalStore::write()` succeeds.
    ///
    /// The delta is produced with an empty tag list.  See
    /// [`Self::produce_delta_with_tags`] when a tag must be part of the signed
    /// payload.
    pub fn produce_delta(
        &mut self,
        automerge_bytes: Vec<u8>,
        priority: PriorityClass,
        causal_parents: Vec<DeltaId>,
    ) -> Result<Delta, TirBaseError> {
        self.produce_delta_with_tags(automerge_bytes, priority, causal_parents, vec![])
    }

    /// Produce a Delta for a local write with `tags` baked into the **signed**
    /// payload.
    ///
    /// The signature (and the DeltaId, SHA-256 of `canonical_bytes`) covers
    /// `tags` — `canonical_bytes` serialises them — so a tag must be present
    /// *before* signing.  Appending a tag to an already-signed Delta would
    /// invalidate its signature for every verifier (peers, Side-Car replay),
    /// which is why the human-reaction auto-tag (Req 19.5) flows through this
    /// path: the tagged delta leaves the device cryptographically valid.
    ///
    /// Steps:
    /// 1. Increment the Lamport clock.
    /// 2. Collect causal parents from the DAG's current tips.
    /// 3. Build the Delta with all metadata (including `tags`).
    /// 4. Sign with the local private key.
    /// 5. Compute and assign the DeltaId.
    /// 6. Insert the DagNode.
    pub(crate) fn produce_delta_with_tags(
        &mut self,
        automerge_bytes: Vec<u8>,
        priority: PriorityClass,
        causal_parents: Vec<DeltaId>,
        tags: Vec<DeltaTag>,
    ) -> Result<Delta, TirBaseError> {
        // 1. Increment Lamport clock.
        self.lamport += 1;

        // 2. Resolve causal parents (use supplied list; callers that don't
        //    track parents explicitly can pass an empty vec — the DAG tips
        //    approach is used in the native path below).
        let parents = self.resolve_causal_parents(causal_parents)?;

        // 3. Build unsigned Delta.
        let created_at = current_timestamp_micros();
        let mut delta = Delta {
            id: [0u8; 32],
            author_did: self.author_did.clone(),
            signature: Ed25519Signature::default(),
            schema_hash: self.known_schema_hash,
            automerge_bytes,
            priority,
            causal_parents: parents,
            tags,
            lamport: self.lamport,
            created_at,
        };

        // 4. Sign: sign the canonical bytes (excludes id + signature).
        let canonical = delta.canonical_bytes();
        let sig = keypair::sign(&self.secret_key, &canonical)?;
        delta.signature = sig;

        // 5. Compute DeltaId = SHA-256(canonical_bytes).
        delta.id = Delta::compute_id(&canonical);

        // 6. Persist DagNode (native).
        self.insert_dag_node(&delta)?;

        Ok(delta)
    }

    /// Apply an incoming Delta from a peer (Req 4.4, 4.5, 4.5a, 8.6).
    ///
    /// Pipeline:
    /// 0. Revocation gate — Delta authored by a REVOKED DID → Rejected (Req 8.6).
    /// 1. Schema-hash gate — unknown hash → Rejected.
    /// 2. Malformed-signature guard.
    /// 3. Ed25519 signature verification via DID resolution.
    /// 4. Merge Automerge changeset into local doc, then read back the actual
    ///    LWW/RGA winner and override the doc on definitive divergence
    ///    (Subphase 6.1 — Req 4.5/4.5a).
    /// 5. Advance Lamport clock.
    /// 6. Persist DagNode.
    ///
    /// Every rejection (steps 0–3) emits a structured
    /// [`DeltaRejectionRecord`] carrying the sender DID and a UTC timestamp
    /// (Subphase 6.2 — Req 7.4/7.5) instead of an `eprintln!` failure log,
    /// then discards the Delta without merging any data.
    pub fn apply(&mut self, delta: &Delta) -> Result<MergeOutcome, TirBaseError> {
        // 0. Revocation gate (Req 8.6) — reject Deltas authored by a REVOKED
        //    DID outright, before any schema or signature processing.  A revoked
        //    author must not be able to inject state through the mesh even with
        //    a correctly-signed Delta (the local write/read gate of Req 8.5
        //    cannot stop the peer, so the merge path must).
        //
        //    Subphase 6.2: the rejection is emitted as a structured record
        //    (RevokedAuthor code, UTC timestamp, sender DID) rather than an
        //    `eprintln!` failure log.
        if self.revoked_dids.contains(&delta.author_did) {
            let reason = format!(
                "author DID '{}' is REVOKED — inbound Deltas from revoked devices are rejected (Req 8.6)",
                delta.author_did
            );
            self.record_rejection(DeltaRejectionCode::RevokedAuthor, delta, reason.clone());
            return Ok(MergeOutcome::Rejected { reason });
        }

        // 1. Schema-hash gate (Req 4.4, 17.2–17.4).  Known hashes merge
        //    (Req 17.2).  Unknown hashes are now classified at the field level
        //    (Subphase 5.3): if the deployment registered the schema's full
        //    definition, a Delta whose schema only *adds* tables/fields merges
        //    (Req 17.3) and a Delta whose schema removes/renames/retypes an
        //    existing field or drops a table is quarantined with
        //    `BreakingSchemaChange` (Req 17.4).  A hash with no registered
        //    definition cannot be classified and falls back to the legacy
        //    unknown-hash quarantine.
        let mut adopt_additive_hash = false;
        match self.classify_incoming_schema(&delta.schema_hash) {
            IncomingSchemaClass::Known => {}
            IncomingSchemaClass::Additive { ref diff } => {
                eprintln!(
                    "[CRDT] delta {} from {} carries additive schema {} ({}); merging against local schema {}",
                    hex::encode(delta.id),
                    delta.author_did,
                    hex::encode(delta.schema_hash),
                    diff.summary(),
                    hex::encode(self.known_schema_hash),
                );
                adopt_additive_hash = true;
            }
            IncomingSchemaClass::Breaking { ref diff } => {
                eprintln!(
                    "[CRDT] Quarantined delta {} from {}: breaking schema change ({} vs local {}): {}",
                    hex::encode(delta.id),
                    delta.author_did,
                    hex::encode(delta.schema_hash),
                    hex::encode(self.known_schema_hash),
                    diff.summary(),
                );
                return Ok(MergeOutcome::Quarantined {
                    reason: QuarantineReason::BreakingSchemaChange,
                });
            }
            IncomingSchemaClass::Unknown => {
                let hash_hex = hex::encode(delta.schema_hash);
                eprintln!(
                    "[CRDT] Rejected delta from {}: unknown schema hash {}",
                    delta.author_did, hash_hex
                );
                return Ok(MergeOutcome::Quarantined {
                    reason: QuarantineReason::UnknownSchemaHash,
                });
            }
        }

        // 2. Malformed-signature guard.
        if delta.signature.0.is_empty() {
            let reason = "malformed delta: missing signature".to_string();
            self.record_rejection(DeltaRejectionCode::MissingSignature, delta, reason.clone());
            return Ok(MergeOutcome::Rejected { reason });
        }

        // 3. DID resolution + Ed25519 verification.
        let public_key = match resolve_did_key_to_public_key(&delta.author_did) {
            Ok(pk) => pk,
            Err(e) => {
                // Req 7.5 — distinct unresolvable-DID failure record.  The
                // record's `author_did` is the DID that could not be resolved.
                let reason = e.to_string();
                self.record_rejection(
                    DeltaRejectionCode::DidResolutionFailed,
                    delta,
                    reason.clone(),
                );
                return Ok(MergeOutcome::Rejected { reason });
            }
        };

        let canonical = delta.canonical_bytes();
        if let Err(e) = keypair::verify(&public_key, &canonical, &delta.signature) {
            // Req 7.4 — failure record carrying the sender DID + UTC timestamp.
            let reason = e.to_string();
            self.record_rejection(
                DeltaRejectionCode::SignatureVerificationFailed,
                delta,
                reason.clone(),
            );
            return Ok(MergeOutcome::Rejected { reason });
        }

        // 3b. Adopt the additive schema only after the Delta's signature
        //     verified: rejected or malformed Deltas must never mutate engine
        //     state (mirrors the revoked/unknown gates above).
        if adopt_additive_hash {
            self.known_schemas.insert(delta.schema_hash);
        }

        // 4. Merge Automerge changeset and verify the actual merged outcome
        //    (Subphase 6.1 — T50).
        //
        //    Load the incoming bytes as a separate AutoCommit doc, then merge.
        //    When the payload is real Automerge format, snapshot the conflicting
        //    ROOT-level keys / list positions present in BOTH docs *before* the
        //    merge, then read the ACTUAL winning value/ordering back from the
        //    merged doc and compare it against the Lamport rule (Req 4.5/4.5a).
        //    On divergence in the definitive zone (`delta.lamport` strictly
        //    exceeds the local clock — the rule then provably mandates the
        //    incoming op), the divergence is logged and the doc is overridden
        //    to the rule winner.  Non-Automerge payloads (the TirBase JSON
        //    envelope) skip the merge and verification entirely.
        if let Some(mut their_doc) = self.load_incoming_doc(&delta.automerge_bytes)? {
            let snapshot = verify::capture_conflicts(&self.doc, &their_doc);
            self.doc
                .merge(&mut their_doc)
                .map_err(|e| TirBaseError::DeltaMalformed {
                    reason: format!("automerge merge failed: {e}"),
                })?;

            if !snapshot.lww.is_empty() || !snapshot.rga.is_empty() {
                let local_actor: Vec<u8> = self.doc.get_actor().to_bytes().to_vec();
                let report = verify::verify_and_override(
                    &mut self.doc,
                    &snapshot,
                    delta.lamport,
                    &public_key,  // verified incoming DID public-key bytes
                    self.lamport, // pre-advance (step 5)
                    &local_actor,
                );
                eprintln!(
                    "[CRDT] post-merge LWW/RGA verification — {} LWW conflict(s), {} RGA conflict(s); \
                     {} divergence(s), {} override(s) applied, {} failed, {} indeterminate",
                    report.lww_checked,
                    report.rga_checked,
                    report.divergences,
                    report.overrides_applied,
                    report.overrides_failed,
                    report.indeterminate,
                );
            }
        }

        // 5. Advance Lamport clock: max(local, incoming) + 1.
        self.lamport = self.lamport.max(delta.lamport) + 1;

        // 6. Persist DagNode.
        self.insert_dag_node(delta)?;

        Ok(MergeOutcome::Merged {
            new_lamport: self.lamport,
        })
    }

    // ─── Private helpers ───────────────────────────────────────────────────

    /// Resolve the causal parent list. If the caller supplies an explicit list
    /// (non-empty), use it. Otherwise derive the current DAG tips on native.
    fn resolve_causal_parents(&self, explicit: Vec<DeltaId>) -> Result<Vec<DeltaId>, TirBaseError> {
        if !explicit.is_empty() {
            return Ok(explicit);
        }
        #[cfg(feature = "native")]
        {
            self.dag_tips()
        }
        #[cfg(not(feature = "native"))]
        {
            Ok(vec![])
        }
    }

    /// Return the set of DAG tip Delta IDs (nodes with no children).
    #[cfg(feature = "native")]
    fn dag_tips(&self) -> Result<Vec<DeltaId>, TirBaseError> {
        // Topological sort gives all nodes; tips are those not referenced
        // as a parent of any other node.  We compute this by fetching all
        // nodes and all edges, then finding nodes with no outgoing child edge.
        // Simpler but correct approach: collect all node IDs and all parent_ids
        // used in the DAG; tips = nodes – parents.
        let all_nodes = self.dag.topological_sort()?;
        if all_nodes.is_empty() {
            return Ok(vec![]);
        }

        // Collect every ID that appears as a parent of some other node.
        let mut as_parent: HashSet<DeltaId> = HashSet::new();
        for node_id in &all_nodes {
            let children = self.dag.children(node_id)?;
            if !children.is_empty() {
                as_parent.insert(*node_id);
            }
        }

        let tips: Vec<DeltaId> = all_nodes
            .into_iter()
            .filter(|id| !as_parent.contains(id))
            .collect();
        Ok(tips)
    }

    /// Insert a DagNode for `delta` into the persistent DAG (native build).
    fn insert_dag_node(&mut self, delta: &Delta) -> Result<(), TirBaseError> {
        #[cfg(feature = "native")]
        {
            // Obtain the Automerge actor ID as bytes for the DagNode.
            let actor_id = self.doc.get_actor().to_bytes().to_vec();

            let node = DagNode {
                delta_id: delta.id,
                payload: delta.automerge_bytes.clone(),
                parent_ids: delta.causal_parents.clone(),
                actor_id,
                lamport: delta.lamport,
                schema_hash: delta.schema_hash,
                compacted: false,
                author_did: delta.author_did.clone(),
            };
            self.dag.insert(node)?;
        }
        Ok(())
    }

    /// Load raw Automerge bytes from a remote peer as a separate doc, or
    /// `None` when there is nothing to merge.
    ///
    /// The idiomatic Automerge approach is to load the bytes as a second
    /// `AutoCommit` and call `local_doc.merge(&mut their_doc)`.  If the bytes
    /// are not valid Automerge format (e.g. JSON metadata from the TirBase
    /// write path), the load is skipped without error — the projection path in
    /// `CoreHandle::receive_inbound()` handles the JSON case separately.
    fn load_incoming_doc(
        &self,
        bytes: &[u8],
    ) -> Result<Option<automerge::AutoCommit>, TirBaseError> {
        if bytes.is_empty() {
            // Empty byte slice — nothing to merge (e.g. test stubs).
            return Ok(None);
        }

        match automerge::AutoCommit::load(bytes) {
            Ok(doc) => Ok(Some(doc)),
            Err(_) => {
                // Non-Automerge bytes (e.g. JSON envelope from TirBase write path).
                // Skip the Automerge-level merge; the projection path will handle
                // data extraction from JSON separately.
                eprintln!(
                    "[CRDT] automerge_bytes are not valid Automerge format — \
                     skipping Automerge merge (JSON/metadata path)"
                );
                Ok(None)
            }
        }
    }

    /// Project all ROOT-level scalar keys from the current Automerge doc to a
    /// `Vec<(String, serde_json::Value)>`.
    ///
    /// Used by the WASM inbound pipeline to materialise a merged Delta's state
    /// into the in-memory `LocalStore` without requiring SQLite (Req 4.3, 1.4).
    pub fn doc_map_range_root(&self) -> Vec<(String, serde_json::Value)> {
        use automerge::ScalarValue;
        use automerge::{ReadDoc, Value, ROOT};

        self.doc
            .map_range(ROOT, ..)
            .filter_map(|item| {
                let json_val = match &item.value {
                    Value::Scalar(scalar) => {
                        match scalar.as_ref() {
                            ScalarValue::Str(s)       => serde_json::Value::String(s.to_string()),
                            ScalarValue::Int(n)       => serde_json::json!(n),
                            ScalarValue::Uint(n)      => serde_json::json!(n),
                            ScalarValue::F64(f)       => serde_json::json!(f),
                            ScalarValue::Boolean(b)   => serde_json::Value::Bool(*b),
                            ScalarValue::Null         => serde_json::Value::Null,
                            ScalarValue::Bytes(b)     => serde_json::Value::String(hex::encode(b)),
                            ScalarValue::Counter(c)   => serde_json::json!(i64::from(c.clone())),
                            ScalarValue::Timestamp(t) => serde_json::json!(t),
                            ScalarValue::Unknown { type_code, bytes } => {
                                serde_json::json!({ "type_code": type_code, "bytes": hex::encode(bytes) })
                            }
                        }
                    }
                    Value::Object(_) => return None,
                };
                Some((item.key.to_string(), json_val))
            })
            .collect()
    }

    /// Project the current Automerge doc state for `table` into the SQL store.
    ///
    /// Used by the inbound pipeline to materialise a peer's merged Delta into
    /// the SQLite projection rows that `LocalStore::read()` and `query()` serve
    /// (Req 4.3, 3.3).
    ///
    /// Walks the doc using `project_table()` (which reads ROOT-level keys) and
    /// then calls `store.write()` for each (key, value) pair so the projection
    /// table stays in sync with the Automerge state.
    #[cfg(feature = "native")]
    pub fn project_table_to_store(
        &self,
        table: &str,
        store: &std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>>,
    ) -> Result<(), TirBaseError> {
        use automerge::ScalarValue;
        use automerge::{ReadDoc, Value, ROOT};

        let mut store_guard = store
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("store mutex poisoned in project_table_to_store: {e}"),
            })?;

        // Walk ROOT-level keys in the Automerge doc.
        let items: Vec<(String, serde_json::Value)> = self.doc
            .map_range(ROOT, ..)
            .filter_map(|item| {
                let json_val = match &item.value {
                    Value::Scalar(scalar) => {
                        match scalar.as_ref() {
                            ScalarValue::Str(s)       => serde_json::Value::String(s.to_string()),
                            ScalarValue::Int(n)       => serde_json::json!(n),
                            ScalarValue::Uint(n)      => serde_json::json!(n),
                            ScalarValue::F64(f)       => serde_json::json!(f),
                            ScalarValue::Boolean(b)   => serde_json::Value::Bool(*b),
                            ScalarValue::Null         => serde_json::Value::Null,
                            ScalarValue::Bytes(b)     => serde_json::Value::String(hex::encode(b)),
                            ScalarValue::Counter(c)   => serde_json::json!(i64::from(c.clone())),
                            ScalarValue::Timestamp(t) => serde_json::json!(t),
                            ScalarValue::Unknown { type_code, bytes } => {
                                serde_json::json!({ "type_code": type_code, "bytes": hex::encode(bytes) })
                            }
                        }
                    }
                    Value::Object(_) => serde_json::Value::Null,
                };
                Some((item.key.to_string(), json_val))
            })
            .collect();

        for (key, val) in items {
            store_guard.write(table, &key, &val)?;
        }

        Ok(())
    }

    /// Apply a local scalar write to the engine's Automerge document and return
    /// the saved document bytes.
    ///
    /// This is the production entry point for the write path: `CoreHandle::write`
    /// calls `LocalStore::write` (SQL) and then this method (Automerge doc), then
    /// signs the returned bytes into a Delta. The bytes carry real Automerge
    /// format so that a peer receiving this Delta through `CrdtEngine::apply`
    /// exercises the full Automerge merge + LWW/RGA read-back verification
    /// (Subphase 6.1 — Req 4.5/4.5a), rather than the JSON-envelope fallback.
    ///
    /// The `table` name is embedded via a `_tirbase_table` ROOT key and `key`
    /// via `_tirbase_key`, so the receiving peer's projection path can recover
    /// the destination table/row from the merged Automerge doc.
    ///
    /// Production caller: `api/mod.rs::CoreHandle::write` (the write path).
    pub fn write_scalar(
        &mut self,
        table: &str,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<Vec<u8>, TirBaseError> {
        use automerge::transaction::Transactable;

        // NOTE: Lamport clock is incremented by produce_delta_with_tags (the
        // caller), not here — incrementing here would double-count.

        // Embed routing metadata so the inbound projection path can recover
        // the table/row from the merged doc.
        self.doc
            .put(automerge::ROOT, "_tirbase_table", table)
            .map_err(|e| TirBaseError::DeltaMalformed {
                reason: format!("automerge put _tirbase_table failed: {e}"),
            })?;
        self.doc
            .put(automerge::ROOT, "_tirbase_key", key)
            .map_err(|e| TirBaseError::DeltaMalformed {
                reason: format!("automerge put _tirbase_key failed: {e}"),
            })?;

        // Write the application value under the user's key.
        // We store the full JSON value so that concurrent writes to the same
        // key produce a real LWW conflict on that ROOT key.
        match value {
            serde_json::Value::String(s) => {
                self.doc
                    .put(automerge::ROOT, key, s.as_str())
                    .map_err(|e| TirBaseError::DeltaMalformed {
                        reason: format!("automerge put {key} (string) failed: {e}"),
                    })?;
            }
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    self.doc.put(automerge::ROOT, key, i).map_err(|e| {
                        TirBaseError::DeltaMalformed {
                            reason: format!("automerge put {key} (int) failed: {e}"),
                        }
                    })?;
                } else if let Some(f) = n.as_f64() {
                    self.doc.put(automerge::ROOT, key, f).map_err(|e| {
                        TirBaseError::DeltaMalformed {
                            reason: format!("automerge put {key} (f64) failed: {e}"),
                        }
                    })?;
                } else if let Some(u) = n.as_u64() {
                    self.doc.put(automerge::ROOT, key, u).map_err(|e| {
                        TirBaseError::DeltaMalformed {
                            reason: format!("automerge put {key} (uint) failed: {e}"),
                        }
                    })?;
                }
            }
            serde_json::Value::Bool(b) => {
                self.doc.put(automerge::ROOT, key, *b).map_err(|e| {
                    TirBaseError::DeltaMalformed {
                        reason: format!("automerge put {key} (bool) failed: {e}"),
                    }
                })?;
            }
            serde_json::Value::Null => {
                self.doc.put(automerge::ROOT, key, ()).map_err(|e| {
                    TirBaseError::DeltaMalformed {
                        reason: format!("automerge put {key} (null) failed: {e}"),
                    }
                })?;
            }
            serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                let json_str =
                    serde_json::to_string(value).map_err(|e| TirBaseError::DeltaMalformed {
                        reason: format!("serialise composite value failed: {e}"),
                    })?;
                self.doc
                    .put(automerge::ROOT, key, json_str.as_str())
                    .map_err(|e| TirBaseError::DeltaMalformed {
                        reason: format!("automerge put {key} (json-str) failed: {e}"),
                    })?;
            }
        }

        // Save the doc state — the saved bytes ARE the Automerge changeset.
        // (AutoCommit::save() returns Vec<u8> directly, infallible.)
        Ok(self.doc.save())
    }

    /// Read back the current value of `key` from the engine's Automerge doc.
    ///
    /// Used by integration tests (and the production read path on WASM) to
    /// assert the *actual* merged value, not just the Lamport-comparison rule
    /// (Subphase 7.1 — Req 4.5).  Returns `None` if the key is absent.
    pub fn read_scalar(&self, key: &str) -> Option<serde_json::Value> {
        use automerge::{ReadDoc, Value};

        self.doc
            .get(automerge::ROOT, key)
            .ok()
            .flatten()
            .and_then(|(val, _exid)| match &val {
                Value::Scalar(sv) => {
                    use automerge::ScalarValue;
                    match sv.as_ref() {
                        ScalarValue::Str(s) => Some(serde_json::Value::String(s.to_string())),
                        ScalarValue::Int(n) => Some(serde_json::json!(n)),
                        ScalarValue::Uint(n) => Some(serde_json::json!(n)),
                        ScalarValue::F64(f) => Some(serde_json::json!(f)),
                        ScalarValue::Boolean(b) => Some(serde_json::Value::Bool(*b)),
                        ScalarValue::Null => Some(serde_json::Value::Null),
                        _ => None,
                    }
                }
                Value::Object(_) => None,
            })
    }
}

// ─── LWW comparison helper (used by merge.rs and tests) ─────────────────────

/// Compare two Deltas for LWW dominance (Req 4.5).
///
/// Returns `true` if `incoming` should overwrite `current`.
///
/// Resolution order:
/// 1. Higher Lamport timestamp wins.
/// 2. On a tie, lexicographically greater `actor_id` (author_did bytes) wins.
pub fn lww_incoming_wins(
    incoming_lamport: u64,
    incoming_actor: &[u8],
    current_lamport: u64,
    current_actor: &[u8],
) -> bool {
    match incoming_lamport.cmp(&current_lamport) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => incoming_actor > current_actor,
    }
}

/// Compare two concurrent RGA insertions at the same position (Req 4.5a).
///
/// Returns `true` if `incoming` should be inserted *before* `current`
/// (i.e. has higher priority in the ordering).
///
/// Order: `(lamport DESC, actor_id DESC)` — higher Lamport first; tie broken by
/// lexicographically greater actor ID first.
pub fn rga_incoming_has_priority(
    incoming_lamport: u64,
    incoming_actor: &[u8],
    current_lamport: u64,
    current_actor: &[u8],
) -> bool {
    // Same ordering as LWW — higher is "earlier" in the list.
    lww_incoming_wins(
        incoming_lamport,
        incoming_actor,
        current_lamport,
        current_actor,
    )
}

// ─── Rejection-record bounds ─────────────────────────────────────────────────

/// Maximum number of structured rejection records retained on the engine
/// (Subphase 6.2).  Oldest records are dropped first, so the buffer is
/// constant-size even under a flood of invalid inbound Deltas.
const MAX_REJECTION_RECORDS: usize = 1024;

// ─── Timestamp helper ────────────────────────────────────────────────────────

/// Current UTC wall-clock time in microseconds since the Unix epoch.
fn current_timestamp_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{DeltaTag, PriorityClass};
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::schema::hash::compute_schema_identifier_hash;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Schema hash used throughout tests.
    fn test_schema_hash() -> SchemaIdentifierHash {
        compute_schema_identifier_hash(&[("users", &[("id", "TEXT"), ("name", "TEXT")])])
    }

    /// Build a fresh engine backed by an in-memory SQLite DB (native) or
    /// the WASM stub (wasm).
    #[cfg(feature = "native")]
    fn make_engine(
        secret: [u8; 32],
        public: [u8; 32],
        did: Did,
        schema: SchemaIdentifierHash,
    ) -> CrdtEngine {
        use std::sync::{Arc, Mutex};
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
            .expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        CrdtEngine::new(secret, public, did, schema, conn)
    }

    /// Generate a test keypair and corresponding did:key DID.
    fn make_identity() -> ([u8; 32], [u8; 32], Did) {
        let (secret, public) = generate_keypair().expect("keygen");
        let did = derive_did_from_public_key(&public);
        (secret, public, did)
    }

    /// Build a signed Delta manually (simulates a peer producing a Delta).
    fn make_signed_delta(
        secret: &[u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
        lamport: u64,
        automerge_bytes: Vec<u8>,
    ) -> Delta {
        let mut d = Delta {
            id: [0u8; 32],
            author_did,
            signature: Ed25519Signature::default(),
            schema_hash,
            automerge_bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = d.canonical_bytes();
        d.signature = sign(secret, &canonical).expect("sign");
        d.id = Delta::compute_id(&canonical);
        d
    }

    // ── DID round-trip ───────────────────────────────────────────────────────

    #[test]
    fn did_derive_and_resolve_round_trip() {
        let (_, public) = generate_keypair().unwrap();
        let did = derive_did_from_public_key(&public);
        let resolved = resolve_did_key_to_public_key(&did).expect("resolve");
        assert_eq!(resolved, public);
    }

    #[test]
    fn resolve_invalid_did_prefix_fails() {
        let result = resolve_did_key_to_public_key("did:web:example.com");
        assert!(result.is_err(), "non-did:key DID should fail to resolve");
    }

    #[test]
    fn resolve_invalid_base58_fails() {
        let result = resolve_did_key_to_public_key("did:key:NOT_VALID_BASE58!!");
        assert!(result.is_err());
    }

    // ── produce_delta ────────────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn produce_delta_increments_lamport() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);

        assert_eq!(engine.lamport(), 0);
        engine
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();
        assert_eq!(engine.lamport(), 1);
        engine
            .produce_delta(vec![], PriorityClass::High, vec![])
            .unwrap();
        assert_eq!(engine.lamport(), 2);
    }

    #[test]
    #[cfg(feature = "native")]
    fn produce_delta_signature_verifies() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);

        let delta = engine
            .produce_delta(vec![1, 2, 3], PriorityClass::Medium, vec![])
            .unwrap();

        let canonical = delta.canonical_bytes();
        keypair::verify(&public, &canonical, &delta.signature)
            .expect("produced delta signature must verify");
    }

    #[test]
    #[cfg(feature = "native")]
    fn produce_delta_id_is_sha256_of_canonical() {
        use sha2::{Digest, Sha256};
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);

        let delta = engine
            .produce_delta(vec![7, 8, 9], PriorityClass::Low, vec![])
            .unwrap();

        let canonical = delta.canonical_bytes();
        let expected: [u8; 32] = Sha256::digest(&canonical).into();
        assert_eq!(delta.id, expected);
    }

    #[test]
    #[cfg(feature = "native")]
    fn produce_delta_sets_schema_hash() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);
        let delta = engine
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();
        assert_eq!(delta.schema_hash, schema);
    }

    // ── apply — schema-hash gate ─────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_unknown_schema_hash_is_quarantined() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret.clone(), public, did.clone(), schema);

        let unknown_schema = [0xFFu8; 32];
        let delta = make_signed_delta(&secret, did, unknown_schema, 1, vec![]);

        let outcome = engine.apply(&delta).unwrap();
        assert_eq!(
            outcome,
            MergeOutcome::Quarantined {
                reason: QuarantineReason::UnknownSchemaHash,
            }
        );
    }

    // ── apply — field-level additive-vs-breaking gate (Subphase 5.3, Req 17.3/17.4) ─
    //
    // The gate classifies an *unknown* hash by diffing its registered schema
    // definition against the device's current schema definition: additive
    // changes merge (and the hash is adopted), breaking changes quarantine
    // with `BreakingSchemaChange`, and hashes with no registered definition
    // keep the legacy unknown-hash quarantine.

    /// Three schema versions for the gate tests: v1 users{id,name};
    /// v2 users{id,name,email} (additive — new field); v3 users{id}
    /// (breaking — removes `name`).  Returns (v1, v2, v3, h1, h2, h3).
    fn gate_schema_fixture() -> (
        Schema,
        Schema,
        Schema,
        SchemaIdentifierHash,
        SchemaIdentifierHash,
        SchemaIdentifierHash,
    ) {
        use crate::schema::{FieldDef, FieldType, TableDef};
        use crate::store::compaction::CompactionPolicy;

        let field = |name: &str, ft: FieldType| FieldDef {
            name: name.to_string(),
            field_type: ft,
            nullable: true,
            default: None,
        };
        let table = |name: &str, fields: Vec<FieldDef>| TableDef {
            name: name.to_string(),
            fields,
            compaction_policy: CompactionPolicy::None,
            constraints: vec![],
        };
        let schema = |tables: Vec<TableDef>| Schema {
            tables,
            version: "1.0.0".to_string(),
        };

        let v1 = schema(vec![table(
            "users",
            vec![field("id", FieldType::Text), field("name", FieldType::Text)],
        )]);
        let v2 = schema(vec![table(
            "users",
            vec![
                field("id", FieldType::Text),
                field("name", FieldType::Text),
                field("email", FieldType::Text),
            ],
        )]);
        let v3 = schema(vec![table("users", vec![field("id", FieldType::Text)])]);

        let h1 = v1.identifier_hash();
        let h2 = v2.identifier_hash();
        let h3 = v3.identifier_hash();
        (v1, v2, v3, h1, h2, h3)
    }

    /// An additive-schema Delta merges (Req 17.3) and its hash is adopted so
    /// later Deltas under it take the known-hash path.
    #[test]
    #[cfg(feature = "native")]
    fn additive_schema_delta_merges_and_adopts_hash() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let (v1, v2, v3, h1, h2, h3) = gate_schema_fixture();

        let mut engine = make_engine(secret_a, public_a, did_a, h1);
        engine.register_schema_definition(h1, v1).unwrap();
        engine.register_schema_definition(h2, v2).unwrap();
        engine.register_schema_definition(h3, v3).unwrap();

        let d1 = make_signed_delta(&secret_b, did_b.clone(), h2, 1, vec![]);
        let outcome = engine.apply(&d1).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Merged { .. }),
            "additive schema delta must merge: {outcome:?}"
        );
        assert!(
            engine.known_schema_hashes().contains(&h2),
            "additive hash must be adopted after a verified merge"
        );

        // Second Delta under h2 now merges through the plain known-hash path.
        let d2 = make_signed_delta(&secret_b, did_b, h2, 2, vec![]);
        let outcome2 = engine.apply(&d2).unwrap();
        assert!(
            matches!(outcome2, MergeOutcome::Merged { .. }),
            "subsequent delta under the adopted additive schema must merge: {outcome2:?}"
        );
    }

    /// A Delta whose registered schema removes an existing field is
    /// quarantined with the field-level `BreakingSchemaChange` reason
    /// (Req 17.4) — previously indistinguishable from an unknown hash.
    #[test]
    #[cfg(feature = "native")]
    fn breaking_schema_delta_quarantined_with_breaking_reason() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let (v1, v2, v3, h1, h2, h3) = gate_schema_fixture();

        let mut engine = make_engine(secret_a, public_a, did_a, h1);
        engine.register_schema_definition(h1, v1).unwrap();
        engine.register_schema_definition(h2, v2).unwrap();
        engine.register_schema_definition(h3, v3).unwrap();

        let delta = make_signed_delta(&secret_b, did_b, h3, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert_eq!(
            outcome,
            MergeOutcome::Quarantined {
                reason: QuarantineReason::BreakingSchemaChange,
            },
            "breaking schema delta must quarantine with BreakingSchemaChange"
        );
        assert!(
            !engine.known_schema_hashes().contains(&h3),
            "breaking schema hash must NOT be adopted"
        );
    }

    /// An unknown hash stays on the legacy quarantine path even when other
    /// definitions are registered — field-level classification requires a
    /// registered definition for the sender's hash.
    #[test]
    #[cfg(feature = "native")]
    fn unregistered_hash_quarantined_unknown_despite_other_definitions() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let (v1, v2, _v3, h1, h2, _h3) = gate_schema_fixture();

        let mut engine = make_engine(secret_a, public_a, did_a, h1);
        engine.register_schema_definition(h1, v1).unwrap();
        engine.register_schema_definition(h2, v2).unwrap();

        let mystery = [0xABu8; 32];
        let delta = make_signed_delta(&secret_b, did_b, mystery, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert_eq!(
            outcome,
            MergeOutcome::Quarantined {
                reason: QuarantineReason::UnknownSchemaHash,
            }
        );
    }

    /// A signature-rejected additive Delta must not leave its hash adopted:
    /// adoption happens only after verification succeeds.
    #[test]
    #[cfg(feature = "native")]
    fn rejected_additive_delta_does_not_adopt_hash() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let (v1, v2, _v3, h1, h2, _h3) = gate_schema_fixture();

        let mut engine = make_engine(secret_a, public_a, did_a, h1);
        engine.register_schema_definition(h1, v1).unwrap();
        engine.register_schema_definition(h2, v2).unwrap();

        // Valid h2 delta, then tamper with the payload after signing.
        let mut delta = make_signed_delta(&secret_b, did_b, h2, 1, vec![1, 2, 3]);
        delta.automerge_bytes = vec![9, 9, 9];
        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "tampered additive delta must be rejected: {outcome:?}"
        );
        assert!(
            !engine.known_schema_hashes().contains(&h2),
            "rejected delta must not adopt its schema hash"
        );
    }

    /// Registering a definition under a hash its structure does not produce is
    /// rejected — otherwise the gate could trust a field-level diff for a hash
    /// that actually denotes a different schema.
    #[test]
    #[cfg(feature = "native")]
    fn register_schema_definition_rejects_hash_mismatch() {
        let (secret, public, did) = make_identity();
        let (v1, _v2, _v3, h1, _h2, _h3) = gate_schema_fixture();

        let mut engine = make_engine(secret, public, did, h1);
        let wrong_hash = [0x42u8; 32];
        let err = engine
            .register_schema_definition(wrong_hash, v1)
            .expect_err("mismatched registration must fail");
        assert!(
            matches!(
                err,
                crate::errors::TirBaseError::SchemaRegistrationFailed { .. }
            ),
            "expected SchemaRegistrationFailed: {err:?}"
        );
    }

    /// `set_current_schema` advances the hash stamped on locally produced
    /// Deltas (Req 4.6) and accepts inbound Deltas under the new schema
    /// (Req 17.2) — the migration-success wiring relies on it.
    #[test]
    #[cfg(feature = "native")]
    fn set_current_schema_advances_produced_and_inbound_hashes() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let (_v1, _v2, _v3, h1, h2, _h3) = gate_schema_fixture();

        let mut engine = make_engine(secret_a, public_a, did_a, h1);
        assert_eq!(engine.current_schema_hash(), h1);

        engine.set_current_schema(h2);
        assert_eq!(engine.current_schema_hash(), h2);

        // Locally produced Deltas now carry h2.
        let produced = engine
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();
        assert_eq!(produced.schema_hash, h2);

        // Inbound Deltas stamped h2 take the known-hash path without needing
        // a registered definition.
        let delta = make_signed_delta(&secret_b, did_b, h2, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Merged { .. }),
            "delta under current schema must merge: {outcome:?}"
        );
    }

    // ── apply — malformed delta ───────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_missing_signature_is_rejected() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did.clone(), schema);

        // Construct a delta with empty signature.
        let delta = Delta {
            id: [0u8; 32],
            author_did: did,
            signature: Ed25519Signature::default(), // empty
            schema_hash: schema,
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };

        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "empty signature must be rejected: {outcome:?}"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_tampered_payload_is_rejected() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret.clone(), public, did.clone(), schema);

        // Build a signed delta, then tamper with automerge_bytes.
        let mut delta = make_signed_delta(&secret, did, schema, 1, vec![1, 2, 3]);
        delta.automerge_bytes = vec![9, 9, 9]; // tampering invalidates signature

        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "tampered payload must be rejected: {outcome:?}"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_wrong_key_delta_is_rejected() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, _did_b) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret_a, public_a, did_a.clone(), schema);

        // Sign delta with key_b but claim did_a as author.
        let delta = make_signed_delta(&secret_b, did_a, schema, 1, vec![]);

        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "mismatched key must be rejected: {outcome:?}"
        );
    }

    // ── apply — structured rejection failure records (Subphase 6.2, Req 7.4/7.5) ─
    //
    // Every `MergeOutcome::Rejected` path in `apply` emits a typed
    // `DeltaRejectionRecord` carrying the sender DID and a UTC timestamp — the
    // structured replacement for the former `eprintln!` rejection logs.
    // Req 7.4 (signature-verification failure) and Req 7.5 (unresolvable-DID
    // failure) must produce *distinct* records, and a rejected Delta must
    // never merge any data.

    #[test]
    #[cfg(feature = "native")]
    fn apply_tampered_payload_emits_signature_verification_failure_record() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret.clone(), public, did.clone(), schema);

        // Build a signed delta, then tamper with automerge_bytes so the
        // Ed25519 signature no longer verifies (Req 7.4).
        let mut delta = make_signed_delta(&secret, did.clone(), schema, 1, vec![1, 2, 3]);
        delta.automerge_bytes = vec![9, 9, 9];

        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "tampered payload must be rejected: {outcome:?}"
        );

        // The engine must retain exactly one structured failure record with
        // the sender DID and a UTC timestamp (Req 7.4).
        let records = engine.rejection_records();
        assert_eq!(records.len(), 1, "exactly one rejection record expected");
        let record = &records[0];
        assert_eq!(
            record.code,
            DeltaRejectionCode::SignatureVerificationFailed,
            "tampered payload must emit the Req 7.4 signature-failure code"
        );
        assert_eq!(record.author_did, did, "record must carry the sender DID");
        assert_eq!(record.delta_id, delta.id, "record must carry the Delta ID");
        assert!(!record.reason.is_empty(), "record must carry a reason");
        let now = current_timestamp_micros();
        assert!(
            record.occurred_at_utc > 0 && record.occurred_at_utc <= now,
            "record must carry a plausible UTC timestamp: {} vs now {now}",
            record.occurred_at_utc
        );
        assert!(
            now - record.occurred_at_utc < 600_000_000,
            "record timestamp must be recent (UTC micros): {}",
            record.occurred_at_utc
        );

        // Req 7.4 — the Delta is discarded without merging any data.
        assert_eq!(
            engine.lamport(),
            0,
            "rejected delta must not advance Lamport"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_unresolvable_did_emits_distinct_did_resolution_failure_record() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);

        // Req 7.5: the sender's DID cannot be resolved to a public key.  The
        // signature is present and non-empty so the rejection is attributable
        // to resolution (not the malformed-signature guard).
        let unresolvable_did = "did:web:example.com/not-a-did-key".to_string();
        let delta = make_signed_delta(&secret, unresolvable_did.clone(), schema, 1, vec![]);

        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "unresolvable DID must be rejected: {outcome:?}"
        );

        let records = engine.rejection_records();
        assert_eq!(records.len(), 1, "exactly one rejection record expected");
        let record = &records[0];
        assert_eq!(
            record.code,
            DeltaRejectionCode::DidResolutionFailed,
            "unresolvable DID must emit the Req 7.5 DID-resolution-failure code"
        );
        // Req 7.5 — the record is *distinct* from the Req 7.4 signature record.
        assert_ne!(
            record.code,
            DeltaRejectionCode::SignatureVerificationFailed,
            "the unresolvable-DID record must be distinct from the signature record"
        );
        // Req 7.5 — the record carries the unresolved DID itself.
        assert_eq!(
            record.author_did, unresolvable_did,
            "record must carry the unresolved DID"
        );
        assert!(
            record.reason.contains("did:web"),
            "reason must name the resolution failure: {}",
            record.reason
        );
        assert!(
            record.occurred_at_utc > 0,
            "record must carry a UTC timestamp"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_missing_signature_emits_missing_signature_record() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did.clone(), schema);

        let delta = Delta {
            id: [0u8; 32],
            author_did: did,
            signature: Ed25519Signature::default(), // empty
            schema_hash: schema,
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };

        let outcome = engine.apply(&delta).unwrap();
        assert!(matches!(outcome, MergeOutcome::Rejected { .. }));
        let records = engine.rejection_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].code, DeltaRejectionCode::MissingSignature);
        assert_eq!(records[0].author_did, delta.author_did);
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_revoked_author_emits_revoked_author_record() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, public_a, did_a, schema);
        engine.mark_did_revoked(&did_b);

        // B produces a *validly signed* delta — the revocation gate (Req 8.6)
        // must still reject it and emit a RevokedAuthor failure record.
        let delta = make_signed_delta(&secret_b, did_b.clone(), schema, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert!(matches!(outcome, MergeOutcome::Rejected { .. }));

        let records = engine.rejection_records();
        assert_eq!(records.len(), 1, "exactly one rejection record expected");
        assert_eq!(records[0].code, DeltaRejectionCode::RevokedAuthor);
        assert_eq!(records[0].author_did, did_b);
        assert!(records[0].reason.contains("REVOKED"));
    }

    #[test]
    #[cfg(feature = "native")]
    fn merged_delta_emits_no_rejection_record() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, public_a, did_a, schema);
        let delta = make_signed_delta(&secret_b, did_b, schema, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert!(matches!(outcome, MergeOutcome::Merged { .. }));
        assert!(
            engine.rejection_records().is_empty(),
            "a merged Delta must not produce rejection records"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn rejection_records_buffer_is_bounded() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did.clone(), schema);

        // Flood the gate with more invalid Deltas than the retention cap: the
        // oldest records must be dropped so a hostile peer cannot grow engine
        // memory without bound.
        for i in 0..(MAX_REJECTION_RECORDS + 64) {
            let mut delta = make_signed_delta(&secret, did.clone(), schema, 1, vec![]);
            delta.automerge_bytes = vec![0xEE, (i & 0xFF) as u8];
            let outcome = engine.apply(&delta).unwrap();
            assert!(matches!(outcome, MergeOutcome::Rejected { .. }));
        }

        assert_eq!(
            engine.rejection_records().len(),
            MAX_REJECTION_RECORDS,
            "rejection buffer must stay capped at MAX_REJECTION_RECORDS"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn rejection_records_carry_stable_distinct_codes() {
        // The render code strings are the stable serialised form of the
        // records; the Req 7.4 vs Req 7.5 distinction must survive rendering.
        assert_eq!(
            DeltaRejectionCode::SignatureVerificationFailed.as_str(),
            "SIGNATURE_VERIFICATION_FAILED"
        );
        assert_eq!(
            DeltaRejectionCode::DidResolutionFailed.as_str(),
            "DID_RESOLUTION_FAILED"
        );
        assert_ne!(
            DeltaRejectionCode::SignatureVerificationFailed.as_str(),
            DeltaRejectionCode::DidResolutionFailed.as_str()
        );
    }

    // ── apply — revocation gate (Req 8.6) ────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_rejects_delta_from_revoked_author() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        // Engine A is the receiver; peer B's DID is marked REVOKED.
        let mut engine = make_engine(secret_a, public_a, did_a, schema);
        engine.mark_did_revoked(&did_b);

        // B produces a *validly signed* delta — it must still be rejected.
        let delta = make_signed_delta(&secret_b, did_b.clone(), schema, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();

        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "delta from revoked author must be Rejected: {outcome:?}"
        );
        match outcome {
            MergeOutcome::Rejected { reason } => {
                assert!(
                    reason.contains("REVOKED") && reason.contains(&did_b),
                    "rejection reason must name the revoked author: {reason}"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_revoked_author_delta_is_not_persisted_to_dag() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, public_a, did_a, schema);
        engine.mark_did_revoked(&did_b);

        let delta = make_signed_delta(&secret_b, did_b, schema, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert!(matches!(outcome, MergeOutcome::Rejected { .. }));

        // Rejected Deltas must never land in the Changeset DAG.
        assert!(
            engine.dag_node(&delta.id).unwrap().is_none(),
            "rejected delta must not be persisted as a DagNode"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_revocation_gate_does_not_block_other_authors() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let (secret_c, _, did_c) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, public_a, did_a, schema);
        engine.mark_did_revoked(&did_b);

        // C is NOT revoked — its delta must merge normally.
        let delta_c = make_signed_delta(&secret_c, did_c, schema, 1, vec![]);
        let outcome = engine.apply(&delta_c).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Merged { .. }),
            "non-revoked author must still merge: {outcome:?}"
        );

        // The revoked author's delta is still rejected after a merge happened.
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 2, vec![]);
        let outcome = engine.apply(&delta_b).unwrap();
        assert!(matches!(outcome, MergeOutcome::Rejected { .. }));
    }

    // ── apply — valid delta ───────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_valid_delta_returns_merged() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        // Peer B produces a signed delta with empty automerge bytes (safe to merge).
        let delta = make_signed_delta(&secret_b, did_b, schema, 1, vec![]);
        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Merged { .. }),
            "valid delta must produce Merged: {outcome:?}"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn apply_valid_delta_advances_lamport() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        // Apply a delta with lamport=10; engine was at 0.
        let delta = make_signed_delta(&secret_b, did_b, schema, 10, vec![]);
        engine.apply(&delta).unwrap();

        // Lamport should be max(0, 10) + 1 = 11.
        assert_eq!(engine.lamport(), 11);
    }

    // ── LWW scalar conflict resolution (Req 4.5) ─────────────────────────────

    #[test]
    fn lww_higher_lamport_wins() {
        // Incoming has higher lamport → should win.
        assert!(lww_incoming_wins(10, b"actor-a", 5, b"actor-a"));
        // Incoming has lower lamport → should NOT win.
        assert!(!lww_incoming_wins(3, b"actor-a", 7, b"actor-a"));
    }

    #[test]
    fn lww_equal_lamport_greater_actor_wins() {
        // Equal lamport — greater actor ID wins.
        assert!(lww_incoming_wins(5, b"actor-b", 5, b"actor-a"));
        assert!(!lww_incoming_wins(5, b"actor-a", 5, b"actor-b"));
    }

    #[test]
    fn lww_equal_lamport_equal_actor_no_win() {
        // Exactly equal — incoming does NOT win (current retained).
        assert!(!lww_incoming_wins(5, b"same-actor", 5, b"same-actor"));
    }

    // ── RGA sequence merge (Req 4.5a) ─────────────────────────────────────────

    #[test]
    fn rga_higher_lamport_has_priority() {
        assert!(rga_incoming_has_priority(10, b"actor-a", 5, b"actor-a"));
        assert!(!rga_incoming_has_priority(3, b"actor-a", 9, b"actor-a"));
    }

    #[test]
    fn rga_equal_lamport_greater_actor_has_priority() {
        assert!(rga_incoming_has_priority(5, b"z-actor", 5, b"a-actor"));
        assert!(!rga_incoming_has_priority(5, b"a-actor", 5, b"z-actor"));
    }

    #[test]
    fn rga_all_insertions_must_be_present_after_merge() {
        // Simulate two concurrent insertions at the same position.
        // Both must appear in the merged result — we order them by priority.
        let ops: Vec<(&[u8], u64, &str)> = vec![
            (b"actor-a", 3, "value-a"),
            (b"actor-b", 5, "value-b"),
            (b"actor-c", 5, "value-c"),
        ];

        // Sort in RGA priority order: (lamport DESC, actor DESC).
        let mut sorted_ops = ops.clone();
        sorted_ops.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(a.0)));

        // Verify all values are present.
        let values: Vec<&str> = sorted_ops.iter().map(|(_, _, v)| *v).collect();
        assert!(values.contains(&"value-a"), "value-a must be in result");
        assert!(values.contains(&"value-b"), "value-b must be in result");
        assert!(values.contains(&"value-c"), "value-c must be in result");

        // Verify ordering: actor-b (lamport=5) and actor-c (lamport=5) come
        // before actor-a (lamport=3); between actor-b and actor-c,
        // actor-c > actor-b lexicographically so actor-c comes first.
        assert_eq!(values[0], "value-c");
        assert_eq!(values[1], "value-b");
        assert_eq!(values[2], "value-a");
    }

    // ── DAG causal traversal ─────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn dag_produces_delta_inserts_node() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);

        let delta = engine
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();

        // The DagNode for this delta must be retrievable.
        let node = engine.dag.get(&delta.id).unwrap();
        assert!(node.is_some(), "produced delta must exist in DAG");
        assert_eq!(node.unwrap().delta_id, delta.id);
    }

    #[test]
    #[cfg(feature = "native")]
    fn dag_causal_traversal_bfs_descendants() {
        use std::sync::{Arc, Mutex};

        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
            .expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        let mut dag = ChangesetDag::new(conn);

        // Insert a root node.
        let root_id = [0x01u8; 32];
        let child_id = [0x02u8; 32];
        let grandchild_id = [0x03u8; 32];

        dag.insert(DagNode {
            delta_id: root_id,
            payload: vec![],
            parent_ids: vec![],
            actor_id: b"a".to_vec(),
            lamport: 1,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk1".to_string(),
        })
        .unwrap();

        dag.insert(DagNode {
            delta_id: child_id,
            payload: vec![],
            parent_ids: vec![root_id],
            actor_id: b"a".to_vec(),
            lamport: 2,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk1".to_string(),
        })
        .unwrap();

        dag.insert(DagNode {
            delta_id: grandchild_id,
            payload: vec![],
            parent_ids: vec![child_id],
            actor_id: b"a".to_vec(),
            lamport: 3,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk1".to_string(),
        })
        .unwrap();

        let descendants = dag.bfs_descendants(&root_id).unwrap();
        assert!(descendants.contains(&root_id));
        assert!(descendants.contains(&child_id));
        assert!(descendants.contains(&grandchild_id));
        assert_eq!(descendants.len(), 3);
    }

    #[test]
    #[cfg(feature = "native")]
    fn dag_topological_sort_respects_causal_order() {
        use std::sync::{Arc, Mutex};

        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
            .expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        let mut dag = ChangesetDag::new(conn);

        let id_a = [0xAAu8; 32];
        let id_b = [0xBBu8; 32];
        let id_c = [0xCCu8; 32];

        dag.insert(DagNode {
            delta_id: id_a,
            payload: vec![],
            parent_ids: vec![],
            actor_id: b"x".to_vec(),
            lamport: 1,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk2".to_string(),
        })
        .unwrap();

        dag.insert(DagNode {
            delta_id: id_b,
            payload: vec![],
            parent_ids: vec![id_a],
            actor_id: b"x".to_vec(),
            lamport: 2,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk2".to_string(),
        })
        .unwrap();

        dag.insert(DagNode {
            delta_id: id_c,
            payload: vec![],
            parent_ids: vec![id_b],
            actor_id: b"x".to_vec(),
            lamport: 3,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk2".to_string(),
        })
        .unwrap();

        let sorted = dag.topological_sort().unwrap();

        // a must come before b, b must come before c.
        let pos_a = sorted.iter().position(|id| id == &id_a).unwrap();
        let pos_b = sorted.iter().position(|id| id == &id_b).unwrap();
        let pos_c = sorted.iter().position(|id| id == &id_c).unwrap();
        assert!(pos_a < pos_b, "a must precede b in topological order");
        assert!(pos_b < pos_c, "b must precede c in topological order");
    }

    // ── Lamport clock ─────────────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn lamport_advances_monotonically_across_produce_and_apply() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        engine
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap(); // lamport=1

        // Apply an incoming delta with lamport=5; engine should jump to 6.
        let delta = make_signed_delta(&secret_b, did_b, schema, 5, vec![]);
        engine.apply(&delta).unwrap();
        assert_eq!(engine.lamport(), 6, "lamport must be max(1, 5) + 1 = 6");

        engine
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap(); // lamport=7
        assert_eq!(engine.lamport(), 7);
    }

    // ── DID-based actor-ID tiebreaking (Req 4.5, 4.5a — Gap B) ──────────────
    //
    // These tests verify that when two engines have the same Lamport timestamp,
    // the winner is determined by lexicographically comparing the 32-byte
    // Ed25519 public-key bytes (DID-derived actor IDs) — NOT Automerge's
    // default random UUID-based ordering.

    /// Given two keys A and B where B > A lexicographically, and both apply
    /// concurrent Deltas at the same Lamport value, `lww_incoming_wins` with
    /// the 32-byte public keys must agree with the expected winner.
    #[test]
    #[cfg(feature = "native")]
    fn lww_tiebreak_uses_did_public_key_bytes() {
        // Generate two identities.
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, public_b, did_b) = make_identity();
        let schema = test_schema_hash();

        // Determine which public key is lexicographically greater.
        let (winner_pk, winner_did, winner_secret, loser_did, loser_secret) = if public_b > public_a
        {
            (public_b, did_b.clone(), secret_b, did_a.clone(), secret_a)
        } else {
            (public_a, did_a.clone(), secret_a, did_b.clone(), secret_b)
        };

        let loser_pk: [u8; 32] = if winner_pk == public_b {
            public_a
        } else {
            public_b
        };

        // Both at the same Lamport = 5.
        let same_lamport = 5u64;

        // lww_incoming_wins: winner arriving as "incoming", loser as "current".
        let incoming_wins =
            lww_incoming_wins(same_lamport, &winner_pk[..], same_lamport, &loser_pk[..]);
        assert!(
            incoming_wins,
            "lww_incoming_wins must return true when incoming actor ID > current actor ID \
             at equal Lamport (both are 32-byte DID public keys)"
        );

        // The reverse: loser as incoming, winner as current → should NOT win.
        let loser_incoming_wins =
            lww_incoming_wins(same_lamport, &loser_pk[..], same_lamport, &winner_pk[..]);
        assert!(
            !loser_incoming_wins,
            "lww_incoming_wins must return false when incoming actor ID < current actor ID \
             at equal Lamport"
        );
    }

    /// Same as above but for RGA sequence ordering: the engine whose public
    /// key is lexicographically greater must have priority in `rga_incoming_has_priority`.
    #[test]
    #[cfg(feature = "native")]
    fn rga_tiebreak_uses_did_public_key_bytes() {
        let (_, public_a, _) = make_identity();
        let (_, public_b, _) = make_identity();

        let (higher_pk, lower_pk) = if public_b > public_a {
            (public_b, public_a)
        } else {
            (public_a, public_b)
        };

        let same_lamport = 3u64;

        // Higher public key as incoming → should have RGA priority.
        assert!(
            rga_incoming_has_priority(same_lamport, &higher_pk[..], same_lamport, &lower_pk[..]),
            "rga_incoming_has_priority must be true when incoming 32-byte DID key > current"
        );

        // Lower public key as incoming → should NOT have priority.
        assert!(
            !rga_incoming_has_priority(same_lamport, &lower_pk[..], same_lamport, &higher_pk[..]),
            "rga_incoming_has_priority must be false when incoming 32-byte DID key < current"
        );
    }

    /// Verify that CrdtEngine's Automerge actor ID is set to the 32-byte
    /// public key bytes (not a random UUID) after construction.
    #[test]
    #[cfg(feature = "native")]
    fn engine_actor_id_matches_public_key() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let engine = make_engine(secret, public, did, schema);

        // The Automerge actor ID must equal the 32-byte Ed25519 public key.
        let actor_bytes: Vec<u8> = engine.doc.get_actor().to_bytes().to_vec();
        assert_eq!(
            actor_bytes,
            public.to_vec(),
            "Automerge actor ID must be the 32-byte Ed25519 public key (Req 4.5)"
        );
    }

    /// Two engines with different keys, equal Lamport — apply produces the
    /// correct LWW winner log (no panic / no error path).
    #[test]
    #[cfg(feature = "native")]
    fn apply_concurrent_deltas_equal_lamport_winner_logged() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, public_b, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_b = make_engine(secret_b, public_b, did_b.clone(), schema);

        // Both engines produce a delta at lamport=1.
        let delta_a = engine_a
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();
        let delta_b = engine_b
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();

        // Engine A applies B's delta — should succeed and log the tiebreak.
        let outcome = engine_a.apply(&delta_b).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Merged { .. }),
            "concurrent equal-lamport delta must still merge: {outcome:?}"
        );

        // Engine B applies A's delta — should also succeed.
        let outcome_b = engine_b.apply(&delta_a).unwrap();
        assert!(
            matches!(outcome_b, MergeOutcome::Merged { .. }),
            "symmetric concurrent merge must succeed: {outcome_b:?}"
        );
    }

    // ── Automerge actor-ID consistency ────────────────────────────────────────

    /// Two engines constructed with the same public key must produce identical
    /// actor IDs (deterministic, not random).
    #[test]
    #[cfg(feature = "native")]
    fn two_engines_same_public_key_same_actor_id() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();

        let engine1 = make_engine(secret, public, did.clone(), schema);
        let engine2 = make_engine(secret, public, did, schema);

        assert_eq!(
            engine1.doc.get_actor().to_bytes(),
            engine2.doc.get_actor().to_bytes(),
            "two engines with the same public key must have identical Automerge actor IDs"
        );
    }

    /// Two engines constructed with different public keys must produce different
    /// actor IDs.
    #[test]
    #[cfg(feature = "native")]
    fn two_engines_different_public_key_different_actor_id() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, public_b, did_b) = make_identity();
        let schema = test_schema_hash();

        let engine_a = make_engine(secret_a, public_a, did_a, schema);
        let engine_b = make_engine(secret_b, public_b, did_b, schema);

        assert_ne!(
            engine_a.doc.get_actor().to_bytes(),
            engine_b.doc.get_actor().to_bytes(),
            "engines with different public keys must have different Automerge actor IDs"
        );
    }

    // ── Post-merge LWW/RGA read-back verification (Subphase 6.1 — T50) ────
    //
    // These are the end-to-end tests the audit demanded: real signed Deltas
    // carrying real Automerge bytes are cross-applied through the production
    // `CrdtEngine::apply()` path, and the assertion reads the MERGED DOCUMENT
    // VALUE/ORDERING back (via `doc_map_range_root` / the engine's doc) rather
    // than only checking `lww_incoming_wins` / `rga_incoming_has_priority` in
    // isolation.

    /// Real Automerge bytes for a scalar write under a fresh doc whose actor is
    /// the engine's DID public key. Every engine built this way gets the same
    /// payload counter for its first write, so concurrent first writes tie on
    /// the counter and resolve by actor bytes — exactly the Req 4.5 tiebreak.
    fn scalar_write_bytes(actor: &[u8; 32], key: &str, value: i64) -> Vec<u8> {
        use automerge::{transaction::Transactable, AutoCommit, ROOT};
        let mut doc = AutoCommit::new().with_actor(automerge::ActorId::from(actor));
        doc.put(ROOT, key, value).unwrap();
        doc.save()
    }

    /// Read a ROOT-level scalar back from the engine's merged Automerge doc
    /// through the production projection read (`doc_map_range_root`).
    fn engine_root_scalar(engine: &CrdtEngine, key: &str) -> Option<serde_json::Value> {
        engine
            .doc_map_range_root()
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Read a ROOT-level list back from the engine's merged doc (in-module test
    /// access to the private `doc`).
    fn engine_root_list(engine: &CrdtEngine, key: &str) -> Vec<String> {
        use automerge::{ObjType, ReadDoc, ScalarValue, Value, ROOT};
        match engine.doc.get(ROOT, key).unwrap() {
            Some((Value::Object(ObjType::List), list_id)) => engine
                .doc
                .list_range(&list_id, ..)
                .filter_map(|item| match item.value {
                    Value::Scalar(sv) => match sv.as_ref() {
                        ScalarValue::Str(s) => Some(s.to_string()),
                        _ => None,
                    },
                    _ => None,
                })
                .collect(),
            _ => vec![],
        }
    }

    /// Shared base: a fresh Automerge doc with an empty ROOT-level list.
    fn base_list_bytes(key: &str) -> Vec<u8> {
        use automerge::{transaction::Transactable, AutoCommit, ObjType, ROOT};
        let mut base = AutoCommit::new();
        base.put_object(ROOT, key, ObjType::List).unwrap();
        base.save()
    }

    /// Fork `base` with the given actor and insert `value` at index 0; returns
    /// a full save (base + insertion) for the local engine's pre-load.
    fn list_insert_full_bytes(base: &[u8], actor: &[u8; 32], key: &str, value: &str) -> Vec<u8> {
        use automerge::{transaction::Transactable, AutoCommit, ObjType, ReadDoc, ROOT};
        let mut doc = AutoCommit::load(base)
            .unwrap()
            .with_actor(automerge::ActorId::from(actor));
        let list = match doc.get(ROOT, key).unwrap() {
            Some((automerge::Value::Object(ObjType::List), id)) => id,
            _ => panic!("base doc has no list '{key}'"),
        };
        doc.insert(&list, 0, value).unwrap();
        doc.save()
    }

    /// Fork `base` with the given actor and insert `value` at index 0; returns
    /// only the incremental insertion change (like a real peer's Delta).
    fn list_insert_incremental_bytes(
        base: &[u8],
        actor: &[u8; 32],
        key: &str,
        value: &str,
    ) -> Vec<u8> {
        use automerge::{transaction::Transactable, AutoCommit, ObjType, ReadDoc, ROOT};
        let mut doc = AutoCommit::load(base)
            .unwrap()
            .with_actor(automerge::ActorId::from(actor));
        let list = match doc.get(ROOT, key).unwrap() {
            Some((automerge::Value::Object(ObjType::List), id)) => id,
            _ => panic!("base doc has no list '{key}'"),
        };
        doc.insert(&list, 0, value).unwrap();
        doc.save_incremental()
    }

    /// T50 end-to-end: two engines write the same key at equal Lamport values;
    /// after cross-applying, the MERGED DOCUMENT VALUE must be the write from
    /// the engine whose 32-byte DID public key is lexicographically greater
    /// (Req 4.5 tiebreak) — asserted by reading the doc, not the predicate.
    #[test]
    #[cfg(feature = "native")]
    fn apply_equal_lamport_lww_merged_value_readback() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, public_b, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_b = make_engine(secret_b, public_b, did_b.clone(), schema);

        let bytes_a = scalar_write_bytes(&public_a, "score", 100);
        let bytes_b = scalar_write_bytes(&public_b, "score", 200);
        let delta_a = make_signed_delta(&secret_a, did_a, schema, 1, bytes_a);
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 1, bytes_b);

        // Each engine applies its own write first, so the peer's delta lands on
        // an existing key and a real conflict is read back after the merge.
        engine_a.apply(&delta_a).unwrap();
        engine_b.apply(&delta_b).unwrap();
        engine_a.apply(&delta_b).unwrap();
        engine_b.apply(&delta_a).unwrap();

        let expected: i64 = if public_b > public_a { 200 } else { 100 };
        assert_eq!(
            engine_root_scalar(&engine_a, "score"),
            Some(serde_json::json!(expected)),
            "engine_a merged doc must hold the equal-Lamport winner (Req 4.5 tiebreak)"
        );
        assert_eq!(
            engine_root_scalar(&engine_b, "score"),
            Some(serde_json::json!(expected)),
            "engine_b merged doc must hold the equal-Lamport winner (Req 4.5 tiebreak)"
        );
    }

    /// A strictly-higher-Lamport write must win the merged doc, and with
    /// aligned payload counters (counter == Lamport) the read-back must agree
    /// with the rule in the definitive zone (no divergence, no override).
    #[test]
    #[cfg(feature = "native")]
    fn apply_higher_lamport_lww_merged_value_readback() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, public_b, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);

        // Engine A: one write (payload counter 1), Lamport 1.
        let bytes_a = scalar_write_bytes(&public_a, "score", 100);
        let delta_a = make_signed_delta(&secret_a, did_a.clone(), schema, 1, bytes_a);
        engine_a.apply(&delta_a).unwrap();

        // Engine B: three writes; the last (counter 3) carries the value that
        // must win. Lamport 3 > engine_a's clock (2) → definitive zone.
        let bytes_b = {
            use automerge::{transaction::Transactable, AutoCommit, ROOT};
            let mut doc = AutoCommit::new().with_actor(automerge::ActorId::from(&public_b));
            doc.put(ROOT, "score", 0).unwrap();
            doc.put(ROOT, "score", 99).unwrap();
            doc.put(ROOT, "score", 200).unwrap();
            doc.save()
        };
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 3, bytes_b);
        engine_a.apply(&delta_b).unwrap();

        assert_eq!(
            engine_root_scalar(&engine_a, "score"),
            Some(serde_json::json!(200)),
            "higher-Lamport write must win the merged doc"
        );
    }

    /// Divergence + override: the incoming delta claims Lamport 50 but its
    /// payload is a fresh doc (counter 1). Automerge resolves (1,pk_B) vs
    /// (1,pk_A) → the LOCAL op wins when pk_A > pk_B, contradicting the rule
    /// (50 > 1). The verification must log the divergence and OVERRIDE the doc
    /// so the merged value is the Lamport-rule winner.
    #[test]
    #[cfg(feature = "native")]
    fn apply_lww_divergence_override_forces_rule_winner() {
        let (secret_a, public_a, did_a, secret_b, public_b, did_b) = loop {
            let (sa, pa, da) = make_identity();
            let (sb, pb, db) = make_identity();
            if pa > pb {
                break (sa, pa, da, sb, pb, db);
            }
        };
        let schema = test_schema_hash();
        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);

        let bytes_a = scalar_write_bytes(&public_a, "score", 100);
        let delta_a = make_signed_delta(&secret_a, did_a.clone(), schema, 1, bytes_a);
        engine_a.apply(&delta_a).unwrap();

        let bytes_b = scalar_write_bytes(&public_b, "score", 200);
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 50, bytes_b);
        engine_a.apply(&delta_b).unwrap();

        assert_eq!(
            engine_root_scalar(&engine_a, "score"),
            Some(serde_json::json!(200)),
            "divergence must be overridden to the Lamport-rule winner"
        );
    }

    /// RGA ordering read-back: two concurrent insertions at the same position
    /// (equal payload counters); the merged list must place the element from
    /// the engine with the greater DID public key FIRST (Req 4.5a).
    #[test]
    #[cfg(feature = "native")]
    fn apply_rga_concurrent_inserts_merged_ordering_readback() {
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, public_b, did_b) = make_identity();
        let schema = test_schema_hash();
        let base = base_list_bytes("items");

        let bytes_a = list_insert_full_bytes(&base, &public_a, "items", "A");
        let bytes_b = list_insert_incremental_bytes(&base, &public_b, "items", "B");

        let delta_a = make_signed_delta(&secret_a, did_a.clone(), schema, 1, bytes_a);
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 1, bytes_b);

        let mut engine_a = make_engine(secret_a, public_a, did_a, schema);
        engine_a.apply(&delta_a).unwrap();
        engine_a.apply(&delta_b).unwrap();

        let expected: Vec<String> = if public_b > public_a {
            vec!["B".to_string(), "A".to_string()]
        } else {
            vec!["A".to_string(), "B".to_string()]
        };
        assert_eq!(
            engine_root_list(&engine_a, "items"),
            expected,
            "merged list must order concurrent inserts by (counter, DID bytes) DESC"
        );
    }

    /// RGA divergence + override: pk_A > pk_B and B's delta claims Lamport 50
    /// (definitive zone) → the rule requires B before A, but Automerge (equal
    /// counters) resolves A first. The verification must reorder the merged
    /// list to the Lamport-rule ordering.
    #[test]
    #[cfg(feature = "native")]
    fn apply_rga_divergence_override_reorders_to_rule_winner() {
        let (secret_a, public_a, did_a, secret_b, public_b, did_b) = loop {
            let (sa, pa, da) = make_identity();
            let (sb, pb, db) = make_identity();
            if pa > pb {
                break (sa, pa, da, sb, pb, db);
            }
        };
        let schema = test_schema_hash();
        let base = base_list_bytes("items");

        let bytes_a = list_insert_full_bytes(&base, &public_a, "items", "A");
        let bytes_b = list_insert_incremental_bytes(&base, &public_b, "items", "B");

        let delta_a = make_signed_delta(&secret_a, did_a.clone(), schema, 1, bytes_a);
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 50, bytes_b);

        let mut engine_a = make_engine(secret_a, public_a, did_a, schema);
        engine_a.apply(&delta_a).unwrap();
        engine_a.apply(&delta_b).unwrap();

        assert_eq!(
            engine_root_list(&engine_a, "items"),
            vec!["B".to_string(), "A".to_string()],
            "RGA divergence must be overridden to the Lamport-rule ordering"
        );
    }

    /// Two-engine LWW divergence override: engine_a receives a higher-lamport
    /// delta from engine_b, but Automerge's actor tiebreak would keep the local
    /// value. The verification block must override to the Lamport-rule winner.
    #[test]
    #[cfg(feature = "native")]
    fn apply_two_engine_lww_divergence_override_verifies_rule_winner() {
        let (secret_a, public_a, did_a, secret_b, public_b, did_b) = loop {
            let (sa, pa, da) = make_identity();
            let (sb, pb, db) = make_identity();
            if pa > pb {
                break (sa, pa, da, sb, pb, db);
            }
        };
        let schema = test_schema_hash();

        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_b = make_engine(secret_b, public_b, did_b.clone(), schema);

        let bytes_a = scalar_write_bytes(&public_a, "score", 100);
        let delta_a = make_signed_delta(&secret_a, did_a.clone(), schema, 1, bytes_a);
        engine_a.apply(&delta_a).unwrap();

        let bytes_b = scalar_write_bytes(&public_b, "score", 200);
        let delta_b = make_signed_delta(&secret_b, did_b, schema, 50, bytes_b);
        engine_b.apply(&delta_b).unwrap();

        engine_a.apply(&delta_b).unwrap();
        engine_b.apply(&delta_a).unwrap();

        assert_eq!(
            engine_root_scalar(&engine_a, "score"),
            Some(serde_json::json!(200)),
            "engine_a definitive-zone merge must hold the Lamport winner"
        );
    }
}
