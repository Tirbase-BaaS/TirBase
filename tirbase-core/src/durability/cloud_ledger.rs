//! Cloud Ledger — the server-side append-only merge ledger (Req 16.1–16.4).
//!
//! The Cloud Ledger runs the **same** `CrdtEngine` used on client devices
//! (native build; no source-code changes required — Req 16.1). It wraps that
//! engine with two additional behaviours:
//!
//! 1. **Append-only invariant** (Req 16.2) — committed Deltas are never deleted
//!    or modified. The `dag_nodes.compacted` flag is the only field the ledger
//!    may update, and then only to record that a Delta was superseded by a
//!    compaction — the payload row is retained.
//!
//! 2. **Idempotent receive** (Req 16.4) — if a Delta that has already been
//!    committed is re-submitted (possible because clients retry until they
//!    receive a per-Delta ack), the ledger returns a success ack without
//!    re-merging. Duplicate detection is O(1) via a `HashSet` of committed
//!    `DeltaId`s that mirrors the `dag_nodes` table.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::crdt::delta::{Delta, DeltaId, Did};
use crate::crdt::merge::MergeOutcome;
use crate::crdt::CrdtEngine;
use crate::errors::TirBaseError;
use crate::schema::hash::SchemaIdentifierHash;
use crate::store::sqlite;

// ─── CloudLedger ─────────────────────────────────────────────────────────────

/// The Cloud Ledger is an append-only merge ledger that accepts incoming
/// Deltas from client devices and merges them using the same `CrdtEngine`
/// semantics as the peer-to-peer path (Req 16.1).
///
/// # Append-only invariant (Req 16.2)
///
/// The internal committed-set only grows. There is no `remove` or `clear`
/// method on `CloudLedger`. Callers can never delete a committed Delta.
///
/// # Idempotent receive (Req 16.4)
///
/// `receive_delta()` checks the committed-set before calling
/// `CrdtEngine::apply()`. If the `DeltaId` is already present, it returns
/// `Ok(ReceiveOutcome::AlreadyCommitted)` without re-merging.
///
/// # CRDT semantics (Req 16.1)
///
/// The underlying `CrdtEngine` is the same one used by client devices.
/// Merge semantics (LWW, RGA, schema-hash gate, signature verification) are
/// therefore identical on the Cloud Ledger and on every client device.
#[cfg(feature = "native")]
pub struct CloudLedger {
    /// CRDT Engine — same implementation as client devices (Req 16.1).
    engine: CrdtEngine,
    /// All Delta IDs that have ever been successfully committed.
    /// Never shrinks — enforces the append-only invariant (Req 16.2, 16.4).
    committed: HashSet<DeltaId>,
    /// Rejection log: `{delta_id_hex → reason}`.
    /// Exposed for inspection in tests and diagnostics.
    pub rejection_log: Vec<RejectionRecord>,
}

/// A record of a rejected Delta receive attempt.
#[derive(Debug, Clone)]
pub struct RejectionRecord {
    pub delta_id: String,
    pub reason: String,
}

/// Outcome of one `CloudLedger::receive_delta()` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// Delta was merged for the first time. Client should consider it acked.
    Committed,
    /// Delta was already committed; this is a duplicate submission.
    /// Client should still consider it acked (idempotent — Req 16.4).
    AlreadyCommitted,
    /// Delta was rejected (bad signature, unknown schema, etc.).
    /// The specific reason is included for diagnostic logging.
    Rejected { reason: String },
}

#[cfg(feature = "native")]
impl CloudLedger {
    /// Create a Cloud Ledger backed by an **in-memory** SQLite database.
    ///
    /// The ledger uses a random (but deterministic across tests) schema hash
    /// so that test Deltas signed with the supplied `secret_key` are accepted.
    ///
    /// # Parameters
    ///
    /// * `secret_key` — Ed25519 secret key seed for the ledger's own identity.
    /// * `author_did` — `did:key:` DID corresponding to `secret_key`.
    /// * `schema_hash` — the schema hash the ledger accepts (must match clients).
    pub fn new_in_memory(
        secret_key: [u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
    ) -> Result<Self, TirBaseError> {
        use ed25519_dalek::SigningKey;
        let public_key: [u8; 32] = SigningKey::from_bytes(&secret_key).verifying_key().to_bytes();

        let conn = rusqlite::Connection::open_in_memory().map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("CloudLedger in-memory SQLite: {e}"),
            }
        })?;
        conn.execute_batch(sqlite::CREATE_SCHEMA_SQL).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("CloudLedger schema init: {e}"),
            }
        })?;
        let conn = Arc::new(Mutex::new(conn));
        let engine = CrdtEngine::new(secret_key, public_key, author_did, schema_hash, conn);

        Ok(Self {
            engine,
            committed: HashSet::new(),
            rejection_log: Vec::new(),
        })
    }

    /// Receive and merge one Delta from a client device.
    ///
    /// # Idempotency (Req 16.4)
    ///
    /// If the Delta's `id` is already in the committed set, this method
    /// returns `ReceiveOutcome::AlreadyCommitted` without calling
    /// `CrdtEngine::apply()`.
    ///
    /// # Append-only (Req 16.2)
    ///
    /// A committed Delta is **never** removed from the committed set.
    ///
    /// # Return value
    ///
    /// - `Ok(ReceiveOutcome::Committed)` — merged for the first time.
    /// - `Ok(ReceiveOutcome::AlreadyCommitted)` — duplicate submission; treat as ack.
    /// - `Ok(ReceiveOutcome::Rejected { reason })` — CRDT engine rejected the Delta.
    pub fn receive_delta(&mut self, delta: &Delta) -> Result<ReceiveOutcome, TirBaseError> {
        // Idempotent check — already committed? (Req 16.4)
        if self.committed.contains(&delta.id) {
            return Ok(ReceiveOutcome::AlreadyCommitted);
        }

        // Apply through the same CrdtEngine pipeline used by client devices (Req 16.1).
        let outcome = self.engine.apply(delta)?;

        match outcome {
            MergeOutcome::Merged { .. } | MergeOutcome::Quarantined { .. } => {
                // Quarantined Deltas are still "received" by the Cloud Ledger
                // (stored in the quarantine ledger) — we record them as committed
                // to avoid re-processing. The Cloud Ledger stores them byte-for-byte
                // as required by the append-only invariant (Req 16.2).
                self.committed.insert(delta.id);
                Ok(ReceiveOutcome::Committed)
            }
            MergeOutcome::Rejected { reason } => {
                // Log the rejection (Req 16.5 context: Cloud Ledger rejection
                // causes the client to retain the Delta in its outbound queue).
                let id_hex = hex::encode(delta.id);
                log_ledger_rejection(&id_hex, &reason);
                self.rejection_log.push(RejectionRecord {
                    delta_id: id_hex,
                    reason: reason.clone(),
                });
                Ok(ReceiveOutcome::Rejected { reason })
            }
        }
    }

    /// Returns `true` if the given Delta ID has been committed.
    ///
    /// This reflects the append-only invariant: once `true`, always `true`.
    pub fn is_committed(&self, delta_id: &DeltaId) -> bool {
        self.committed.contains(delta_id)
    }

    /// Number of committed Deltas.
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// Add an additional known schema hash to the ledger's CRDT engine.
    ///
    /// Called when a schema migration is applied so the ledger can accept
    /// Deltas from the new schema version.
    pub fn add_known_schema(&mut self, hash: SchemaIdentifierHash) {
        self.engine.add_known_schema(hash);
    }
}

// ─── CloudLedgerConnection ───────────────────────────────────────────────────

/// A `CloudConnection` implementation backed by a real `CloudLedger`.
///
/// This is the production adapter that plugs the `CloudLedger` into the
/// `cloud_sync_loop()`.  In tests, the same type is used with an in-memory
/// ledger to exercise the full sync pipeline without network I/O.
#[cfg(feature = "native")]
pub struct CloudLedgerConnection<'a> {
    pub ledger: &'a mut CloudLedger,
}

#[cfg(feature = "native")]
impl<'a> CloudLedgerConnection<'a> {
    pub fn new(ledger: &'a mut CloudLedger) -> Self {
        Self { ledger }
    }
}

/// Implement `CloudConnection` so `CloudLedgerConnection` can be passed directly
/// to `cloud_sync_loop()`.
///
/// The connection deserialises the raw bytes back into a `Delta`, then calls
/// `CloudLedger::receive_delta()`.  Ack/rejection semantics match Req 16.3–16.5:
/// - `AlreadyCommitted` and `Committed` both return `Ok(())` — the client removes
///   the entry from its outbound queue.
/// - `Rejected` returns `Err(reason)` — the client retains the entry and logs it.
#[cfg(feature = "native")]
impl<'a> crate::durability::cloud_queue::CloudConnection for CloudLedgerConnection<'a> {
    fn send_delta(&mut self, delta_id: &DeltaId, bytes: &[u8]) -> Result<(), String> {
        // Deserialise the Delta from the bytes provided by the sync loop.
        let delta: Delta = serde_json::from_slice(bytes).map_err(|e| {
            format!("failed to deserialise Delta {}: {e}", hex::encode(delta_id))
        })?;

        match self.ledger.receive_delta(&delta) {
            Ok(ReceiveOutcome::Committed) => Ok(()),
            Ok(ReceiveOutcome::AlreadyCommitted) => {
                // Idempotent success — client should consider it acked (Req 16.4).
                Ok(())
            }
            Ok(ReceiveOutcome::Rejected { reason }) => Err(reason),
            Err(e) => Err(e.to_string()),
        }
    }
}

// ─── Internal logging ────────────────────────────────────────────────────────

fn log_ledger_rejection(delta_id: &str, reason: &str) {
    eprintln!(
        "[cloud_ledger] Rejected delta {delta_id}: {reason}"
    );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "native")]
mod tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use crate::crdt::derive_did_from_public_key;
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::schema::hash::compute_schema_identifier_hash;

    fn test_schema_hash() -> SchemaIdentifierHash {
        compute_schema_identifier_hash(&[("reports", &[("id", "TEXT"), ("body", "TEXT")])])
    }

    fn make_identity() -> ([u8; 32], [u8; 32], Did) {
        let (secret, public) = generate_keypair().expect("keygen");
        let did = derive_did_from_public_key(&public);
        (secret, public, did)
    }

    fn make_signed_delta(
        secret: &[u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
        lamport: u64,
    ) -> Delta {
        let mut d = Delta {
            id: [0u8; 32],
            author_did,
            signature: Ed25519Signature::default(),
            schema_hash,
            automerge_bytes: vec![],
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

    fn make_ledger() -> (CloudLedger, [u8; 32], Did, SchemaIdentifierHash) {
        let (secret, _, ledger_did) = make_identity();
        let schema = test_schema_hash();
        let ledger = CloudLedger::new_in_memory(secret, ledger_did.clone(), schema)
            .expect("new_in_memory");
        (ledger, secret, ledger_did, schema)
    }

    // ── Basic receive ─────────────────────────────────────────────────────────

    #[test]
    fn receive_valid_delta_returns_committed() {
        let (mut ledger, _, _, schema) = make_ledger();
        let (secret, _, did) = make_identity();
        let delta = make_signed_delta(&secret, did, schema, 1);

        let outcome = ledger.receive_delta(&delta).unwrap();
        assert_eq!(outcome, ReceiveOutcome::Committed);
        assert!(ledger.is_committed(&delta.id));
        assert_eq!(ledger.committed_count(), 1);
    }

    // ── Idempotent receive (Req 16.4) ─────────────────────────────────────────

    #[test]
    fn receive_same_delta_twice_is_idempotent() {
        let (mut ledger, _, _, schema) = make_ledger();
        let (secret, _, did) = make_identity();
        let delta = make_signed_delta(&secret, did, schema, 1);

        // First submission.
        let first = ledger.receive_delta(&delta).unwrap();
        assert_eq!(first, ReceiveOutcome::Committed);

        // Second submission — same Delta ID.
        let second = ledger.receive_delta(&delta).unwrap();
        assert_eq!(second, ReceiveOutcome::AlreadyCommitted,
            "re-submitting the same Delta must return AlreadyCommitted");

        // Committed count must remain 1 (no duplicate stored).
        assert_eq!(ledger.committed_count(), 1);
    }

    // ── Rejection (bad signature) ─────────────────────────────────────────────

    #[test]
    fn receive_tampered_delta_is_rejected() {
        let (mut ledger, _, _, schema) = make_ledger();
        let (secret, _, did) = make_identity();
        let mut delta = make_signed_delta(&secret, did, schema, 1);

        // Tamper with the automerge bytes after signing — signature no longer valid.
        delta.automerge_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let outcome = ledger.receive_delta(&delta).unwrap();
        assert!(
            matches!(outcome, ReceiveOutcome::Rejected { .. }),
            "tampered Delta must be rejected: {outcome:?}"
        );
        assert!(!ledger.is_committed(&delta.id), "rejected Delta must not be committed");
        assert_eq!(ledger.rejection_log.len(), 1);
    }

    // ── Append-only invariant (Req 16.2) ─────────────────────────────────────

    #[test]
    fn committed_set_never_shrinks() {
        let (mut ledger, _, _, schema) = make_ledger();
        let (s1, _, d1) = make_identity();
        let (s2, _, d2) = make_identity();

        let delta_a = make_signed_delta(&s1, d1, schema, 1);
        let delta_b = make_signed_delta(&s2, d2, schema, 2);

        ledger.receive_delta(&delta_a).unwrap();
        ledger.receive_delta(&delta_b).unwrap();

        assert_eq!(ledger.committed_count(), 2);
        // There is no API to remove committed Deltas — this test confirms it
        // by compiling: CloudLedger has no remove/clear method.
        assert!(ledger.is_committed(&delta_a.id));
        assert!(ledger.is_committed(&delta_b.id));
    }

    // ── Unknown schema hash ────────────────────────────────────────────────────

    #[test]
    fn receive_delta_with_unknown_schema_is_quarantined_not_rejected() {
        // A Delta with an unknown schema hash is quarantined (not rejected
        // with a hard error). The Cloud Ledger still records it as "committed"
        // (byte-for-byte stored in the quarantine ledger) so the client can
        // move on. (Req 16.4 — we don't want the client to retry forever on
        // a schema mismatch.)
        let (mut ledger, _, _, _) = make_ledger();
        let (secret, _, did) = make_identity();
        let unknown_schema = [0xFFu8; 32]; // not registered with the ledger
        let delta = make_signed_delta(&secret, did, unknown_schema, 1);

        let outcome = ledger.receive_delta(&delta).unwrap();
        // Quarantined Deltas are treated as Committed on the Cloud Ledger
        // (stored for later replay).
        assert_eq!(outcome, ReceiveOutcome::Committed);
        assert!(ledger.is_committed(&delta.id));
    }
}
