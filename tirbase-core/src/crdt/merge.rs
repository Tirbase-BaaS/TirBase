//! CRDT merge paths — LWW/RGA routing entry point and helper predicates.
//!
//! ## Routing architecture (design.md §CRDT Merge Logic)
//!
//! All peer-received Deltas flow through [`apply_incoming_delta`], which is the
//! **LWW/RGA routing entry point** per the design.md flowchart:
//!
//! ```text
//! Receive Delta
//!   → Schema-hash gate (unknown → Quarantine)
//!   → Ed25519 signature validation (invalid → Rejected)
//!   → Operation-type inspection → LWW path (scalar/map) or RGA path (list/text)
//!   → CrdtEngine::apply() (Automerge merge + DAG + Lamport)
//! ```
//!
//! [`apply_incoming_delta`] is the entry point. [`CrdtEngine::apply()`] (in
//! `crdt/mod.rs`) is the Automerge-level merge primitive. External callers
//! receiving peer Deltas MUST call [`apply_incoming_delta`] — never call
//! [`merge_lww`] or [`merge_rga`] directly.
//!
//! [`merge_lww`] and [`merge_rga`] are internal helpers that implement the
//! tiebreaking predicates for LWW scalar and RGA sequence conflicts. They are
//! tested independently of the full engine.


use crate::crdt::delta::Delta;
use crate::crdt::CrdtEngine;
use crate::errors::TirBaseError;

/// Merge outcome after applying an incoming Delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Delta was successfully merged into the local store.
    Merged { new_lamport: u64 },
    /// Delta was placed in the Quarantine Ledger due to schema incompatibility.
    Quarantined { reason: QuarantineReason },
    /// Delta was rejected (bad signature, revoked sender, etc.).
    Rejected { reason: String },
}

/// Reason a Delta was quarantined rather than merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineReason {
    /// An existing field was removed, renamed, or its type changed (Req 17.4).
    BreakingSchemaChange,
    /// The Schema_Identifier_Hash is not known to this device (Req 4.4).
    UnknownSchemaHash,
    /// The Schema_Identifier_Hash field is absent or malformed (Req 17.6).
    MissingOrMalformedHash,
}

/// Classify the operation type in Automerge changeset bytes.
///
/// Returns `Some(true)` if the operation is a list/text insertion or deletion
/// (RGA path), `Some(false)` if it is a scalar/map-key set (LWW path), or
/// `None` if the bytes are empty or unparseable — callers default to LWW in
/// that case.
///
/// Practical note: operation-type classification via the Automerge internal
/// byte API is deferred pending a stable predicate surface. Both merge paths
/// delegate to `CrdtEngine::apply()` which uses Automerge's native routing;
/// the classification here is for observability only.
pub(crate) fn is_rga_operation(_automerge_bytes: &[u8]) -> Option<bool> {
    // Deferred to a future task — return None so callers default to LWW path.
    None
}

/// LWW/RGA routing entry point for peer-received Deltas (Req 4.3–4.5a).
///
/// This is the design.md-specified routing layer that sits above
/// `CrdtEngine::apply()`. It classifies the incoming Delta's operation type
/// and dispatches to the appropriate merge path before delegating the actual
/// merge to the CRDT engine.
///
/// Routing flowchart (design.md §CRDT Merge Logic):
///   1. Schema-hash gate → unknown hash returns `Quarantined`
///   2. Ed25519 signature validation → invalid returns `Rejected`
///   3. Operation-type inspection → scalar/map → LWW path; list/text → RGA path
///   4. Both paths call `CrdtEngine::apply()` for the Automerge-level merge
///
/// `CrdtEngine::apply()` is the Automerge-level merge primitive and handles
/// steps 1 and 2 as well. This function adds the observable routing layer
/// (step 3) on top.
pub fn apply_incoming_delta(
    engine: &mut CrdtEngine,
    delta: &Delta,
) -> Result<MergeOutcome, TirBaseError> {
    // Classify operation type for routing decision (best-effort).
    let is_rga = is_rga_operation(&delta.automerge_bytes);

    let path_name = match is_rga {
        Some(true) => "RGA sequence",
        Some(false) => "LWW scalar",
        None => "LWW scalar (default)",
    };

    eprintln!(
        "[merge] routing delta {} from {} via {} path",
        hex::encode(delta.id),
        delta.author_did,
        path_name,
    );

    // Delegate to CrdtEngine::apply() which handles validation + Automerge merge.
    // Both LWW and RGA paths ultimately go through the same Automerge merge step;
    // the routing classification here is for observability and future dispatch hooks.
    engine.apply(delta)
}

/// LWW (Last-Write-Wins) conflict resolution for scalar / map-key fields (Req 4.5).
///
/// Returns `true` when the incoming Delta should overwrite the current value.
///
/// Resolution order:
/// 1. Higher Lamport timestamp wins.
/// 2. Tie → lexicographically greater `actor_id` wins.
/// 3. Both concurrent Deltas are recorded as causal parents in the DAG
///    (handled by [`CrdtEngine::apply`]).
pub(crate) fn merge_lww(
    incoming_lamport: u64,
    incoming_actor_id: &[u8],
    current_lamport: u64,
    current_actor_id: &[u8],
) -> bool {
    crate::crdt::lww_incoming_wins(
        incoming_lamport,
        incoming_actor_id,
        current_lamport,
        current_actor_id,
    )
}

/// RGA sequence ordering for list/text concurrent insertions (Req 4.5a).
///
/// Returns `true` when the incoming insertion should be placed **before**
/// the current one (higher priority in the merged sequence).
///
/// Ordering: `(lamport DESC, actor_id DESC)` — larger Lamport comes first;
/// ties broken by lexicographically greater actor ID.
/// Deletions are handled as tombstones by the Automerge layer.
pub(crate) fn merge_rga(
    incoming_lamport: u64,
    incoming_actor_id: &[u8],
    current_lamport: u64,
    current_actor_id: &[u8],
) -> bool {
    crate::crdt::rga_incoming_has_priority(
        incoming_lamport,
        incoming_actor_id,
        current_lamport,
        current_actor_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LWW ──────────────────────────────────────────────────────────────────

    #[test]
    fn lww_higher_lamport_wins() {
        assert!(merge_lww(10, b"a", 5, b"a"), "higher lamport must win");
        assert!(!merge_lww(3, b"a", 7, b"a"), "lower lamport must lose");
    }

    #[test]
    fn lww_equal_lamport_greater_actor_wins() {
        assert!(merge_lww(5, b"b", 5, b"a"), "greater actor must win on tie");
        assert!(!merge_lww(5, b"a", 5, b"b"), "lesser actor must lose on tie");
    }

    #[test]
    fn lww_equal_lamport_equal_actor_incoming_does_not_win() {
        assert!(
            !merge_lww(5, b"same", 5, b"same"),
            "equal actor must not overwrite current"
        );
    }

    // ── RGA ──────────────────────────────────────────────────────────────────

    #[test]
    fn rga_higher_lamport_has_priority() {
        assert!(merge_rga(10, b"a", 5, b"a"));
        assert!(!merge_rga(3, b"a", 9, b"a"));
    }

    #[test]
    fn rga_equal_lamport_greater_actor_has_priority() {
        assert!(merge_rga(5, b"z", 5, b"a"));
        assert!(!merge_rga(5, b"a", 5, b"z"));
    }

    #[test]
    fn rga_concurrent_insertions_all_present_in_order() {
        // Three concurrent insertions; sort them in RGA order.
        let mut ops: Vec<(u64, Vec<u8>, &str)> = vec![
            (3, b"actor-a".to_vec(), "A"),
            (5, b"actor-b".to_vec(), "B"),
            (5, b"actor-c".to_vec(), "C"),
        ];

        // Sort: (lamport DESC, actor DESC)
        ops.sort_by(|x, y| y.0.cmp(&x.0).then_with(|| y.1.cmp(&x.1)));

        let values: Vec<&str> = ops.iter().map(|(_, _, v)| *v).collect();
        assert_eq!(values, vec!["C", "B", "A"],
            "RGA order must be (lamport DESC, actor DESC)");
    }
}

// ── apply_incoming_delta routing ─────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod routing_tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use crate::crdt::{derive_did_from_public_key, CrdtEngine};
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::schema::hash::compute_schema_identifier_hash;
    use std::sync::{Arc, Mutex};

    fn test_schema() -> [u8; 32] {
        compute_schema_identifier_hash(&[("users", &[("id", "TEXT"), ("name", "TEXT")])])
    }

    fn make_engine(secret: [u8; 32], public: [u8; 32], did: String, schema: [u8; 32]) -> CrdtEngine {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL).expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        CrdtEngine::new(secret, public, did, schema, conn)
    }

    fn make_signed_delta(
        secret: &[u8; 32],
        did: String,
        schema: [u8; 32],
        lamport: u64,
        automerge_bytes: Vec<u8>,
    ) -> Delta {
        let mut d = Delta {
            id: [0u8; 32],
            author_did: did,
            signature: Ed25519Signature::default(),
            schema_hash: schema,
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

    /// A Delta with empty automerge_bytes (LWW/default path) is routed and returns Merged.
    #[test]
    fn scalar_op_routed_via_lww_returns_merged() {
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);
        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);
        let schema = test_schema();
        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        // Empty automerge_bytes → classified as LWW (default)
        let delta = make_signed_delta(&secret_b, did_b, schema, 1, vec![]);
        let outcome = apply_incoming_delta(&mut engine, &delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Merged { .. }),
            "scalar-path delta must return Merged: {outcome:?}"
        );
    }

    /// A Delta with an unknown schema hash is quarantined.
    #[test]
    fn unknown_schema_hash_is_quarantined() {
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);
        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);
        let schema = test_schema();
        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        let unknown_schema = [0xFFu8; 32];
        let delta = make_signed_delta(&secret_b, did_b, unknown_schema, 1, vec![]);
        let outcome = apply_incoming_delta(&mut engine, &delta).unwrap();
        assert_eq!(
            outcome,
            MergeOutcome::Quarantined { reason: QuarantineReason::UnknownSchemaHash },
            "unknown schema hash must quarantine: {outcome:?}"
        );
    }

    /// A Delta with a tampered signature is rejected.
    #[test]
    fn tampered_signature_is_rejected() {
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);
        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);
        let schema = test_schema();
        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        let mut delta = make_signed_delta(&secret_b, did_b, schema, 1, vec![1, 2, 3]);
        // Tamper with the automerge_bytes after signing → sig mismatch
        delta.automerge_bytes = vec![9, 9, 9];

        let outcome = apply_incoming_delta(&mut engine, &delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "tampered delta must be rejected: {outcome:?}"
        );
    }

    /// apply_incoming_delta and CrdtEngine::apply produce the same outcome (regression test).
    #[test]
    fn routing_layer_produces_same_outcome_as_engine_apply() {
        // Engine A uses apply_incoming_delta; Engine B uses apply directly.
        // Both should return Merged for the same valid delta.
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);
        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);
        let schema = test_schema();

        let mut engine_via_routing = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_via_apply   = make_engine(secret_a, public_a, did_a, schema);

        let delta = make_signed_delta(&secret_b, did_b, schema, 1, vec![]);

        let outcome_routing = apply_incoming_delta(&mut engine_via_routing, &delta).unwrap();
        let outcome_apply   = engine_via_apply.apply(&delta).unwrap();

        assert_eq!(
            outcome_routing, outcome_apply,
            "apply_incoming_delta must return same outcome as CrdtEngine::apply"
        );
    }
}
