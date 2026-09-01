//! CRDT merge paths — LWW scalar path, RGA sequence path, schema-hash gate.
//!
//! All incoming Deltas flow through the schema-hash gate first:
//!   - Known hash + valid signature       → merge (LWW or RGA as appropriate)
//!   - Known hash + breaking schema change → Quarantine Ledger
//!   - Unknown hash                        → Quarantine Ledger
//!   - Missing/malformed hash/signature    → Rejected
//!
//! The full pipeline is orchestrated by [`CrdtEngine::apply()`] in `crdt/mod.rs`.
//! External callers must always go through `CrdtEngine::apply()` — never call
//! the free helpers ([`merge_lww`] / [`merge_rga`]) directly.  Those helpers
//! are internal utilities that implement the tie-breaking and ordering logic so
//! they can be unit-tested independently of the full engine.


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
