//! CRDT merge paths — LWW scalar path, RGA sequence path, schema-hash gate.
//!
//! All incoming Deltas flow through the schema-hash gate first:
//!   - Known hash + additive schema change → merge
//!   - Known hash + breaking schema change → Quarantine Ledger
//!   - Unknown hash                        → Quarantine Ledger
//!   - Missing/malformed hash              → Quarantine Ledger + log

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{Delta, DeltaId};
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

/// Apply an incoming Delta through the full merge pipeline:
/// 1. Ed25519 signature validation
/// 2. Schema-hash gate
/// 3. Route to LWW or RGA merge path
/// 4. Persist to DAG and Local Store
pub fn apply_incoming_delta(delta: &Delta) -> Result<MergeOutcome, TirBaseError> {
    todo!("Task 5: implement full merge pipeline")
}

/// LWW (Last-Write-Wins) path for scalar / map-key conflicts (Req 4.5).
///
/// Conflict resolution:
/// 1. Higher Lamport timestamp wins.
/// 2. Tie → lexicographically greater actor ID wins.
/// 3. Both concurrent Deltas are recorded as causal parents.
pub(crate) fn merge_lww(
    incoming: &Delta,
    current_lamport: u64,
    current_actor_id: &[u8],
) -> Result<(), TirBaseError> {
    todo!("Task 5: implement LWW merge")
}

/// RGA sequence path for list/text concurrent insertions (Req 4.5a).
///
/// Concurrent insertions at the same position are ordered by
/// `(lamport DESC, actor_id DESC)`. Deletions become tombstones.
pub(crate) fn merge_rga(incoming: &Delta) -> Result<(), TirBaseError> {
    todo!("Task 5: implement RGA merge")
}
