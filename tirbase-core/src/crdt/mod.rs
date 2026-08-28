//! CRDT Engine — wrapper around automerge::AutoCommit (Req 4.1).
//!
//! The CrdtEngine converts writes into Automerge 3.0 changesets (Deltas) and
//! merges incoming Deltas from peers. It maintains the ChangesetDag and drives
//! the LWW and RGA merge paths.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod dag;
pub mod delta;
pub mod merge;
pub mod schema_hash;

use crate::errors::TirBaseError;
use delta::{Delta, DeltaId, PriorityClass};
use schema_hash::SchemaIdentifierHash;

/// The CRDT Engine wraps `automerge::AutoCommit` and adds TirBase-specific
/// routing, signing, and DAG management.
pub struct CrdtEngine {
    // TODO(task-5): embed automerge::AutoCommit docs (one per table)
    // TODO(task-5): embed ChangesetDag
    // TODO(task-5): embed Lamport clock
}

impl CrdtEngine {
    /// Create a new CrdtEngine for the given schema.
    pub fn new(schema_hash: SchemaIdentifierHash) -> Self {
        todo!("Task 5 scaffold")
    }

    /// Produce a Delta for a local write that has already been committed to the
    /// Local Store (Req 4.2). Called after `LocalStore::write()` succeeds.
    pub fn produce_delta(
        &mut self,
        automerge_bytes: Vec<u8>,
        priority: PriorityClass,
        causal_parents: Vec<DeltaId>,
    ) -> Result<Delta, TirBaseError> {
        todo!("Task 5 scaffold")
    }

    /// Apply an incoming Delta from a peer (Req 4.4, 4.5, 4.5a).
    /// Validates Ed25519 signature and Schema_Identifier_Hash before merging.
    pub fn apply(&mut self, delta: &Delta) -> Result<merge::MergeOutcome, TirBaseError> {
        todo!("Task 5 scaffold")
    }

    /// Current Lamport clock value.
    pub fn lamport(&self) -> u64 {
        todo!("Task 5 scaffold")
    }
}
