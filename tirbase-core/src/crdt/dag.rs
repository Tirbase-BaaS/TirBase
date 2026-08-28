//! ChangesetDag — SQLite-backed DAG node storage and causal traversal.
//!
//! The DAG records causal ordering across all known Deltas. Each node stores
//! a zstd-compressed Delta payload and inline parent IDs for fast graph traversal.
//!
//! SQLite schema (created by LocalStore in Task 3):
//! ```sql
//! CREATE TABLE dag_nodes (
//!     id          BLOB PRIMARY KEY,
//!     payload     BLOB,      -- zstd-compressed Delta bytes
//!     lamport     INTEGER,
//!     schema_hash BLOB,
//!     compacted   INTEGER,   -- 0 | 1
//!     author_did  TEXT,
//!     tags_json   TEXT
//! );
//! CREATE TABLE dag_edges (
//!     parent_id BLOB,
//!     child_id  BLOB,
//!     PRIMARY KEY (parent_id, child_id)
//! );
//! ```

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{ActorId, DeltaId, Did};
use crate::errors::TirBaseError;
use crate::schema::hash::SchemaIdentifierHash;
use serde::{Deserialize, Serialize};

/// A node in the Changeset DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    /// Delta ID (SHA-256 of canonical_bytes).
    pub delta_id: DeltaId,
    /// zstd-compressed serialised Delta.
    pub payload: Vec<u8>,
    /// Inline copy of causal_parents for fast graph traversal.
    pub parent_ids: Vec<DeltaId>,
    /// Automerge actor ID (for LWW tiebreaking).
    pub actor_id: ActorId,
    pub lamport: u64,
    pub schema_hash: SchemaIdentifierHash,
    /// If true, the payload has been compacted from the hot read path.
    /// The Delta is still retained in the Cloud Ledger outbound queue until Tier-2
    /// durability is confirmed (Req 14.8).
    pub compacted: bool,
    /// DID of the Delta author.
    pub author_did: Did,
}

/// SQLite-backed Changeset DAG with BFS/DFS causal traversal APIs.
pub struct ChangesetDag {
    // TODO(task-3): inject LocalStore handle
}

impl ChangesetDag {
    /// Insert a new node and its parent edges into the DAG.
    pub fn insert(&mut self, node: DagNode) -> Result<(), TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }

    /// Return all child Delta IDs of the given parent.
    pub fn children(&self, parent_id: &DeltaId) -> Result<Vec<DeltaId>, TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }

    /// Return all parent Delta IDs of the given child.
    pub fn parents(&self, child_id: &DeltaId) -> Result<Vec<DeltaId>, TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }

    /// BFS walk from `root_id` following child edges (forward reachability).
    pub fn bfs_descendants(
        &self,
        root_id: &DeltaId,
    ) -> Result<Vec<DeltaId>, TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }

    /// Topological sort of the entire DAG (Kahn's algorithm, causal order).
    pub fn topological_sort(&self) -> Result<Vec<DeltaId>, TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }

    /// Look up a single node by its Delta ID.
    pub fn get(&self, delta_id: &DeltaId) -> Result<Option<DagNode>, TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }

    /// Mark a node as compacted (hot-path payload pruned).
    pub fn mark_compacted(&mut self, delta_id: &DeltaId) -> Result<(), TirBaseError> {
        todo!("Task 3: implement with LocalStore")
    }
}
