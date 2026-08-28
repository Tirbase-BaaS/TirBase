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

// ─── Payload compression helpers ─────────────────────────────────────────────

/// Compress `data` with zstd (native) or return a plain copy (wasm).
///
/// On the native build this uses the `zstd` C-backed crate.  The WASM build
/// cannot link zstd's C FFI into `wasm32-unknown-unknown`, so payloads are
/// stored uncompressed (Task 8 will add a pure-Rust deflate path if needed).
///
/// The returned bytes are always safe to pass to [`decompress_payload`].
pub fn compress_payload(data: &[u8]) -> Result<Vec<u8>, TirBaseError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        zstd::encode_all(data, 3 /* default level */).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("zstd compress: {e}"),
            }
        })
    }
    #[cfg(target_arch = "wasm32")]
    {
        // No zstd on WASM — store uncompressed until Task 8 adds a pure-Rust path.
        Ok(data.to_vec())
    }
}

/// Decompress a payload previously produced by [`compress_payload`].
pub fn decompress_payload(data: &[u8]) -> Result<Vec<u8>, TirBaseError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        zstd::decode_all(data).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("zstd decompress: {e}"),
        })
    }
    #[cfg(target_arch = "wasm32")]
    {
        Ok(data.to_vec())
    }
}

// ─── DagNode ─────────────────────────────────────────────────────────────────

/// A node in the Changeset DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    /// Delta ID (SHA-256 of canonical_bytes).
    pub delta_id: DeltaId,
    /// zstd-compressed serialised Delta (native); uncompressed on WASM.
    /// Use [`compress_payload`] / [`decompress_payload`] to encode/decode.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dag_node_serde_round_trip() {
        let node = DagNode {
            delta_id: [0xAAu8; 32],
            payload: b"raw-delta-bytes".to_vec(),
            parent_ids: vec![[0xBBu8; 32]],
            actor_id: b"actor-1".to_vec(),
            lamport: 17,
            schema_hash: [0xCCu8; 32],
            compacted: false,
            author_did: "did:key:z6MkDag".to_string(),
        };

        let json = serde_json::to_string(&node).expect("serialise DagNode");
        let decoded: DagNode = serde_json::from_str(&json).expect("deserialise DagNode");

        assert_eq!(node.delta_id, decoded.delta_id);
        assert_eq!(node.payload, decoded.payload);
        assert_eq!(node.parent_ids, decoded.parent_ids);
        assert_eq!(node.lamport, decoded.lamport);
        assert_eq!(node.compacted, decoded.compacted);
    }

    /// On native builds, compress → decompress must recover the original bytes.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn compress_decompress_native_round_trip() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let compressed = compress_payload(&data).expect("compress");
        let recovered = decompress_payload(&compressed).expect("decompress");
        assert_eq!(data, recovered);
    }

    /// On wasm, both operations are identity — bytes are returned unchanged.
    #[test]
    #[cfg(target_arch = "wasm32")]
    fn compress_decompress_wasm_identity() {
        let data = b"wasm-passthrough".to_vec();
        let out1 = compress_payload(&data).unwrap();
        let out2 = decompress_payload(&out1).unwrap();
        assert_eq!(data, out1);
        assert_eq!(data, out2);
    }

    #[test]
    fn compress_empty_payload_round_trips() {
        let data: Vec<u8> = vec![];
        let compressed = compress_payload(&data).expect("compress empty");
        let recovered = decompress_payload(&compressed).expect("decompress empty");
        assert_eq!(data, recovered);
    }
}
