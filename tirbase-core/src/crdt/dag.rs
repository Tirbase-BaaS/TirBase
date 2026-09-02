//! ChangesetDag — SQLite-backed DAG node storage and causal traversal.
//!
//! The DAG records causal ordering across all known Deltas. Each node stores
//! a zstd-compressed Delta payload and inline parent IDs for fast graph traversal.
//!
//! SQLite schema (created by `LocalStore::open`):
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
/// stored uncompressed. A pure-Rust deflate path is deferred to a post-v1 task
/// if compression on WASM is later required.
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
        // No zstd on WASM — payloads stored uncompressed (pure-Rust deflate deferred to post-v1).
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

// ─── ChangesetDag (native) ────────────────────────────────────────────────────

/// SQLite-backed Changeset DAG with BFS/DFS causal traversal APIs.
pub struct ChangesetDag {
    #[cfg(feature = "native")]
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
    /// In-memory node store for WASM builds.
    #[cfg(not(feature = "native"))]
    nodes: std::collections::HashMap<DeltaId, DagNode>,
    /// In-memory children edges for WASM builds: parent → [child, ...].
    #[cfg(not(feature = "native"))]
    children_map: std::collections::HashMap<DeltaId, Vec<DeltaId>>,
}

#[cfg(feature = "native")]
impl ChangesetDag {
    /// Create a new ChangesetDag backed by the given SQLite connection.
    pub fn new(conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>) -> Self {
        ChangesetDag { conn }
    }

    /// Insert a new node and its parent edges into the DAG.
    ///
    /// The `tags_json` column stores an empty JSON array initially.
    pub fn insert(&mut self, node: DagNode) -> Result<(), TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("DAG mutex poisoned: {e}"),
        })?;

        // Compress the payload before storing.
        let compressed = compress_payload(&node.payload)?;

        // Serialise parent_ids as JSON for the tags_json column placeholder.
        // The actual tags_json is separate — we store an empty array for new nodes.
        let tags_json = "[]".to_string();
        let schema_hash_bytes = node.schema_hash.as_ref();
        let id_bytes = node.delta_id.as_ref();

        conn.execute_batch("BEGIN;")
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("DAG BEGIN failed: {e}"),
            })?;

        let insert_result = conn.execute(
            "INSERT OR IGNORE INTO dag_nodes \
             (id, payload, lamport, schema_hash, compacted, author_did, tags_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
            rusqlite::params![
                id_bytes,
                compressed,
                node.lamport as i64,
                schema_hash_bytes,
                if node.compacted { 1i64 } else { 0i64 },
                node.author_did,
                tags_json,
            ],
        );

        if let Err(e) = insert_result {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(TirBaseError::LocalStoreWriteFailed {
                reason: format!("INSERT dag_nodes failed: {e}"),
            });
        }

        // Insert parent→child edges.
        for parent_id in &node.parent_ids {
            let edge_result = conn.execute(
                "INSERT OR IGNORE INTO dag_edges (parent_id, child_id) VALUES (?1, ?2);",
                rusqlite::params![parent_id.as_ref(), id_bytes],
            );
            if let Err(e) = edge_result {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(TirBaseError::LocalStoreWriteFailed {
                    reason: format!("INSERT dag_edges failed: {e}"),
                });
            }
        }

        conn.execute_batch("COMMIT;")
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("DAG COMMIT failed: {e}"),
            })?;

        Ok(())
    }

    /// Return all child Delta IDs of the given parent.
    pub fn children(&self, parent_id: &DeltaId) -> Result<Vec<DeltaId>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("DAG mutex poisoned: {e}"),
        })?;

        let mut stmt = conn
            .prepare("SELECT child_id FROM dag_edges WHERE parent_id = ?1;")
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Prepare children query failed: {e}"),
            })?;

        let ids = stmt
            .query_map(rusqlite::params![parent_id.as_ref()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query dag_edges children failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|bytes| bytes.try_into().ok())
            .collect();

        Ok(ids)
    }

    /// Return all parent Delta IDs of the given child.
    pub fn parents(&self, child_id: &DeltaId) -> Result<Vec<DeltaId>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("DAG mutex poisoned: {e}"),
        })?;

        let mut stmt = conn
            .prepare("SELECT parent_id FROM dag_edges WHERE child_id = ?1;")
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Prepare parents query failed: {e}"),
            })?;

        let ids = stmt
            .query_map(rusqlite::params![child_id.as_ref()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query dag_edges parents failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|bytes| bytes.try_into().ok())
            .collect();

        Ok(ids)
    }

    /// BFS walk from `root_id` following child edges (forward reachability).
    ///
    /// Returns all reachable Delta IDs including `root_id` itself.
    pub fn bfs_descendants(
        &self,
        root_id: &DeltaId,
    ) -> Result<Vec<DeltaId>, TirBaseError> {
        let mut visited: std::collections::HashSet<DeltaId> = std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<DeltaId> = std::collections::VecDeque::new();
        let mut result: Vec<DeltaId> = Vec::new();

        queue.push_back(*root_id);

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current) {
                continue; // already visited
            }
            result.push(current);

            let children = self.children(&current)?;
            for child in children {
                if !visited.contains(&child) {
                    queue.push_back(child);
                }
            }
        }

        Ok(result)
    }

    /// Topological sort of the entire DAG (Kahn's algorithm, causal order).
    ///
    /// Returns Delta IDs in causal order: all parents before their children.
    pub fn topological_sort(&self) -> Result<Vec<DeltaId>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("DAG mutex poisoned: {e}"),
        })?;

        // Fetch all node IDs.
        let all_ids: Vec<DeltaId> = {
            let mut stmt = conn
                .prepare("SELECT id FROM dag_nodes;")
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("Prepare all_ids failed: {e}"),
                })?;
            let x: Vec<DeltaId> = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("Query all dag_nodes failed: {e}"),
                })?
                .filter_map(|r| r.ok())
                .filter_map(|b| b.try_into().ok())
                .collect();
            x
        };

        // Fetch all edges (parent_id, child_id).
        let all_edges: Vec<(DeltaId, DeltaId)> = {
            let mut stmt = conn
                .prepare("SELECT parent_id, child_id FROM dag_edges;")
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("Prepare all_edges failed: {e}"),
                })?;
            let x: Vec<(DeltaId, DeltaId)> = stmt.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query all dag_edges failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(p, c)| {
                let p: DeltaId = p.try_into().ok()?;
                let c: DeltaId = c.try_into().ok()?;
                Some((p, c))
            })
            .collect();
            x
        };

        // Drop the lock before doing the in-memory Kahn's computation.
        drop(conn);

        // Build adjacency and in-degree maps.
        use std::collections::HashMap;
        let mut in_degree: HashMap<DeltaId, usize> = HashMap::new();
        let mut children_map: HashMap<DeltaId, Vec<DeltaId>> = HashMap::new();

        for id in &all_ids {
            in_degree.entry(*id).or_insert(0);
            children_map.entry(*id).or_default();
        }

        for (parent, child) in &all_edges {
            *in_degree.entry(*child).or_insert(0) += 1;
            children_map.entry(*parent).or_default().push(*child);
        }

        // Kahn's algorithm.
        let mut queue: std::collections::VecDeque<DeltaId> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(id, _)| *id)
            .collect();

        let mut sorted: Vec<DeltaId> = Vec::new();

        while let Some(node) = queue.pop_front() {
            sorted.push(node);
            if let Some(children) = children_map.get(&node) {
                for &child in children {
                    let deg = in_degree.entry(child).or_insert(0);
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(child);
                    }
                }
            }
        }

        Ok(sorted)
    }

    /// Look up a single node by its Delta ID.
    pub fn get(&self, delta_id: &DeltaId) -> Result<Option<DagNode>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("DAG mutex poisoned: {e}"),
        })?;

        let result = conn.query_row(
            "SELECT id, payload, lamport, schema_hash, compacted, author_did \
             FROM dag_nodes WHERE id = ?1;",
            rusqlite::params![delta_id.as_ref()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        );

        match result {
            Ok((id_bytes, payload_bytes, lamport, schema_bytes, compacted, author_did)) => {
                let delta_id_arr: DeltaId = id_bytes
                    .try_into()
                    .map_err(|_| TirBaseError::LocalStoreWriteFailed {
                        reason: "Invalid delta_id length in dag_nodes".to_string(),
                    })?;
                let schema_hash: SchemaIdentifierHash = schema_bytes
                    .try_into()
                    .map_err(|_| TirBaseError::LocalStoreWriteFailed {
                        reason: "Invalid schema_hash length in dag_nodes".to_string(),
                    })?;

                // Decompress payload.
                drop(conn); // release the lock before decompression
                let decompressed = decompress_payload(&payload_bytes)?;

                // Fetch parent IDs for this node.
                let parent_ids = self.parents(&delta_id_arr)?;

                Ok(Some(DagNode {
                    delta_id: delta_id_arr,
                    payload: decompressed,
                    parent_ids,
                    actor_id: vec![],
                    lamport: lamport as u64,
                    schema_hash,
                    compacted: compacted != 0,
                    author_did,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(TirBaseError::LocalStoreWriteFailed {
                reason: format!("SELECT dag_nodes failed: {e}"),
            }),
        }
    }

    /// Mark a node as compacted (hot-path payload pruned).
    pub fn mark_compacted(&mut self, delta_id: &DeltaId) -> Result<(), TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("DAG mutex poisoned: {e}"),
        })?;

        conn.execute(
            "UPDATE dag_nodes SET compacted = 1 WHERE id = ?1;",
            rusqlite::params![delta_id.as_ref()],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("UPDATE dag_nodes compacted failed: {e}"),
        })?;

        Ok(())
    }
}

// ─── WASM stubs ───────────────────────────────────────────────────────────────

#[cfg(not(feature = "native"))]
impl ChangesetDag {
    /// Create a new in-memory ChangesetDag (WASM build — no SQLite connection).
    pub fn new() -> Self {
        ChangesetDag {
            nodes: std::collections::HashMap::new(),
            children_map: std::collections::HashMap::new(),
        }
    }

    pub fn insert(&mut self, node: DagNode) -> Result<(), TirBaseError> {
        // Register parent → child edges.
        for parent_id in &node.parent_ids {
            self.children_map
                .entry(*parent_id)
                .or_default()
                .push(node.delta_id);
        }
        // Ensure the node itself has an (empty) entry in children_map.
        self.children_map.entry(node.delta_id).or_default();
        self.nodes.insert(node.delta_id, node);
        Ok(())
    }

    pub fn children(&self, parent_id: &DeltaId) -> Result<Vec<DeltaId>, TirBaseError> {
        Ok(self
            .children_map
            .get(parent_id)
            .cloned()
            .unwrap_or_default())
    }

    pub fn parents(&self, child_id: &DeltaId) -> Result<Vec<DeltaId>, TirBaseError> {
        Ok(self
            .nodes
            .get(child_id)
            .map(|n| n.parent_ids.clone())
            .unwrap_or_default())
    }

    pub fn bfs_descendants(
        &self,
        root_id: &DeltaId,
    ) -> Result<Vec<DeltaId>, TirBaseError> {
        let mut visited: std::collections::HashSet<DeltaId> =
            std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<DeltaId> =
            std::collections::VecDeque::new();
        let mut result: Vec<DeltaId> = Vec::new();

        queue.push_back(*root_id);
        while let Some(current) = queue.pop_front() {
            if !visited.insert(current) {
                continue;
            }
            result.push(current);
            for child in self.children(&current)? {
                if !visited.contains(&child) {
                    queue.push_back(child);
                }
            }
        }
        Ok(result)
    }

    pub fn topological_sort(&self) -> Result<Vec<DeltaId>, TirBaseError> {
        use std::collections::HashMap;

        let all_ids: Vec<DeltaId> = self.nodes.keys().copied().collect();

        // Build in-degree map and children adjacency.
        let mut in_degree: HashMap<DeltaId, usize> = HashMap::new();
        let mut adj: HashMap<DeltaId, Vec<DeltaId>> = HashMap::new();

        for id in &all_ids {
            in_degree.entry(*id).or_insert(0);
            adj.entry(*id).or_default();
        }
        for node in self.nodes.values() {
            for parent in &node.parent_ids {
                *in_degree.entry(node.delta_id).or_insert(0) += 1;
                adj.entry(*parent).or_default().push(node.delta_id);
            }
        }

        // Kahn's algorithm.
        let mut queue: std::collections::VecDeque<DeltaId> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(id, _)| *id)
            .collect();

        let mut sorted: Vec<DeltaId> = Vec::new();
        while let Some(node) = queue.pop_front() {
            sorted.push(node);
            if let Some(children) = adj.get(&node) {
                for &child in children {
                    let deg = in_degree.entry(child).or_insert(0);
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(child);
                    }
                }
            }
        }
        Ok(sorted)
    }

    pub fn get(&self, delta_id: &DeltaId) -> Result<Option<DagNode>, TirBaseError> {
        Ok(self.nodes.get(delta_id).cloned())
    }

    pub fn mark_compacted(&mut self, delta_id: &DeltaId) -> Result<(), TirBaseError> {
        if let Some(node) = self.nodes.get_mut(delta_id) {
            node.compacted = true;
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

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
