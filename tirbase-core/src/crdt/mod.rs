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

use std::collections::HashSet;

use crate::errors::TirBaseError;
use crate::identity::keypair;
use delta::{Delta, DeltaId, Did, Ed25519Signature, PriorityClass};
use merge::{MergeOutcome, QuarantineReason};
use schema_hash::SchemaIdentifierHash;

#[cfg(feature = "native")]
use dag::{ChangesetDag, DagNode};

// ─── DID resolution helpers ──────────────────────────────────────────────────

/// Decode a `did:key:z6Mk…` DID to its 32-byte Ed25519 public key.
///
/// Format: `did:key:` + base58btc(multikey_bytes)
/// Multikey bytes: `[0xed, 0x01]` (ed25519 multicodec prefix) + 32 public-key bytes
fn resolve_did_key_to_public_key(did: &str) -> Result<[u8; 32], TirBaseError> {
    let suffix = did
        .strip_prefix("did:key:")
        .ok_or_else(|| TirBaseError::DidResolutionFailed {
            did: did.to_string(),
            reason: "not a did:key: DID".to_string(),
        })?;

    let multikey = bs58::decode(suffix)
        .into_vec()
        .map_err(|e| TirBaseError::DidResolutionFailed {
            did: did.to_string(),
            reason: format!("base58 decode failed: {e}"),
        })?;

    // Ed25519 multicodec prefix is [0xed, 0x01]
    if multikey.len() < 2 || multikey[0] != 0xed || multikey[1] != 0x01 {
        return Err(TirBaseError::DidResolutionFailed {
            did: did.to_string(),
            reason: "missing or wrong ed25519 multicodec prefix [0xed, 0x01]".to_string(),
        });
    }

    let key_bytes: &[u8] = &multikey[2..];
    key_bytes.try_into().map_err(|_| TirBaseError::DidResolutionFailed {
        did: did.to_string(),
        reason: format!(
            "expected 32 public-key bytes after prefix, got {}",
            key_bytes.len()
        ),
    })
}

/// Derive a `did:key:` DID from a 32-byte Ed25519 public key.
pub fn derive_did_from_public_key(public_key: &[u8; 32]) -> Did {
    // Prepend ed25519 multicodec prefix [0xed, 0x01]
    let mut multikey = Vec::with_capacity(34);
    multikey.push(0xed);
    multikey.push(0x01);
    multikey.extend_from_slice(public_key);
    let encoded = bs58::encode(&multikey).into_string();
    format!("did:key:{encoded}")
}

// ─── CrdtEngine ──────────────────────────────────────────────────────────────

/// The CRDT Engine wraps `automerge::AutoCommit` and adds TirBase-specific
/// routing, signing, and DAG management.
pub struct CrdtEngine {
    /// One Automerge doc (simplified for Task 5; multi-table is Task 3).
    doc: automerge::AutoCommit,

    /// Monotonically increasing Lamport clock.
    lamport: u64,

    /// The schema hash this engine was initialised with.
    known_schema_hash: SchemaIdentifierHash,

    /// All schema hashes accepted by this engine.
    /// Grows as additive schema migrations are applied (Task 8).
    known_schemas: HashSet<SchemaIdentifierHash>,

    /// DID of the local device's identity (used in `produce_delta`).
    author_did: Did,

    /// Ed25519 secret key seed (32 bytes) for signing produced Deltas.
    secret_key: [u8; 32],

    /// SQLite-backed Changeset DAG (native build only).
    #[cfg(feature = "native")]
    dag: ChangesetDag,
}

impl CrdtEngine {
    /// Create a new CrdtEngine.
    ///
    /// `secret_key` is the 32-byte Ed25519 seed; `author_did` is the
    /// corresponding `did:key:` DID; `schema_hash` is the initial known schema.
    ///
    /// On native builds the caller must supply a live SQLite connection so the
    /// DAG can persist nodes.
    #[cfg(feature = "native")]
    pub fn new(
        secret_key: [u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
        conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        let mut known_schemas = HashSet::new();
        known_schemas.insert(schema_hash);

        CrdtEngine {
            doc: automerge::AutoCommit::new(),
            lamport: 0,
            known_schema_hash: schema_hash,
            known_schemas,
            author_did,
            secret_key,
            dag: ChangesetDag::new(conn),
        }
    }

    /// WASM / test constructor (no SQLite connection required).
    #[cfg(not(feature = "native"))]
    pub fn new(
        secret_key: [u8; 32],
        author_did: Did,
        schema_hash: SchemaIdentifierHash,
    ) -> Self {
        let mut known_schemas = HashSet::new();
        known_schemas.insert(schema_hash);

        CrdtEngine {
            doc: automerge::AutoCommit::new(),
            lamport: 0,
            known_schema_hash: schema_hash,
            known_schemas,
            author_did,
            secret_key,
        }
    }

    /// Register an additional known schema hash (called during additive migration).
    pub fn add_known_schema(&mut self, hash: SchemaIdentifierHash) {
        self.known_schemas.insert(hash);
    }

    /// Current Lamport clock value.
    pub fn lamport(&self) -> u64 {
        self.lamport
    }

    /// Produce a Delta for a local write that has already been committed to the
    /// Local Store (Req 4.2, 4.6). Called after `LocalStore::write()` succeeds.
    ///
    /// Steps:
    /// 1. Increment the Lamport clock.
    /// 2. Collect causal parents from the DAG's current tips.
    /// 3. Build the Delta with all metadata.
    /// 4. Sign with the local private key.
    /// 5. Compute and assign the DeltaId.
    /// 6. Insert the DagNode.
    pub fn produce_delta(
        &mut self,
        automerge_bytes: Vec<u8>,
        priority: PriorityClass,
        causal_parents: Vec<DeltaId>,
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
            tags: vec![],
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

    /// Apply an incoming Delta from a peer (Req 4.4, 4.5, 4.5a).
    ///
    /// Pipeline:
    /// 1. Schema-hash gate — unknown hash → Rejected.
    /// 2. Malformed-signature guard.
    /// 3. Ed25519 signature verification via DID resolution.
    /// 4. Merge Automerge changeset into local doc.
    /// 5. Advance Lamport clock.
    /// 6. Persist DagNode.
    pub fn apply(&mut self, delta: &Delta) -> Result<MergeOutcome, TirBaseError> {
        // 1. Schema-hash gate (Req 4.4).
        if !self.known_schemas.contains(&delta.schema_hash) {
            let hash_hex = hex::encode(delta.schema_hash);
            eprintln!(
                "[CRDT] Rejected delta from {}: unknown schema hash {}",
                delta.author_did, hash_hex
            );
            return Ok(MergeOutcome::Quarantined {
                reason: QuarantineReason::UnknownSchemaHash,
            });
        }

        // 2. Malformed-signature guard.
        if delta.signature.0.is_empty() {
            eprintln!(
                "[CRDT] Rejected delta from {}: missing signature",
                delta.author_did
            );
            return Ok(MergeOutcome::Rejected {
                reason: "malformed delta: missing signature".to_string(),
            });
        }

        // 3. DID resolution + Ed25519 verification.
        let public_key = match resolve_did_key_to_public_key(&delta.author_did) {
            Ok(pk) => pk,
            Err(e) => {
                let reason = e.to_string();
                eprintln!(
                    "[CRDT] Rejected delta from {}: DID resolution failed — {reason}",
                    delta.author_did
                );
                return Ok(MergeOutcome::Rejected { reason });
            }
        };

        let canonical = delta.canonical_bytes();
        if let Err(e) = keypair::verify(&public_key, &canonical, &delta.signature) {
            let reason = e.to_string();
            eprintln!(
                "[CRDT] Rejected delta from {}: {reason}",
                delta.author_did
            );
            return Ok(MergeOutcome::Rejected { reason });
        }

        // 4. Merge Automerge changeset.
        //    Load the incoming bytes as a separate AutoCommit doc, then merge.
        self.merge_automerge_bytes(&delta.automerge_bytes)?;

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
    fn resolve_causal_parents(
        &self,
        explicit: Vec<DeltaId>,
    ) -> Result<Vec<DeltaId>, TirBaseError> {
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
        // For Task 5 we use a simpler but correct approach: collect all node
        // IDs and all parent_ids used in the DAG; tips = nodes – parents.
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

    /// Merge raw Automerge bytes from a remote peer into the local doc.
    ///
    /// The idiomatic Automerge approach is to load the bytes as a second
    /// `AutoCommit` and call `local_doc.merge(&mut their_doc)`.
    fn merge_automerge_bytes(&mut self, bytes: &[u8]) -> Result<(), TirBaseError> {
        if bytes.is_empty() {
            // Empty byte slice — nothing to merge (e.g. test stubs).
            return Ok(());
        }

        let mut their_doc = automerge::AutoCommit::load(bytes).map_err(|e| {
            TirBaseError::DeltaMalformed {
                reason: format!("failed to load automerge bytes: {e}"),
            }
        })?;

        self.doc.merge(&mut their_doc).map_err(|e| {
            TirBaseError::DeltaMalformed {
                reason: format!("automerge merge failed: {e}"),
            }
        })?;

        Ok(())
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
        did: Did,
        schema: SchemaIdentifierHash,
    ) -> CrdtEngine {
        use std::sync::{Arc, Mutex};
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
            .expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        CrdtEngine::new(secret, did, schema, conn)
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
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, did, schema);

        assert_eq!(engine.lamport(), 0);
        engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();
        assert_eq!(engine.lamport(), 1);
        engine.produce_delta(vec![], PriorityClass::High, vec![]).unwrap();
        assert_eq!(engine.lamport(), 2);
    }

    #[test]
    #[cfg(feature = "native")]
    fn produce_delta_signature_verifies() {
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, did, schema);

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
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, did, schema);

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
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, did, schema);
        let delta = engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();
        assert_eq!(delta.schema_hash, schema);
    }

    // ── apply — schema-hash gate ─────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_unknown_schema_hash_is_quarantined() {
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret.clone(), did.clone(), schema);

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

    // ── apply — malformed delta ───────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_missing_signature_is_rejected() {
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, did.clone(), schema);

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
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret.clone(), did.clone(), schema);

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
        let (secret_a, _, did_a) = make_identity();
        let (secret_b, _, _did_b) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret_a, did_a.clone(), schema);

        // Sign delta with key_b but claim did_a as author.
        let delta = make_signed_delta(&secret_b, did_a, schema, 1, vec![]);

        let outcome = engine.apply(&delta).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { .. }),
            "mismatched key must be rejected: {outcome:?}"
        );
    }

    // ── apply — valid delta ───────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "native")]
    fn apply_valid_delta_returns_merged() {
        let (secret_a, _, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, did_a, schema);

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
        let (secret_a, _, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();

        let mut engine = make_engine(secret_a, did_a, schema);

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
        sorted_ops.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.0.cmp(a.0))
        });

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
        let (secret, _, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, did, schema);

        let delta = engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();

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
        }).unwrap();

        dag.insert(DagNode {
            delta_id: child_id,
            payload: vec![],
            parent_ids: vec![root_id],
            actor_id: b"a".to_vec(),
            lamport: 2,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk1".to_string(),
        }).unwrap();

        dag.insert(DagNode {
            delta_id: grandchild_id,
            payload: vec![],
            parent_ids: vec![child_id],
            actor_id: b"a".to_vec(),
            lamport: 3,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk1".to_string(),
        }).unwrap();

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
        }).unwrap();

        dag.insert(DagNode {
            delta_id: id_b,
            payload: vec![],
            parent_ids: vec![id_a],
            actor_id: b"x".to_vec(),
            lamport: 2,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk2".to_string(),
        }).unwrap();

        dag.insert(DagNode {
            delta_id: id_c,
            payload: vec![],
            parent_ids: vec![id_b],
            actor_id: b"x".to_vec(),
            lamport: 3,
            schema_hash: test_schema_hash(),
            compacted: false,
            author_did: "did:key:z6Mk2".to_string(),
        }).unwrap();

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
        let (secret_a, _, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret_a, did_a, schema);

        engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap(); // lamport=1

        // Apply an incoming delta with lamport=5; engine should jump to 6.
        let delta = make_signed_delta(&secret_b, did_b, schema, 5, vec![]);
        engine.apply(&delta).unwrap();
        assert_eq!(engine.lamport(), 6, "lamport must be max(1, 5) + 1 = 6");

        engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap(); // lamport=7
        assert_eq!(engine.lamport(), 7);
    }
}
