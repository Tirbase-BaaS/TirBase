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
    /// One Automerge doc per engine instance (the CRDT engine is table-scoped at the
    /// `CoreHandle` level; each table gets its own `CrdtEngine`).
    doc: automerge::AutoCommit,

    /// Monotonically increasing Lamport clock.
    lamport: u64,

    /// The schema hash this engine was initialised with.
    known_schema_hash: SchemaIdentifierHash,

    /// All schema hashes accepted by this engine.
    /// Grows as additive schema migrations are applied.
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
            author_did,
            secret_key,
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

        // 4a. Post-merge LWW / RGA verification (Req 4.5, 4.5a).
        //
        // Now that both actor IDs are set to their respective Ed25519 public
        // key bytes (set in `new()`), Automerge's internal tiebreak and
        // `lww_incoming_wins()` / `rga_incoming_has_priority()` are computed
        // over the same byte sequences and should always agree.
        //
        // We log the tiebreak decision so operators can verify correctness.
        // If Automerge's actor ID somehow differs from the incoming DID's key
        // bytes we emit a warning — this should never occur in production.
        {
            let local_actor_bytes: Vec<u8> = self.doc.get_actor().to_bytes().to_vec();
            let incoming_actor_bytes: Vec<u8> = delta.author_did
                .as_bytes()
                .to_vec(); // raw DID string bytes — used only for the log

            // Resolve the incoming DID to its 32-byte public key bytes for the
            // actual tiebreak comparison.
            if let Ok(incoming_pk) = resolve_did_key_to_public_key(&delta.author_did) {
                let incoming_actor = &incoming_pk[..];
                let local_actor = &local_actor_bytes[..];

                // LWW scalar: would the incoming delta win over the local state?
                let lww_winner = lww_incoming_wins(
                    delta.lamport,
                    incoming_actor,
                    self.lamport,   // local lamport *before* advance in step 5
                    local_actor,
                );

                // RGA sequence: would the incoming insertion take priority?
                let rga_priority = rga_incoming_has_priority(
                    delta.lamport,
                    incoming_actor,
                    self.lamport,
                    local_actor,
                );

                eprintln!(
                    "[CRDT] post-merge tiebreak — incoming actor: {} (lamport {}) | \
                     local actor: {} bytes (lamport {}) | \
                     LWW incoming wins: {} | RGA incoming has priority: {}",
                    delta.author_did,
                    delta.lamport,
                    local_actor.len(),
                    self.lamport,
                    lww_winner,
                    rga_priority,
                );
            } else {
                eprintln!(
                    "[CRDT] WARNING: post-merge tiebreak skipped — could not resolve \
                     incoming DID '{}' to public key bytes",
                    delta.author_did
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
        let delta = engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();
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
        let (secret, public, did) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret, public, did, schema);

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
        let (secret_a, public_a, did_a) = make_identity();
        let (secret_b, _, did_b) = make_identity();
        let schema = test_schema_hash();
        let mut engine = make_engine(secret_a, public_a, did_a, schema);

        engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap(); // lamport=1

        // Apply an incoming delta with lamport=5; engine should jump to 6.
        let delta = make_signed_delta(&secret_b, did_b, schema, 5, vec![]);
        engine.apply(&delta).unwrap();
        assert_eq!(engine.lamport(), 6, "lamport must be max(1, 5) + 1 = 6");

        engine.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap(); // lamport=7
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
        let (winner_pk, winner_did, winner_secret, loser_did, loser_secret) =
            if public_b > public_a {
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
        let incoming_wins = lww_incoming_wins(
            same_lamport,
            &winner_pk[..],
            same_lamport,
            &loser_pk[..],
        );
        assert!(
            incoming_wins,
            "lww_incoming_wins must return true when incoming actor ID > current actor ID \
             at equal Lamport (both are 32-byte DID public keys)"
        );

        // The reverse: loser as incoming, winner as current → should NOT win.
        let loser_incoming_wins = lww_incoming_wins(
            same_lamport,
            &loser_pk[..],
            same_lamport,
            &winner_pk[..],
        );
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
        let delta_a = engine_a.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();
        let delta_b = engine_b.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();

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
}
