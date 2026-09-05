//! Delta — the atomic unit of change in TirBase.
//!
//! A Delta wraps an Automerge 3.0 changeset with TirBase-specific metadata:
//! identity, signature, schema hash, priority, causal parents, and an
//! append-only tag log for contamination tracking.

#![allow(dead_code, unused_variables)]

use serde::{Deserialize, Serialize};
use serde_bytes;
use sha2::{Digest, Sha256};

// Re-export the shared SchemaIdentifierHash type
pub use crate::schema::hash::SchemaIdentifierHash;

// ─── Primitive newtypes ───────────────────────────────────────────────────────

/// Unique Delta identifier: SHA-256(canonical_bytes()).
pub type DeltaId = [u8; 32];

/// Ed25519 signature (64 bytes) — serialised as a byte blob.
///
/// We wrap `Vec<u8>` so that serde works without large-array helpers.
/// All crypto operations accept `&[u8]` and validate length at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Ed25519Signature(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Ed25519Signature {
    /// Create from a 64-byte array.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes.to_vec())
    }

    /// Try to extract as a fixed 64-byte array.
    pub fn as_bytes(&self) -> Option<[u8; 64]> {
        self.0.as_slice().try_into().ok()
    }
}

/// Automerge actor ID (opaque bytes; used for LWW tiebreaking).
pub type ActorId = Vec<u8>;

/// DID string, e.g. "did:key:z6Mk…"
pub type Did = String;

// ─── PriorityClass ────────────────────────────────────────────────────────────

/// Bandwidth priority class assigned by the DRR scheduler (Req 12.1, 12.5–12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PriorityClass {
    /// 70% guaranteed bandwidth floor.
    /// Revocation_Deltas, safety-alert, emergency-alert payloads.
    High,
    /// 20% guaranteed bandwidth floor.
    /// Peer reachability, link-state, session-validity records.
    Medium,
    /// 10% guaranteed bandwidth floor.
    /// All other application Deltas.
    Low,
}

// ─── DeltaTag ─────────────────────────────────────────────────────────────────

/// Append-only tag log entry on a Delta (Req 10.2–10.4).
///
/// Tags are **never** modified or removed; the log only grows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaTag {
    /// This Delta (or one of its causal ancestors) is a contamination root.
    Contaminated {
        root_id: DeltaId,
        incident_id: uuid::Uuid,
    },
    /// All contamination roots that led to this Delta are now resolved.
    Decontaminated {
        incident_id: uuid::Uuid,
        resolved_at: i64,
    },
    /// A Manager_DID has verified data for this root Delta.
    Resolved {
        by_manager_did: Did,
        at: i64,
    },
    /// This Delta was written while the local projection was CONTAMINATED
    /// or the incoming stream was quarantined (Req 19.5).
    ContaminatedByHumanReaction {
        incident_id: uuid::Uuid,
    },
    /// This Delta (or one of its causal ancestors) was authored under a
    /// schema produced by a migration that was later revoked as corrupted
    /// (Req 19.1).
    ContaminatedByCorruptedMigration {
        migration_id: [u8; 32],
    },
    /// Side-Car replay completed with zero conflicts for this migration (Req 19.6).
    ReplayComplete {
        migration_id: [u8; 32],
    },
}

// ─── Delta ────────────────────────────────────────────────────────────────────

/// The atomic unit of change in TirBase (design §Data Models / Delta).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    /// Unique identifier: SHA-256(canonical_bytes()).
    pub id: DeltaId,

    /// The originating device's DID ("did:key:z6Mk…").
    pub author_did: Did,

    /// Ed25519 signature over `canonical_bytes()` (excluding this field).
    pub signature: Ed25519Signature,

    /// Deterministic hash of the schema at write time (Req 17.1, 4.6).
    pub schema_hash: SchemaIdentifierHash,

    /// Raw Automerge 3.0 changeset bytes (opaque to layers above CRDT).
    pub automerge_bytes: Vec<u8>,

    /// Priority class assigned by the DRR scheduler.
    pub priority: PriorityClass,

    /// Causal parent Delta IDs (mirrors Automerge dependencies).
    pub causal_parents: Vec<DeltaId>,

    /// Append-only tag log; never mutated, only extended (Req 10.4).
    pub tags: Vec<DeltaTag>,

    /// Lamport clock value at write time (for LWW tiebreaking).
    pub lamport: u64,

    /// Wall-clock timestamp (UTC, microseconds); informational only.
    pub created_at: i64,
}

impl Delta {
    /// Produce the canonical byte representation of this Delta **excluding**
    /// the `signature` and `id` fields. This is the payload that is signed
    /// with the author's Ed25519 private key (Req 7.2).
    ///
    /// ## Determinism guarantee (Property 1 / Req 1.4)
    ///
    /// The serialisation uses `serde_json` with a helper struct whose fields
    /// are declared in a fixed order.  `serde_json` serialises struct fields
    /// in declaration order (not hash-map order), so the output is byte-stable
    /// across every platform and build target — native and WASM — for the same
    /// logical Delta contents.  Floating-point fields are absent from the
    /// canonical payload (all numeric fields are integers), eliminating any
    /// cross-platform float formatting variance.
    ///
    /// A future migration to CBOR or a length-prefixed binary codec would
    /// preserve this guarantee and improve compactness, but is not required
    /// for correctness — the JSON codec is already deterministic here.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let payload = CanonicalDeltaPayload {
            author_did: &self.author_did,
            schema_hash: &self.schema_hash,
            automerge_bytes: &self.automerge_bytes,
            priority: &self.priority,
            causal_parents: &self.causal_parents,
            tags: &self.tags,
            lamport: self.lamport,
            created_at: self.created_at,
        };
        serde_json::to_vec(&payload)
            .expect("canonical_bytes serialisation must not fail")
    }

    /// Compute the `DeltaId` as SHA-256 of `canonical_bytes()` (Req 7.2 / design).
    pub fn compute_id(canonical: &[u8]) -> DeltaId {
        let mut hasher = Sha256::new();
        hasher.update(canonical);
        hasher.finalize().into()
    }
}

/// Helper struct for deterministic canonical serialisation (excludes `id` and `signature`).
#[derive(Serialize)]
struct CanonicalDeltaPayload<'a> {
    author_did: &'a Did,
    schema_hash: &'a SchemaIdentifierHash,
    automerge_bytes: &'a [u8],
    priority: &'a PriorityClass,
    causal_parents: &'a [DeltaId],
    tags: &'a [DeltaTag],
    lamport: u64,
    created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Construct a minimal but complete Delta for testing.
    fn make_delta(lamport: u64, author: &str, automerge_bytes: Vec<u8>) -> Delta {
        Delta {
            id: [0u8; 32],
            author_did: author.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [1u8; 32],
            automerge_bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 1_720_000_000_000_000,
        }
    }

    // ── canonical_bytes ────────────────────────────────────────────────────

    #[test]
    fn canonical_bytes_is_deterministic() {
        let d = make_delta(42, "did:key:z6MkA", b"am-bytes".to_vec());
        let b1 = d.canonical_bytes();
        let b2 = d.canonical_bytes();
        assert_eq!(b1, b2, "canonical_bytes must return identical bytes on repeated calls");
    }

    #[test]
    fn canonical_bytes_excludes_signature_field() {
        let mut d = make_delta(1, "did:key:z6MkB", b"payload".to_vec());
        let before = d.canonical_bytes();

        // Change the signature — canonical_bytes must NOT change.
        d.signature = Ed25519Signature(vec![0xFF; 64]);
        let after = d.canonical_bytes();

        assert_eq!(
            before, after,
            "canonical_bytes must not include the signature field"
        );
    }

    #[test]
    fn canonical_bytes_excludes_id_field() {
        let mut d = make_delta(1, "did:key:z6MkC", b"payload".to_vec());
        let before = d.canonical_bytes();

        d.id = [0xAB; 32];
        let after = d.canonical_bytes();

        assert_eq!(before, after, "canonical_bytes must not include the id field");
    }

    #[test]
    fn canonical_bytes_changes_with_payload_field() {
        let d1 = make_delta(1, "did:key:z6MkD", b"bytes-v1".to_vec());
        let d2 = make_delta(1, "did:key:z6MkD", b"bytes-v2".to_vec());
        assert_ne!(
            d1.canonical_bytes(),
            d2.canonical_bytes(),
            "different automerge_bytes must produce different canonical_bytes"
        );
    }

    // ── compute_id ────────────────────────────────────────────────────────

    #[test]
    fn compute_id_is_sha256_of_canonical_bytes() {
        use sha2::{Digest, Sha256};
        let d = make_delta(7, "did:key:z6MkE", b"data".to_vec());
        let canonical = d.canonical_bytes();
        let expected: [u8; 32] = Sha256::digest(&canonical).into();
        assert_eq!(
            Delta::compute_id(&canonical),
            expected,
            "compute_id must be SHA-256 of canonical_bytes"
        );
    }

    #[test]
    fn compute_id_changes_with_different_canonical_bytes() {
        let d1 = make_delta(1, "did:key:z6MkF", b"a".to_vec());
        let d2 = make_delta(1, "did:key:z6MkF", b"b".to_vec());
        assert_ne!(
            Delta::compute_id(&d1.canonical_bytes()),
            Delta::compute_id(&d2.canonical_bytes()),
        );
    }

    // ── DeltaTag serde round-trips ─────────────────────────────────────────

    #[test]
    fn delta_tag_contaminated_round_trip() {
        let tag = DeltaTag::Contaminated {
            root_id: [0xCA; 32],
            incident_id: Uuid::now_v7(),
        };
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: DeltaTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    #[test]
    fn delta_tag_decontaminated_round_trip() {
        let tag = DeltaTag::Decontaminated {
            incident_id: Uuid::now_v7(),
            resolved_at: 1_720_001_000_000,
        };
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: DeltaTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    #[test]
    fn delta_tag_resolved_round_trip() {
        let tag = DeltaTag::Resolved {
            by_manager_did: "did:key:z6MkMgr".to_string(),
            at: 1_720_005_000_000,
        };
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: DeltaTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    #[test]
    fn delta_tag_contaminated_by_human_reaction_round_trip() {
        let tag = DeltaTag::ContaminatedByHumanReaction {
            incident_id: Uuid::now_v7(),
        };
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: DeltaTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    #[test]
    fn delta_tag_replay_complete_round_trip() {
        let tag = DeltaTag::ReplayComplete { migration_id: [0xBB; 32] };
        let json = serde_json::to_string(&tag).unwrap();
        let decoded: DeltaTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, decoded);
    }

    // ── PriorityClass serde ────────────────────────────────────────────────

    #[test]
    fn priority_class_all_variants_round_trip() {
        for p in [PriorityClass::High, PriorityClass::Medium, PriorityClass::Low] {
            let json = serde_json::to_string(&p).unwrap();
            let decoded: PriorityClass = serde_json::from_str(&json).unwrap();
            assert_eq!(p, decoded);
        }
    }

    // ── Ed25519Signature helpers ───────────────────────────────────────────

    #[test]
    fn ed25519_signature_from_and_as_bytes_round_trip() {
        let arr: [u8; 64] = std::array::from_fn(|i| i as u8);
        let sig = Ed25519Signature::from_bytes(arr);
        assert_eq!(sig.as_bytes(), Some(arr));
    }

    #[test]
    fn ed25519_signature_wrong_length_returns_none() {
        let sig = Ed25519Signature(vec![0u8; 32]); // wrong length
        assert_eq!(sig.as_bytes(), None);
    }
}
