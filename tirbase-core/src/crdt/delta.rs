//! Delta — the atomic unit of change in TirBase.
//!
//! A Delta wraps an Automerge 3.0 changeset with TirBase-specific metadata:
//! identity, signature, schema hash, priority, causal parents, and an
//! append-only tag log for contamination tracking.

#![allow(dead_code, unused_variables)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Re-export the shared SchemaIdentifierHash type
pub use crate::schema::hash::SchemaIdentifierHash;

// ─── Primitive newtypes ───────────────────────────────────────────────────────

/// Unique Delta identifier: SHA-256(canonical_bytes()).
pub type DeltaId = [u8; 32];

/// Ed25519 signature (64 bytes).
pub type Ed25519Signature = [u8; 64];

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
    /// The serialisation is deterministic: fields are encoded in declaration
    /// order using little-endian fixed-width integers where applicable.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Deterministic serialisation used as the signing payload.
        // We encode all fields except `signature` and `id`.
        // CBOR/bincode would be preferable; for the scaffold we use serde_json
        // with sorted keys (stable ordering guaranteed by struct field order).
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
        // TODO(task-2): replace with a proper binary codec (e.g., CBOR) for
        // byte-stability guarantees across platform builds.
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
