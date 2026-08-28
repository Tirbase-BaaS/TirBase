//! TirBaseError — typed error enum for all tirbase-core public API boundaries.
//!
//! All errors propagate through `Result<T, TirBaseError>` and use `thiserror`
//! for ergonomic derive-based formatting (design §Error Handling).

#![allow(dead_code)]

use crate::contamination::incident::IncidentState;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TirBaseError {
    // ─── Identity / Auth ──────────────────────────────────────────────────────
    #[error("DID resolution failed for {did}: {reason}")]
    DidResolutionFailed { did: String, reason: String },

    #[error("Ed25519 signature verification failed: {reason}")]
    SignatureVerificationFailed { reason: String },

    #[error("Peer revoked: {peer_did}")]
    PeerRevoked { peer_did: String },

    #[error("Threshold not met: got {got} signatures, need {need}")]
    ThresholdNotMet { got: usize, need: usize },

    #[error("Authorisation error: {reason}")]
    AuthorisationFailed { reason: String },

    // ─── CRDT / Schema ────────────────────────────────────────────────────────
    #[error("Unknown schema hash: {hash}")]
    UnknownSchemaHash { hash: String },

    #[error("Delta malformed: {reason}")]
    DeltaMalformed { reason: String },

    #[error("Schema parse error at {line}:{col}: {description}")]
    SchemaParseError {
        line: u32,
        col: u32,
        description: String,
    },

    #[error("Version path mismatch: local={local}, migration_source={source}, expected_next={expected_next}")]
    VersionPathMismatch {
        local: String,
        source: String,
        expected_next: String,
    },

    // ─── Transport ────────────────────────────────────────────────────────────
    #[error("Noise handshake failed with peer {peer_did}: {reason}")]
    NoiseHandshakeFailed { peer_did: String, reason: String },

    #[error("Fragment reassembly failed from {sender_did}: expected {expected} fragments")]
    FragmentReassemblyFailed {
        sender_did: String,
        expected: u32,
    },

    #[error("Cloud outbound queue full: depth={depth}")]
    CloudQueueFull { depth: usize },

    // ─── Contamination ────────────────────────────────────────────────────────
    #[error("Unsupported taint source")]
    UnsupportedTaintSource,

    #[error("Invalid incident state: expected OPEN, got {got:?}")]
    InvalidIncidentState { got: IncidentState },

    // ─── Migration ────────────────────────────────────────────────────────────
    #[error("Migration CA signature invalid: {migration_id}")]
    MigrationCaSignatureInvalid { migration_id: String },

    #[error("Migration hash mismatch: {migration_id}")]
    MigrationHashMismatch { migration_id: String },

    #[error("Migration transform timeout: {migration_id}")]
    MigrationTransformTimeout { migration_id: String },

    // ─── Storage ──────────────────────────────────────────────────────────────
    #[error("Local store write failed: {reason}")]
    LocalStoreWriteFailed { reason: String },

    #[error("Compaction failed on table {table}: {reason}")]
    CompactionFailed { table: String, reason: String },

    // ─── Durability ───────────────────────────────────────────────────────────
    #[error("Re-fetch unavailable for delta {delta_id}")]
    RefetchUnavailable { delta_id: String },

    #[error("Spatial diversity degraded: available={available}, required={required}")]
    SpatialDiversityDegraded {
        available: usize,
        required: usize,
    },
}
