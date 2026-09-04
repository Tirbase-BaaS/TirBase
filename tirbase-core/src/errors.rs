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

    #[error("Version path mismatch: local={local_ver}, migration_source={source_ver}, expected_next={expected_next}")]
    VersionPathMismatch {
        local_ver: String,
        source_ver: String,
        expected_next: String,
    },

    #[error("Schema definition registration failed: {reason}")]
    SchemaRegistrationFailed { reason: String },

    // ─── Transport ────────────────────────────────────────────────────────────
    #[error("Noise handshake failed with peer {peer_did}: {reason}")]
    NoiseHandshakeFailed { peer_did: String, reason: String },

    #[error("Mesh unavailable: {reason}")]
    MeshUnavailable { reason: String },

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

    /// Another migration transform is currently executing; schema migrations
    /// are strictly serialised because each step validates against the
    /// device's current schema hash (Req 18.3a).
    #[error("Another migration is already in progress: {migration_id}")]
    MigrationInProgress { migration_id: String },

    /// A `MigrationRevocationDelta` targeted a migration hash this device has
    /// never seen (no CA-validated `MigrationDelta` for it was received).
    /// Revocations are only accepted for known, previously-seen migration
    /// hashes (Req 18.7) — an arbitrary-hash revocation would permanently
    /// poison the registry with a block on a migration that was never
    /// distributed.
    #[error("Migration revocation targets an unknown migration hash: {migration_id}")]
    UnknownMigrationHash { migration_id: String },

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contamination::incident::IncidentState;

    #[test]
    fn error_display_did_resolution_failed() {
        let e = TirBaseError::DidResolutionFailed {
            did: "did:key:z6Mk".to_string(),
            reason: "key not found".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("did:key:z6Mk"), "display: {s}");
        assert!(s.contains("key not found"), "display: {s}");
    }

    #[test]
    fn error_display_threshold_not_met() {
        let e = TirBaseError::ThresholdNotMet { got: 1, need: 3 };
        let s = e.to_string();
        assert!(s.contains('1') && s.contains('3'), "display: {s}");
    }

    #[test]
    fn error_display_schema_parse_error() {
        let e = TirBaseError::SchemaParseError {
            line: 5,
            col: 12,
            description: "unexpected token".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("5:12"), "display: {s}");
        assert!(s.contains("unexpected token"), "display: {s}");
    }

    #[test]
    fn error_display_invalid_incident_state() {
        let e = TirBaseError::InvalidIncidentState { got: IncidentState::Closed };
        let s = e.to_string();
        assert!(s.contains("OPEN"), "display: {s}");
        assert!(s.contains("Closed"), "display: {s}");
    }

    #[test]
    fn error_display_schema_registration_failed() {
        let e = TirBaseError::SchemaRegistrationFailed {
            reason: "version 1: hash mismatch".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("hash mismatch"), "display: {s}");
    }

    #[test]
    fn error_display_migration_in_progress() {
        let e = TirBaseError::MigrationInProgress {
            migration_id: "abc123".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("already in progress"), "display: {s}");
        assert!(s.contains("abc123"), "display: {s}");
    }

    #[test]
    fn error_display_migration_ca_signature_invalid() {
        let e = TirBaseError::MigrationCaSignatureInvalid {
            migration_id: "abc123".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("abc123"), "display: {s}");
    }

    #[test]
    fn error_display_unknown_migration_hash() {
        let e = TirBaseError::UnknownMigrationHash {
            migration_id: "deadbeef".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("deadbeef"), "display: {s}");
        assert!(s.contains("unknown"), "display: {s}");
    }

    #[test]
    fn error_display_cloud_queue_full() {
        let e = TirBaseError::CloudQueueFull { depth: 100_000 };
        let s = e.to_string();
        assert!(s.contains("100000"), "display: {s}");
    }

    #[test]
    fn error_display_spatial_diversity_degraded() {
        let e = TirBaseError::SpatialDiversityDegraded { available: 1, required: 3 };
        let s = e.to_string();
        assert!(s.contains("available=1"), "display: {s}");
        assert!(s.contains("required=3"), "display: {s}");
    }

    #[test]
    fn error_implements_std_error() {
        // Verify TirBaseError satisfies the std::error::Error bound.
        fn takes_error(_: &dyn std::error::Error) {}
        let e = TirBaseError::UnsupportedTaintSource;
        takes_error(&e);
    }
}
