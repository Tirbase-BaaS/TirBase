//! IncidentContextObject and CompositeIncidentInstance data models (Req 10).

#![allow(dead_code)]

use crate::crdt::delta::{DeltaId, Did};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Unique identifier for an Incident Context Object.
pub type IncidentId = Uuid;

/// The state of an Incident Context Object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IncidentState {
    Open,
    Closed,
    /// Superseded by a CompositeIncidentInstance.
    SupersededBy(IncidentId),
    /// Decomposed back into independent ICOs after a root was resolved.
    Decomposed,
}

/// The taint source that opened an incident (Req 10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintSource {
    /// A Revocation_Delta was applied (Req 10.1 / Table row 1).
    DeviceRevocation { revocation_delta_id: DeltaId },
    /// A Migration_Revocation_Delta was applied (Req 10.1 / Table row 2).
    BadMigration { migration_id: [u8; 32] },
    /// A write was made while the local projection was CONTAMINATED or
    /// the incoming Delta stream was quarantined (Req 10.1 / Table row 3, 19.5).
    HumanReaction { triggered_by_incident_id: IncidentId },
}

/// An aggregated record grouping all Deltas and rows involved in a single
/// contamination incident (Req 10.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentContextObject {
    /// UUID v7 (Req 10.7).
    pub id: IncidentId,
    pub state: IncidentState,
    pub taint_source: TaintSource,
    /// The original Delta(s) that started this incident.
    pub contamination_roots: Vec<DeltaId>,
    /// All transitively descended Deltas (Req 10.2).
    pub contaminated_deltas: BTreeSet<DeltaId>,
    /// All rows in the Local Store derived from contaminated Deltas (Req 10.7).
    pub affected_rows: Vec<AffectedRow>,
    /// Set when two or more independent chains share a node (Req 10.5).
    pub composite_of: Option<Vec<IncidentId>>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Immutable audit log for VERIFY_DATA and ADMIN_CLOSE operations (Req 11.4).
    pub audit_log: Vec<AuditEntry>,
}

/// A row in the Local Store whose current value was derived from a contaminated Delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedRow {
    pub table: String,
    pub row_key: String,
    /// The most recent contaminated Delta that set this row.
    pub delta_id: DeltaId,
}

/// An immutable audit record appended on VERIFY_DATA or ADMIN_CLOSE (Req 11.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub operation: AuditOperation,
    pub manager_did: Did,
    /// UTC timestamp (microseconds).
    pub utc_timestamp: i64,
    /// Affected Delta IDs (or incident ID for AdminClose).
    pub affected_delta_ids: Vec<DeltaId>,
}

/// The operation type recorded in an audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperation {
    VerifyData,
    AdminClose,
}

/// A graph-joined incident formed when two or more independent contamination
/// chains share at least one Delta node in the Changeset DAG (Req 10.5).
///
/// When overlap is detected the original `IncidentContextObject`s are marked
/// `IncidentState::SupersededBy(composite_id)` and this record becomes the
/// single active incident for the merged chain.  If one root is later resolved
/// the composite is `IncidentState::Decomposed` and surviving sub-chains are
/// re-registered as fresh `IncidentContextObject`s (Req 10.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeIncidentInstance {
    /// UUID v7 — unique ID for this composite.
    pub id: IncidentId,
    pub state: IncidentState,
    /// IDs of the original `IncidentContextObject`s that were merged.
    pub composite_of: Vec<IncidentId>,
    /// Union of contamination roots from all merged chains.
    pub contamination_roots: Vec<DeltaId>,
    /// Union of all transitively reachable Deltas from every merged chain.
    pub contaminated_deltas: BTreeSet<DeltaId>,
    /// Union of all affected Local Store rows (deduplicated by row_key).
    pub affected_rows: Vec<AffectedRow>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Immutable audit log — same semantics as `IncidentContextObject::audit_log`.
    pub audit_log: Vec<AuditEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_audit_entry() -> AuditEntry {
        AuditEntry {
            operation: AuditOperation::VerifyData,
            manager_did: "did:key:z6MkTest".to_string(),
            utc_timestamp: 1_720_000_000_000_000,
            affected_delta_ids: vec![[0u8; 32]],
        }
    }

    fn make_affected_row() -> AffectedRow {
        AffectedRow {
            table: "reports".to_string(),
            row_key: "row-1".to_string(),
            delta_id: [1u8; 32],
        }
    }

    #[test]
    fn incident_context_object_serde_round_trip() {
        let ico = IncidentContextObject {
            id: Uuid::now_v7(),
            state: IncidentState::Open,
            taint_source: TaintSource::DeviceRevocation { revocation_delta_id: [0u8; 32] },
            contamination_roots: vec![[0u8; 32]],
            contaminated_deltas: BTreeSet::from([[0u8; 32], [1u8; 32]]),
            affected_rows: vec![make_affected_row()],
            composite_of: None,
            created_at: 1_720_000_000,
            updated_at: 1_720_000_001,
            audit_log: vec![make_audit_entry()],
        };

        let json = serde_json::to_string(&ico).expect("serialise ICO");
        let decoded: IncidentContextObject =
            serde_json::from_str(&json).expect("deserialise ICO");

        assert_eq!(ico.id, decoded.id);
        assert_eq!(ico.state, decoded.state);
        assert_eq!(ico.contaminated_deltas, decoded.contaminated_deltas);
        assert_eq!(ico.affected_rows, decoded.affected_rows);
    }

    #[test]
    fn composite_incident_instance_serde_round_trip() {
        let id_a = Uuid::now_v7();
        let id_b = Uuid::now_v7();
        let composite_id = Uuid::now_v7();

        let composite = CompositeIncidentInstance {
            id: composite_id,
            state: IncidentState::Open,
            composite_of: vec![id_a, id_b],
            contamination_roots: vec![[0u8; 32], [1u8; 32]],
            contaminated_deltas: BTreeSet::from([[0u8; 32], [1u8; 32], [2u8; 32]]),
            affected_rows: vec![make_affected_row()],
            created_at: 1_720_000_000,
            updated_at: 1_720_000_001,
            audit_log: vec![],
        };

        let json = serde_json::to_string(&composite).expect("serialise composite");
        let decoded: CompositeIncidentInstance =
            serde_json::from_str(&json).expect("deserialise composite");

        assert_eq!(composite.id, decoded.id);
        assert_eq!(composite.composite_of, decoded.composite_of);
        assert_eq!(composite.contaminated_deltas, decoded.contaminated_deltas);
    }

    #[test]
    fn incident_state_superseded_by_serde_round_trip() {
        let parent_id = Uuid::now_v7();
        let state = IncidentState::SupersededBy(parent_id);
        let json = serde_json::to_string(&state).unwrap();
        let decoded: IncidentState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn taint_source_variants_serde_round_trip() {
        let sources = vec![
            TaintSource::DeviceRevocation { revocation_delta_id: [7u8; 32] },
            TaintSource::BadMigration { migration_id: [9u8; 32] },
            TaintSource::HumanReaction { triggered_by_incident_id: Uuid::now_v7() },
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let decoded: TaintSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*src, decoded);
        }
    }

    #[test]
    fn audit_operation_serde_round_trip() {
        for op in [AuditOperation::VerifyData, AuditOperation::AdminClose] {
            let json = serde_json::to_string(&op).unwrap();
            let decoded: AuditOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(op, decoded);
        }
    }
}
