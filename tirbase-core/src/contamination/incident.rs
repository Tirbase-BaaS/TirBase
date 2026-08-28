//! IncidentContextObject and CompositeIncidentInstance data models (Req 10).

#![allow(dead_code)]

use crate::crdt::delta::{Delta, DeltaId, Did};
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
