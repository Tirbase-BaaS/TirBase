// SPDX-License-Identifier: AGPL-3.0-only

//! Wire model shared by the backend and the Apache-2.0 console.

use serde::{Deserialize, Serialize};

/// Who is looking at or acting on the command center.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Front-line operator: observes, acknowledges, dispatches and escalates.
    Operator,
    /// Shift supervisor: full incident control, lockdown request/approval and drills.
    Supervisor,
    /// Safety officer: incident control, lockdown approval and audit.
    SafetyOfficer,
    /// Read-only auditor with access to the audit and reports.
    Auditor,
}

impl Role {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            Role::Operator => "operator",
            Role::Supervisor => "supervisor",
            Role::SafetyOfficer => "safety_officer",
            Role::Auditor => "auditor",
        }
    }

    /// Parse a role name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "operator" => Some(Role::Operator),
            "supervisor" => Some(Role::Supervisor),
            "safety_officer" | "safety" => Some(Role::SafetyOfficer),
            "auditor" => Some(Role::Auditor),
            _ => None,
        }
    }

    /// Every role, in display order.
    pub fn all() -> [Role; 4] {
        [
            Role::Operator,
            Role::Supervisor,
            Role::SafetyOfficer,
            Role::Auditor,
        ]
    }

    /// Whether this role holds `capability`.
    pub fn can(self, capability: Capability) -> bool {
        match capability {
            Capability::View => true,
            Capability::IncidentAcknowledge => matches!(
                self,
                Role::Operator | Role::Supervisor | Role::SafetyOfficer
            ),
            Capability::IncidentDispatch | Capability::IncidentEscalate => {
                matches!(
                    self,
                    Role::Operator | Role::Supervisor | Role::SafetyOfficer
                )
            }
            Capability::IncidentResolve | Capability::IncidentReport => {
                matches!(self, Role::Supervisor | Role::SafetyOfficer)
            }
            Capability::LockdownRequest | Capability::LockdownApprove => {
                matches!(self, Role::Supervisor | Role::SafetyOfficer)
            }
            Capability::DrillControl => matches!(self, Role::Supervisor | Role::SafetyOfficer),
            Capability::AuditView => true,
        }
    }

    /// Capability codes for the UI.
    pub fn capabilities(self) -> Vec<&'static str> {
        Capability::all()
            .iter()
            .copied()
            .filter(|capability| self.can(*capability))
            .map(Capability::code)
            .collect()
    }
}

/// One permission checked by the backend before a mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Read the state document.
    View,
    /// Acknowledge an incident.
    IncidentAcknowledge,
    /// Dispatch a response unit.
    IncidentDispatch,
    /// Escalate an incident.
    IncidentEscalate,
    /// Resolve an incident.
    IncidentResolve,
    /// Generate the after-action report.
    IncidentReport,
    /// Request a lockdown or release.
    LockdownRequest,
    /// Count as an approver.
    LockdownApprove,
    /// Start or end a drill.
    DrillControl,
    /// Read the audit trail.
    AuditView,
}

impl Capability {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            Capability::View => "view",
            Capability::IncidentAcknowledge => "incident.acknowledge",
            Capability::IncidentDispatch => "incident.dispatch",
            Capability::IncidentEscalate => "incident.escalate",
            Capability::IncidentResolve => "incident.resolve",
            Capability::IncidentReport => "incident.report",
            Capability::LockdownRequest => "lockdown.request",
            Capability::LockdownApprove => "lockdown.approve",
            Capability::DrillControl => "drill.control",
            Capability::AuditView => "audit.view",
        }
    }

    /// Every capability, in display order.
    pub fn all() -> [Capability; 10] {
        [
            Capability::View,
            Capability::IncidentAcknowledge,
            Capability::IncidentDispatch,
            Capability::IncidentEscalate,
            Capability::IncidentResolve,
            Capability::IncidentReport,
            Capability::LockdownRequest,
            Capability::LockdownApprove,
            Capability::DrillControl,
            Capability::AuditView,
        ]
    }
}

/// Live operations or a drill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Live venue state.
    Live,
    /// Isolated drill state.
    Drill,
}

impl Mode {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            Mode::Live => "live",
            Mode::Drill => "drill",
        }
    }
}

/// Incident lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Raised, not yet acknowledged.
    Open,
    /// An operator owns it.
    Acknowledged,
    /// A response unit is assigned.
    Dispatched,
    /// Raised to a higher level.
    Escalated,
    /// Closed with a resolution.
    Resolved,
    /// After-action report generated.
    Reported,
}

impl IncidentStatus {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            IncidentStatus::Open => "open",
            IncidentStatus::Acknowledged => "acknowledged",
            IncidentStatus::Dispatched => "dispatched",
            IncidentStatus::Escalated => "escalated",
            IncidentStatus::Resolved => "resolved",
            IncidentStatus::Reported => "reported",
        }
    }
}

/// Incident severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    /// Informational.
    Info,
    /// Needs attention.
    Warning,
    /// Immediate danger to operations.
    Critical,
}

impl IncidentSeverity {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            IncidentSeverity::Info => "info",
            IncidentSeverity::Warning => "warning",
            IncidentSeverity::Critical => "critical",
        }
    }
}

/// One workflow action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentActionKind {
    /// Take ownership.
    Acknowledge,
    /// Assign a response unit.
    Dispatch,
    /// Raise the incident.
    Escalate,
    /// Close with a resolution.
    Resolve,
    /// Generate the after-action report.
    Report,
}

impl IncidentActionKind {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            IncidentActionKind::Acknowledge => "acknowledge",
            IncidentActionKind::Dispatch => "dispatch",
            IncidentActionKind::Escalate => "escalate",
            IncidentActionKind::Resolve => "resolve",
            IncidentActionKind::Report => "report",
        }
    }

    /// Parse an action name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "acknowledge" => Some(IncidentActionKind::Acknowledge),
            "dispatch" => Some(IncidentActionKind::Dispatch),
            "escalate" => Some(IncidentActionKind::Escalate),
            "resolve" => Some(IncidentActionKind::Resolve),
            "report" => Some(IncidentActionKind::Report),
            _ => None,
        }
    }

    /// Permission required to perform the action.
    pub fn capability(self) -> Capability {
        match self {
            IncidentActionKind::Acknowledge => Capability::IncidentAcknowledge,
            IncidentActionKind::Dispatch => Capability::IncidentDispatch,
            IncidentActionKind::Escalate => Capability::IncidentEscalate,
            IncidentActionKind::Resolve => Capability::IncidentResolve,
            IncidentActionKind::Report => Capability::IncidentReport,
        }
    }
}

/// One attributable incident action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentAction {
    /// Action identifier.
    pub action_id: String,
    /// What was done.
    pub kind: IncidentActionKind,
    /// Who did it.
    pub actor: String,
    /// Their role at the time.
    pub role: Role,
    /// When.
    pub at_utc_us: i64,
    /// Operator note, unit or resolution.
    pub note: String,
    /// Status before.
    pub from_status: IncidentStatus,
    /// Status after.
    pub to_status: IncidentStatus,
}

/// An incident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    /// Incident identifier.
    pub id: String,
    /// Short title.
    pub title: String,
    /// Zone.
    pub zone_id: String,
    /// Gate, when lane-specific.
    pub gate_id: Option<String>,
    /// Severity.
    pub severity: IncidentSeverity,
    /// Current status.
    pub status: IncidentStatus,
    /// When it was raised.
    pub opened_utc_us: i64,
    /// When it last changed.
    pub updated_utc_us: i64,
    /// Every action, oldest first.
    pub actions: Vec<IncidentAction>,
}

/// One append-only audit row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence.
    pub seq: u64,
    /// When.
    pub at_utc_us: i64,
    /// Who.
    pub actor: String,
    /// Their role.
    pub role: Role,
    /// Action code.
    pub action: String,
    /// Incident, command or drill subject.
    pub subject: String,
    /// Secret-free detail.
    pub detail: String,
    /// Whether this happened in a drill.
    pub drill: bool,
}

/// An active lockdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownView {
    /// Request id.
    pub request_id: String,
    /// Scope label.
    pub scope: String,
    /// Reason.
    pub reason: String,
    /// Requester.
    pub requested_by: String,
    /// Approvers.
    pub approvers: Vec<String>,
    /// When it engaged.
    pub engaged_at_utc_us: i64,
    /// When it expires.
    pub expires_at_utc_us: i64,
}

/// One after-action report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AfterActionReport {
    /// Report id.
    pub report_id: String,
    /// Incident, if this is an incident report.
    pub incident_id: Option<String>,
    /// Whether the report came from a drill.
    pub drill: bool,
    /// When generated.
    pub generated_at_utc_us: i64,
    /// Who generated it.
    pub generated_by: String,
    /// Human summary.
    pub summary: String,
    /// Everyone who acted.
    pub participants: Vec<String>,
    /// Ordered timeline lines.
    pub timeline: Vec<String>,
    /// Drill only: live gate state was unchanged.
    pub live_gate_state_unchanged: bool,
}

/// One gate on the venue map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateView {
    /// Gate id.
    pub gate_id: String,
    /// Human name.
    pub name: String,
    /// People currently through this lane.
    pub occupancy: u32,
    /// `normal`, `locked` or `break_glass_open`.
    pub posture: String,
    /// Ingress currently possible.
    pub ingress_allowed: bool,
    /// Egress currently possible.
    pub egress_allowed: bool,
    /// Alarm state for this lane.
    pub alarm_state: String,
}

/// One zone on the venue map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneView {
    /// Zone id.
    pub zone_id: String,
    /// Human name.
    pub name: String,
    /// People in the zone.
    pub occupancy: u32,
    /// Soft limit.
    pub soft_limit: u32,
    /// Hard limit.
    pub hard_limit: u32,
    /// `normal`, `warning` or `critical`.
    pub alarm_state: String,
    /// Whether the zone is locked.
    pub locked: bool,
    /// Gates.
    pub gates: Vec<GateView>,
}

/// The venue map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapView {
    /// Venue id.
    pub venue_id: String,
    /// Venue name.
    pub name: String,
    /// Venue occupancy.
    pub occupancy: u32,
    /// Venue capacity.
    pub capacity: u32,
    /// Zones.
    pub zones: Vec<ZoneView>,
}

/// Role capabilities for the UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleView {
    /// Role.
    pub role: Role,
    /// Capability codes.
    pub capabilities: Vec<String>,
}

/// The complete state document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Live or drill.
    pub mode: Mode,
    /// When the drill started.
    pub drill_started_utc_us: Option<i64>,
    /// Venue map.
    pub venue: MapView,
    /// Incidents.
    pub incidents: Vec<Incident>,
    /// Active lockdowns.
    pub active_lockdowns: Vec<LockdownView>,
    /// Audit rows, newest last.
    pub audit: Vec<AuditEntry>,
    /// After-action reports.
    pub after_action_reports: Vec<AfterActionReport>,
    /// Capabilities of the requesting role.
    pub capabilities: Vec<String>,
    /// Actor the state was rendered for.
    pub actor: String,
    /// Requesting role.
    pub role: Role,
    /// Every role and its capabilities.
    pub roles: Vec<RoleView>,
}

/// Parse an incident action name, returning a typed error message.
pub fn parse_action(value: &str) -> Option<IncidentActionKind> {
    IncidentActionKind::parse(value)
}

/// Severity ordering helper for alarm state.
pub fn worse(left: &str, right: &str) -> String {
    let rank = |value: &str| match value {
        "critical" => 3,
        "warning" => 2,
        "info" => 1,
        _ => 0,
    };
    if rank(right) > rank(left) {
        right.to_string()
    } else {
        left.to_string()
    }
}
