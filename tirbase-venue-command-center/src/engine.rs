// SPDX-License-Identifier: AGPL-3.0-only

//! Command-center state, incident workflow and approved lockdown control.
//!
//! Live and drill states are separate [`TacticalState`] values. There is no
//! path from a drill mutation to the live state: incidents, audit rows, command
//! ids and the ST-08 [`tirbase_venue_lockdown::LockdownEngine`] all live inside
//! the selected state. Ending a drill records an after-action report and the
//! proof that the live gate fingerprint did not change.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, VenueId, ZoneId};
use tirbase_venue_capacity::{CapacityConfig, CapacityLimit, HardPolicy};
use tirbase_venue_lockdown::{
    ApprovalPolicy, CommandAction, CommandRequest, LockScope, LockdownEngine, LockdownError,
    SignedCommand,
};
use tirbase_venue_ticket::{Ed25519Signer, IssuerKey, IssuerKeyRing, IssuerKeyState, TicketSigner};

use crate::model::{
    worse, AfterActionReport, AuditEntry, Capability, GateView, Incident, IncidentAction,
    IncidentActionKind, IncidentSeverity, IncidentStatus, LockdownView, MapView, Mode, Role,
    RoleView, Snapshot, ZoneView,
};

/// Venue id used by the command center.
pub const VENUE_ID: &str = "venue-1";
/// Venue display name.
pub const VENUE_NAME: &str = "TirBase Arena";
/// Venue capacity.
pub const VENUE_CAPACITY: u32 = 1_800;
/// Command validity window, in microseconds.
pub const COMMAND_WINDOW_US: i64 = 3_600_000_000;
/// Maximum retained audit rows per state.
pub const MAX_AUDIT: usize = 2_000;
/// Number of recent audit rows returned in a snapshot.
pub const SNAPSHOT_AUDIT: usize = 250;

/// A lockdown or release request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockCommand {
    /// Engage a lockdown.
    Lockdown,
    /// Release a lockdown.
    Release,
}

impl LockCommand {
    /// Stable wire name.
    pub fn code(self) -> &'static str {
        match self {
            LockCommand::Lockdown => "lockdown",
            LockCommand::Release => "release",
        }
    }

    /// Parse a command name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "lockdown" => Some(LockCommand::Lockdown),
            "release" => Some(LockCommand::Release),
            _ => None,
        }
    }
}

/// Result of an accepted lockdown command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownOutcome {
    /// `executed` or `already_executed`.
    pub status: String,
    /// Request id.
    pub request_id: String,
    /// `lockdown` or `release`.
    pub command: String,
    /// Scope label.
    pub scope: String,
    /// Approvers.
    pub approvers: Vec<String>,
    /// Live or drill.
    pub mode: Mode,
}

/// Why a command-center operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandError {
    /// Stable machine code.
    pub code: &'static str,
    /// Operator-facing message.
    pub message: String,
}

impl CommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// HTTP status for this error.
    pub fn http_status(&self) -> u16 {
        match self.code {
            "forbidden" => 403,
            "actor_required" | "invalid_body" => 400,
            "not_found" => 404,
            "already_in_mode" | "not_in_drill" | "invalid_transition" | "not_locked" => 409,
            _ => 422,
        }
    }

    fn forbidden() -> Self {
        Self::new("forbidden", "this role may not perform that action")
    }

    fn actor_required() -> Self {
        Self::new("actor_required", "every action must name its actor")
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CommandError {}

fn engine_error(error: LockdownError) -> CommandError {
    CommandError::new("engine", error.to_string())
}

fn lock_error(error: LockdownError) -> CommandError {
    let code = lockdown_code(&error);
    CommandError::new(code, error.to_string())
}

fn lockdown_code(error: &LockdownError) -> &'static str {
    match error {
        LockdownError::InsufficientApprovals { .. } => "insufficient_approvals",
        LockdownError::DuplicateApprover { .. } => "duplicate_approver",
        LockdownError::SelfApproval { .. } => "self_approval",
        LockdownError::DuplicateSigner { .. } => "duplicate_signer",
        LockdownError::Expired { .. } => "expired",
        LockdownError::NotLocked { .. } => "not_locked",
        LockdownError::Signature { .. } => "signature",
        LockdownError::UnknownZone(_) => "unknown_zone",
        LockdownError::UnknownGate(_) => "unknown_gate",
        LockdownError::VenueMismatch { .. } => "venue_mismatch",
        _ => "command_refused",
    }
}

struct TacticalState {
    engine: LockdownEngine,
    occupancy: BTreeMap<ZoneId, u32>,
    gate_occupancy: BTreeMap<GateId, u32>,
    incidents: BTreeMap<String, Incident>,
    audit: Vec<AuditEntry>,
    action_seq: u64,
    audit_seq: u64,
    report_seq: u64,
    command_seq: u64,
    lockdown_commands: u32,
    after_action_reports: Vec<AfterActionReport>,
}

impl TacticalState {
    fn new(config: CapacityConfig, policy: ApprovalPolicy, now: i64) -> Result<Self, CommandError> {
        let engine = LockdownEngine::new(config, policy).map_err(engine_error)?;
        let mut occupancy = BTreeMap::new();
        occupancy.insert(zone("zone-north"), 640);
        occupancy.insert(zone("zone-south"), 210);
        let mut gate_occupancy = BTreeMap::new();
        gate_occupancy.insert(gate("gate-n1"), 420);
        gate_occupancy.insert(gate("gate-n2"), 220);
        gate_occupancy.insert(gate("gate-s1"), 210);

        let mut incidents = BTreeMap::new();
        incidents.insert(
            "inc-1".to_string(),
            Incident {
                id: "inc-1".to_string(),
                title: "Crowd surge at north turnstiles".to_string(),
                zone_id: "zone-north".to_string(),
                gate_id: Some("gate-n1".to_string()),
                severity: IncidentSeverity::Warning,
                status: IncidentStatus::Open,
                opened_utc_us: now - 60_000_000,
                updated_utc_us: now - 60_000_000,
                actions: Vec::new(),
            },
        );
        let action = IncidentAction {
            action_id: "act-1".to_string(),
            kind: IncidentActionKind::Acknowledge,
            actor: "ops-1".to_string(),
            role: Role::Operator,
            at_utc_us: now - 120_000_000,
            note: "Reader power-cycled; monitoring the lane.".to_string(),
            from_status: IncidentStatus::Open,
            to_status: IncidentStatus::Acknowledged,
        };
        incidents.insert(
            "inc-2".to_string(),
            Incident {
                id: "inc-2".to_string(),
                title: "Gate S1 reader offline".to_string(),
                zone_id: "zone-south".to_string(),
                gate_id: Some("gate-s1".to_string()),
                severity: IncidentSeverity::Info,
                status: IncidentStatus::Acknowledged,
                opened_utc_us: now - 180_000_000,
                updated_utc_us: now - 120_000_000,
                actions: vec![action.clone()],
            },
        );

        let audit = vec![AuditEntry {
            seq: 1,
            at_utc_us: action.at_utc_us,
            actor: action.actor.clone(),
            role: action.role,
            action: "incident.acknowledge".to_string(),
            subject: "inc-2".to_string(),
            detail: action.note.clone(),
            drill: false,
        }];

        Ok(Self {
            engine,
            occupancy,
            gate_occupancy,
            incidents,
            audit,
            action_seq: 1,
            audit_seq: 1,
            report_seq: 0,
            command_seq: 0,
            lockdown_commands: 0,
            after_action_reports: Vec::new(),
        })
    }

    fn fork(&self, config: CapacityConfig, policy: ApprovalPolicy) -> Result<Self, CommandError> {
        let mut state = Self::new(config, policy, 0)?;
        state.occupancy = self.occupancy.clone();
        state.gate_occupancy = self.gate_occupancy.clone();
        state.incidents = self.incidents.clone();
        state.action_seq = self.action_seq;
        state.command_seq = self.command_seq;
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_push(
        &mut self,
        now: i64,
        actor: &str,
        role: Role,
        action: &str,
        subject: &str,
        detail: impl Into<String>,
        drill: bool,
    ) {
        self.audit_seq += 1;
        self.audit.push(AuditEntry {
            seq: self.audit_seq,
            at_utc_us: now,
            actor: actor.to_string(),
            role,
            action: action.to_string(),
            subject: subject.to_string(),
            detail: detail.into(),
            drill,
        });
        if self.audit.len() > MAX_AUDIT {
            let excess = self.audit.len() - MAX_AUDIT;
            self.audit.drain(0..excess);
        }
    }

    fn fingerprint(&self, now: i64) -> String {
        let mut out = String::new();
        for gate in [gate("gate-n1"), gate("gate-n2"), gate("gate-s1")] {
            out.push_str(gate.as_str());
            out.push('=');
            out.push_str(self.engine.gate_posture(&gate, now).code());
            out.push(';');
        }
        out
    }

    fn participants(&self) -> Vec<String> {
        self.audit
            .iter()
            .map(|entry| entry.actor.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// The command center.
pub struct CommandCenter {
    venue_id: VenueId,
    config: CapacityConfig,
    policy: ApprovalPolicy,
    ring: IssuerKeyRing,
    live: TacticalState,
    drill: Option<TacticalState>,
    mode: Mode,
    drill_started_utc_us: Option<i64>,
    drill_baseline: Option<String>,
}

impl CommandCenter {
    /// Build a command center with live venue state at `now_utc_us`.
    pub fn new(now_utc_us: i64) -> Result<Self, CommandError> {
        let venue_id = VenueId::new(VENUE_ID).expect("literal venue id");
        let config = venue_config(venue_id.clone());
        let policy = ApprovalPolicy::new(2, 2, 2, 2).map_err(engine_error)?;
        let ring = issuer_ring(now_utc_us);
        let live = TacticalState::new(config.clone(), policy, now_utc_us)?;
        Ok(Self {
            venue_id,
            config,
            policy,
            ring,
            live,
            drill: None,
            mode: Mode::Live,
            drill_started_utc_us: None,
            drill_baseline: None,
        })
    }

    /// Current mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    fn state(&self) -> &TacticalState {
        match self.mode {
            Mode::Live => &self.live,
            Mode::Drill => self.drill.as_ref().expect("drill mode has drill state"),
        }
    }

    fn state_mut(&mut self) -> &mut TacticalState {
        match self.mode {
            Mode::Live => &mut self.live,
            Mode::Drill => self.drill.as_mut().expect("drill mode has drill state"),
        }
    }

    /// The state document for `actor` with `role`.
    pub fn snapshot(&self, actor: &str, role: Role, now_utc_us: i64) -> Snapshot {
        let state = self.state();
        let mut zones = Vec::new();
        for (zone_id, name, gates) in zone_spec() {
            let zone = zone(zone_id);
            let mut gate_views = Vec::new();
            for gate_id in gates {
                let gate = gate(gate_id);
                let posture = state.engine.gate_posture(&gate, now_utc_us);
                gate_views.push(GateView {
                    gate_id: gate_id.to_string(),
                    name: match gate_id {
                        "gate-n1" => "North 1",
                        "gate-n2" => "North 2",
                        _ => "South 1",
                    }
                    .to_string(),
                    occupancy: state.gate_occupancy.get(&gate).copied().unwrap_or(0),
                    posture: posture.code().to_string(),
                    ingress_allowed: state.engine.ingress_allowed(&gate, now_utc_us),
                    egress_allowed: state.engine.egress_allowed(),
                    alarm_state: alarm_state(&state.incidents, zone_id, Some(gate_id)),
                });
            }
            zones.push(ZoneView {
                zone_id: zone_id.to_string(),
                name: name.to_string(),
                occupancy: state.occupancy.get(&zone).copied().unwrap_or(0),
                soft_limit: 800,
                hard_limit: 1_000,
                alarm_state: alarm_state(&state.incidents, zone_id, None),
                locked: gate_views.iter().any(|gate| gate.posture == "locked"),
                gates: gate_views,
            });
        }
        let venue_occupancy = state.occupancy.values().sum();
        let active_lockdowns = state
            .engine
            .active_lockdowns(now_utc_us)
            .into_iter()
            .map(|lock| LockdownView {
                request_id: lock.request_id.clone(),
                scope: lock.scope.label(),
                reason: lock.reason.clone(),
                requested_by: lock.requested_by.clone(),
                approvers: lock.approvers.clone(),
                engaged_at_utc_us: lock.engaged_at_utc_us,
                expires_at_utc_us: lock.expires_at_utc_us,
            })
            .collect();
        let skip = state.audit.len().saturating_sub(SNAPSHOT_AUDIT);
        Snapshot {
            mode: self.mode,
            drill_started_utc_us: self.drill_started_utc_us,
            venue: MapView {
                venue_id: self.venue_id.as_str().to_string(),
                name: VENUE_NAME.to_string(),
                occupancy: venue_occupancy,
                capacity: VENUE_CAPACITY,
                zones,
            },
            incidents: state.incidents.values().cloned().collect(),
            active_lockdowns,
            audit: state.audit[skip..].to_vec(),
            after_action_reports: state.after_action_reports.clone(),
            capabilities: role
                .capabilities()
                .into_iter()
                .map(str::to_string)
                .collect(),
            actor: actor.to_string(),
            role,
            roles: Role::all()
                .into_iter()
                .map(|candidate| RoleView {
                    role: candidate,
                    capabilities: candidate
                        .capabilities()
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                })
                .collect(),
        }
    }

    /// Perform one incident workflow action.
    #[allow(clippy::too_many_arguments)]
    pub fn incident_action(
        &mut self,
        actor: &str,
        role: Role,
        incident_id: &str,
        kind: IncidentActionKind,
        note: Option<&str>,
        now_utc_us: i64,
    ) -> Result<Incident, CommandError> {
        let actor = actor.trim();
        if actor.is_empty() {
            return Err(CommandError::actor_required());
        }
        if !role.can(kind.capability()) {
            return Err(CommandError::forbidden());
        }
        let note = note.unwrap_or("").trim();
        if matches!(
            kind,
            IncidentActionKind::Escalate | IncidentActionKind::Resolve
        ) && note.is_empty()
        {
            return Err(CommandError::new(
                "note_required",
                "escalation and resolution require an attributable note",
            ));
        }
        let drill = self.mode == Mode::Drill;
        let state = self.state_mut();
        state.action_seq += 1;
        let action_id = format!("act-{}", state.action_seq);
        let (from_status, to_status, note_text) = {
            let incident = state
                .incidents
                .get_mut(incident_id)
                .ok_or_else(|| CommandError::new("not_found", "unknown incident"))?;
            let from_status = incident.status;
            let to_status = transition(from_status, kind).ok_or_else(|| {
                CommandError::new(
                    "invalid_transition",
                    format!(
                        "{} cannot {} an incident in status {}",
                        role.code(),
                        kind.code(),
                        from_status.code()
                    ),
                )
            })?;
            let note_text = match (kind, note.is_empty()) {
                (IncidentActionKind::Dispatch, true) => "Response unit dispatched.".to_string(),
                (IncidentActionKind::Report, true) => "After-action report generated.".to_string(),
                (_, true) => String::new(),
                (_, false) => note.to_string(),
            };
            let action = IncidentAction {
                action_id: action_id.clone(),
                kind,
                actor: actor.to_string(),
                role,
                at_utc_us: now_utc_us,
                note: note_text.clone(),
                from_status,
                to_status,
            };
            incident.actions.push(action);
            incident.status = to_status;
            incident.updated_utc_us = now_utc_us;
            (from_status, to_status, note_text)
        };
        state.audit_push(
            now_utc_us,
            actor,
            role,
            &format!("incident.{}", kind.code()),
            incident_id,
            format!(
                "{} -> {}: {}",
                from_status.code(),
                to_status.code(),
                note_text
            ),
            drill,
        );
        if kind == IncidentActionKind::Report {
            state.report_seq += 1;
            let incident = state
                .incidents
                .get(incident_id)
                .expect("incident exists after report");
            let report = AfterActionReport {
                report_id: format!("aar-{}-{}", incident_id, state.report_seq),
                incident_id: Some(incident_id.to_string()),
                drill,
                generated_at_utc_us: now_utc_us,
                generated_by: actor.to_string(),
                summary: format!(
                    "{} — {} after {} action(s).",
                    incident.title,
                    incident.status.code(),
                    incident.actions.len()
                ),
                participants: incident
                    .actions
                    .iter()
                    .map(|action| action.actor.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                timeline: incident
                    .actions
                    .iter()
                    .map(|action| {
                        format!(
                            "{} {} ({}) — {}: {}",
                            action.at_utc_us,
                            action.actor,
                            action.role.code(),
                            action.kind.code(),
                            action.note
                        )
                    })
                    .collect(),
                live_gate_state_unchanged: true,
            };
            state.after_action_reports.push(report);
        }
        Ok(state
            .incidents
            .get(incident_id)
            .expect("incident exists")
            .clone())
    }

    /// Engage or release a lockdown with M-of-N approvals.
    #[allow(clippy::too_many_arguments)]
    pub fn lockdown(
        &mut self,
        actor: &str,
        role: Role,
        command: LockCommand,
        scope: &str,
        reason: &str,
        approvers: &[String],
        now_utc_us: i64,
    ) -> Result<LockdownOutcome, CommandError> {
        let actor = actor.trim();
        if actor.is_empty() {
            return Err(CommandError::actor_required());
        }
        if !role.can(Capability::LockdownRequest) {
            return Err(CommandError::forbidden());
        }
        if reason.trim().is_empty() || reason.len() > 512 {
            return Err(CommandError::new(
                "reason_required",
                "a lockdown or release needs a reason of at most 512 bytes",
            ));
        }
        let required = match command {
            LockCommand::Lockdown => self.policy.lockdown,
            LockCommand::Release => self.policy.release,
        } as usize;
        if approvers.len() < required {
            return Err(CommandError::new(
                "insufficient_approvals",
                format!(
                    "{} requires {required} approvals, {} provided",
                    command.code(),
                    approvers.len()
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for approver in approvers {
            if approver.trim().is_empty() {
                return Err(CommandError::new(
                    "unknown_approver",
                    "an approver must name a known supervisor or safety officer",
                ));
            }
            if approver.trim() == actor {
                return Err(CommandError::new(
                    "self_approval",
                    "the requester cannot approve their own command",
                ));
            }
            let approver_role = approver_role(approver).ok_or_else(|| {
                CommandError::new(
                    "unknown_approver",
                    format!("{approver:?} is not a known approver"),
                )
            })?;
            if !approver_role.can(Capability::LockdownApprove) {
                return Err(CommandError::new(
                    "unknown_approver",
                    format!("{approver:?} may not approve a lockdown"),
                ));
            }
            if !seen.insert(approver.trim().to_string()) {
                return Err(CommandError::new(
                    "duplicate_approver",
                    "each approver may sign only once",
                ));
            }
        }
        let lock_scope = self.parse_scope(scope)?;
        let action = match command {
            LockCommand::Lockdown => CommandAction::Lockdown {
                scope: lock_scope.clone(),
            },
            LockCommand::Release => CommandAction::ReleaseLockdown {
                scope: lock_scope.clone(),
            },
        };
        self.state_mut().command_seq += 1;
        let request_id = format!("cmd-{}", self.state().command_seq);
        let request = CommandRequest::new(
            request_id.clone(),
            action,
            reason.trim(),
            actor,
            now_utc_us,
            now_utc_us + COMMAND_WINDOW_US,
            required as u32,
        )
        .map_err(engine_error)?;
        let signers: Vec<(String, Ed25519Signer)> = approvers
            .iter()
            .map(|approver| {
                (
                    approver.trim().to_string(),
                    custodian_signer(approver.trim()).expect("known approver"),
                )
            })
            .collect();
        let pairs: Vec<(&str, &dyn TicketSigner)> = signers
            .iter()
            .map(|(name, signer)| (name.as_str(), signer as &dyn TicketSigner))
            .collect();
        let signed = SignedCommand::sign(request, &pairs, now_utc_us).map_err(lock_error)?;
        let ring = self.ring.clone();
        let drill = self.mode == Mode::Drill;
        let state = self.state_mut();
        let outcome = state
            .engine
            .execute(&signed, &ring, now_utc_us)
            .map_err(lock_error)?;
        let status = outcome.code().to_string();
        if outcome.is_executed() {
            state.lockdown_commands += 1;
        }
        state.audit_push(
            now_utc_us,
            actor,
            role,
            match command {
                LockCommand::Lockdown => "lockdown.engaged",
                LockCommand::Release => "lockdown.released",
            },
            &lock_scope.label(),
            format!(
                "{} by {} with approvals {}: {}",
                command.code(),
                actor,
                approvers.join(", "),
                reason.trim()
            ),
            drill,
        );
        Ok(LockdownOutcome {
            status,
            request_id,
            command: command.code().to_string(),
            scope: lock_scope.label(),
            approvers: approvers.to_vec(),
            mode: self.mode,
        })
    }

    /// Start an isolated drill. Refused while a drill is already running.
    pub fn start_drill(
        &mut self,
        actor: &str,
        role: Role,
        now_utc_us: i64,
    ) -> Result<Snapshot, CommandError> {
        let actor = actor.trim();
        if actor.is_empty() {
            return Err(CommandError::actor_required());
        }
        if !role.can(Capability::DrillControl) {
            return Err(CommandError::forbidden());
        }
        if self.mode == Mode::Drill {
            return Err(CommandError::new(
                "already_in_mode",
                "a drill is already running",
            ));
        }
        let baseline = self.live.fingerprint(now_utc_us);
        let mut drill = self.live.fork(self.config.clone(), self.policy)?;
        drill.audit_push(
            now_utc_us,
            actor,
            role,
            "drill.started",
            "drill",
            "isolated drill state created; live gates untouched",
            true,
        );
        self.drill = Some(drill);
        self.mode = Mode::Drill;
        self.drill_started_utc_us = Some(now_utc_us);
        self.drill_baseline = Some(baseline);
        Ok(self.snapshot(actor, role, now_utc_us))
    }

    /// End the drill and return its after-action report.
    pub fn end_drill(
        &mut self,
        actor: &str,
        role: Role,
        now_utc_us: i64,
    ) -> Result<AfterActionReport, CommandError> {
        let actor = actor.trim();
        if actor.is_empty() {
            return Err(CommandError::actor_required());
        }
        if !role.can(Capability::DrillControl) {
            return Err(CommandError::forbidden());
        }
        if self.mode != Mode::Drill {
            return Err(CommandError::new("not_in_drill", "no drill is running"));
        }
        let mut drill = self.drill.take().expect("drill mode has drill state");
        drill.audit_push(
            now_utc_us,
            actor,
            role,
            "drill.ended",
            "drill",
            "drill state closed",
            true,
        );
        let unchanged = self
            .drill_baseline
            .as_deref()
            .map(|baseline| baseline == self.live.fingerprint(now_utc_us))
            .unwrap_or(false);
        self.live.report_seq += 1;
        let report = AfterActionReport {
            report_id: format!("aar-drill-{}", self.live.report_seq),
            incident_id: None,
            drill: true,
            generated_at_utc_us: now_utc_us,
            generated_by: actor.to_string(),
            summary: format!(
                "Drill completed: {} incident(s), {} audit action(s), {} lockdown command(s); live gate state {}.",
                drill.incidents.len(),
                drill.audit.len(),
                drill.lockdown_commands,
                if unchanged { "unchanged" } else { "CHANGED" }
            ),
            participants: drill.participants(),
            timeline: drill
                .audit
                .iter()
                .map(|entry| {
                    format!(
                        "{} {} ({}) — {}: {}",
                        entry.at_utc_us,
                        entry.actor,
                        entry.role.code(),
                        entry.action,
                        entry.detail
                    )
                })
                .collect(),
            live_gate_state_unchanged: unchanged,
        };
        self.live.audit_push(
            now_utc_us,
            actor,
            role,
            "drill.report",
            &report.report_id,
            format!("drill after-action report: {}", report.summary),
            false,
        );
        self.live.after_action_reports.push(report.clone());
        self.mode = Mode::Live;
        self.drill_started_utc_us = None;
        self.drill_baseline = None;
        Ok(report)
    }

    fn parse_scope(&self, scope: &str) -> Result<LockScope, CommandError> {
        if scope.trim() == "venue" {
            return Ok(LockScope::Venue {
                venue_id: self.venue_id.clone(),
            });
        }
        if let Some(zone_id) = scope.trim().strip_prefix("zone:") {
            let zone: ZoneId = zone_id
                .parse()
                .map_err(|error| CommandError::new("invalid_scope", format!("{error}")))?;
            if !matches!(zone.as_str(), "zone-north" | "zone-south") {
                return Err(CommandError::new("unknown_zone", "unknown zone"));
            }
            return Ok(LockScope::Zone { zone_id: zone });
        }
        Err(CommandError::new(
            "invalid_scope",
            "scope must be `venue` or `zone:<id>`",
        ))
    }

    /// Live state is never mutated by a drill; exposed for the drill report test.
    pub fn live_fingerprint(&self, now_utc_us: i64) -> String {
        self.live.fingerprint(now_utc_us)
    }
}

fn transition(from: IncidentStatus, kind: IncidentActionKind) -> Option<IncidentStatus> {
    use IncidentActionKind as Action;
    use IncidentStatus as Status;
    match kind {
        Action::Acknowledge if from == Status::Open => Some(Status::Acknowledged),
        Action::Dispatch if matches!(from, Status::Open | Status::Acknowledged) => {
            Some(Status::Dispatched)
        }
        Action::Escalate
            if matches!(
                from,
                Status::Open | Status::Acknowledged | Status::Dispatched
            ) =>
        {
            Some(Status::Escalated)
        }
        Action::Resolve
            if matches!(
                from,
                Status::Acknowledged | Status::Dispatched | Status::Escalated
            ) =>
        {
            Some(Status::Resolved)
        }
        Action::Report if from == Status::Resolved => Some(Status::Reported),
        _ => None,
    }
}

fn venue_config(venue_id: VenueId) -> CapacityConfig {
    let limit = |soft, hard| {
        CapacityLimit::new(soft, hard, HardPolicy::Reject).expect("valid venue limits")
    };
    let mut config = CapacityConfig::new(venue_id, limit(1_500, VENUE_CAPACITY));
    config = config.with_zone(
        zone("zone-north"),
        limit(800, 1_000),
        vec![gate("gate-n1"), gate("gate-n2")],
    );
    config = config.with_zone(zone("zone-south"), limit(300, 400), vec![gate("gate-s1")]);
    config
        .with_gate_limit(gate("gate-n1"), limit(500, 600))
        .with_gate_limit(gate("gate-n2"), limit(300, 400))
        .with_gate_limit(gate("gate-s1"), limit(300, 400))
}

fn issuer_ring(now_utc_us: i64) -> IssuerKeyRing {
    let mut ring = IssuerKeyRing::new();
    for (index, name) in ["custodian-1", "custodian-2", "custodian-3"]
        .iter()
        .enumerate()
    {
        let signer = custodian_signer(name).expect("known custodian");
        ring.add_key(IssuerKey {
            key_id: (*name).to_string(),
            public_key: signer.public_key(),
            not_before_utc_us: now_utc_us - 86_400_000_000,
            not_after_utc_us: now_utc_us + 365 * 86_400_000_000,
            state: if index == 0 {
                IssuerKeyState::Active
            } else {
                IssuerKeyState::Retiring
            },
        })
        .expect("deterministic command key");
    }
    ring
}

fn custodian_signer(name: &str) -> Option<Ed25519Signer> {
    let seed = match name {
        "custodian-1" => 41u8,
        "custodian-2" => 42u8,
        "custodian-3" => 43u8,
        _ => return None,
    };
    Some(Ed25519Signer::from_seed(name, [seed; 32]))
}

fn approver_role(name: &str) -> Option<Role> {
    match name {
        "custodian-1" | "custodian-3" => Some(Role::Supervisor),
        "custodian-2" => Some(Role::SafetyOfficer),
        _ => None,
    }
}

fn zone_spec() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("zone-north", "North concourse", vec!["gate-n1", "gate-n2"]),
        ("zone-south", "South concourse", vec!["gate-s1"]),
    ]
}

fn zone(value: &str) -> ZoneId {
    value.parse().expect("literal zone id")
}

fn gate(value: &str) -> GateId {
    value.parse().expect("literal gate id")
}

fn alarm_state(
    incidents: &BTreeMap<String, Incident>,
    zone_id: &str,
    gate_id: Option<&str>,
) -> String {
    let mut state = "normal".to_string();
    for incident in incidents.values() {
        if matches!(
            incident.status,
            IncidentStatus::Resolved | IncidentStatus::Reported
        ) {
            continue;
        }
        if incident.zone_id != zone_id {
            continue;
        }
        if let Some(gate_id) = gate_id {
            if incident.gate_id.as_deref() != Some(gate_id) {
                continue;
            }
        }
        state = worse(&state, incident.severity.code());
    }
    state
}
