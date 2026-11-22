// SPDX-License-Identifier: AGPL-3.0-only

//! The scenario interpreter.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, TicketId, VenueId, ZoneId};
use tirbase_venue_admission::{
    DeltaPolicy, EpochPolicy, GateAdmission, GateDecision, GateReplayGuard, RevocationDelta,
    SignedRevocationDelta, StalePolicy, SubmitOutcome,
};
use tirbase_venue_capacity::{
    Alarm, CapacityConfig, CapacityEngine, CapacityLimit, Decision, Direction, EventSource,
    HardPolicy, LimitScope, Observation as CapacityObservation, ObservationKind, OverrideGrant,
    PresenceEvent,
};
use tirbase_venue_gate::{FailMode, GateSim};
use tirbase_venue_lockdown::{
    ApprovalPolicy, CommandAction, CommandRequest, LockScope, LockdownEngine, LockdownError,
    SignedCommand,
};
use tirbase_venue_scenarios::{
    FailModeSpec, HardPolicySpec, InitialState, LimitSpec, Scenario, StalePolicySpec,
    TicketSpec, TimelineStep,
};
use tirbase_venue_ticket::{
    Ed25519Signer, EventId, IssuerKey, IssuerKeyRing, IssuerKeyState, SignedTicket, TicketPayload,
    TicketSigner, VenueScope,
};

const ROUTINE_APPROVER: &str = "duty-manager";
const EVENT_ID: &str = "event-1";

/// One observed step outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepObservation {
    pub index: usize,
    pub action: String,
    pub at_offset_us: i64,
    pub result: String,
    pub reason: Option<String>,
}

/// The observed invariant result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantObservation {
    pub id: String,
    pub statement: String,
    pub passed: bool,
    pub detail: String,
}

/// The observed final state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalState {
    pub venue_occupancy: u32,
    pub zone_occupancy: BTreeMap<String, u32>,
    pub revocation_version: u64,
    pub revoked_tickets: Vec<String>,
    pub lockdowns: Vec<String>,
    pub gate_postures: BTreeMap<String, String>,
    pub security_events: Vec<String>,
    pub capacity_audit_events: Vec<String>,
    pub revocation_alarm: Option<String>,
    pub gate_positions: BTreeMap<String, String>,
}

/// A complete, deterministic run record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub scenario_id: String,
    pub invariant: InvariantObservation,
    pub steps: Vec<StepObservation>,
    pub final_state: FinalState,
}

/// Why a run failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunError {
    /// The scenario is structurally invalid or names an unknown reference.
    Invalid(String),
    /// An engine refused an operation the scenario needed.
    Engine(String),
    /// A step's observed outcome differs from the scenario expectation.
    StepMismatch {
        index: usize,
        expected: String,
        observed: String,
    },
    /// The final state differs from the scenario expectation.
    FinalMismatch {
        field: String,
        expected: String,
        observed: String,
    },
    /// The scenario's safety invariant does not hold over the observed trace.
    InvariantFailed { id: String, detail: String },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Invalid(reason) => write!(f, "invalid scenario: {reason}"),
            RunError::Engine(reason) => write!(f, "engine error: {reason}"),
            RunError::StepMismatch {
                index,
                expected,
                observed,
            } => write!(f, "step {index}: expected {expected}, observed {observed}"),
            RunError::FinalMismatch {
                field,
                expected,
                observed,
            } => write!(f, "final {field}: expected {expected}, observed {observed}"),
            RunError::InvariantFailed { id, detail } => {
                write!(f, "invariant {id} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for RunError {}

/// Run one scenario end to end.
pub fn run_scenario(scenario: &Scenario) -> Result<Observation, RunError> {
    scenario.validate().map_err(RunError::Invalid)?;
    let mut runner = Runner::new(scenario)?;
    runner.run()?;
    runner.finish()
}

#[derive(Clone, Debug)]
struct CapacityCheck {
    gate_id: String,
    gate_occupancy: u32,
    gate_hard: u32,
    gate_override: bool,
    zone_id: String,
    zone_occupancy: u32,
    zone_hard: u32,
    zone_override: bool,
    venue_occupancy: u32,
    venue_hard: u32,
    venue_override: bool,
}

impl CapacityCheck {
    fn violation(&self) -> Option<String> {
        if self.gate_occupancy > self.gate_hard && !self.gate_override {
            return Some(format!(
                "gate {} reached {} over hard {} without an override",
                self.gate_id, self.gate_occupancy, self.gate_hard
            ));
        }
        if self.zone_occupancy > self.zone_hard && !self.zone_override {
            return Some(format!(
                "zone {} reached {} over hard {} without an override",
                self.zone_id, self.zone_occupancy, self.zone_hard
            ));
        }
        if self.venue_occupancy > self.venue_hard && !self.venue_override {
            return Some(format!(
                "venue reached {} over hard {} without an override",
                self.venue_occupancy, self.venue_hard
            ));
        }
        None
    }
}

#[derive(Clone, Debug)]
struct AdoptionCheck {
    actor: String,
    reason: String,
    audited: bool,
    alarm: bool,
}

#[derive(Clone, Debug)]
struct StaleCheck {
    stale: bool,
    result: String,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
struct CommandUse {
    kind: &'static str,
    request_id: String,
    approvals: u32,
    threshold: u32,
}

#[derive(Clone, Debug)]
struct PowerCheck {
    gate_id: String,
    position: String,
    expected: String,
    egress: bool,
}

struct Runner<'a> {
    scenario: &'a Scenario,
    base_utc_us: i64,
    venue_id: VenueId,
    config: CapacityConfig,
    capacity: CapacityEngine,
    admission: GateAdmission,
    lockdown: LockdownEngine,
    gate_sims: BTreeMap<GateId, GateSim>,
    gate_modes: BTreeMap<GateId, FailMode>,
    approval_ring: IssuerKeyRing,
    ticket_ring: IssuerKeyRing,
    delta_policy: DeltaPolicy,
    approval_policy: ApprovalPolicy,
    ticket_specs: BTreeMap<String, TicketSpec>,
    signed_commands: BTreeMap<String, SignedCommand>,
    observations: Vec<StepObservation>,
    admissions: BTreeMap<String, u32>,
    capacity_checks: Vec<CapacityCheck>,
    adoptions: Vec<AdoptionCheck>,
    stale_checks: Vec<StaleCheck>,
    command_uses: Vec<CommandUse>,
    reuse_attempts: Vec<bool>,
    power_checks: Vec<PowerCheck>,
}

impl<'a> Runner<'a> {
    fn new(scenario: &'a Scenario) -> Result<Self, RunError> {
        let initial = &scenario.initial;
        let venue_id: VenueId = parse(&initial.venue_id)?;
        let config = build_config(initial)?;
        let stale_policy = match initial.stale_policy {
            StalePolicySpec::FailClosed => StalePolicy::FailClosed,
            StalePolicySpec::Alarm => StalePolicy::Alarm,
        };
        let approval_policy = ApprovalPolicy::new(
            initial.approval_policy.lockdown,
            initial.approval_policy.release,
            initial.approval_policy.capacity_override,
            initial.approval_policy.emergency_gate_open,
        )
        .map_err(|error| RunError::Invalid(error.to_string()))?;

        let mut gate_sims = BTreeMap::new();
        let mut gate_modes = BTreeMap::new();
        for gate in &initial.gates {
            let gate_id: GateId = parse(&gate.gate_id)?;
            let mode = match gate.fail_mode {
                FailModeSpec::FailSafe => FailMode::FailSafe,
                FailModeSpec::FailSecure => FailMode::FailSecure,
            };
            gate_modes.insert(gate_id.clone(), mode);
            gate_sims.insert(gate_id, GateSim::new(mode));
        }

        let ticket_ring = {
            let signer = ticket_signer();
            let mut ring = IssuerKeyRing::new();
            ring.add_public_key(
                signer.key_id(),
                signer.public_key(),
                initial.base_utc_us - 86_400_000_000,
                initial.base_utc_us + 365 * 86_400_000_000,
            )
            .map_err(|error| RunError::Engine(error.to_string()))?;
            ring
        };
        let approval_ring = approval_ring(initial.base_utc_us);

        let guard = GateReplayGuard::new(EpochPolicy::default(), 4_096)
            .map_err(|error| RunError::Engine(error.to_string()))?;
        let mut admission = GateAdmission::new(guard, stale_policy);
        let baseline = RevocationDelta::new(
            0,
            1,
            initial.base_utc_us,
            initial.base_utc_us + initial.revocation_valid_for_us,
            Vec::new(),
            Vec::new(),
        )
        .map_err(|error| RunError::Engine(error.to_string()))?;
        let custodian_one = custodian(1);
        let baseline = SignedRevocationDelta::sign(
            baseline,
            &[&custodian_one as &dyn TicketSigner],
        )
        .map_err(|error| RunError::Engine(error.to_string()))?;
        admission
            .apply_delta(
                &baseline,
                &approval_ring,
                &DeltaPolicy::standard(),
                initial.base_utc_us,
            )
            .map_err(|error| RunError::Engine(error.to_string()))?;

        let capacity = CapacityEngine::new(config.clone())
            .map_err(|error| RunError::Engine(error.to_string()))?;
        let lockdown = LockdownEngine::new(config.clone(), approval_policy)
            .map_err(|error| RunError::Engine(error.to_string()))?;

        let ticket_specs = initial
            .tickets
            .iter()
            .map(|ticket| (ticket.ticket_id.clone(), ticket.clone()))
            .collect();

        Ok(Self {
            scenario,
            base_utc_us: initial.base_utc_us,
            venue_id,
            config,
            capacity,
            admission,
            lockdown,
            gate_sims,
            gate_modes,
            approval_ring,
            ticket_ring,
            delta_policy: DeltaPolicy::standard(),
            approval_policy,
            ticket_specs,
            signed_commands: BTreeMap::new(),
            observations: Vec::new(),
            admissions: BTreeMap::new(),
            capacity_checks: Vec::new(),
            adoptions: Vec::new(),
            stale_checks: Vec::new(),
            command_uses: Vec::new(),
            reuse_attempts: Vec::new(),
            power_checks: Vec::new(),
        })
    }

    fn run(&mut self) -> Result<(), RunError> {
        for (index, step) in self.scenario.timeline.iter().enumerate() {
            self.execute_step(index, step)?;
        }
        Ok(())
    }

    fn execute_step(&mut self, index: usize, step: &TimelineStep) -> Result<(), RunError> {
        let at = self.base_utc_us + step.at_offset_us();
        let action = step.action();
        match step {
            TimelineStep::PresentTicket {
                ticket_id,
                gate_id,
                ..
            } => {
                let gate: GateId = parse(gate_id)?;
                let ledger = self.admission.ledger();
                let stale = ledger.version() == 0 || ledger.expires_at_utc_us() <= at;
                let (result, reason) = if !self.lockdown.ingress_allowed(&gate, at) {
                    ("denied".to_string(), Some("locked".to_string()))
                } else {
                    let ticket = self.build_ticket(ticket_id)?;
                    match self
                        .admission
                        .admit(&ticket, &gate, at, &self.ticket_ring)
                    {
                        GateDecision::Admitted { .. } => {
                            let count = self.admissions.entry(ticket_id.clone()).or_insert(0);
                            *count = count.saturating_add(1);
                            ("admitted".to_string(), None)
                        }
                        GateDecision::Denied(denial) => {
                            ("denied".to_string(), Some(denial.code().to_string()))
                        }
                    }
                };
                self.stale_checks.push(StaleCheck {
                    stale,
                    result: result.clone(),
                    reason: reason.clone(),
                });
                self.observe(index, action, step.at_offset_us(), result, reason);
            }
            TimelineStep::CountIngress {
                event_id, gate_id, ..
            } => {
                let gate: GateId = parse(gate_id)?;
                if !self.lockdown.ingress_allowed(&gate, at) {
                    self.observe(
                        index,
                        action,
                        step.at_offset_us(),
                        "denied".to_string(),
                        Some("locked".to_string()),
                    );
                } else {
                    let zone = self.zone_of_gate(&gate)?;
                    let event = PresenceEvent::new(
                        event_id.clone(),
                        Direction::Ingress,
                        self.venue_id.clone(),
                        zone.clone(),
                        gate.clone(),
                        at,
                        EventSource::GateController {
                            gate_id: gate.clone(),
                        },
                    );
                    let decision = self
                        .capacity
                        .record(&event)
                        .map_err(|error| RunError::Engine(error.to_string()))?;
                    let (result, reason) = decision_parts(&decision);
                    if result == "allowed" {
                        self.capacity_checks.push(self.capacity_check(&gate, &zone, at));
                    }
                    self.observe(index, action, step.at_offset_us(), result, reason);
                }
            }
            TimelineStep::CountEgress {
                event_id, gate_id, ..
            } => {
                let gate: GateId = parse(gate_id)?;
                let zone = self.zone_of_gate(&gate)?;
                let event = PresenceEvent::new(
                    event_id.clone(),
                    Direction::Egress,
                    self.venue_id.clone(),
                    zone,
                    gate,
                    at,
                    EventSource::GateController {
                        gate_id: parse(gate_id)?,
                    },
                );
                let decision = self
                    .capacity
                    .record(&event)
                    .map_err(|error| RunError::Engine(error.to_string()))?;
                let (result, reason) = decision_parts(&decision);
                self.observe(index, action, step.at_offset_us(), result, reason);
            }
            TimelineStep::ObserveSensor {
                zone_id,
                occupancy,
                adopt,
                actor,
                reason,
                ..
            } => {
                let zone: ZoneId = parse(zone_id)?;
                let observation = CapacityObservation::new(
                    format!("obs-{index}"),
                    zone.clone(),
                    format!("sensor-{zone_id}"),
                    at,
                    ObservationKind::Occupancy {
                        occupancy: *occupancy,
                    },
                );
                let report = self
                    .capacity
                    .reconcile(&observation)
                    .map_err(|error| RunError::Engine(error.to_string()))?;
                let status = report.status.code().to_string();
                if *adopt {
                    let actor = actor.clone().unwrap_or_default();
                    let reason = reason.clone().unwrap_or_default();
                    let adoption = self
                        .capacity
                        .adopt_observation(&observation, &actor, &reason)
                        .map_err(|error| RunError::Engine(error.to_string()))?;
                    let audited = self.capacity.audit().any(|entry| {
                        entry.action.code() == "reconciliation_adopted"
                            && entry.reference == format!("obs-{index}")
                            && entry.actor == actor
                    });
                    let alarm = adoption
                        .alarms
                        .iter()
                        .any(|alarm| matches!(alarm, Alarm::SensorDisagreement { .. }));
                    self.adoptions.push(AdoptionCheck {
                        actor,
                        reason,
                        audited,
                        alarm,
                    });
                    self.observe(
                        index,
                        action,
                        step.at_offset_us(),
                        "adopted".to_string(),
                        Some(status),
                    );
                } else {
                    self.observe(
                        index,
                        action,
                        step.at_offset_us(),
                        "observed".to_string(),
                        Some(status),
                    );
                }
            }
            TimelineStep::ApplyRevocationDelta {
                base_version,
                version,
                added,
                expires_offset_us,
                emergency,
                approvals,
                ..
            } => {
                let added_ids: Vec<TicketId> = added
                    .iter()
                    .map(|id| parse(id))
                    .collect::<Result<_, RunError>>()?;
                let mut delta = RevocationDelta::new(
                    *base_version,
                    *version,
                    at,
                    at + expires_offset_us,
                    added_ids,
                    Vec::new(),
                )
                .map_err(|error| RunError::Engine(error.to_string()))?;
                if *emergency {
                    delta = delta
                        .with_emergency(approvals.len() as u32)
                        .map_err(|error| RunError::Engine(error.to_string()))?;
                }
                let signers = approval_signers(approvals)?;
                let pairs: Vec<&dyn TicketSigner> = signers
                    .iter()
                    .map(|(_, signer)| signer as &dyn TicketSigner)
                    .collect();
                let signed = SignedRevocationDelta::sign(delta, &pairs)
                    .map_err(|error| RunError::Engine(error.to_string()))?;
                let (result, reason) = match self.admission.apply_delta(
                    &signed,
                    &self.approval_ring,
                    &self.delta_policy,
                    at,
                ) {
                    Ok(SubmitOutcome::Applied { .. }) => ("applied".to_string(), None),
                    Ok(SubmitOutcome::Queued { .. }) => ("queued".to_string(), None),
                    Ok(SubmitOutcome::AlreadyApplied { .. }) => {
                        ("already_applied".to_string(), None)
                    }
                    Err(error) => (
                        "denied".to_string(),
                        Some(revocation_error_code(&error).to_string()),
                    ),
                };
                self.observe(index, action, step.at_offset_us(), result, reason);
            }
            TimelineStep::Lockdown {
                request_id,
                scope,
                reason,
                approvals,
                expires_offset_us,
                ..
            } => {
                let scope = parse_lock_scope(scope, &self.venue_id)?;
                let request = CommandRequest::new(
                    request_id.clone(),
                    CommandAction::Lockdown { scope },
                    reason.clone(),
                    ROUTINE_APPROVER,
                    at,
                    at + expires_offset_us,
                    1,
                )
                .map_err(|error| RunError::Engine(error.to_string()))?;
                let signed = self.sign_command(request, approvals, at)?;
                let (result, reason) =
                    match self.lockdown.execute(&signed, &self.approval_ring, at) {
                        Ok(outcome) => {
                            if outcome.is_executed() {
                                self.signed_commands.insert(request_id.clone(), signed.clone());
                                self.command_uses.push(CommandUse {
                                    kind: "lockdown",
                                    request_id: request_id.clone(),
                                    approvals: signed.approvals.len() as u32,
                                    threshold: self.approval_policy.lockdown,
                                });
                            }
                            (outcome.code().to_string(), None)
                        }
                        Err(error) => (
                            "denied".to_string(),
                            Some(lockdown_error_code(&error).to_string()),
                        ),
                    };
                self.observe(index, action, step.at_offset_us(), result, reason);
            }
            TimelineStep::ReleaseLockdown {
                request_id,
                scope,
                reason,
                approvals,
                expires_offset_us,
                reuse_approvals_from,
                ..
            } => {
                let scope = parse_lock_scope(scope, &self.venue_id)?;
                let release_action = CommandAction::ReleaseLockdown { scope };
                if let Some(source) = reuse_approvals_from {
                    let source = self.signed_commands.get(source).ok_or_else(|| {
                        RunError::Invalid(format!("no signed command {source} to reuse"))
                    })?;
                    // The release request is otherwise well-formed and inside
                    // the approvals' decision window, so the only defect left
                    // is that the signatures commit to the lockdown request.
                    let request = CommandRequest::new(
                        request_id.clone(),
                        release_action,
                        reason.clone(),
                        ROUTINE_APPROVER,
                        at - 2_000_000,
                        at + expires_offset_us,
                        1,
                    )
                    .map_err(|error| RunError::Engine(error.to_string()))?;
                    let reused = SignedCommand {
                        request,
                        approvals: source.approvals.clone(),
                    };
                    let outcome = self.lockdown.execute(&reused, &self.approval_ring, at);
                    self.reuse_attempts.push(outcome.is_err());
                    let (result, reason) = match outcome {
                        Ok(outcome) => (outcome.code().to_string(), None),
                        Err(error) => (
                            "denied".to_string(),
                            Some(lockdown_error_code(&error).to_string()),
                        ),
                    };
                    self.observe(index, action, step.at_offset_us(), result, reason);
                } else {
                    let request = CommandRequest::new(
                        request_id.clone(),
                        release_action,
                        reason.clone(),
                        ROUTINE_APPROVER,
                        at,
                        at + expires_offset_us,
                        1,
                    )
                    .map_err(|error| RunError::Engine(error.to_string()))?;
                    let signed = self.sign_command(request, approvals, at)?;
                    let (result, reason) =
                        match self.lockdown.execute(&signed, &self.approval_ring, at) {
                            Ok(outcome) => {
                                if outcome.is_executed() {
                                    self.command_uses.push(CommandUse {
                                        kind: "release_lockdown",
                                        request_id: request_id.clone(),
                                        approvals: signed.approvals.len() as u32,
                                        threshold: self.approval_policy.release,
                                    });
                                }
                                (outcome.code().to_string(), None)
                            }
                            Err(error) => (
                                "denied".to_string(),
                                Some(lockdown_error_code(&error).to_string()),
                            ),
                        };
                    self.observe(index, action, step.at_offset_us(), result, reason);
                }
            }
            TimelineStep::CapacityOverride {
                request_id,
                scope,
                headroom,
                reason,
                approvals,
                expires_offset_us,
                ..
            } => {
                let limit_scope = parse_limit_scope(scope)?;
                let request = CommandRequest::new(
                    request_id.clone(),
                    CommandAction::CapacityOverride {
                        scope: limit_scope.clone(),
                        headroom: *headroom,
                    },
                    reason.clone(),
                    ROUTINE_APPROVER,
                    at,
                    at + expires_offset_us,
                    1,
                )
                .map_err(|error| RunError::Engine(error.to_string()))?;
                let signed = self.sign_command(request, approvals, at)?;
                let (result, reason) =
                    match self.lockdown.execute(&signed, &self.approval_ring, at) {
                        Ok(outcome) => {
                            if outcome.is_executed() {
                                self.command_uses.push(CommandUse {
                                    kind: "capacity_override",
                                    request_id: request_id.clone(),
                                    approvals: signed.approvals.len() as u32,
                                    threshold: self.approval_policy.capacity_override,
                                });
                                // ST-08 authorises the override; ST-06 enforces it
                                // against the hard limit with its own bounded grant.
                                self.capacity
                                    .grant_override(OverrideGrant {
                                        override_id: request_id.clone(),
                                        scope: limit_scope,
                                        requested_by: ROUTINE_APPROVER.to_string(),
                                        approved_by: approvals
                                            .first()
                                            .cloned()
                                            .unwrap_or_default(),
                                        reason: reason.clone(),
                                        granted_at_utc_us: at,
                                        expires_at_utc_us: at + expires_offset_us,
                                        max_headroom: *headroom,
                                        max_uses: *headroom,
                                    })
                                    .map_err(|error| RunError::Engine(error.to_string()))?;
                            }
                            (outcome.code().to_string(), None)
                        }
                        Err(error) => (
                            "denied".to_string(),
                            Some(lockdown_error_code(&error).to_string()),
                        ),
                    };
                self.observe(index, action, step.at_offset_us(), result, reason);
            }
            TimelineStep::EmergencyGateOpen {
                request_id,
                gate_id,
                reason,
                approvals,
                expires_offset_us,
                ..
            } => {
                let gate: GateId = parse(gate_id)?;
                let request = CommandRequest::new(
                    request_id.clone(),
                    CommandAction::EmergencyGateOpen { gate_id: gate },
                    reason.clone(),
                    ROUTINE_APPROVER,
                    at,
                    at + expires_offset_us,
                    1,
                )
                .map_err(|error| RunError::Engine(error.to_string()))?;
                let signed = self.sign_command(request, approvals, at)?;
                let (result, reason) =
                    match self.lockdown.execute(&signed, &self.approval_ring, at) {
                        Ok(outcome) => {
                            if outcome.is_executed() {
                                self.command_uses.push(CommandUse {
                                    kind: "emergency_gate_open",
                                    request_id: request_id.clone(),
                                    approvals: signed.approvals.len() as u32,
                                    threshold: self.approval_policy.emergency_gate_open,
                                });
                            }
                            (outcome.code().to_string(), None)
                        }
                        Err(error) => (
                            "denied".to_string(),
                            Some(lockdown_error_code(&error).to_string()),
                        ),
                    };
                self.observe(index, action, step.at_offset_us(), result, reason);
            }
            TimelineStep::PowerLoss { gate_id, .. } => {
                let gate: GateId = parse(gate_id)?;
                let mode = *self.gate_modes.get(&gate).ok_or_else(|| {
                    RunError::Invalid(format!("gate {gate_id} has no declared fail mode"))
                })?;
                let expected = mode.safe_state().position().as_str().to_string();
                let position = {
                    let sim = self
                        .gate_sims
                        .get_mut(&gate)
                        .ok_or_else(|| RunError::Invalid(format!("gate {gate_id} has no simulator")))?;
                    sim.power_cut();
                    sim.position().as_str().to_string()
                };
                self.power_checks.push(PowerCheck {
                    gate_id: gate_id.clone(),
                    position,
                    expected,
                    egress: self.lockdown.egress_allowed(),
                });
                self.observe(
                    index,
                    action,
                    step.at_offset_us(),
                    "power_lost".to_string(),
                    None,
                );
            }
            TimelineStep::PowerRestore { gate_id, .. } => {
                let gate: GateId = parse(gate_id)?;
                let sim = self
                    .gate_sims
                    .get_mut(&gate)
                    .ok_or_else(|| RunError::Invalid(format!("gate {gate_id} has no simulator")))?;
                sim.power_restore();
                self.observe(
                    index,
                    action,
                    step.at_offset_us(),
                    "power_restored".to_string(),
                    None,
                );
            }
            TimelineStep::Sweep { .. } => {
                self.lockdown.sweep(at);
                self.observe(
                    index,
                    action,
                    step.at_offset_us(),
                    "swept".to_string(),
                    None,
                );
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Observation, RunError> {
        let last_offset = self
            .scenario
            .timeline
            .last()
            .map(TimelineStep::at_offset_us)
            .unwrap_or(0);
        let end = self.base_utc_us + last_offset;
        let final_state = self.final_state(end);
        self.check_steps()?;
        self.check_final(&final_state)?;
        let invariant = self.invariant_observation();
        if !matches!(
            self.scenario.safety_invariant.id.as_str(),
            "ticket_admitted_at_most_once"
                | "ingress_never_exceeds_hard_limit_without_approved_override"
                | "sensor_occupancy_change_requires_audited_adoption"
                | "lockdown_and_release_use_distinct_m_of_n_approvals"
                | "stale_revocation_list_never_admits"
                | "power_loss_leaves_gate_in_safe_state"
        ) {
            return Err(RunError::InvariantFailed {
                id: self.scenario.safety_invariant.id.clone(),
                detail: "unknown invariant".to_string(),
            });
        }
        if !invariant.passed {
            return Err(RunError::InvariantFailed {
                id: invariant.id.clone(),
                detail: invariant.detail.clone(),
            });
        }
        let steps = std::mem::take(&mut self.observations);
        Ok(Observation {
            scenario_id: self.scenario.id.clone(),
            invariant,
            steps,
            final_state,
        })
    }

    fn check_steps(&self) -> Result<(), RunError> {
        for expected in &self.scenario.expected_steps {
            let observed = &self.observations[expected.index];
            if observed.result != expected.result {
                return Err(RunError::StepMismatch {
                    index: expected.index,
                    expected: expected.result.clone(),
                    observed: observed.result.clone(),
                });
            }
            if let Some(reason) = &expected.reason {
                if observed.reason.as_deref() != Some(reason.as_str()) {
                    return Err(RunError::StepMismatch {
                        index: expected.index,
                        expected: format!("reason {reason}"),
                        observed: format!("reason {:?}", observed.reason),
                    });
                }
            }
        }
        Ok(())
    }

    fn check_final(&self, state: &FinalState) -> Result<(), RunError> {
        let expected = &self.scenario.expected_final;
        if let Some(value) = expected.venue_occupancy {
            if state.venue_occupancy != value {
                return Err(final_mismatch("venue_occupancy", value, state.venue_occupancy));
            }
        }
        for (zone, value) in &expected.zone_occupancy {
            let observed = state.zone_occupancy.get(zone).copied().unwrap_or(0);
            if &observed != value {
                return Err(final_mismatch(&format!("zone_occupancy[{zone}]"), value, observed));
            }
        }
        if let Some(value) = expected.revocation_version {
            if state.revocation_version != value {
                return Err(final_mismatch(
                    "revocation_version",
                    value,
                    state.revocation_version,
                ));
            }
        }
        let mut revoked = expected.revoked_tickets.clone();
        revoked.sort();
        if state.revoked_tickets != revoked {
            return Err(RunError::FinalMismatch {
                field: "revoked_tickets".to_string(),
                expected: format!("{revoked:?}"),
                observed: format!("{:?}", state.revoked_tickets),
            });
        }
        let mut lockdowns = expected.lockdowns.clone();
        lockdowns.sort();
        if state.lockdowns != lockdowns {
            return Err(RunError::FinalMismatch {
                field: "lockdowns".to_string(),
                expected: format!("{lockdowns:?}"),
                observed: format!("{:?}", state.lockdowns),
            });
        }
        for (gate, value) in &expected.gate_postures {
            let observed = state
                .gate_postures
                .get(gate)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            if &observed != value {
                return Err(final_mismatch(
                    &format!("gate_postures[{gate}]"),
                    value,
                    observed,
                ));
            }
        }
        for event in &expected.security_events {
            if !state.security_events.contains(event) {
                return Err(RunError::FinalMismatch {
                    field: "security_events".to_string(),
                    expected: event.clone(),
                    observed: format!("{:?}", state.security_events),
                });
            }
        }
        for event in &expected.capacity_audit_events {
            if !state.capacity_audit_events.contains(event) {
                return Err(RunError::FinalMismatch {
                    field: "capacity_audit_events".to_string(),
                    expected: event.clone(),
                    observed: format!("{:?}", state.capacity_audit_events),
                });
            }
        }
        if let Some(value) = &expected.revocation_alarm {
            if state.revocation_alarm.as_ref() != Some(value) {
                return Err(RunError::FinalMismatch {
                    field: "revocation_alarm".to_string(),
                    expected: value.clone(),
                    observed: format!("{:?}", state.revocation_alarm),
                });
            }
        }
        for (gate, value) in &expected.gate_positions {
            let observed = state
                .gate_positions
                .get(gate)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            if &observed != value {
                return Err(final_mismatch(
                    &format!("gate_positions[{gate}]"),
                    value,
                    observed,
                ));
            }
        }
        Ok(())
    }

    fn invariant_observation(&self) -> InvariantObservation {
        let detail = match self.scenario.safety_invariant.id.as_str() {
            "ticket_admitted_at_most_once" => self.invariant_admitted_once(),
            "ingress_never_exceeds_hard_limit_without_approved_override" => {
                self.invariant_capacity()
            }
            "sensor_occupancy_change_requires_audited_adoption" => self.invariant_adoption(),
            "lockdown_and_release_use_distinct_m_of_n_approvals" => self.invariant_lockdown(),
            "stale_revocation_list_never_admits" => self.invariant_stale_revocation(),
            "power_loss_leaves_gate_in_safe_state" => self.invariant_power_loss(),
            other => Err(format!("unknown invariant {other}")),
        };
        let (passed, detail) = match detail {
            Ok(()) => (true, "holds across every observed step".to_string()),
            Err(detail) => (false, detail),
        };
        InvariantObservation {
            id: self.scenario.safety_invariant.id.clone(),
            statement: self.scenario.safety_invariant.statement.clone(),
            passed,
            detail,
        }
    }

    fn invariant_admitted_once(&self) -> Result<(), String> {
        if let Some((ticket, count)) = self.admissions.iter().find(|(_, count)| **count > 1) {
            return Err(format!("ticket {ticket} was admitted {count} times"));
        }
        Ok(())
    }

    fn invariant_capacity(&self) -> Result<(), String> {
        if self.capacity_checks.is_empty() {
            return Err("no admitted ingress was observed".to_string());
        }
        for check in &self.capacity_checks {
            if let Some(detail) = check.violation() {
                return Err(detail);
            }
        }
        Ok(())
    }

    fn invariant_adoption(&self) -> Result<(), String> {
        if self.adoptions.is_empty() {
            return Err("no sensor adoption was observed".to_string());
        }
        for adoption in &self.adoptions {
            if !adoption.audited {
                return Err("adoption is missing from the capacity audit log".to_string());
            }
            if adoption.actor.trim().is_empty() || adoption.reason.trim().is_empty() {
                return Err("adoption lacks an attributable actor and reason".to_string());
            }
            if !adoption.alarm {
                return Err("adoption did not raise a sensor-disagreement alarm".to_string());
            }
        }
        Ok(())
    }

    fn invariant_lockdown(&self) -> Result<(), String> {
        let engaged: Vec<&CommandUse> = self
            .command_uses
            .iter()
            .filter(|use_| use_.kind == "lockdown")
            .collect();
        let released: Vec<&CommandUse> = self
            .command_uses
            .iter()
            .filter(|use_| use_.kind == "release_lockdown")
            .collect();
        if engaged.is_empty() {
            return Err("no lockdown was executed".to_string());
        }
        if released.is_empty() {
            return Err("no release was executed".to_string());
        }
        for use_ in &engaged {
            if use_.approvals < use_.threshold {
                return Err(format!(
                    "lockdown {} engaged with {} approvals, {} required",
                    use_.request_id, use_.approvals, use_.threshold
                ));
            }
        }
        for use_ in &released {
            if engaged
                .iter()
                .any(|engaged| engaged.request_id == use_.request_id)
            {
                return Err(format!(
                    "release {} reuses the lockdown request id",
                    use_.request_id
                ));
            }
            if use_.approvals < use_.threshold {
                return Err(format!(
                    "release {} executed with {} approvals, {} required",
                    use_.request_id, use_.approvals, use_.threshold
                ));
            }
        }
        if self.reuse_attempts.iter().any(|denied| !denied) {
            return Err("a reused approval set was accepted".to_string());
        }
        Ok(())
    }

    fn invariant_stale_revocation(&self) -> Result<(), String> {
        if !self.stale_checks.iter().any(|check| check.stale) {
            return Err("no stale revocation list was observed".to_string());
        }
        for check in &self.stale_checks {
            if check.stale && check.result == "admitted" {
                return Err(format!(
                    "stale list admitted a ticket (reason {:?})",
                    check.reason
                ));
            }
        }
        Ok(())
    }

    fn invariant_power_loss(&self) -> Result<(), String> {
        if self.power_checks.is_empty() {
            return Err("no power loss was observed".to_string());
        }
        for check in &self.power_checks {
            if check.position != check.expected {
                return Err(format!(
                    "gate {} fell to {} instead of safe state {}",
                    check.gate_id, check.position, check.expected
                ));
            }
            if !check.egress {
                return Err(format!("egress was blocked at {} on power loss", check.gate_id));
            }
        }
        Ok(())
    }

    fn final_state(&self, end_utc_us: i64) -> FinalState {
        let gate_postures: BTreeMap<String, String> = self
            .config
            .gates()
            .iter()
            .map(|gate| {
                (
                    gate.as_str().to_string(),
                    self.lockdown.gate_posture(gate, end_utc_us).code().to_string(),
                )
            })
            .collect();
        let zone_occupancy: BTreeMap<String, u32> = self
            .config
            .zones()
            .map(|(zone, _)| {
                (
                    zone.as_str().to_string(),
                    self.capacity.zone_occupancy(zone),
                )
            })
            .collect();
        let gate_positions: BTreeMap<String, String> = self
            .gate_sims
            .iter()
            .map(|(gate, sim)| (gate.as_str().to_string(), sim.position().as_str().to_string()))
            .collect();
        let revoked_tickets: Vec<String> = self
            .admission
            .ledger()
            .revoked()
            .map(|ticket| ticket.as_str().to_string())
            .collect();
        let lockdowns = self
            .lockdown
            .active_lockdowns(end_utc_us)
            .into_iter()
            .map(|lock| lock.scope.label())
            .collect();
        let security_events = self
            .lockdown
            .events()
            .map(|event| event.kind.code().to_string())
            .collect();
        let capacity_audit_events = self
            .capacity
            .audit()
            .map(|entry| entry.action.code().to_string())
            .collect();
        let revocation_alarm = self.admission.alarm().map(|alarm| match alarm.reason {
            tirbase_venue_admission::StaleReason::Missing => "missing".to_string(),
            tirbase_venue_admission::StaleReason::Expired => "expired".to_string(),
        });
        FinalState {
            venue_occupancy: self.capacity.venue_occupancy(),
            zone_occupancy,
            revocation_version: self.admission.ledger().version(),
            revoked_tickets,
            lockdowns,
            gate_postures,
            security_events,
            capacity_audit_events,
            revocation_alarm,
            gate_positions,
        }
    }

    fn capacity_check(&self, gate: &GateId, zone: &ZoneId, at: i64) -> CapacityCheck {
        CapacityCheck {
            gate_id: gate.as_str().to_string(),
            gate_occupancy: self.capacity.gate_occupancy(gate),
            gate_hard: self
                .config
                .gate_limit(gate)
                .map(|limit| limit.hard)
                .unwrap_or(u32::MAX),
            gate_override: self
                .lockdown
                .capacity_override(&LimitScope::Gate(gate.clone()), at)
                .is_some(),
            zone_id: zone.as_str().to_string(),
            zone_occupancy: self.capacity.zone_occupancy(zone),
            zone_hard: self
                .config
                .zone_limit(zone)
                .map(|limit| limit.hard)
                .unwrap_or(u32::MAX),
            zone_override: self
                .lockdown
                .capacity_override(&LimitScope::Zone(zone.clone()), at)
                .is_some(),
            venue_occupancy: self.capacity.venue_occupancy(),
            venue_hard: self.config.venue_limit().hard,
            venue_override: self
                .lockdown
                .capacity_override(&LimitScope::Venue, at)
                .is_some(),
        }
    }

    fn build_ticket(&self, ticket_id: &str) -> Result<SignedTicket, RunError> {
        let spec = self
            .ticket_specs
            .get(ticket_id)
            .ok_or_else(|| RunError::Invalid(format!("ticket {ticket_id} is not declared")))?;
        let payload = TicketPayload::new(
            parse(ticket_id)?,
            VenueScope::new(
                EventId::new(EVENT_ID).map_err(|error| RunError::Invalid(error.to_string()))?,
                self.venue_id.clone(),
                parse(&spec.gate_id)?,
                parse(&spec.zone_id)?,
            ),
            self.base_utc_us + spec.valid_from_offset_us,
            self.base_utc_us + spec.valid_until_offset_us,
            spec.nonce,
        )
        .map_err(|error| RunError::Engine(error.to_string()))?;
        SignedTicket::sign(payload, &ticket_signer())
            .map_err(|error| RunError::Engine(error.to_string()))
    }

    fn sign_command(
        &self,
        request: CommandRequest,
        approvals: &[String],
        at: i64,
    ) -> Result<SignedCommand, RunError> {
        let signers = approval_signers(approvals)?;
        let pairs: Vec<(&str, &dyn TicketSigner)> = signers
            .iter()
            .map(|(name, signer)| (*name, signer as &dyn TicketSigner))
            .collect();
        SignedCommand::sign(request, &pairs, at)
            .map_err(|error| RunError::Engine(error.to_string()))
    }

    fn zone_of_gate(&self, gate: &GateId) -> Result<ZoneId, RunError> {
        self.config
            .zone_of_gate(gate)
            .cloned()
            .ok_or_else(|| RunError::Invalid(format!("gate {} is in no zone", gate.as_str())))
    }

    fn observe(
        &mut self,
        index: usize,
        action: &str,
        at_offset_us: i64,
        result: String,
        reason: Option<String>,
    ) {
        self.observations.push(StepObservation {
            index,
            action: action.to_string(),
            at_offset_us,
            result,
            reason,
        });
    }
}

fn parse<T>(value: &str) -> Result<T, RunError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .parse()
        .map_err(|error| RunError::Invalid(format!("{value}: {error}")))
}

fn ticket_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed("issuer-1", [7u8; 32])
}

fn custodian(index: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(
        format!("custodian-{index}"),
        [30u8.wrapping_add(index); 32],
    )
}

fn approval_signers(names: &[String]) -> Result<Vec<(&'static str, Ed25519Signer)>, RunError> {
    let mut signers = Vec::with_capacity(names.len());
    for name in names {
        let signer = match name.as_str() {
            "custodian-1" => ("custodian-1", custodian(1)),
            "custodian-2" => ("custodian-2", custodian(2)),
            "custodian-3" => ("custodian-3", custodian(3)),
            other => {
                return Err(RunError::Invalid(format!(
                    "unknown approver {other}: scenarios may only use custodian-1..3"
                )))
            }
        };
        signers.push(signer);
    }
    Ok(signers)
}

fn approval_ring(base_utc_us: i64) -> IssuerKeyRing {
    let mut ring = IssuerKeyRing::new();
    let signers: [(&'static str, Ed25519Signer); 3] = [
        ("custodian-1", custodian(1)),
        ("custodian-2", custodian(2)),
        ("custodian-3", custodian(3)),
    ];
    for (index, (name, signer)) in signers.iter().enumerate() {
        ring.add_key(IssuerKey {
            key_id: (*name).to_string(),
            public_key: signer.public_key(),
            not_before_utc_us: base_utc_us - 86_400_000_000,
            not_after_utc_us: base_utc_us + 365 * 86_400_000_000,
            state: if index == 0 {
                IssuerKeyState::Active
            } else {
                IssuerKeyState::Retiring
            },
        })
        .expect("deterministic approval key");
    }
    ring
}

fn build_config(initial: &InitialState) -> Result<CapacityConfig, RunError> {
    let mut config = CapacityConfig::new(parse(&initial.venue_id)?, limit(&initial.venue_limit)?);
    for zone in &initial.zones {
        let gates: Vec<GateId> = zone
            .gates
            .iter()
            .map(|gate| parse(gate))
            .collect::<Result<_, RunError>>()?;
        config = config.with_zone(parse(&zone.zone_id)?, limit(&zone.limit)?, gates);
    }
    for gate_limit in &initial.gate_limits {
        config = config.with_gate_limit(parse(&gate_limit.gate_id)?, limit(&gate_limit.limit)?);
    }
    config
        .validate()
        .map_err(|error| RunError::Invalid(format!("capacity config: {error}")))?;
    Ok(config)
}

fn limit(spec: &LimitSpec) -> Result<CapacityLimit, RunError> {
    let policy = match spec.hard_policy {
        HardPolicySpec::Reject => HardPolicy::Reject,
        HardPolicySpec::Alarm => HardPolicy::Alarm,
    };
    CapacityLimit::new(spec.soft, spec.hard, policy)
        .map_err(|error| RunError::Invalid(format!("limit: {error}")))
}

fn parse_lock_scope(scope: &str, venue_id: &VenueId) -> Result<LockScope, RunError> {
    if scope == "venue" {
        return Ok(LockScope::Venue {
            venue_id: venue_id.clone(),
        });
    }
    if let Some(zone) = scope.strip_prefix("zone:") {
        return Ok(LockScope::Zone {
            zone_id: parse(zone)?,
        });
    }
    Err(RunError::Invalid(format!("unknown lockdown scope {scope}")))
}

fn parse_limit_scope(scope: &str) -> Result<LimitScope, RunError> {
    if scope == "venue" {
        return Ok(LimitScope::Venue);
    }
    if let Some(zone) = scope.strip_prefix("zone:") {
        return Ok(LimitScope::Zone(parse(zone)?));
    }
    if let Some(gate) = scope.strip_prefix("gate:") {
        return Ok(LimitScope::Gate(parse(gate)?));
    }
    Err(RunError::Invalid(format!("unknown capacity scope {scope}")))
}

fn decision_parts(decision: &Decision) -> (String, Option<String>) {
    match decision {
        Decision::Allowed { .. } => ("allowed".to_string(), None),
        Decision::Duplicate { .. } => ("duplicate".to_string(), None),
        Decision::Denied { denial, .. } => {
            ("denied".to_string(), Some(denial.code().to_string()))
        }
    }
}

fn lockdown_error_code(error: &LockdownError) -> &'static str {
    match error {
        LockdownError::InvalidConfig(_) => "invalid_config",
        LockdownError::InvalidCommand(_) => "invalid_command",
        LockdownError::InvalidEncoding(_) => "invalid_encoding",
        LockdownError::VenueMismatch { .. } => "venue_mismatch",
        LockdownError::UnknownZone(_) => "unknown_zone",
        LockdownError::UnknownGate(_) => "unknown_gate",
        LockdownError::Expired { .. } => "expired",
        LockdownError::ApprovalBeforeRequest { .. } => "approval_before_request",
        LockdownError::ApprovalAfterExpiry { .. } => "approval_after_expiry",
        LockdownError::Signature { .. } => "signature",
        LockdownError::DuplicateApprover { .. } => "duplicate_approver",
        LockdownError::DuplicateSigner { .. } => "duplicate_signer",
        LockdownError::SelfApproval { .. } => "self_approval",
        LockdownError::InsufficientApprovals { .. } => "insufficient_approvals",
        LockdownError::LockdownActive { .. } => "lockdown_active",
        LockdownError::NotLocked { .. } => "not_locked",
        LockdownError::CapacityOverrideActive { .. } => "capacity_override_active",
        LockdownError::BreakGlassActive { .. } => "break_glass_active",
    }
}

fn revocation_error_code(error: &tirbase_venue_admission::RevocationError) -> &'static str {
    use tirbase_venue_admission::RevocationError;
    match error {
        RevocationError::Expired { .. } => "expired",
        RevocationError::Signature { .. } => "signature",
        RevocationError::DuplicateSigner { .. } => "duplicate_signer",
        RevocationError::InsufficientApprovals { .. } => "insufficient_approvals",
        RevocationError::EmergencyTtlTooLong { .. } => "emergency_ttl_too_long",
        RevocationError::Gap { .. } => "gap",
        RevocationError::PendingFull { .. } => "pending_full",
        RevocationError::ConflictingVersion { .. } => "conflicting_version",
        _ => "rejected",
    }
}

fn final_mismatch(field: &str, expected: impl fmt::Display, observed: impl fmt::Display) -> RunError {
    RunError::FinalMismatch {
        field: field.to_string(),
        expected: expected.to_string(),
        observed: observed.to_string(),
    }
}

