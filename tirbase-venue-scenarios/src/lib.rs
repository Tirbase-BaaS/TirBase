// SPDX-License-Identifier: Apache-2.0

//! # tirbase-venue-scenarios — data-only venue scenario pack (ST-09)
//!
//! Six deterministic scenarios for the venue stack, each declaring:
//!
//! * an **initial state** (venue layout, limits, approval policy, stale-list
//!   policy, tickets and gate fail modes);
//! * a **timeline** of data steps — ticket presentations, ingress/egress
//!   events, sensor observations, signed revocation deltas, signed lockdown and
//!   override commands, power loss/restore and sweeps;
//! * **commands and approvals** (approver identities and request ids);
//! * **expected step outcomes** and **expected final state**;
//! * one **safety invariant** the runner must assert, not merely log.
//!
//! The pack contains no executable hooks, no device access and links no
//! TirBase runtime crate. Scenario content is JSON embedded at compile time;
//! the AGPL integration runner (`tirbase-venue-scenario-runner`) interprets it
//! against the real ST-02…ST-08 engines.
//!
//! Non-goals: this pack is not safety certification, does not cover biometric
//! identification, and never controls a fire system.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Invariant identifiers the runner knows how to assert.
pub const INVARIANTS: &[&str] = &[
    "ticket_admitted_at_most_once",
    "ingress_never_exceeds_hard_limit_without_approved_override",
    "sensor_occupancy_change_requires_audited_adoption",
    "lockdown_and_release_use_distinct_m_of_n_approvals",
    "stale_revocation_list_never_admits",
    "power_loss_leaves_gate_in_safe_state",
];

/// Embedded scenario documents, in deterministic order.
pub const SCENARIOS: &[(&str, &str)] = &[
    (
        "capacity-breach",
        include_str!("../scenarios/capacity-breach.json"),
    ),
    ("gate-replay", include_str!("../scenarios/gate-replay.json")),
    (
        "power-loss-gate",
        include_str!("../scenarios/power-loss-gate.json"),
    ),
    (
        "revocation-expiry",
        include_str!("../scenarios/revocation-expiry.json"),
    ),
    ("sensor-spoof", include_str!("../scenarios/sensor-spoof.json")),
    (
        "venue-lockdown",
        include_str!("../scenarios/venue-lockdown.json"),
    ),
];

/// Parse every embedded scenario.
pub fn load_all() -> Result<Vec<Scenario>, serde_json::Error> {
    SCENARIOS
        .iter()
        .map(|(_, json)| serde_json::from_str(json))
        .collect()
}

/// Parse and validate every embedded scenario.
pub fn validated() -> Result<Vec<Scenario>, String> {
    let scenarios = load_all().map_err(|error| format!("scenario parse failed: {error}"))?;
    for scenario in &scenarios {
        scenario.validate()?;
    }
    Ok(scenarios)
}

/// One scenario document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub title: String,
    pub description: String,
    pub safety_invariant: InvariantSpec,
    pub initial: InitialState,
    pub timeline: Vec<TimelineStep>,
    pub expected_steps: Vec<ExpectedStep>,
    pub expected_final: ExpectedFinal,
}

/// The safety invariant a scenario asserts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSpec {
    pub id: String,
    pub statement: String,
}

/// The state every run starts from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialState {
    pub venue_id: String,
    pub base_utc_us: i64,
    pub venue_limit: LimitSpec,
    pub zones: Vec<ZoneSpec>,
    #[serde(default)]
    pub gate_limits: Vec<GateLimitSpec>,
    pub approval_policy: ApprovalSpec,
    pub stale_policy: StalePolicySpec,
    /// How long the initially synced revocation list stays fresh.
    pub revocation_valid_for_us: i64,
    pub tickets: Vec<TicketSpec>,
    #[serde(default)]
    pub gates: Vec<GateSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitSpec {
    pub soft: u32,
    pub hard: u32,
    pub hard_policy: HardPolicySpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardPolicySpec {
    Reject,
    Alarm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneSpec {
    pub zone_id: String,
    pub gates: Vec<String>,
    pub limit: LimitSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateLimitSpec {
    pub gate_id: String,
    pub limit: LimitSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSpec {
    pub lockdown: u32,
    pub release: u32,
    pub capacity_override: u32,
    pub emergency_gate_open: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StalePolicySpec {
    FailClosed,
    Alarm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketSpec {
    pub ticket_id: String,
    pub nonce: u64,
    pub gate_id: String,
    pub zone_id: String,
    pub valid_from_offset_us: i64,
    pub valid_until_offset_us: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSpec {
    pub gate_id: String,
    pub fail_mode: FailModeSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailModeSpec {
    FailSafe,
    FailSecure,
}

/// A data-only step in a scenario timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum TimelineStep {
    PresentTicket {
        at_offset_us: i64,
        ticket_id: String,
        gate_id: String,
    },
    CountIngress {
        at_offset_us: i64,
        event_id: String,
        gate_id: String,
    },
    CountEgress {
        at_offset_us: i64,
        event_id: String,
        gate_id: String,
    },
    ObserveSensor {
        at_offset_us: i64,
        zone_id: String,
        occupancy: u32,
        #[serde(default)]
        adopt: bool,
        #[serde(default)]
        actor: Option<String>,
        #[serde(default)]
        reason: Option<String>,
    },
    ApplyRevocationDelta {
        at_offset_us: i64,
        base_version: u64,
        version: u64,
        #[serde(default)]
        added: Vec<String>,
        expires_offset_us: i64,
        #[serde(default)]
        emergency: bool,
        approvals: Vec<String>,
    },
    Lockdown {
        at_offset_us: i64,
        request_id: String,
        scope: String,
        reason: String,
        approvals: Vec<String>,
        expires_offset_us: i64,
    },
    ReleaseLockdown {
        at_offset_us: i64,
        request_id: String,
        scope: String,
        reason: String,
        approvals: Vec<String>,
        expires_offset_us: i64,
        #[serde(default)]
        reuse_approvals_from: Option<String>,
    },
    CapacityOverride {
        at_offset_us: i64,
        request_id: String,
        scope: String,
        headroom: u32,
        reason: String,
        approvals: Vec<String>,
        expires_offset_us: i64,
    },
    EmergencyGateOpen {
        at_offset_us: i64,
        request_id: String,
        gate_id: String,
        reason: String,
        approvals: Vec<String>,
        expires_offset_us: i64,
    },
    PowerLoss {
        at_offset_us: i64,
        gate_id: String,
    },
    PowerRestore {
        at_offset_us: i64,
        gate_id: String,
    },
    Sweep {
        at_offset_us: i64,
    },
}

impl TimelineStep {
    pub fn at_offset_us(&self) -> i64 {
        match self {
            TimelineStep::PresentTicket { at_offset_us, .. }
            | TimelineStep::CountIngress { at_offset_us, .. }
            | TimelineStep::CountEgress { at_offset_us, .. }
            | TimelineStep::ObserveSensor { at_offset_us, .. }
            | TimelineStep::ApplyRevocationDelta { at_offset_us, .. }
            | TimelineStep::Lockdown { at_offset_us, .. }
            | TimelineStep::ReleaseLockdown { at_offset_us, .. }
            | TimelineStep::CapacityOverride { at_offset_us, .. }
            | TimelineStep::EmergencyGateOpen { at_offset_us, .. }
            | TimelineStep::PowerLoss { at_offset_us, .. }
            | TimelineStep::PowerRestore { at_offset_us, .. }
            | TimelineStep::Sweep { at_offset_us } => *at_offset_us,
        }
    }

    pub fn action(&self) -> &'static str {
        match self {
            TimelineStep::PresentTicket { .. } => "present_ticket",
            TimelineStep::CountIngress { .. } => "count_ingress",
            TimelineStep::CountEgress { .. } => "count_egress",
            TimelineStep::ObserveSensor { .. } => "observe_sensor",
            TimelineStep::ApplyRevocationDelta { .. } => "apply_revocation_delta",
            TimelineStep::Lockdown { .. } => "lockdown",
            TimelineStep::ReleaseLockdown { .. } => "release_lockdown",
            TimelineStep::CapacityOverride { .. } => "capacity_override",
            TimelineStep::EmergencyGateOpen { .. } => "emergency_gate_open",
            TimelineStep::PowerLoss { .. } => "power_loss",
            TimelineStep::PowerRestore { .. } => "power_restore",
            TimelineStep::Sweep { .. } => "sweep",
        }
    }
}

/// The expected outcome of one timeline step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedStep {
    pub index: usize,
    pub result: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// The expected state at the end of the timeline.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFinal {
    #[serde(default)]
    pub venue_occupancy: Option<u32>,
    #[serde(default)]
    pub zone_occupancy: BTreeMap<String, u32>,
    #[serde(default)]
    pub revocation_version: Option<u64>,
    #[serde(default)]
    pub revoked_tickets: Vec<String>,
    #[serde(default)]
    pub lockdowns: Vec<String>,
    #[serde(default)]
    pub gate_postures: BTreeMap<String, String>,
    #[serde(default)]
    pub security_events: Vec<String>,
    #[serde(default)]
    pub capacity_audit_events: Vec<String>,
    #[serde(default)]
    pub revocation_alarm: Option<String>,
    #[serde(default)]
    pub gate_positions: BTreeMap<String, String>,
}

impl Scenario {
    /// Structural validation independent of any runtime engine.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("scenario id is empty".to_string());
        }
        if self.title.trim().is_empty() {
            return Err(format!("{}: title is empty", self.id));
        }
        if self.description.trim().is_empty() {
            return Err(format!("{}: description is empty", self.id));
        }
        if !INVARIANTS.contains(&self.safety_invariant.id.as_str()) {
            return Err(format!(
                "{}: unknown invariant {}",
                self.id, self.safety_invariant.id
            ));
        }
        if self.safety_invariant.statement.trim().is_empty() {
            return Err(format!("{}: invariant statement is empty", self.id));
        }
        if self.timeline.is_empty() {
            return Err(format!("{}: timeline is empty", self.id));
        }
        let mut last = 0;
        for step in &self.timeline {
            if step.at_offset_us() < 0 {
                return Err(format!("{}: negative step offset", self.id));
            }
            if step.at_offset_us() < last {
                return Err(format!("{}: timeline goes backwards", self.id));
            }
            last = step.at_offset_us();
        }

        if self.initial.base_utc_us <= 0 {
            return Err(format!("{}: base time must be positive", self.id));
        }
        if self.initial.revocation_valid_for_us <= 0 {
            return Err(format!("{}: revocation validity must be positive", self.id));
        }
        if self.initial.zones.is_empty() {
            return Err(format!("{}: no zones", self.id));
        }

        let gates: BTreeSet<&str> = self
            .initial
            .zones
            .iter()
            .flat_map(|zone| zone.gates.iter().map(String::as_str))
            .collect();
        let zones: BTreeSet<&str> = self
            .initial
            .zones
            .iter()
            .map(|zone| zone.zone_id.as_str())
            .collect();
        let ticket_ids: BTreeSet<&str> = self
            .initial
            .tickets
            .iter()
            .map(|ticket| ticket.ticket_id.as_str())
            .collect();

        for zone in &self.initial.zones {
            if zone.gates.is_empty() {
                return Err(format!("{}: zone {} has no gates", self.id, zone.zone_id));
            }
            if zone.limit.soft > zone.limit.hard {
                return Err(format!("{}: zone {} limit is inverted", self.id, zone.zone_id));
            }
        }
        if self.initial.venue_limit.soft > self.initial.venue_limit.hard {
            return Err(format!("{}: venue limit is inverted", self.id));
        }
        for gate_limit in &self.initial.gate_limits {
            if !gates.contains(gate_limit.gate_id.as_str()) {
                return Err(format!("{}: gate limit names unknown gate", self.id));
            }
            if gate_limit.limit.soft > gate_limit.limit.hard {
                return Err(format!("{}: gate limit is inverted", self.id));
            }
        }
        for gate in &self.initial.gates {
            if !gates.contains(gate.gate_id.as_str()) {
                return Err(format!("{}: gate state names unknown gate", self.id));
            }
        }
        for ticket in &self.initial.tickets {
            if !zones.contains(ticket.zone_id.as_str()) || !gates.contains(ticket.gate_id.as_str()) {
                return Err(format!("{}: ticket names unknown zone or gate", self.id));
            }
            if ticket.valid_until_offset_us <= ticket.valid_from_offset_us {
                return Err(format!("{}: ticket window is empty", self.id));
            }
        }
        let approval_policy = self.initial.approval_policy;
        if [
            approval_policy.lockdown,
            approval_policy.release,
            approval_policy.capacity_override,
            approval_policy.emergency_gate_open,
        ]
        .contains(&0)
        {
            return Err(format!("{}: approval threshold is zero", self.id));
        }

        let mut expected_indices = BTreeSet::new();
        for expected in &self.expected_steps {
            if expected.index >= self.timeline.len() {
                return Err(format!(
                    "{}: expected step {} is outside the timeline",
                    self.id, expected.index
                ));
            }
            if !expected_indices.insert(expected.index) {
                return Err(format!("{}: duplicate expected step {}", self.id, expected.index));
            }
        }

        for step in &self.timeline {
            match step {
                TimelineStep::PresentTicket { ticket_id, gate_id, .. } => {
                    if !ticket_ids.contains(ticket_id.as_str()) {
                        return Err(format!("{}: ticket {ticket_id} is not declared", self.id));
                    }
                    if !gates.contains(gate_id.as_str()) {
                        return Err(format!("{}: gate {gate_id} is not declared", self.id));
                    }
                }
                TimelineStep::CountIngress { gate_id, .. }
                | TimelineStep::CountEgress { gate_id, .. } => {
                    if !gates.contains(gate_id.as_str()) {
                        return Err(format!("{}: gate {gate_id} is not declared", self.id));
                    }
                }
                TimelineStep::ObserveSensor { zone_id, .. } => {
                    if !zones.contains(zone_id.as_str()) {
                        return Err(format!("{}: zone {zone_id} is not declared", self.id));
                    }
                }
                TimelineStep::ApplyRevocationDelta { approvals, .. }
                | TimelineStep::Lockdown { approvals, .. }
                | TimelineStep::ReleaseLockdown { approvals, .. }
                | TimelineStep::CapacityOverride { approvals, .. }
                | TimelineStep::EmergencyGateOpen { approvals, .. } => {
                    if approvals.is_empty() {
                        return Err(format!("{}: step has no approvals", self.id));
                    }
                }
                TimelineStep::PowerLoss { gate_id, .. }
                | TimelineStep::PowerRestore { gate_id, .. } => {
                    if !gates.contains(gate_id.as_str()) {
                        return Err(format!("{}: gate {gate_id} is not declared", self.id));
                    }
                }
                TimelineStep::Sweep { .. } => {}
            }
        }
        Ok(())
    }
}
