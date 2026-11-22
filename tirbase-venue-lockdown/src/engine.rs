// SPDX-License-Identifier: AGPL-3.0-only

//! Lockdown state, fail-safe gate posture and command execution.
//!
//! A lockdown is engaged only by an M-of-N signed command and ends at its
//! stated expiry. While it is active, ingress is refused at every affected
//! gate and egress stays free: the fail-safe posture is "closed to entry, open
//! to leave". Break-glass opens exactly one named gate for a bounded interval
//! and needs its own approvals. Capacity overrides are grants with their own
//! scope, headroom and expiry. Every execution and expiry produces one
//! attributable security event.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, ZoneId};
use tirbase_venue_capacity::{CapacityConfig, LimitScope};
use tirbase_venue_ticket::IssuerKeyRing;

use crate::command::{
    ApprovalPolicy, CommandAction, CommandKind, CommandRequest, LockScope, SignedCommand,
};
use crate::error::LockdownError;
use crate::events::{Expiry, SecurityEvent, SecurityEventKind, MAX_SECURITY_EVENTS};

/// Largest remembered set of executed request ids.
pub const MAX_EXECUTED_COMMANDS: usize = 10_000;

/// One active lockdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockdown {
    pub request_id: String,
    pub scope: LockScope,
    pub reason: String,
    pub requested_by: String,
    pub approvers: Vec<String>,
    pub engaged_at_utc_us: i64,
    pub expires_at_utc_us: i64,
}

/// One approved capacity headroom grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityOverrideGrant {
    pub request_id: String,
    pub scope: LimitScope,
    pub headroom: u32,
    pub reason: String,
    pub requested_by: String,
    pub approvers: Vec<String>,
    pub granted_at_utc_us: i64,
    pub expires_at_utc_us: i64,
}

/// One approved break-glass opening.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlass {
    pub request_id: String,
    pub gate_id: GateId,
    pub reason: String,
    pub requested_by: String,
    pub approvers: Vec<String>,
    pub opened_at_utc_us: i64,
    pub expires_at_utc_us: i64,
}

/// How a gate should behave at an instant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "posture", rename_all = "snake_case")]
pub enum GatePosture {
    Normal,
    Locked {
        reason: String,
        since_utc_us: i64,
        until_utc_us: i64,
    },
    BreakGlassOpen {
        until_utc_us: i64,
    },
}

impl GatePosture {
    pub fn is_locked(&self) -> bool {
        matches!(self, GatePosture::Locked { .. })
    }

    pub fn is_break_glass(&self) -> bool {
        matches!(self, GatePosture::BreakGlassOpen { .. })
    }

    pub fn code(&self) -> &'static str {
        match self {
            GatePosture::Normal => "normal",
            GatePosture::Locked { .. } => "locked",
            GatePosture::BreakGlassOpen { .. } => "break_glass_open",
        }
    }
}

/// What executing a command did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommandOutcome {
    Executed {
        request_id: String,
        action: CommandAction,
        approvals: u32,
    },
    AlreadyExecuted {
        request_id: String,
    },
}

impl CommandOutcome {
    pub fn is_executed(&self) -> bool {
        matches!(self, CommandOutcome::Executed { .. })
    }

    pub fn code(&self) -> &'static str {
        match self {
            CommandOutcome::Executed { .. } => "executed",
            CommandOutcome::AlreadyExecuted { .. } => "already_executed",
        }
    }
}

/// Venue lockdown and override state.
#[derive(Clone, Debug)]
pub struct LockdownEngine {
    config: CapacityConfig,
    policy: ApprovalPolicy,
    venue_lockdown: Option<Lockdown>,
    zone_lockdowns: BTreeMap<ZoneId, Lockdown>,
    capacity_overrides: BTreeMap<String, CapacityOverrideGrant>,
    break_glass: BTreeMap<GateId, BreakGlass>,
    executed: BTreeMap<String, u64>,
    execution_seq: u64,
    events: VecDeque<SecurityEvent>,
    event_seq: u64,
    events_dropped: u64,
}

impl LockdownEngine {
    /// Build an engine for a venue layout and approval policy.
    pub fn new(config: CapacityConfig, policy: ApprovalPolicy) -> Result<Self, LockdownError> {
        config
            .validate()
            .map_err(|_| LockdownError::InvalidConfig("venue layout is invalid"))?;
        Ok(Self {
            config,
            policy,
            venue_lockdown: None,
            zone_lockdowns: BTreeMap::new(),
            capacity_overrides: BTreeMap::new(),
            break_glass: BTreeMap::new(),
            executed: BTreeMap::new(),
            execution_seq: 0,
            events: VecDeque::new(),
            event_seq: 0,
            events_dropped: 0,
        })
    }

    pub fn config(&self) -> &CapacityConfig {
        &self.config
    }

    pub fn policy(&self) -> ApprovalPolicy {
        self.policy
    }

    /// Security events in sequence order.
    pub fn events(&self) -> impl Iterator<Item = &SecurityEvent> {
        self.events.iter()
    }

    /// Events dropped because the log was full.
    pub fn events_dropped(&self) -> u64 {
        self.events_dropped
    }

    /// Execute a signed command, verifying its approvals first.
    ///
    /// Re-executing an already executed request id is reported as
    /// `AlreadyExecuted` and changes nothing.
    pub fn execute(
        &mut self,
        command: &SignedCommand,
        ring: &IssuerKeyRing,
        at_utc_us: i64,
    ) -> Result<CommandOutcome, LockdownError> {
        let approvals = command.verify(ring, &self.policy, at_utc_us)?;
        let request = &command.request;
        self.sweep(at_utc_us);
        if self.executed.contains_key(&request.request_id) {
            return Ok(CommandOutcome::AlreadyExecuted {
                request_id: request.request_id.clone(),
            });
        }

        let mut detail = request.reason.clone();
        match &request.action {
            CommandAction::Lockdown { scope } => {
                self.check_lock_scope(scope)?;
                if self.active_lockdown(scope, at_utc_us).is_some() {
                    return Err(LockdownError::LockdownActive { scope: scope.clone() });
                }
                let record = Lockdown {
                    request_id: request.request_id.clone(),
                    scope: scope.clone(),
                    reason: request.reason.clone(),
                    requested_by: request.requested_by.clone(),
                    approvers: approver_ids(command),
                    engaged_at_utc_us: at_utc_us,
                    expires_at_utc_us: request.expires_at_utc_us,
                };
                match scope {
                    LockScope::Venue { .. } => self.venue_lockdown = Some(record),
                    LockScope::Zone { zone_id } => {
                        self.zone_lockdowns.insert(zone_id.clone(), record);
                    }
                }
            }
            CommandAction::ReleaseLockdown { scope } => {
                self.check_lock_scope(scope)?;
                let released = match scope {
                    LockScope::Venue { .. } => self.venue_lockdown.take(),
                    LockScope::Zone { zone_id } => self.zone_lockdowns.remove(zone_id),
                };
                let Some(released) = released else {
                    return Err(LockdownError::NotLocked { scope: scope.clone() });
                };
                detail = format!("{} (released {})", request.reason, released.request_id);
            }
            CommandAction::CapacityOverride { scope, headroom } => {
                self.check_limit_scope(scope)?;
                if *headroom == 0 {
                    return Err(LockdownError::InvalidCommand(
                        "capacity headroom must be positive",
                    ));
                }
                if self.capacity_override(scope, at_utc_us).is_some() {
                    return Err(LockdownError::CapacityOverrideActive {
                        scope: scope.clone(),
                    });
                }
                self.capacity_overrides.insert(
                    request.request_id.clone(),
                    CapacityOverrideGrant {
                        request_id: request.request_id.clone(),
                        scope: scope.clone(),
                        headroom: *headroom,
                        reason: request.reason.clone(),
                        requested_by: request.requested_by.clone(),
                        approvers: approver_ids(command),
                        granted_at_utc_us: at_utc_us,
                        expires_at_utc_us: request.expires_at_utc_us,
                    },
                );
            }
            CommandAction::EmergencyGateOpen { gate_id } => {
                self.check_gate(gate_id)?;
                if self.break_glass(gate_id, at_utc_us).is_some() {
                    return Err(LockdownError::BreakGlassActive {
                        gate_id: gate_id.clone(),
                    });
                }
                self.break_glass.insert(
                    gate_id.clone(),
                    BreakGlass {
                        request_id: request.request_id.clone(),
                        gate_id: gate_id.clone(),
                        reason: request.reason.clone(),
                        requested_by: request.requested_by.clone(),
                        approvers: approver_ids(command),
                        opened_at_utc_us: at_utc_us,
                        expires_at_utc_us: request.expires_at_utc_us,
                    },
                );
            }
        }

        self.remember_executed(&request.request_id);
        let kind = match request.kind() {
            CommandKind::Lockdown => SecurityEventKind::LockdownEngaged,
            CommandKind::ReleaseLockdown => SecurityEventKind::LockdownReleased,
            CommandKind::CapacityOverride => SecurityEventKind::CapacityOverrideGranted,
            CommandKind::EmergencyGateOpen => SecurityEventKind::BreakGlassOpened,
        };
        self.push_event(
            at_utc_us,
            EventDraft {
                kind,
                request_id: request.request_id.clone(),
                action: request.kind().code().to_owned(),
                scope: request.action.scope_label(),
                actor: request.requested_by.clone(),
                approvers: approver_ids(command),
                detail,
            },
        );
        Ok(CommandOutcome::Executed {
            request_id: request.request_id.clone(),
            action: request.action.clone(),
            approvals,
        })
    }

    /// Remove expired lockdowns, overrides and break-glass openings, recording
    /// one expiry event each. Returns what expired.
    pub fn sweep(&mut self, at_utc_us: i64) -> Vec<Expiry> {
        let mut expired = Vec::new();

        if self
            .venue_lockdown
            .as_ref()
            .is_some_and(|lock| at_utc_us >= lock.expires_at_utc_us)
        {
            if let Some(lock) = self.venue_lockdown.take() {
                expired.push(self.expire_lockdown(at_utc_us, lock));
            }
        }

        let expired_zones: Vec<ZoneId> = self
            .zone_lockdowns
            .iter()
            .filter(|(_, lock)| at_utc_us >= lock.expires_at_utc_us)
            .map(|(zone_id, _)| zone_id.clone())
            .collect();
        for zone_id in expired_zones {
            if let Some(lock) = self.zone_lockdowns.remove(&zone_id) {
                expired.push(self.expire_lockdown(at_utc_us, lock));
            }
        }

        let expired_grants: Vec<String> = self
            .capacity_overrides
            .iter()
            .filter(|(_, grant)| at_utc_us >= grant.expires_at_utc_us)
            .map(|(request_id, _)| request_id.clone())
            .collect();
        for request_id in expired_grants {
            if let Some(grant) = self.capacity_overrides.remove(&request_id) {
                let scope = format!("capacity:{}", grant.scope);
                self.push_event(
                    at_utc_us,
                    EventDraft {
                        kind: SecurityEventKind::CapacityOverrideExpired,
                        request_id: grant.request_id.clone(),
                        action: CommandKind::CapacityOverride.code().to_owned(),
                        scope: scope.clone(),
                        actor: grant.requested_by.clone(),
                        approvers: grant.approvers.clone(),
                        detail: format!("expired at {}", grant.expires_at_utc_us),
                    },
                );
                expired.push(Expiry {
                    kind: SecurityEventKind::CapacityOverrideExpired,
                    request_id: grant.request_id,
                    scope,
                });
            }
        }

        let expired_gates: Vec<GateId> = self
            .break_glass
            .iter()
            .filter(|(_, glass)| at_utc_us >= glass.expires_at_utc_us)
            .map(|(gate_id, _)| gate_id.clone())
            .collect();
        for gate_id in expired_gates {
            if let Some(glass) = self.break_glass.remove(&gate_id) {
                let scope = format!("gate:{gate_id}");
                self.push_event(
                    at_utc_us,
                    EventDraft {
                        kind: SecurityEventKind::BreakGlassExpired,
                        request_id: glass.request_id.clone(),
                        action: CommandKind::EmergencyGateOpen.code().to_owned(),
                        scope: scope.clone(),
                        actor: glass.requested_by.clone(),
                        approvers: glass.approvers.clone(),
                        detail: format!("expired at {}", glass.expires_at_utc_us),
                    },
                );
                expired.push(Expiry {
                    kind: SecurityEventKind::BreakGlassExpired,
                    request_id: glass.request_id,
                    scope,
                });
            }
        }

        expired
    }

    /// The active venue lockdown, if any.
    pub fn venue_lockdown(&self, at_utc_us: i64) -> Option<&Lockdown> {
        self.venue_lockdown
            .as_ref()
            .filter(|lock| lock_contains(lock, at_utc_us))
    }

    /// The active lockdown for a zone, if any.
    pub fn zone_lockdown(&self, zone_id: &ZoneId, at_utc_us: i64) -> Option<&Lockdown> {
        self.zone_lockdowns
            .get(zone_id)
            .filter(|lock| lock_contains(lock, at_utc_us))
    }

    /// Every active lockdown, venue first, then zones in id order.
    pub fn active_lockdowns(&self, at_utc_us: i64) -> Vec<&Lockdown> {
        let mut active = Vec::new();
        if let Some(lock) = self.venue_lockdown(at_utc_us) {
            active.push(lock);
        }
        active.extend(
            self.zone_lockdowns
                .values()
                .filter(|lock| lock_contains(lock, at_utc_us)),
        );
        active
    }

    /// The active capacity override for a scope, if any.
    pub fn capacity_override(
        &self,
        scope: &LimitScope,
        at_utc_us: i64,
    ) -> Option<&CapacityOverrideGrant> {
        self.capacity_overrides.values().find(|grant| {
            &grant.scope == scope
                && at_utc_us >= grant.granted_at_utc_us
                && at_utc_us < grant.expires_at_utc_us
        })
    }

    /// The active break-glass opening for a gate, if any.
    pub fn break_glass(&self, gate_id: &GateId, at_utc_us: i64) -> Option<&BreakGlass> {
        self.break_glass.get(gate_id).filter(|glass| {
            at_utc_us >= glass.opened_at_utc_us && at_utc_us < glass.expires_at_utc_us
        })
    }

    /// The gate's posture: an approved break-glass opening wins over lockdown.
    pub fn gate_posture(&self, gate_id: &GateId, at_utc_us: i64) -> GatePosture {
        if let Some(glass) = self.break_glass(gate_id, at_utc_us) {
            return GatePosture::BreakGlassOpen {
                until_utc_us: glass.expires_at_utc_us,
            };
        }
        if let Some(lock) = self.venue_lockdown(at_utc_us) {
            return GatePosture::Locked {
                reason: lock.reason.clone(),
                since_utc_us: lock.engaged_at_utc_us,
                until_utc_us: lock.expires_at_utc_us,
            };
        }
        if let Some(zone_id) = self.config.zone_of_gate(gate_id).cloned() {
            if let Some(lock) = self.zone_lockdown(&zone_id, at_utc_us) {
                return GatePosture::Locked {
                    reason: lock.reason.clone(),
                    since_utc_us: lock.engaged_at_utc_us,
                    until_utc_us: lock.expires_at_utc_us,
                };
            }
        }
        GatePosture::Normal
    }

    /// Ingress is refused while locked unless break-glass is open for this gate.
    pub fn ingress_allowed(&self, gate_id: &GateId, at_utc_us: i64) -> bool {
        !self.gate_posture(gate_id, at_utc_us).is_locked()
    }

    /// Fail-safe posture: egress is never blocked, including during lockdown.
    pub fn egress_allowed(&self) -> bool {
        true
    }

    fn active_lockdown(&self, scope: &LockScope, at_utc_us: i64) -> Option<&Lockdown> {
        match scope {
            LockScope::Venue { .. } => self.venue_lockdown(at_utc_us),
            LockScope::Zone { zone_id } => self.zone_lockdown(zone_id, at_utc_us),
        }
    }

    fn expire_lockdown(&mut self, at_utc_us: i64, lock: Lockdown) -> Expiry {
        let action = CommandKind::Lockdown.code().to_owned();
        let scope = lock.scope.label();
        self.push_event(
            at_utc_us,
            EventDraft {
                kind: SecurityEventKind::LockdownExpired,
                request_id: lock.request_id.clone(),
                action,
                scope: scope.clone(),
                actor: lock.requested_by.clone(),
                approvers: lock.approvers.clone(),
                detail: format!("expired at {}", lock.expires_at_utc_us),
            },
        );
        Expiry {
            kind: SecurityEventKind::LockdownExpired,
            request_id: lock.request_id,
            scope,
        }
    }

    fn check_lock_scope(&self, scope: &LockScope) -> Result<(), LockdownError> {
        match scope {
            LockScope::Venue { venue_id } if venue_id == self.config.venue_id() => Ok(()),
            LockScope::Venue { venue_id } => Err(LockdownError::VenueMismatch {
                expected: self.config.venue_id().clone(),
                presented: venue_id.clone(),
            }),
            LockScope::Zone { zone_id } => {
                if self.config.zone_limit(zone_id).is_some() {
                    Ok(())
                } else {
                    Err(LockdownError::UnknownZone(zone_id.clone()))
                }
            }
        }
    }

    fn check_limit_scope(&self, scope: &LimitScope) -> Result<(), LockdownError> {
        match scope {
            LimitScope::Venue => Ok(()),
            LimitScope::Zone(zone_id) => {
                if self.config.zone_limit(zone_id).is_some() {
                    Ok(())
                } else {
                    Err(LockdownError::UnknownZone(zone_id.clone()))
                }
            }
            LimitScope::Gate(gate_id) => self.check_gate(gate_id),
        }
    }

    fn check_gate(&self, gate_id: &GateId) -> Result<(), LockdownError> {
        if self.config.zone_of_gate(gate_id).is_some() {
            Ok(())
        } else {
            Err(LockdownError::UnknownGate(gate_id.clone()))
        }
    }

    fn remember_executed(&mut self, request_id: &str) {
        self.execution_seq = self.execution_seq.saturating_add(1);
        while self.executed.len() >= MAX_EXECUTED_COMMANDS {
            let Some(oldest) = self
                .executed
                .iter()
                .min_by_key(|(_, seq)| **seq)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.executed.remove(&oldest);
        }
        self.executed
            .insert(request_id.to_owned(), self.execution_seq);
    }

    fn push_event(&mut self, at_utc_us: i64, draft: EventDraft) {
        self.event_seq = self.event_seq.saturating_add(1);
        if self.events.len() >= MAX_SECURITY_EVENTS {
            self.events.pop_front();
            self.events_dropped = self.events_dropped.saturating_add(1);
        }
        self.events.push_back(SecurityEvent {
            seq: self.event_seq,
            at_utc_us,
            kind: draft.kind,
            request_id: draft.request_id,
            action: draft.action,
            scope: draft.scope,
            actor: draft.actor,
            approvers: draft.approvers,
            detail: draft.detail,
        });
    }
}

struct EventDraft {
    kind: SecurityEventKind,
    request_id: String,
    action: String,
    scope: String,
    actor: String,
    approvers: Vec<String>,
    detail: String,
}

fn lock_contains(lock: &Lockdown, at_utc_us: i64) -> bool {
    at_utc_us >= lock.engaged_at_utc_us && at_utc_us < lock.expires_at_utc_us
}

fn approver_ids(command: &SignedCommand) -> Vec<String> {
    command
        .approvals
        .iter()
        .map(|approval| approval.approver.clone())
        .collect()
}

/// Re-export the request type for engine callers.
pub type Command = CommandRequest;
