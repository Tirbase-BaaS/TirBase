// SPDX-License-Identifier: AGPL-3.0-only

//! Gate controller: mechanism state machine, offline decisions, timeouts,
//! fire/tamper handling, power-loss safe state, local audit and events.
//!
//! The controller decides and commands; it never touches hardware. Drive
//! commands are queued for the caller and position feedback is fed back in.

use std::collections::{BTreeMap, VecDeque};

use tirbase_venue::{GateId, TicketId};
use tirbase_venue_access::{AccessController, AccessGrant, CredentialId, PresentedCredential};

use crate::audit::{AuditAction, AuditLog};
use crate::config::{FailMode, GateConfig, SafeState};
use crate::error::GateError;
use crate::events::{GateEvent, GateEventRecord, GateHealth};
use crate::mechanism::{DriveCommand, GatePosition, PositionFeedback};

/// A credential presentation with the reader's monotonic nonce.
///
/// The nonce is what makes a replay detectable: the controller accepts a
/// strictly increasing nonce per card, so the same tap replayed (or a captured
/// frame re-sent) is refused before any access decision is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub credential: PresentedCredential,
    pub nonce: u64,
}

impl Presentation {
    pub fn new(credential: PresentedCredential, nonce: u64) -> Self {
        Self { credential, nonce }
    }
}

/// The result of an accepted presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateDecision {
    pub permit_id: u64,
    pub grant: AccessGrant,
    pub expires_at_utc_us: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PassagePermit {
    id: u64,
    credential_id: CredentialId,
    ticket_id: TicketId,
    fingerprint: String,
    expires_at_utc_us: i64,
}

/// One gate/turnstile lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateController {
    config: GateConfig,
    access: AccessController,
    position: GatePosition,
    powered: bool,
    tamper: bool,
    fire_alarm: bool,
    permit: Option<PassagePermit>,
    next_permit_id: u64,
    last_nonce: BTreeMap<String, u64>,
    last_passage: BTreeMap<String, i64>,
    commands: VecDeque<DriveCommand>,
    lock_deadline: Option<i64>,
    close_at: Option<i64>,
    faults: u32,
    audit: AuditLog,
    events: VecDeque<GateEventRecord>,
    event_capacity: usize,
    event_seq: u64,
    events_dropped: u64,
}

impl GateController {
    /// Create a controller in the locked, powered, tamper-clear state.
    pub fn new(config: GateConfig, access: AccessController) -> Result<Self, GateError> {
        config.validate()?;
        let audit = AuditLog::new(config.gate_id.clone(), config.audit_capacity)?;
        Ok(Self {
            event_capacity: config.event_capacity,
            config,
            access,
            position: GatePosition::Locked,
            powered: true,
            tamper: false,
            fire_alarm: false,
            permit: None,
            next_permit_id: 1,
            last_nonce: BTreeMap::new(),
            last_passage: BTreeMap::new(),
            commands: VecDeque::new(),
            lock_deadline: None,
            close_at: None,
            faults: 0,
            audit,
            events: VecDeque::new(),
            event_seq: 0,
            events_dropped: 0,
        })
    }

    // --- accessors -------------------------------------------------------

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    pub fn gate_id(&self) -> &GateId {
        &self.config.gate_id
    }

    pub fn position(&self) -> GatePosition {
        self.position
    }

    pub fn fail_mode(&self) -> FailMode {
        self.config.fail_mode
    }

    pub fn safe_state(&self) -> SafeState {
        self.config.safe_state()
    }

    pub fn is_powered(&self) -> bool {
        self.powered
    }

    pub fn is_tampered(&self) -> bool {
        self.tamper
    }

    pub fn fire_alarm_active(&self) -> bool {
        self.fire_alarm
    }

    pub fn permit_id(&self) -> Option<u64> {
        self.permit.as_ref().map(|permit| permit.id)
    }

    pub fn faults(&self) -> u32 {
        self.faults
    }

    pub fn access(&self) -> &AccessController {
        &self.access
    }

    pub fn access_mut(&mut self) -> &mut AccessController {
        &mut self.access
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn events(&self) -> impl Iterator<Item = &GateEventRecord> {
        self.events.iter()
    }

    pub fn last_event_seq(&self) -> u64 {
        self.event_seq
    }

    /// Drain queued actuator commands.
    pub fn take_commands(&mut self) -> Vec<DriveCommand> {
        self.commands.drain(..).collect()
    }

    pub fn queued_commands(&self) -> usize {
        self.commands.len()
    }

    /// Drain the event stream for the gateway/guard console.
    pub fn drain_events(&mut self) -> Vec<GateEventRecord> {
        self.events.drain(..).collect()
    }

    /// Health snapshot including the configured safe state.
    pub fn health(&self) -> GateHealth {
        GateHealth {
            gate_id: self.config.gate_id.clone(),
            position: self.position,
            fail_mode: self.config.fail_mode,
            safe_state: self.config.safe_state(),
            powered: self.powered,
            tamper: self.tamper,
            fire_alarm: self.fire_alarm,
            passage_outstanding: self.permit.is_some(),
            faults: self.faults,
            degraded: self.faults > 0 || self.tamper || self.position == GatePosition::Unknown,
            last_event_seq: self.event_seq,
            events_dropped: self.events_dropped,
            audit_entries: self.audit.len(),
            audit_dropped: self.audit.dropped(),
        }
    }

    /// Persist the local audit log.
    pub fn audit_json(&self) -> Result<String, GateError> {
        self.audit.to_json()
    }

    /// Restore a persisted local audit log for this gate.
    pub fn restore_audit(&mut self, json: &str) -> Result<(), GateError> {
        let log = AuditLog::from_json(json, self.config.audit_capacity)?;
        if log.gate_id() != self.gate_id() {
            return Err(GateError::AuditCorrupt("audit belongs to another gate"));
        }
        self.audit = log;
        Ok(())
    }

    // --- presentation ----------------------------------------------------

    /// Present a credential at this gate.
    pub fn present(
        &mut self,
        presentation: &Presentation,
        gate_id: &GateId,
        at_utc_us: i64,
    ) -> Result<GateDecision, GateError> {
        if gate_id != &self.config.gate_id {
            return Err(GateError::WrongGate {
                expected: self.config.gate_id.clone(),
                presented: gate_id.clone(),
            });
        }
        if !self.powered {
            return self.refuse(at_utc_us, &presentation.credential, GateError::PowerOff);
        }
        if self.fire_alarm {
            return self.refuse(at_utc_us, &presentation.credential, GateError::FireAlarmActive);
        }
        if self.tamper {
            return self.refuse(at_utc_us, &presentation.credential, GateError::TamperLatched);
        }

        let fingerprint = presentation.credential.fingerprint();
        if let Some(last) = self.last_nonce.get(&fingerprint).copied() {
            if presentation.nonce <= last {
                self.audit.record(
                    at_utc_us,
                    None,
                    Some(fingerprint.clone()),
                    AuditAction::Replayed,
                    format!("nonce {} <= last accepted {last}", presentation.nonce),
                );
                self.push_event(
                    at_utc_us,
                    GateEvent::Replay {
                        fingerprint,
                        nonce: presentation.nonce,
                    },
                );
                return Err(GateError::ReplayRejected {
                    nonce: presentation.nonce,
                    last_accepted: last,
                });
            }
        }

        if self.permit.is_some() {
            return self.refuse(
                at_utc_us,
                &presentation.credential,
                GateError::PassageInProgress,
            );
        }

        if let Some(last) = self.last_passage.get(&fingerprint).copied() {
            if at_utc_us.saturating_sub(last) < self.config.timings.reuse_interval_us {
                self.audit.record(
                    at_utc_us,
                    None,
                    Some(fingerprint.clone()),
                    AuditAction::Replayed,
                    format!("credential opened the lane at {last}"),
                );
                self.push_event(
                    at_utc_us,
                    GateEvent::Replay {
                        fingerprint,
                        nonce: presentation.nonce,
                    },
                );
                return Err(GateError::ReuseTooSoon {
                    last_passage_utc_us: last,
                });
            }
        }

        match self
            .access
            .authorize(&presentation.credential, gate_id, at_utc_us)
        {
            Ok(grant) => {
                self.last_nonce
                    .insert(fingerprint.clone(), presentation.nonce);
                let permit_id = self.next_permit_id;
                self.next_permit_id = self.next_permit_id.saturating_add(1);
                let expires_at_utc_us =
                    at_utc_us.saturating_add(self.config.timings.permit_timeout_us);
                self.permit = Some(PassagePermit {
                    id: permit_id,
                    credential_id: grant.credential_id.clone(),
                    ticket_id: grant.ticket_id.clone(),
                    fingerprint: fingerprint.clone(),
                    expires_at_utc_us,
                });
                self.queue(DriveCommand::Unlock);
                self.audit.record(
                    at_utc_us,
                    Some(grant.credential_id.clone()),
                    Some(fingerprint),
                    AuditAction::Granted,
                    format!("permit {permit_id} armed"),
                );
                self.push_event(
                    at_utc_us,
                    GateEvent::Authorized {
                        credential_id: grant.credential_id.clone(),
                        permit_id,
                        expires_at_utc_us,
                    },
                );
                Ok(GateDecision {
                    permit_id,
                    grant,
                    expires_at_utc_us,
                })
            }
            Err(error) => {
                self.audit.record(
                    at_utc_us,
                    None,
                    Some(fingerprint.clone()),
                    AuditAction::Denied,
                    error.to_string(),
                );
                self.push_event(
                    at_utc_us,
                    GateEvent::Denied {
                        fingerprint,
                        reason: error.to_string(),
                    },
                );
                Err(GateError::Denied(error))
            }
        }
    }

    fn refuse(
        &mut self,
        at_utc_us: i64,
        credential: &PresentedCredential,
        error: GateError,
    ) -> Result<GateDecision, GateError> {
        let fingerprint = credential.fingerprint();
        self.audit.record(
            at_utc_us,
            None,
            Some(fingerprint.clone()),
            AuditAction::Denied,
            error.to_string(),
        );
        self.push_event(
            at_utc_us,
            GateEvent::Denied {
                fingerprint,
                reason: error.to_string(),
            },
        );
        Err(error)
    }

    // --- passage ---------------------------------------------------------

    /// A passage sensor fired. Consumes the outstanding permit exactly once.
    pub fn passage(&mut self, at_utc_us: i64) -> Result<u64, GateError> {
        let Some(permit) = self.permit.take() else {
            self.audit.record(
                at_utc_us,
                None,
                None,
                AuditAction::UnpermittedPassage,
                "passage with no permit",
            );
            self.push_event(at_utc_us, GateEvent::UnpermittedPassage);
            return Err(GateError::NoActivePermit);
        };
        if at_utc_us >= permit.expires_at_utc_us {
            self.queue(DriveCommand::Lock);
            self.audit.record(
                at_utc_us,
                Some(permit.credential_id.clone()),
                Some(permit.fingerprint.clone()),
                AuditAction::Timeout,
                format!("permit {} expired before passage", permit.id),
            );
            self.push_event(at_utc_us, GateEvent::PermitExpired { permit_id: permit.id });
            return Err(GateError::PassageExpired);
        }
        self.last_passage
            .insert(permit.fingerprint.clone(), at_utc_us);
        self.position = GatePosition::Open;
        self.close_at = Some(at_utc_us.saturating_add(self.config.timings.open_hold_us));
        self.audit.record(
            at_utc_us,
            Some(permit.credential_id.clone()),
            Some(permit.fingerprint.clone()),
            AuditAction::Passage,
            format!("permit {}", permit.id),
        );
        self.push_event(
            at_utc_us,
            GateEvent::PassageDetected {
                permit_id: permit.id,
                credential_id: permit.credential_id,
            },
        );
        Ok(permit.id)
    }

    // --- clocks and feedback --------------------------------------------

    /// Advance time: expire permits, close lanes and detect lock timeouts.
    pub fn tick(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        let mut raised = Vec::new();
        if !self.powered {
            return raised;
        }

        if let Some(permit) = self.permit.as_ref() {
            if at_utc_us >= permit.expires_at_utc_us {
                let permit_id = permit.id;
                let credential_id = permit.credential_id.clone();
                let fingerprint = permit.fingerprint.clone();
                self.permit = None;
                self.queue(DriveCommand::Lock);
                self.audit.record(
                    at_utc_us,
                    Some(credential_id),
                    Some(fingerprint),
                    AuditAction::Timeout,
                    format!("permit {permit_id} expired"),
                );
                raised.push(self.push_event(
                    at_utc_us,
                    GateEvent::PermitExpired { permit_id },
                ));
            }
        }

        if let Some(close_at) = self.close_at {
            if at_utc_us >= close_at {
                self.close_at = None;
                self.queue(DriveCommand::Lock);
                self.lock_deadline =
                    Some(at_utc_us.saturating_add(self.config.timings.lock_timeout_us));
                self.audit.record(
                    at_utc_us,
                    None,
                    None,
                    AuditAction::Locked,
                    "open hold elapsed, re-locking",
                );
                raised.push(self.push_event(at_utc_us, GateEvent::Closing));
            }
        }

        if let Some(deadline) = self.lock_deadline {
            if at_utc_us > deadline && self.position != GatePosition::Locked {
                self.lock_deadline = None;
                self.faults = self.faults.saturating_add(1);
                self.audit.record(
                    at_utc_us,
                    None,
                    None,
                    AuditAction::Fault,
                    "lock did not report engaged before the timeout",
                );
                raised.push(self.push_event(at_utc_us, GateEvent::LockTimeout));
            }
        }

        raised
    }

    /// Fold position/tamper feedback from the lane's sensors.
    pub fn apply_feedback(
        &mut self,
        feedback: PositionFeedback,
        at_utc_us: i64,
    ) -> Vec<GateEventRecord> {
        let mut raised = Vec::new();
        if feedback.tamper && !self.tamper {
            self.tamper = true;
            self.audit.record(
                at_utc_us,
                None,
                None,
                AuditAction::Tamper,
                "tamper switch open",
            );
            raised.push(self.push_event(at_utc_us, GateEvent::TamperDetected));
        }
        if !self.powered {
            return raised;
        }

        let expected = self.expected_positions();
        if expected.contains(&feedback.position) {
            if self.position != feedback.position {
                self.position = feedback.position;
                match feedback.position {
                    GatePosition::Locked => {
                        self.lock_deadline = None;
                        self.audit.record(
                            at_utc_us,
                            None,
                            None,
                            AuditAction::Locked,
                            "mechanism reported locked",
                        );
                        raised.push(self.push_event(at_utc_us, GateEvent::Locked));
                    }
                    GatePosition::Unlocked | GatePosition::Open => {
                        raised.push(self.push_event(at_utc_us, GateEvent::Unlocked));
                    }
                    GatePosition::Unknown => {}
                }
            }
        } else {
            self.faults = self.faults.saturating_add(1);
            self.position = GatePosition::Unknown;
            self.audit.record(
                at_utc_us,
                None,
                None,
                AuditAction::Fault,
                format!(
                    "reported {} while expecting {:?}",
                    feedback.position.as_str(),
                    expected
                ),
            );
            raised.push(self.push_event(
                at_utc_us,
                GateEvent::PositionFault {
                    expected,
                    reported: feedback.position,
                },
            ));
        }
        raised
    }

    fn expected_positions(&self) -> Vec<GatePosition> {
        if self.fire_alarm {
            vec![GatePosition::Open, GatePosition::Unlocked]
        } else if self.permit.is_some() || self.close_at.is_some() {
            vec![GatePosition::Unlocked, GatePosition::Open]
        } else {
            vec![GatePosition::Locked]
        }
    }

    // --- life safety, tamper, power --------------------------------------

    /// Assert the fire-alarm input: egress is released until it clears.
    pub fn engage_fire_alarm(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if self.fire_alarm {
            return Vec::new();
        }
        self.fire_alarm = true;
        self.permit = None;
        self.close_at = None;
        self.queue(DriveCommand::Release);
        self.position = GatePosition::Open;
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::FireAlarm,
            "egress released",
        );
        vec![self.push_event(at_utc_us, GateEvent::FireAlarmEngaged)]
    }

    /// Clear the fire-alarm input and re-secure the lane when powered.
    pub fn clear_fire_alarm(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if !self.fire_alarm {
            return Vec::new();
        }
        self.fire_alarm = false;
        if self.powered {
            self.queue(DriveCommand::Lock);
            self.position = GatePosition::Unknown;
            self.lock_deadline =
                Some(at_utc_us.saturating_add(self.config.timings.lock_timeout_us));
        }
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::FireAlarm,
            "alarm cleared, re-securing",
        );
        vec![self.push_event(at_utc_us, GateEvent::FireAlarmCleared)]
    }

    /// Latch a tamper reported outside the normal feedback path.
    pub fn observe_tamper(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if self.tamper {
            return Vec::new();
        }
        self.tamper = true;
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::Tamper,
            "tamper input asserted",
        );
        vec![self.push_event(at_utc_us, GateEvent::TamperDetected)]
    }

    /// Clear a tamper latch. Requires an explicit authorised reset.
    pub fn clear_tamper(
        &mut self,
        authorised: bool,
        at_utc_us: i64,
    ) -> Result<Vec<GateEventRecord>, GateError> {
        if !self.tamper {
            return Ok(Vec::new());
        }
        if !authorised {
            return Err(GateError::TamperLatched);
        }
        self.tamper = false;
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::Tamper,
            "tamper reset authorised",
        );
        Ok(vec![self.push_event(at_utc_us, GateEvent::TamperCleared)])
    }

    /// Power lost: withdraw any permit and drive the configured safe state.
    pub fn power_loss(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if !self.powered {
            return Vec::new();
        }
        self.powered = false;
        self.permit = None;
        self.close_at = None;
        self.lock_deadline = None;
        self.commands.clear();
        let safe_state = self.config.safe_state();
        self.position = safe_state.position();
        self.queue(safe_state.drive_command());
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::PowerLoss,
            safe_state.as_str(),
        );
        vec![self.push_event(
            at_utc_us,
            GateEvent::PowerLost { safe_state },
        )]
    }

    /// Power restored: the position must be re-established from feedback.
    pub fn power_restore(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if self.powered {
            return Vec::new();
        }
        self.powered = true;
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::PowerRestored,
            "power restored",
        );
        if self.fire_alarm {
            self.queue(DriveCommand::Release);
            self.position = GatePosition::Open;
        } else {
            self.queue(DriveCommand::Lock);
            self.position = GatePosition::Unknown;
            self.lock_deadline =
                Some(at_utc_us.saturating_add(self.config.timings.lock_timeout_us));
        }
        vec![self.push_event(at_utc_us, GateEvent::PowerRestored)]
    }

    // --- manual commands -------------------------------------------------

    /// Operator lock command.
    pub fn manual_lock(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if !self.powered {
            return Vec::new();
        }
        self.permit = None;
        self.queue(DriveCommand::Lock);
        self.lock_deadline = Some(at_utc_us.saturating_add(self.config.timings.lock_timeout_us));
        self.audit
            .record(at_utc_us, None, None, AuditAction::Locked, "manual lock");
        vec![self.push_event(
            at_utc_us,
            GateEvent::ManualCommand {
                command: DriveCommand::Lock,
            },
        )]
    }

    /// Operator release command (egress override). Does not arm a permit.
    pub fn manual_release(&mut self, at_utc_us: i64) -> Vec<GateEventRecord> {
        if !self.powered {
            return Vec::new();
        }
        self.permit = None;
        self.queue(DriveCommand::Release);
        self.position = GatePosition::Unknown;
        self.audit.record(
            at_utc_us,
            None,
            None,
            AuditAction::Unlocked,
            "manual release",
        );
        vec![self.push_event(
            at_utc_us,
            GateEvent::ManualCommand {
                command: DriveCommand::Release,
            },
        )]
    }

    // --- internals -------------------------------------------------------

    fn queue(&mut self, command: DriveCommand) {
        self.commands.push_back(command);
    }

    fn push_event(&mut self, at_utc_us: i64, event: GateEvent) -> GateEventRecord {
        self.event_seq = self.event_seq.saturating_add(1);
        let record = GateEventRecord {
            seq: self.event_seq,
            at_utc_us,
            event,
        };
        if self.events.len() >= self.event_capacity {
            self.events.pop_front();
            self.events_dropped = self.events_dropped.saturating_add(1);
        }
        self.events.push_back(record.clone());
        record
    }
}

