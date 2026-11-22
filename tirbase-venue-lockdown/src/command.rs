// SPDX-License-Identifier: AGPL-3.0-only

//! Signed lockdown and override commands with M-of-N approval.
//!
//! Every command names one exact action, one reason, one requester and one
//! expiry. Each approver signs bytes that bind the request id, the whole action
//! (scope and any headroom), the reason, the requester, the approval threshold
//! and the validity window, plus their own approver identity and approval
//! instant. A signature for a lockdown is therefore worthless for a release or
//! for a different scope, and one approver or one signing key can never count
//! twice.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, VenueId, ZoneId};
use tirbase_venue_capacity::LimitScope;
use tirbase_venue_ticket::{IssuerKeyRing, TicketSigner};

use crate::error::LockdownError;

/// Domain separation for command and approval signatures.
pub const COMMAND_DOMAIN: &str = "TirBase/v1/VenueCommand";
const MAX_ID_LEN: usize = 128;
const MAX_REASON_LEN: usize = 512;

/// The part of a venue a lockdown covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lock_scope", rename_all = "snake_case")]
pub enum LockScope {
    Venue { venue_id: VenueId },
    Zone { zone_id: ZoneId },
}

impl LockScope {
    pub fn code(&self) -> &'static str {
        match self {
            LockScope::Venue { .. } => "venue",
            LockScope::Zone { .. } => "zone",
        }
    }

    pub fn label(&self) -> String {
        match self {
            LockScope::Venue { venue_id } => format!("venue:{venue_id}"),
            LockScope::Zone { zone_id } => format!("zone:{zone_id}"),
        }
    }

    pub fn venue_id(&self) -> Option<&VenueId> {
        match self {
            LockScope::Venue { venue_id } => Some(venue_id),
            LockScope::Zone { .. } => None,
        }
    }

    pub fn zone_id(&self) -> Option<&ZoneId> {
        match self {
            LockScope::Zone { zone_id } => Some(zone_id),
            LockScope::Venue { .. } => None,
        }
    }
}

impl fmt::Display for LockScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The four command families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Lockdown,
    ReleaseLockdown,
    CapacityOverride,
    EmergencyGateOpen,
}

impl CommandKind {
    pub fn code(&self) -> &'static str {
        match self {
            CommandKind::Lockdown => "lockdown",
            CommandKind::ReleaseLockdown => "release_lockdown",
            CommandKind::CapacityOverride => "capacity_override",
            CommandKind::EmergencyGateOpen => "emergency_gate_open",
        }
    }
}

/// The exact action a command authorises.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CommandAction {
    Lockdown { scope: LockScope },
    ReleaseLockdown { scope: LockScope },
    CapacityOverride { scope: LimitScope, headroom: u32 },
    EmergencyGateOpen { gate_id: GateId },
}

impl CommandAction {
    pub fn kind(&self) -> CommandKind {
        match self {
            CommandAction::Lockdown { .. } => CommandKind::Lockdown,
            CommandAction::ReleaseLockdown { .. } => CommandKind::ReleaseLockdown,
            CommandAction::CapacityOverride { .. } => CommandKind::CapacityOverride,
            CommandAction::EmergencyGateOpen { .. } => CommandKind::EmergencyGateOpen,
        }
    }

    /// Human-readable action and scope label for audit rows.
    pub fn scope_label(&self) -> String {
        match self {
            CommandAction::Lockdown { scope } | CommandAction::ReleaseLockdown { scope } => {
                scope.label()
            }
            CommandAction::CapacityOverride { scope, .. } => format!("capacity:{scope}"),
            CommandAction::EmergencyGateOpen { gate_id } => format!("gate:{gate_id}"),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), LockdownError> {
        match self {
            CommandAction::Lockdown { scope } => {
                out.push(0);
                encode_lock_scope(scope, out)?;
            }
            CommandAction::ReleaseLockdown { scope } => {
                out.push(1);
                encode_lock_scope(scope, out)?;
            }
            CommandAction::CapacityOverride { scope, headroom } => {
                out.push(2);
                encode_limit_scope(scope, out)?;
                out.extend_from_slice(&headroom.to_le_bytes());
            }
            CommandAction::EmergencyGateOpen { gate_id } => {
                out.push(3);
                push_str(out, gate_id.as_str())?;
            }
        }
        Ok(())
    }
}

fn encode_lock_scope(scope: &LockScope, out: &mut Vec<u8>) -> Result<(), LockdownError> {
    match scope {
        LockScope::Venue { venue_id } => {
            out.push(0);
            push_str(out, venue_id.as_str())?;
        }
        LockScope::Zone { zone_id } => {
            out.push(1);
            push_str(out, zone_id.as_str())?;
        }
    }
    Ok(())
}

fn encode_limit_scope(scope: &LimitScope, out: &mut Vec<u8>) -> Result<(), LockdownError> {
    match scope {
        LimitScope::Venue => out.push(0),
        LimitScope::Zone(zone_id) => {
            out.push(1);
            push_str(out, zone_id.as_str())?;
        }
        LimitScope::Gate(gate_id) => {
            out.push(2);
            push_str(out, gate_id.as_str())?;
        }
    }
    Ok(())
}

fn push_str(out: &mut Vec<u8>, value: &str) -> Result<(), LockdownError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ID_LEN {
        return Err(LockdownError::InvalidEncoding(
            "identifier length out of range",
        ));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A command awaiting or carrying approvals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest {
    pub request_id: String,
    pub action: CommandAction,
    pub reason: String,
    pub requested_by: String,
    pub requested_at_utc_us: i64,
    /// End of the approval window; also the effect's expiry where the action is
    /// a lockdown, capacity override or break-glass opening.
    pub expires_at_utc_us: i64,
    pub approvals_required: u32,
}

impl CommandRequest {
    /// Build and validate a command request.
    pub fn new(
        request_id: impl Into<String>,
        action: CommandAction,
        reason: impl Into<String>,
        requested_by: impl Into<String>,
        requested_at_utc_us: i64,
        expires_at_utc_us: i64,
        approvals_required: u32,
    ) -> Result<Self, LockdownError> {
        let request_id = request_id.into();
        let reason = reason.into();
        let requested_by = requested_by.into();
        if request_id.trim().is_empty() || request_id.len() > MAX_ID_LEN {
            return Err(LockdownError::InvalidCommand("request id is invalid"));
        }
        if reason.trim().is_empty() || reason.len() > MAX_REASON_LEN {
            return Err(LockdownError::InvalidCommand("reason is missing or too long"));
        }
        if requested_by.trim().is_empty() || requested_by.len() > MAX_ID_LEN {
            return Err(LockdownError::InvalidCommand("requester is invalid"));
        }
        if expires_at_utc_us <= requested_at_utc_us {
            return Err(LockdownError::InvalidCommand(
                "expiry must be after the request time",
            ));
        }
        if approvals_required == 0 {
            return Err(LockdownError::InvalidCommand(
                "approval threshold must be positive",
            ));
        }
        Ok(Self {
            request_id,
            action,
            reason,
            requested_by,
            requested_at_utc_us,
            expires_at_utc_us,
            approvals_required,
        })
    }

    pub fn kind(&self) -> CommandKind {
        self.action.kind()
    }

    /// Bytes that bind one exact action, reason, requester and window.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, LockdownError> {
        let mut out = Vec::with_capacity(160 + self.reason.len());
        out.extend_from_slice(COMMAND_DOMAIN.as_bytes());
        out.push(0);
        push_str(&mut out, key_id)?;
        push_str(&mut out, &self.request_id)?;
        self.action.encode(&mut out)?;
        out.extend_from_slice(&self.approvals_required.to_le_bytes());
        push_str(&mut out, &self.requested_by)?;
        push_str(&mut out, &self.reason)?;
        out.extend_from_slice(&self.requested_at_utc_us.to_le_bytes());
        out.extend_from_slice(&self.expires_at_utc_us.to_le_bytes());
        Ok(out)
    }

    /// Bytes one approver signs: the request plus their identity and instant.
    pub fn approval_bytes(
        &self,
        key_id: &str,
        approver: &str,
        approved_at_utc_us: i64,
    ) -> Result<Vec<u8>, LockdownError> {
        let mut out = self.signing_bytes(key_id)?;
        push_str(&mut out, approver)?;
        out.extend_from_slice(&approved_at_utc_us.to_le_bytes());
        Ok(out)
    }
}

/// One approver's signature over one command request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub key_id: String,
    pub approved_at_utc_us: i64,
    pub signature: String,
}

/// A command request with its approvers' signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommand {
    pub request: CommandRequest,
    pub approvals: Vec<Approval>,
}

impl SignedCommand {
    /// Sign a request once per `(approver, signer)` pair.
    pub fn sign(
        request: CommandRequest,
        approvals: &[(&str, &dyn TicketSigner)],
        approved_at_utc_us: i64,
    ) -> Result<Self, LockdownError> {
        if approvals.is_empty() {
            return Err(LockdownError::InsufficientApprovals {
                provided: 0,
                required: request.approvals_required.max(1),
            });
        }
        let mut signed = Vec::with_capacity(approvals.len());
        for (approver, signer) in approvals {
            let message =
                request.approval_bytes(signer.key_id(), approver, approved_at_utc_us)?;
            signed.push(Approval {
                approver: (*approver).to_owned(),
                key_id: signer.key_id().to_owned(),
                approved_at_utc_us,
                signature: hex::encode(signer.sign(&message)),
            });
        }
        Ok(Self {
            request,
            approvals: signed,
        })
    }

    /// Verify the window, every signature and the M-of-N threshold.
    ///
    /// Returns the number of distinct valid approvers.
    pub fn verify(
        &self,
        ring: &IssuerKeyRing,
        policy: &ApprovalPolicy,
        at_utc_us: i64,
    ) -> Result<u32, LockdownError> {
        if self.request.expires_at_utc_us <= at_utc_us {
            return Err(LockdownError::Expired {
                expires_at_utc_us: self.request.expires_at_utc_us,
            });
        }
        let mut approvers = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let requester = self.request.requested_by.trim();
        for approval in &self.approvals {
            if approval.approver.trim().is_empty() {
                return Err(LockdownError::InvalidCommand("approver is empty"));
            }
            if approval.approver.trim() == requester {
                return Err(LockdownError::SelfApproval {
                    approver: approval.approver.clone(),
                });
            }
            if !approvers.insert(approval.approver.clone()) {
                return Err(LockdownError::DuplicateApprover {
                    approver: approval.approver.clone(),
                });
            }
            if !keys.insert(approval.key_id.clone()) {
                return Err(LockdownError::DuplicateSigner {
                    key_id: approval.key_id.clone(),
                });
            }
            if approval.approved_at_utc_us < self.request.requested_at_utc_us {
                return Err(LockdownError::ApprovalBeforeRequest {
                    approved_at_utc_us: approval.approved_at_utc_us,
                    requested_at_utc_us: self.request.requested_at_utc_us,
                });
            }
            if approval.approved_at_utc_us >= self.request.expires_at_utc_us {
                return Err(LockdownError::ApprovalAfterExpiry {
                    approved_at_utc_us: approval.approved_at_utc_us,
                    expires_at_utc_us: self.request.expires_at_utc_us,
                });
            }
            let message = self.request.approval_bytes(
                &approval.key_id,
                &approval.approver,
                approval.approved_at_utc_us,
            )?;
            ring.verify(
                &approval.key_id,
                &message,
                &approval.signature,
                at_utc_us,
            )
            .map_err(|_| LockdownError::Signature {
                key_id: approval.key_id.clone(),
            })?;
        }
        let provided = self.approvals.len() as u32;
        let required = self
            .request
            .approvals_required
            .max(policy.required_for(self.request.kind()));
        if provided < required {
            return Err(LockdownError::InsufficientApprovals { provided, required });
        }
        Ok(provided)
    }
}

/// Minimum approvals per command family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub lockdown: u32,
    pub release: u32,
    pub capacity_override: u32,
    pub emergency_gate_open: u32,
}

impl ApprovalPolicy {
    /// Build a policy; every threshold must be at least one.
    pub fn new(
        lockdown: u32,
        release: u32,
        capacity_override: u32,
        emergency_gate_open: u32,
    ) -> Result<Self, LockdownError> {
        let thresholds = [lockdown, release, capacity_override, emergency_gate_open];
        if thresholds.contains(&0) {
            return Err(LockdownError::InvalidConfig(
                "approval thresholds must be positive",
            ));
        }
        Ok(Self {
            lockdown,
            release,
            capacity_override,
            emergency_gate_open,
        })
    }

    /// Two approvals for every command family.
    pub fn standard() -> Self {
        Self {
            lockdown: 2,
            release: 2,
            capacity_override: 2,
            emergency_gate_open: 2,
        }
    }

    pub fn required_for(&self, kind: CommandKind) -> u32 {
        match kind {
            CommandKind::Lockdown => self.lockdown,
            CommandKind::ReleaseLockdown => self.release,
            CommandKind::CapacityOverride => self.capacity_override,
            CommandKind::EmergencyGateOpen => self.emergency_gate_open,
        }
    }
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self::standard()
    }
}
