// SPDX-License-Identifier: AGPL-3.0-only

//! Why a command or configuration was refused.

use std::fmt;

use tirbase_venue::{GateId, VenueId, ZoneId};
use tirbase_venue_capacity::LimitScope;

use crate::command::LockScope;

/// A refused command, approval or configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockdownError {
    InvalidConfig(&'static str),
    InvalidCommand(&'static str),
    InvalidEncoding(&'static str),
    VenueMismatch { expected: VenueId, presented: VenueId },
    UnknownZone(ZoneId),
    UnknownGate(GateId),
    /// The command's own validity window has passed.
    Expired { expires_at_utc_us: i64 },
    /// An approval claims to predate the command request.
    ApprovalBeforeRequest {
        approved_at_utc_us: i64,
        requested_at_utc_us: i64,
    },
    /// An approval was issued after the command's expiry.
    ApprovalAfterExpiry {
        approved_at_utc_us: i64,
        expires_at_utc_us: i64,
    },
    /// A signature did not verify under its key.
    Signature { key_id: String },
    /// The same approver identity appears twice.
    DuplicateApprover { approver: String },
    /// The same signing key appears twice.
    DuplicateSigner { key_id: String },
    /// The requester approved their own command.
    SelfApproval { approver: String },
    /// Fewer distinct valid approvals than the M-of-N threshold.
    InsufficientApprovals { provided: u32, required: u32 },
    /// A lockdown for this scope is already active.
    LockdownActive { scope: LockScope },
    /// A release named a scope with no active lockdown.
    NotLocked { scope: LockScope },
    /// A capacity override for this scope is already active.
    CapacityOverrideActive { scope: LimitScope },
    /// A break-glass opening for this gate is already active.
    BreakGlassActive { gate_id: GateId },
}

impl fmt::Display for LockdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockdownError::InvalidConfig(reason) => write!(f, "invalid lockdown config: {reason}"),
            LockdownError::InvalidCommand(reason) => write!(f, "invalid command: {reason}"),
            LockdownError::InvalidEncoding(reason) => write!(f, "cannot encode command: {reason}"),
            LockdownError::VenueMismatch { expected, presented } => {
                write!(f, "command is for venue {presented}, not {expected}")
            }
            LockdownError::UnknownZone(zone) => write!(f, "zone {zone} is not configured"),
            LockdownError::UnknownGate(gate) => write!(f, "gate {gate} is not configured"),
            LockdownError::Expired { expires_at_utc_us } => {
                write!(f, "command expired at {expires_at_utc_us}")
            }
            LockdownError::ApprovalBeforeRequest {
                approved_at_utc_us,
                requested_at_utc_us,
            } => write!(
                f,
                "approval at {approved_at_utc_us} predates the request at {requested_at_utc_us}"
            ),
            LockdownError::ApprovalAfterExpiry {
                approved_at_utc_us,
                expires_at_utc_us,
            } => write!(
                f,
                "approval at {approved_at_utc_us} came after expiry {expires_at_utc_us}"
            ),
            LockdownError::Signature { key_id } => {
                write!(f, "approval signature does not verify for {key_id}")
            }
            LockdownError::DuplicateApprover { approver } => {
                write!(f, "approver {approver} appears twice")
            }
            LockdownError::DuplicateSigner { key_id } => {
                write!(f, "signing key {key_id} appears twice")
            }
            LockdownError::SelfApproval { approver } => {
                write!(f, "{approver} cannot approve their own command")
            }
            LockdownError::InsufficientApprovals { provided, required } => {
                write!(f, "{provided} approval(s) provided, {required} required")
            }
            LockdownError::LockdownActive { scope } => {
                write!(f, "a lockdown is already active for {scope}")
            }
            LockdownError::NotLocked { scope } => write!(f, "no active lockdown for {scope}"),
            LockdownError::CapacityOverrideActive { scope } => {
                write!(f, "a capacity override is already active for {scope}")
            }
            LockdownError::BreakGlassActive { gate_id } => {
                write!(f, "break-glass is already open at {gate_id}")
            }
        }
    }
}

impl std::error::Error for LockdownError {}
