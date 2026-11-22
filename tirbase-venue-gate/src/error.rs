// SPDX-License-Identifier: AGPL-3.0-only

//! Errors raised by the gate controller.

use std::fmt;

use tirbase_venue::GateId;
use tirbase_venue_access::AccessError;

/// A rejected or failed gate operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateError {
    /// An identifier was empty or contained control characters.
    InvalidIdentifier(&'static str),
    /// A timeout was zero, negative or above the documented bound.
    InvalidTimeout(&'static str),
    /// A capacity was zero.
    InvalidCapacity(&'static str),
    /// A configuration document was malformed or incomplete.
    InvalidConfig(&'static str),
    /// The presentation was for another gate.
    WrongGate { expected: GateId, presented: GateId },
    /// The controller is unpowered.
    PowerOff,
    /// A fire alarm is active; egress is released and entry refused.
    FireAlarmActive,
    /// The tamper latch has not been cleared.
    TamperLatched,
    /// The same reader nonce was presented again.
    ReplayRejected { nonce: u64, last_accepted: u64 },
    /// The credential opened the lane too recently to open it again.
    ReuseTooSoon { last_passage_utc_us: i64 },
    /// A passage is already outstanding on this lane.
    PassageInProgress,
    /// No authorised permit is outstanding.
    NoActivePermit,
    /// The permit expired before a passage was detected.
    PassageExpired,
    /// The access layer refused the credential.
    Denied(AccessError),
    /// A mechanism fault was detected.
    Fault(&'static str),
    /// The local audit chain did not verify.
    AuditChainBroken(u64),
    /// A persisted audit log could not be read.
    AuditCorrupt(&'static str),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::InvalidIdentifier(what) => write!(f, "invalid identifier: {what}"),
            GateError::InvalidTimeout(what) => write!(f, "invalid timeout: {what}"),
            GateError::InvalidCapacity(what) => write!(f, "invalid capacity: {what}"),
            GateError::InvalidConfig(what) => write!(f, "invalid configuration: {what}"),
            GateError::WrongGate { expected, presented } => {
                write!(f, "presentation for gate {presented}, controller owns {expected}")
            }
            GateError::PowerOff => write!(f, "gate is unpowered"),
            GateError::FireAlarmActive => write!(f, "fire alarm is active"),
            GateError::TamperLatched => write!(f, "gate tamper is latched"),
            GateError::ReplayRejected {
                nonce,
                last_accepted,
            } => write!(
                f,
                "replayed reader nonce {nonce} (last accepted {last_accepted})"
            ),
            GateError::ReuseTooSoon { last_passage_utc_us } => write!(
                f,
                "credential already opened the lane at {last_passage_utc_us}"
            ),
            GateError::PassageInProgress => write!(f, "a passage is already outstanding"),
            GateError::NoActivePermit => write!(f, "no authorised permit is outstanding"),
            GateError::PassageExpired => write!(f, "the authorised permit expired"),
            GateError::Denied(error) => write!(f, "access denied: {error}"),
            GateError::Fault(reason) => write!(f, "gate fault: {reason}"),
            GateError::AuditChainBroken(seq) => {
                write!(f, "local audit chain broken at entry {seq}")
            }
            GateError::AuditCorrupt(reason) => write!(f, "local audit corrupt: {reason}"),
        }
    }
}

impl std::error::Error for GateError {}

impl From<AccessError> for GateError {
    fn from(error: AccessError) -> Self {
        GateError::Denied(error)
    }
}
