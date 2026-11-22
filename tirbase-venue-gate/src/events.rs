// SPDX-License-Identifier: AGPL-3.0-only

//! Event stream and health snapshot for the guard console / venue gateway.

use tirbase_venue::GateId;
use tirbase_venue_access::CredentialId;

use crate::config::{FailMode, SafeState};
use crate::mechanism::{DriveCommand, GatePosition};

/// One gate event, suitable for `serde` transport to the gateway.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum GateEvent {
    /// A credential was authorised and a permit armed.
    Authorized {
        credential_id: CredentialId,
        permit_id: u64,
        expires_at_utc_us: i64,
    },
    /// A presentation was refused.
    Denied { fingerprint: String, reason: String },
    /// A reader nonce or local re-use guard refused a repeat.
    Replay { fingerprint: String, nonce: u64 },
    /// A passage consumed the permit.
    PassageDetected {
        permit_id: u64,
        credential_id: CredentialId,
    },
    /// A passage was seen with no permit outstanding.
    UnpermittedPassage,
    /// The lane began closing after the hold expired.
    Closing,
    /// The mechanism reported locked.
    Locked,
    /// The mechanism reported unlocked.
    Unlocked,
    /// A drive command was queued.
    DriveCommanded { command: DriveCommand },
    /// The permit expired with no passage.
    PermitExpired { permit_id: u64 },
    /// The lock did not report engaged in time.
    LockTimeout,
    /// The reported position contradicts the commanded state.
    PositionFault {
        expected: Vec<GatePosition>,
        reported: GatePosition,
    },
    /// A fire-alarm input was asserted; egress released.
    FireAlarmEngaged,
    /// The fire-alarm input cleared.
    FireAlarmCleared,
    /// A tamper switch opened.
    TamperDetected,
    /// A tamper latch was cleared by an authorised reset.
    TamperCleared,
    /// Power was lost; the gate is in its configured safe state.
    PowerLost { safe_state: SafeState },
    /// Power returned; the position must be re-established.
    PowerRestored,
    /// An operator command (lock/unlock) was issued.
    ManualCommand { command: DriveCommand },
}

/// An event with its sequence number and time.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateEventRecord {
    pub seq: u64,
    pub at_utc_us: i64,
    pub event: GateEvent,
}

/// Health snapshot pushed to the guard console and gateway.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateHealth {
    pub gate_id: GateId,
    pub position: GatePosition,
    pub fail_mode: FailMode,
    pub safe_state: SafeState,
    pub powered: bool,
    pub tamper: bool,
    pub fire_alarm: bool,
    pub passage_outstanding: bool,
    pub faults: u32,
    pub degraded: bool,
    pub last_event_seq: u64,
    pub events_dropped: u64,
    pub audit_entries: usize,
    pub audit_dropped: u64,
}
