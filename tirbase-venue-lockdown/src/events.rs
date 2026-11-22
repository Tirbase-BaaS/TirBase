// SPDX-License-Identifier: AGPL-3.0-only

//! Security events: one row per executed override and per expiry.

use serde::{Deserialize, Serialize};

/// Largest retained security history.
pub const MAX_SECURITY_EVENTS: usize = 1_024;

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    LockdownEngaged,
    LockdownReleased,
    LockdownExpired,
    CapacityOverrideGranted,
    CapacityOverrideExpired,
    BreakGlassOpened,
    BreakGlassExpired,
}

impl SecurityEventKind {
    pub fn code(&self) -> &'static str {
        match self {
            SecurityEventKind::LockdownEngaged => "lockdown_engaged",
            SecurityEventKind::LockdownReleased => "lockdown_released",
            SecurityEventKind::LockdownExpired => "lockdown_expired",
            SecurityEventKind::CapacityOverrideGranted => "capacity_override_granted",
            SecurityEventKind::CapacityOverrideExpired => "capacity_override_expired",
            SecurityEventKind::BreakGlassOpened => "break_glass_opened",
            SecurityEventKind::BreakGlassExpired => "break_glass_expired",
        }
    }
}

/// One attributable security event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub seq: u64,
    pub at_utc_us: i64,
    pub kind: SecurityEventKind,
    pub request_id: String,
    /// Command family code, e.g. `lockdown`.
    pub action: String,
    /// Scope label, e.g. `zone:zone-north` or `capacity:gate:gate-n1`.
    pub scope: String,
    /// The requester the command is attributed to.
    pub actor: String,
    /// Every distinct approver, in signature order.
    pub approvers: Vec<String>,
    pub detail: String,
}

/// Which state a sweep expired, for the caller's bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expiry {
    pub kind: SecurityEventKind,
    pub request_id: String,
    pub scope: String,
}
