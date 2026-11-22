// SPDX-License-Identifier: AGPL-3.0-only

//! Gate configuration: fail mode, bounded timings and capacities.
//!
//! [`FailMode`] has no `Default` on purpose. A gate's power-loss behaviour is a
//! life-safety decision, so both the constructor and deserialization require it
//! to be stated explicitly.

use tirbase_venue::GateId;

use crate::error::GateError;
use crate::mechanism::{DriveCommand, GatePosition};

/// How a gate behaves when power is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Power loss releases the lock: egress remains possible (life safety).
    FailSafe,
    /// Power loss leaves the lock engaged: the lane stays secured.
    FailSecure,
}

impl FailMode {
    /// The position a gate must be in when unpowered.
    pub fn safe_state(self) -> SafeState {
        match self {
            FailMode::FailSafe => SafeState::Released,
            FailMode::FailSecure => SafeState::Secured,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FailMode::FailSafe => "fail_safe",
            FailMode::FailSecure => "fail_secure",
        }
    }
}

/// The safe state a configured gate falls back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeState {
    /// Lock released, lane passable.
    Released,
    /// Lock engaged, lane held closed.
    Secured,
}

impl SafeState {
    /// Actuator command that produces this state.
    pub fn drive_command(self) -> DriveCommand {
        match self {
            SafeState::Released => DriveCommand::Release,
            SafeState::Secured => DriveCommand::Lock,
        }
    }

    /// Position the gate reports while it is in this state.
    pub fn position(self) -> GatePosition {
        match self {
            SafeState::Released => GatePosition::Unlocked,
            SafeState::Secured => GatePosition::Locked,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SafeState::Released => "released",
            SafeState::Secured => "secured",
        }
    }
}

/// Upper bound for any single gate timeout: two minutes.
pub const MAX_TIMEOUT_US: i64 = 120_000_000;
/// Upper bound for the local re-use guard: one hour.
pub const MAX_REUSE_US: i64 = 3_600_000_000;

/// Bounded timeouts and the local re-use interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateTimings {
    /// How long an authorised permit stays valid before it is withdrawn.
    pub permit_timeout_us: i64,
    /// How long the lane stays open after a passage before re-locking.
    pub open_hold_us: i64,
    /// How long the lock may take to report engaged before it is a fault.
    pub lock_timeout_us: i64,
    /// Minimum time before the same credential may open the lane again.
    pub reuse_interval_us: i64,
}

impl GateTimings {
    /// Standard venue timings: 10 s permit, 5 s hold, 3 s lock, 30 s re-use.
    pub fn standard() -> Self {
        Self {
            permit_timeout_us: 10_000_000,
            open_hold_us: 5_000_000,
            lock_timeout_us: 3_000_000,
            reuse_interval_us: 30_000_000,
        }
    }

    /// Build timings, rejecting zero, negative or over-long values.
    pub fn new(
        permit_timeout_us: i64,
        open_hold_us: i64,
        lock_timeout_us: i64,
        reuse_interval_us: i64,
    ) -> Result<Self, GateError> {
        let timings = Self {
            permit_timeout_us,
            open_hold_us,
            lock_timeout_us,
            reuse_interval_us,
        };
        timings.validate()?;
        Ok(timings)
    }

    /// Every timeout must be positive and bounded.
    pub fn validate(&self) -> Result<(), GateError> {
        for (name, value, max) in [
            ("permit_timeout_us", self.permit_timeout_us, MAX_TIMEOUT_US),
            ("open_hold_us", self.open_hold_us, MAX_TIMEOUT_US),
            ("lock_timeout_us", self.lock_timeout_us, MAX_TIMEOUT_US),
            ("reuse_interval_us", self.reuse_interval_us, MAX_REUSE_US),
        ] {
            if value <= 0 || value > max {
                return Err(GateError::InvalidTimeout(name));
            }
        }
        Ok(())
    }
}

/// Immutable configuration for one gate controller.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateConfig {
    pub gate_id: GateId,
    /// Power-loss behaviour. Never defaulted.
    pub fail_mode: FailMode,
    pub timings: GateTimings,
    /// Local audit capacity, in entries.
    pub audit_capacity: usize,
    /// Event stream capacity, in events.
    pub event_capacity: usize,
}

impl GateConfig {
    /// Build a configuration. `fail_mode` is required.
    pub fn new(gate_id: GateId, fail_mode: FailMode, timings: GateTimings) -> Result<Self, GateError> {
        timings.validate()?;
        Ok(Self {
            gate_id,
            fail_mode,
            timings,
            audit_capacity: 1024,
            event_capacity: 512,
        })
    }

    pub fn with_audit_capacity(mut self, capacity: usize) -> Result<Self, GateError> {
        if capacity == 0 {
            return Err(GateError::InvalidCapacity("audit_capacity"));
        }
        self.audit_capacity = capacity;
        Ok(self)
    }

    pub fn with_event_capacity(mut self, capacity: usize) -> Result<Self, GateError> {
        if capacity == 0 {
            return Err(GateError::InvalidCapacity("event_capacity"));
        }
        self.event_capacity = capacity;
        Ok(self)
    }

    /// The safe state implied by the configured fail mode.
    pub fn safe_state(&self) -> SafeState {
        self.fail_mode.safe_state()
    }

    /// Validate a configuration parsed from a file.
    pub fn validate(&self) -> Result<(), GateError> {
        self.timings.validate()?;
        if self.audit_capacity == 0 {
            return Err(GateError::InvalidCapacity("audit_capacity"));
        }
        if self.event_capacity == 0 {
            return Err(GateError::InvalidCapacity("event_capacity"));
        }
        Ok(())
    }

    /// Parse a configuration document. A missing `fail_mode` is an error.
    pub fn from_json(json: &str) -> Result<Self, GateError> {
        let config: Self =
            serde_json::from_str(json).map_err(|_| GateError::InvalidConfig("config parse failed"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_json(&self) -> Result<String, GateError> {
        serde_json::to_string(self).map_err(|_| GateError::InvalidConfig("config serialize failed"))
    }
}
