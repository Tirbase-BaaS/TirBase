// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic lane simulator with fault injection.
//!
//! The simulator models the physical lane: it accepts [`DriveCommand`]s and
//! reports position feedback. Faults let tests prove the controller notices a
//! mechanism that does not do what it was told.

use crate::config::{FailMode, SafeState};
use crate::mechanism::{DriveCommand, GatePosition, PositionFeedback};

/// Injected mechanism faults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Faults {
    /// The lock never releases: unlock/release commands are ignored.
    pub stuck_locked: bool,
    /// The lane cannot re-lock: lock commands leave it unlocked.
    pub stuck_open: bool,
    /// The lock engages but never reports engaged.
    pub no_lock_engage: bool,
    /// The position sensor reports `Unknown`.
    pub sensor_dead: bool,
}

impl Faults {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn stuck_open() -> Self {
        Self {
            stuck_open: true,
            ..Self::default()
        }
    }

    pub fn no_lock_engage() -> Self {
        Self {
            no_lock_engage: true,
            ..Self::default()
        }
    }
}

/// A simulated turnstile/gate lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateSim {
    fail_mode: FailMode,
    powered: bool,
    position: GatePosition,
    tamper: bool,
    faults: Faults,
    applied: u32,
}

impl GateSim {
    /// A powered, locked lane.
    pub fn new(fail_mode: FailMode) -> Self {
        Self {
            fail_mode,
            powered: true,
            position: GatePosition::Locked,
            tamper: false,
            faults: Faults::none(),
            applied: 0,
        }
    }

    pub fn position(&self) -> GatePosition {
        self.position
    }

    pub fn is_powered(&self) -> bool {
        self.powered
    }

    pub fn faults(&self) -> Faults {
        self.faults
    }

    /// Number of drive commands applied.
    pub fn applied(&self) -> u32 {
        self.applied
    }

    pub fn inject(&mut self, faults: Faults) {
        self.faults = faults;
    }

    pub fn set_tamper(&mut self, tamper: bool) {
        self.tamper = tamper;
    }

    /// Apply an actuator command.
    pub fn apply(&mut self, command: DriveCommand) {
        if !self.powered {
            // An unpowered lane cannot actuate: it stays in its safe state.
            return;
        }
        self.applied = self.applied.saturating_add(1);
        match command {
            DriveCommand::Unlock => {
                if !self.faults.stuck_locked {
                    self.position = GatePosition::Unlocked;
                }
            }
            DriveCommand::Lock => {
                self.position = if self.faults.stuck_open || self.faults.no_lock_engage {
                    GatePosition::Unlocked
                } else {
                    GatePosition::Locked
                };
            }
            DriveCommand::Release => {
                if !self.faults.stuck_locked {
                    self.position = GatePosition::Open;
                }
            }
        }
    }

    /// Current sensor feedback.
    pub fn feedback(&self) -> PositionFeedback {
        if self.faults.sensor_dead {
            PositionFeedback::with_tamper(GatePosition::Unknown, self.tamper)
        } else {
            PositionFeedback::with_tamper(self.position, self.tamper)
        }
    }

    /// Cut power: the lane falls to its configured safe state.
    pub fn power_cut(&mut self) {
        self.powered = false;
        let safe_state = self.fail_mode.safe_state();
        self.position = match safe_state {
            SafeState::Released => GatePosition::Unlocked,
            SafeState::Secured => GatePosition::Locked,
        };
    }

    /// Restore power: the position is unknown until the next command.
    pub fn power_restore(&mut self) {
        self.powered = true;
        self.position = GatePosition::Unknown;
    }
}
