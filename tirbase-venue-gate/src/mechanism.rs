// SPDX-License-Identifier: AGPL-3.0-only

//! Mechanism state, drive commands and position feedback.

/// Where a lane/barrier physically is.
///
/// `Unlocked` means the lock is released but nobody has passed yet; `Open` is
/// a lane that has been driven open (a passage, or a fire-alarm release).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GatePosition {
    /// Lock engaged, lane held closed.
    Locked,
    /// Lock released, awaiting a passage.
    Unlocked,
    /// Lane driven open / free-wheeling.
    Open,
    /// Position could not be established (sensor fault, power-up).
    Unknown,
}

impl GatePosition {
    pub fn as_str(self) -> &'static str {
        match self {
            GatePosition::Locked => "locked",
            GatePosition::Unlocked => "unlocked",
            GatePosition::Open => "open",
            GatePosition::Unknown => "unknown",
        }
    }

    /// True when the lane currently allows a person through.
    pub fn is_passable(self) -> bool {
        matches!(self, GatePosition::Unlocked | GatePosition::Open)
    }
}

/// Actuator command emitted for the caller (or the simulator) to apply.
///
/// The controller never touches hardware: it queues commands and the caller
/// drains them with [`crate::GateController::take_commands`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DriveCommand {
    /// Release the lock for one authorised passage.
    Unlock,
    /// Engage the lock.
    Lock,
    /// Release the lock and let the lane free-wheel (egress / fail-safe).
    Release,
}

impl DriveCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            DriveCommand::Unlock => "unlock",
            DriveCommand::Lock => "lock",
            DriveCommand::Release => "release",
        }
    }
}

/// Position and tamper feedback from the lane's sensors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PositionFeedback {
    pub position: GatePosition,
    /// True when the lane's tamper switch is open.
    pub tamper: bool,
}

impl PositionFeedback {
    pub fn new(position: GatePosition) -> Self {
        Self {
            position,
            tamper: false,
        }
    }

    pub fn with_tamper(position: GatePosition, tamper: bool) -> Self {
        Self { position, tamper }
    }
}
