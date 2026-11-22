// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-gate — Turnstile and gate controller (ST-04)
//!
//! One controlled lane, from credential to mechanism and back:
//!
//! * open/close/lock with position feedback, a tamper latch and a fire-alarm
//!   input that releases egress;
//! * an offline decision path: the ST-03 [`AccessController`] resolves cached
//!   grants, revocation and reader health locally, and every decision lands in
//!   a bounded, hash-chained local audit log;
//! * per-gate **fail-safe** or **fail-secure** behaviour, stated explicitly in
//!   configuration (`FailMode` has no default);
//! * bounded timeouts for permit validity, open hold and lock engagement, and
//!   a power-loss path that drives the configured safe state;
//! * a deterministic lane simulator with fault injection;
//! * a `serde` event stream and health snapshot for the guard console and the
//!   venue gateway.
//!
//! The controller never touches hardware. It queues [`DriveCommand`]s for the
//! caller and folds [`PositionFeedback`] back in, so the same state machine
//! runs against a real lane controller or the simulator.
//!
//! [`AccessController`]: tirbase_venue_access::AccessController
//! [`DriveCommand`]: crate::DriveCommand
//! [`PositionFeedback`]: crate::PositionFeedback

#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod controller;
pub mod error;
pub mod events;
pub mod mechanism;
pub mod sim;

pub use audit::{AuditAction, AuditEntry, AuditLog};
pub use config::{
    FailMode, GateConfig, GateTimings, SafeState, MAX_REUSE_US, MAX_TIMEOUT_US,
};
pub use controller::{GateController, GateDecision, Presentation};
pub use error::GateError;
pub use events::{GateEvent, GateEventRecord, GateHealth};
pub use mechanism::{DriveCommand, GatePosition, PositionFeedback};
pub use sim::{Faults, GateSim};
