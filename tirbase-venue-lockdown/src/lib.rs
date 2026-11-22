// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-lockdown — Lockdown and M-of-N override (ST-08)
//!
//! The control path for the venue: who may close it, who may reopen it, and who
//! may exceed capacity or open a gate in an emergency.
//!
//! * **Signed lockdown commands** — venue-wide or one zone, with a reason, a
//!   requester and an expiry — authorised by distinct approvers.
//! * **Fail-safe gate posture** — a lockdown refuses ingress and keeps egress
//!   free; a break-glass command opens exactly one named gate for a bounded
//!   interval.
//! * **M-of-N approval** for lockdown, release, capacity override and emergency
//!   gate open, with per-family thresholds.
//! * **Exact-action binding** — every approver signs the request id, the whole
//!   action, the reason, the requester, the threshold and the window, plus their
//!   own identity and approval instant. Release approvals cannot be reused from
//!   the lockdown, and no approver or key can count twice.
//! * **Audit and security events** for every execution and every expiry, with
//!   request id, requester, approvers, action, scope and reason.

#![forbid(unsafe_code)]

pub mod command;
pub mod engine;
pub mod error;
pub mod events;

pub use command::{
    Approval, ApprovalPolicy, CommandAction, CommandKind, CommandRequest, LockScope, SignedCommand,
    COMMAND_DOMAIN,
};
pub use engine::{
    BreakGlass, CapacityOverrideGrant, CommandOutcome, GatePosture, Lockdown, LockdownEngine,
    MAX_EXECUTED_COMMANDS,
};
pub use error::LockdownError;
pub use events::{Expiry, SecurityEvent, SecurityEventKind, MAX_SECURITY_EVENTS};
