// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-command-center — command center and incident UI backend (ST-11)
//!
//! The command center is the venue's operator-facing control plane. It joins
//! the ST-08 lockdown/override engine to an incident workflow and exposes one
//! JSON state document to the Apache-2.0 console:
//!
//! * a live venue map of zones, gates, occupancy and alarm state;
//! * an attributable incident workflow — acknowledge, dispatch, escalate,
//!   resolve, report — with role permissions and an append-only audit;
//! * lockdown and release controls that require the configured M-of-N approvals
//!   from supervisor/safety-officer identities, executed by ST-08;
//! * a drill mode with its own incident, audit and lockdown state, so a drill
//!   can never alter live occupancy or gate posture;
//! * after-action reports for incidents and drills;
//! * role-aware state for operator, supervisor, safety officer and auditor.
//!
//! The backend is AGPL-3.0-only. The UI is Apache-2.0 and talks to it over
//! HTTP only; no UI code links the runtime.

#![forbid(unsafe_code)]

pub mod engine;
pub mod http;
pub mod model;

pub use engine::{CommandCenter, CommandError, LockCommand, LockdownOutcome};
pub use model::{
    AfterActionReport, AuditEntry, Capability, GateView, Incident, IncidentAction,
    IncidentActionKind, IncidentSeverity, IncidentStatus, LockdownView, MapView, Mode, Role,
    RoleView, Snapshot, ZoneView,
};
