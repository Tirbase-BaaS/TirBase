// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-capacity — Capacity envelopes (ST-06)
//!
//! Enforces the venue's capacity plan at every gate:
//!
//! * **per-gate, per-zone and venue-wide limits**, each with a soft and a hard
//!   threshold; a hard breach either rejects the passage or admits it with an
//!   alarm, as configured;
//! * **idempotent ingress/egress counting** keyed on the presence event id, so a
//!   retried delivery or a repeated ticket admission never inflates occupancy
//!   (ST-05 admissions map to `ticket:<id>#<nonce>`);
//! * **reconciliation** against turnstile counters and occupancy sensors,
//!   reporting the gap and adopting a correction only as an audited operator
//!   action;
//! * an **override path** with separation of duties (requester ≠ approver), a
//!   bounded headroom and use count, an expiry, and an attributable bounded
//!   audit trail for grants, uses, revocations and expiries.
//!
//! The engine reads no clock and does no I/O: every call carries its instant,
//! and the venue gateway is the caller.

#![forbid(unsafe_code)]

pub mod audit;
pub mod engine;
pub mod error;
pub mod event;
pub mod limit;
pub mod overrides;
pub mod reconcile;

pub use audit::{AuditAction, AuditEntry, MAX_AUDIT_ENTRIES};
pub use engine::{
    CapacityEngine, DEFAULT_DEDUPE_CAPACITY, DEFAULT_DEDUPE_RETENTION_US, MAX_DEDUPE_CAPACITY,
    MAX_DEDUPE_RETENTION_US,
};
pub use error::CapacityError;
pub use event::{
    ticket_event_id, Alarm, Decision, Denial, Direction, EventSource, Occupancy, PresenceEvent,
};
pub use limit::{CapacityConfig, CapacityLimit, HardPolicy, LimitScope};
pub use overrides::{CapacityOverride, OverrideGrant, OverrideState};
pub use reconcile::{
    Adoption, Observation, ObservationKind, ReconciliationReport, ReconciliationStatus, SourceKind,
};
