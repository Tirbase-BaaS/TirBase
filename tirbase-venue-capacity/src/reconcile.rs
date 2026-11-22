// SPDX-License-Identifier: AGPL-3.0-only

//! Occupancy reconciliation from turnstile counters and occupancy sensors.
//!
//! Two independent observations are supported:
//!
//! * turnstile counters — cumulative ingress and egress totals for a zone, from
//!   which an implied occupancy `ingress - egress` is derived;
//! * occupancy sensors — an absolute headcount reading for a zone.
//!
//! Reconciliation never changes occupancy on its own. It reports the gap; an
//! operator adoption is a separate audited action.

use serde::{Deserialize, Serialize};
use tirbase_venue::ZoneId;

use crate::event::Alarm;

/// What a source reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationKind {
    /// Cumulative counters since the turnstiles were commissioned.
    Turnstile { ingress_total: u32, egress_total: u32 },
    /// An absolute occupancy reading.
    Occupancy { occupancy: u32 },
}

/// Which family a reading came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Turnstile,
    OccupancySensor,
}

impl SourceKind {
    pub fn code(&self) -> &'static str {
        match self {
            SourceKind::Turnstile => "turnstile",
            SourceKind::OccupancySensor => "occupancy_sensor",
        }
    }
}

/// One reconciliation observation for a zone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub observation_id: String,
    pub zone_id: ZoneId,
    /// Turnstile bank or sensor identifier.
    pub source: String,
    pub at_utc_us: i64,
    pub kind: ObservationKind,
}

impl Observation {
    pub fn new(
        observation_id: impl Into<String>,
        zone_id: ZoneId,
        source: impl Into<String>,
        at_utc_us: i64,
        kind: ObservationKind,
    ) -> Self {
        Self {
            observation_id: observation_id.into(),
            zone_id,
            source: source.into(),
            at_utc_us,
            kind,
        }
    }
}

/// How the observation compares with counted occupancy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    Agree,
    ObservedHigher,
    ObservedLower,
}

impl ReconciliationStatus {
    pub fn code(&self) -> &'static str {
        match self {
            ReconciliationStatus::Agree => "agree",
            ReconciliationStatus::ObservedHigher => "observed_higher",
            ReconciliationStatus::ObservedLower => "observed_lower",
        }
    }
}

/// The comparison result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub observation_id: String,
    pub zone_id: ZoneId,
    pub source: String,
    pub source_kind: SourceKind,
    pub at_utc_us: i64,
    /// Counted occupancy before reconciliation.
    pub tracked: u32,
    /// Occupancy implied by the observation (may be negative for counters).
    pub observed: i64,
    /// `observed - tracked`.
    pub delta: i64,
    pub status: ReconciliationStatus,
}

/// The result of an operator adoption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adoption {
    pub report: ReconciliationReport,
    pub previous: u32,
    pub adopted: u32,
    pub alarms: Vec<Alarm>,
    pub audit_seq: u64,
}
