// SPDX-License-Identifier: AGPL-3.0-only

//! Configuration and attribution errors.
//!
//! These are programmer/configuration mistakes. Capacity *decisions* (a full
//! zone, an unbalanced lane, an expired override) are typed
//! `Decision`/`Alarm`/`Denial` values, never errors.

use std::fmt;

use tirbase_venue::{GateId, VenueId, ZoneId};

use crate::limit::LimitScope;

/// Why the capacity engine refused an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapacityError {
    /// A limit, dedupe bound or configuration document is invalid.
    InvalidConfig(&'static str),
    /// A presence event has an empty id.
    EmptyEventId,
    /// The event names a venue the envelope does not cover.
    VenueMismatch { expected: VenueId, presented: VenueId },
    /// The event names an unconfigured zone.
    UnknownZone(ZoneId),
    /// The event names an unconfigured gate.
    UnknownGate(GateId),
    /// The gate does not belong to the event's zone.
    GateNotInZone { gate_id: GateId, zone_id: ZoneId },
    /// The observation sheet is unusable.
    InvalidObservation(&'static str),
    /// An override grant is malformed or is not a permitted action.
    InvalidOverride(&'static str),
    /// An override already covers this scope.
    OverrideAlreadyActive(LimitScope),
    /// No override with that id exists.
    UnknownOverride(String),
    /// An operator action lacks an attributable actor or reason.
    EmptyAttribution(&'static str),
}

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapacityError::InvalidConfig(reason) => write!(f, "invalid capacity config: {reason}"),
            CapacityError::EmptyEventId => write!(f, "presence event id is empty"),
            CapacityError::VenueMismatch { expected, presented } => {
                write!(f, "event is for venue {presented}, not {expected}")
            }
            CapacityError::UnknownZone(zone) => write!(f, "zone {zone} is not configured"),
            CapacityError::UnknownGate(gate) => write!(f, "gate {gate} is not configured"),
            CapacityError::GateNotInZone { gate_id, zone_id } => {
                write!(f, "gate {gate_id} does not belong to zone {zone_id}")
            }
            CapacityError::InvalidObservation(reason) => {
                write!(f, "invalid capacity observation: {reason}")
            }
            CapacityError::InvalidOverride(reason) => write!(f, "invalid override: {reason}"),
            CapacityError::OverrideAlreadyActive(scope) => {
                write!(f, "an override is already active for {scope}")
            }
            CapacityError::UnknownOverride(id) => write!(f, "override {id} does not exist"),
            CapacityError::EmptyAttribution(field) => {
                write!(f, "{field} must name an attributable person or system")
            }
        }
    }
}

impl std::error::Error for CapacityError {}
