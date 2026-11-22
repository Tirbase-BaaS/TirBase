// SPDX-License-Identifier: AGPL-3.0-only

//! Presence events, occupancy and typed decisions.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, TicketId, TurnstileId, VenueId, ZoneId};
use tirbase_venue_ticket::Admission;

use crate::limit::LimitScope;

/// Which way a person crossed the line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub fn code(&self) -> &'static str {
        match self {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        }
    }
}

/// Where the count came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum EventSource {
    Turnstile { turnstile_id: TurnstileId },
    GateController { gate_id: GateId },
    Manual { operator: String },
}

/// One ingress or egress fact.
///
/// `event_id` is the idempotency key. Turnstile/controller adapters must derive
/// it from the physical traversal (for tickets, `ticket_id#nonce` via
/// [`PresenceEvent::from_admission`]) so a retried delivery cannot count twice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceEvent {
    pub event_id: String,
    pub direction: Direction,
    pub venue_id: VenueId,
    pub zone_id: ZoneId,
    pub gate_id: GateId,
    pub at_utc_us: i64,
    pub source: EventSource,
}

impl PresenceEvent {
    pub fn new(
        event_id: impl Into<String>,
        direction: Direction,
        venue_id: VenueId,
        zone_id: ZoneId,
        gate_id: GateId,
        at_utc_us: i64,
        source: EventSource,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            direction,
            venue_id,
            zone_id,
            gate_id,
            at_utc_us,
            source,
        }
    }

    /// Build the counting event for an ST-05 admission.
    ///
    /// The event id is `ticket:<ticket_id>#<nonce>`, so the same admitted
    /// ticket presentation can never inflate occupancy, even across retries or
    /// a reader restart.
    pub fn from_admission(
        admission: &Admission,
        direction: Direction,
        at_utc_us: i64,
        source: EventSource,
    ) -> Self {
        Self::new(
            format!("ticket:{}#{}", admission.ticket_id.as_str(), admission.nonce),
            direction,
            admission.venue_id.clone(),
            admission.zone_id.clone(),
            admission.gate_id.clone(),
            at_utc_us,
            source,
        )
    }
}

/// Current counted occupancy.
///
/// The venue total is the sum of the zone counts. A gate's count is the net of
/// ingress and egress *through that gate* (a lane flow counter, not the
/// headcount standing behind it) and is floored at zero; an egress at a gate
/// with no outstanding ingress raises [`crate::Alarm::GateUnbalanced`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Occupancy {
    pub(crate) venue: u32,
    pub(crate) zones: BTreeMap<ZoneId, u32>,
    pub(crate) gates: BTreeMap<GateId, u32>,
}

impl Occupancy {
    pub fn venue(&self) -> u32 {
        self.venue
    }

    pub fn zone(&self, zone_id: &ZoneId) -> u32 {
        self.zones.get(zone_id).copied().unwrap_or(0)
    }

    pub fn gate(&self, gate_id: &GateId) -> u32 {
        self.gates.get(gate_id).copied().unwrap_or(0)
    }

    /// Zone counts in zone-id order.
    pub fn zones(&self) -> impl Iterator<Item = (&ZoneId, u32)> {
        self.zones.iter().map(|(id, count)| (id, *count))
    }

    /// Gate counts in gate-id order.
    pub fn gates(&self) -> impl Iterator<Item = (&GateId, u32)> {
        self.gates.iter().map(|(id, count)| (id, *count))
    }

    pub(crate) fn with_scope(config: &crate::limit::CapacityConfig) -> Self {
        let zones = config.zones().map(|(id, _)| (id.clone(), 0)).collect();
        let gates = config.gates().into_iter().map(|id| (id, 0)).collect();
        Self {
            venue: 0,
            zones,
            gates,
        }
    }

    pub(crate) fn increment(&mut self, zone_id: &ZoneId, gate_id: &GateId) {
        self.venue = self.venue.saturating_add(1);
        if let Some(count) = self.zones.get_mut(zone_id) {
            *count = count.saturating_add(1);
        }
        if let Some(count) = self.gates.get_mut(gate_id) {
            *count = count.saturating_add(1);
        }
    }

    pub(crate) fn decrement(&mut self, zone_id: &ZoneId, gate_id: &GateId) {
        self.venue = self.venue.saturating_sub(1);
        if let Some(count) = self.zones.get_mut(zone_id) {
            *count = count.saturating_sub(1);
        }
        if let Some(count) = self.gates.get_mut(gate_id) {
            *count = count.saturating_sub(1);
        }
    }

    pub(crate) fn set_zone(&mut self, zone_id: &ZoneId, count: u32) {
        self.zones.insert(zone_id.clone(), count);
        self.venue = self.zones.values().copied().sum();
    }
}

/// Why a passage was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "denial", rename_all = "snake_case")]
pub enum Denial {
    /// The passage would cross a hard limit configured to reject.
    HardLimit {
        scope: LimitScope,
        limit: u32,
        occupancy: u32,
        attempted: u32,
    },
    /// Egress with no one counted inside at that scope.
    EgressUnderflow {
        scope: LimitScope,
        occupancy: u32,
    },
}

impl Denial {
    pub fn code(&self) -> &'static str {
        match self {
            Denial::HardLimit { .. } => "hard_limit",
            Denial::EgressUnderflow { .. } => "egress_underflow",
        }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::HardLimit {
                scope,
                limit,
                occupancy,
                attempted,
            } => write!(
                f,
                "hard limit {limit} reached at {scope} (occupancy {occupancy}, attempted {attempted})"
            ),
            Denial::EgressUnderflow { scope, occupancy } => {
                write!(f, "egress with no one inside at {scope} (occupancy {occupancy})")
            }
        }
    }
}

/// Something an operator needs to see, but which did not refuse the passage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alarm", rename_all = "snake_case")]
pub enum Alarm {
    /// Occupancy is at or above the soft limit.
    SoftLimit {
        scope: LimitScope,
        limit: u32,
        occupancy: u32,
    },
    /// Occupancy is at or above a hard limit configured to alarm, not reject.
    HardLimit {
        scope: LimitScope,
        limit: u32,
        occupancy: u32,
    },
    /// The passage was admitted under an override.
    OverrideUsed {
        override_id: String,
        scope: LimitScope,
        occupancy: u32,
    },
    /// Egress at a gate with no outstanding ingress through it.
    GateUnbalanced { gate_id: GateId },
    /// A reconciled observation disagreed with the counted occupancy.
    SensorDisagreement {
        zone_id: ZoneId,
        tracked: u32,
        observed: i64,
    },
}

impl Alarm {
    pub fn code(&self) -> &'static str {
        match self {
            Alarm::SoftLimit { .. } => "soft_limit",
            Alarm::HardLimit { .. } => "hard_limit",
            Alarm::OverrideUsed { .. } => "override_used",
            Alarm::GateUnbalanced { .. } => "gate_unbalanced",
            Alarm::SensorDisagreement { .. } => "sensor_disagreement",
        }
    }
}

/// The engine's answer for one presence event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Counted; occupancy changed.
    Allowed {
        occupancy: Occupancy,
        alarms: Vec<Alarm>,
    },
    /// Already counted; occupancy unchanged.
    Duplicate {
        occupancy: Occupancy,
        event_id: String,
    },
    /// Refused; occupancy unchanged.
    Denied {
        denial: Denial,
        occupancy: Occupancy,
        alarms: Vec<Alarm>,
    },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed { .. })
    }

    pub fn is_duplicate(&self) -> bool {
        matches!(self, Decision::Duplicate { .. })
    }

    pub fn occupancy(&self) -> &Occupancy {
        match self {
            Decision::Allowed { occupancy, .. }
            | Decision::Duplicate { occupancy, .. }
            | Decision::Denied { occupancy, .. } => occupancy,
        }
    }

    pub fn alarms(&self) -> &[Alarm] {
        match self {
            Decision::Allowed { alarms, .. } | Decision::Denied { alarms, .. } => alarms,
            Decision::Duplicate { .. } => &[],
        }
    }

    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Decision::Denied { denial, .. } => Some(denial),
            _ => None,
        }
    }
}

/// Helper so callers can build a count event from a ticket id and nonce.
pub fn ticket_event_id(ticket_id: &TicketId, nonce: u64) -> String {
    format!("ticket:{}#{nonce}", ticket_id.as_str())
}
