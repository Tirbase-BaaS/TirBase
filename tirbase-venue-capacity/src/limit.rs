// SPDX-License-Identifier: AGPL-3.0-only

//! Capacity limits per scope.
//!
//! Every scope may carry a soft and a hard limit. Crossing the soft limit
//! always alarms but admits. Crossing the hard limit either rejects the
//! passage or admits it with an alarm, per [`HardPolicy`]. A venue-wide limit is
//! mandatory; zone and gate limits are optional and independent of it, so all
//! three are evaluated on every ingress.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, VenueId, ZoneId};

use crate::error::CapacityError;

/// What a hard-limit breach does to the passage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardPolicy {
    /// Refuse the ingress unless an override covers it.
    Reject,
    /// Admit the ingress and raise a hard-limit alarm.
    Alarm,
}

impl HardPolicy {
    pub fn code(&self) -> &'static str {
        match self {
            HardPolicy::Reject => "reject",
            HardPolicy::Alarm => "alarm",
        }
    }
}

/// A soft/hard pair plus the hard-limit behaviour.
///
/// `soft <= hard` is enforced. `soft == hard` is a legal "no amber window"
/// configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityLimit {
    pub soft: u32,
    pub hard: u32,
    pub hard_policy: HardPolicy,
}

impl CapacityLimit {
    /// Build a limit, rejecting `soft > hard`.
    pub fn new(soft: u32, hard: u32, hard_policy: HardPolicy) -> Result<Self, CapacityError> {
        if soft > hard {
            return Err(CapacityError::InvalidConfig(
                "soft limit must not exceed the hard limit",
            ));
        }
        Ok(Self {
            soft,
            hard,
            hard_policy,
        })
    }

    /// A limit that rejects hard-limit breaches.
    pub fn rejecting(soft: u32, hard: u32) -> Result<Self, CapacityError> {
        Self::new(soft, hard, HardPolicy::Reject)
    }

    /// A limit that alarms on hard-limit breaches and admits.
    pub fn alarming(soft: u32, hard: u32) -> Result<Self, CapacityError> {
        Self::new(soft, hard, HardPolicy::Alarm)
    }
}

/// Which envelope a limit or decision belongs to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitScope {
    Venue,
    Zone(ZoneId),
    Gate(GateId),
}

impl LimitScope {
    /// Stable machine code for gateway events and alarm routing.
    pub fn code(&self) -> &'static str {
        match self {
            LimitScope::Venue => "venue",
            LimitScope::Zone(_) => "zone",
            LimitScope::Gate(_) => "gate",
        }
    }
}

impl fmt::Display for LimitScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitScope::Venue => write!(f, "venue"),
            LimitScope::Zone(zone) => write!(f, "zone:{zone}"),
            LimitScope::Gate(gate) => write!(f, "gate:{gate}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ZoneEnvelope {
    limit: CapacityLimit,
    gates: BTreeSet<GateId>,
}

/// The capacity envelope for one venue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityConfig {
    venue_id: VenueId,
    venue: CapacityLimit,
    zones: BTreeMap<ZoneId, ZoneEnvelope>,
    gates: BTreeMap<GateId, CapacityLimit>,
}

impl CapacityConfig {
    /// Start an envelope with the mandatory venue-wide limit.
    pub fn new(venue_id: VenueId, venue: CapacityLimit) -> Self {
        Self {
            venue_id,
            venue,
            zones: BTreeMap::new(),
            gates: BTreeMap::new(),
        }
    }

    /// Add or replace a zone and the gates that serve it.
    pub fn with_zone(
        mut self,
        zone_id: ZoneId,
        limit: CapacityLimit,
        gates: impl IntoIterator<Item = GateId>,
    ) -> Self {
        self.zones.insert(
            zone_id,
            ZoneEnvelope {
                limit,
                gates: gates.into_iter().collect(),
            },
        );
        self
    }

    /// Add or replace a gate's own limit.
    pub fn with_gate_limit(mut self, gate_id: GateId, limit: CapacityLimit) -> Self {
        self.gates.insert(gate_id, limit);
        self
    }

    pub fn venue_id(&self) -> &VenueId {
        &self.venue_id
    }

    pub fn venue_limit(&self) -> CapacityLimit {
        self.venue
    }

    pub fn zone_limit(&self, zone_id: &ZoneId) -> Option<CapacityLimit> {
        self.zones.get(zone_id).map(|zone| zone.limit)
    }

    pub fn gate_limit(&self, gate_id: &GateId) -> Option<CapacityLimit> {
        self.gates.get(gate_id).copied()
    }

    /// The gate's zone, if the gate is in a configured zone.
    pub fn zone_of_gate(&self, gate_id: &GateId) -> Option<&ZoneId> {
        self.zones
            .iter()
            .find(|(_, zone)| zone.gates.contains(gate_id))
            .map(|(zone_id, _)| zone_id)
    }

    /// Zones with their limits, in zone-id order.
    pub fn zones(&self) -> impl Iterator<Item = (&ZoneId, CapacityLimit)> {
        self.zones.iter().map(|(id, zone)| (id, zone.limit))
    }

    /// Every gate in the envelope, whether or not it has its own limit.
    pub fn gates(&self) -> BTreeSet<GateId> {
        self.zones
            .values()
            .flat_map(|zone| zone.gates.iter().cloned())
            .collect()
    }

    /// Validate structural invariants.
    ///
    /// Rejects a gate claimed by two zones, a gate limit for a gate in no zone,
    /// and an invalid limit pair.
    pub fn validate(&self) -> Result<(), CapacityError> {
        CapacityLimit::new(self.venue.soft, self.venue.hard, self.venue.hard_policy)?;
        let mut claimed: BTreeMap<&GateId, &ZoneId> = BTreeMap::new();
        for (zone_id, zone) in &self.zones {
            CapacityLimit::new(zone.limit.soft, zone.limit.hard, zone.limit.hard_policy)?;
            if zone.gates.is_empty() {
                return Err(CapacityError::InvalidConfig(
                    "every zone needs at least one gate",
                ));
            }
            for gate in &zone.gates {
                if claimed.insert(gate, zone_id).is_some() {
                    return Err(CapacityError::InvalidConfig(
                        "a gate belongs to more than one zone",
                    ));
                }
            }
        }
        for gate in self.gates.keys() {
            if !claimed.contains_key(gate) {
                return Err(CapacityError::InvalidConfig(
                    "a gate limit names a gate in no zone",
                ));
            }
        }
        Ok(())
    }
}
