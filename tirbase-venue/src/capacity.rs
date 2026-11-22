// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic capacity attribution across zones and gates.
//!
//! Capacity is derived from the immutable venue topology plus the space model:
//!
//! * a zone contributes one seat per seat in its sections, plus the declared
//!   capacity of every standing area assigned to it;
//! * a zone's total is distributed across its gates in gate-id order, with the
//!   remainder seats assigned to the first gates in that order.
//!
//! Attribution therefore depends only on the set of entities, never on the
//! order in which they were inserted or iterated, and the sum of gate
//! contributions always equals the zone total.

use std::collections::BTreeMap;

use crate::error::VenueError;
use crate::ids::{GateId, ZoneId};
use crate::space::SpaceModel;
use crate::topology::TopologyVersion;

/// Capacity attributed to one zone.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZoneCapacity {
    pub zone_id: ZoneId,
    /// Seats counted from the zone's seated/mixed sections.
    pub seated: u32,
    /// Sum of the declared standing-area capacities in the zone.
    pub standing: u32,
    /// `seated + standing`.
    pub total: u32,
}

/// Capacity attributed to one gate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateCapacityContribution {
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    /// This gate's deterministic share of its zone's total capacity.
    pub capacity: u32,
}

/// Capacity contribution per zone and per gate for one topology version.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapacityAttribution {
    zones: BTreeMap<ZoneId, ZoneCapacity>,
    gates: BTreeMap<GateId, GateCapacityContribution>,
    total: u32,
}

impl CapacityAttribution {
    /// Compute capacity attribution for a topology version and space model.
    ///
    /// Fails if the space model references a zone outside the topology, if a
    /// count overflows, or if a zone has capacity but no gate to attribute it
    /// to.
    pub fn compute(topology: &TopologyVersion, space: &SpaceModel) -> Result<Self, VenueError> {
        let mut zones: BTreeMap<ZoneId, ZoneCapacity> = topology
            .zones()
            .map(|zone| {
                (
                    zone.id.clone(),
                    ZoneCapacity {
                        zone_id: zone.id.clone(),
                        seated: 0,
                        standing: 0,
                        total: 0,
                    },
                )
            })
            .collect();

        let mut seats_by_section = BTreeMap::new();
        for seat in space.seats() {
            let count: &mut u32 = seats_by_section.entry(seat.section_id.clone()).or_insert(0);
            *count = count.checked_add(1).ok_or(VenueError::ArithmeticOverflow)?;
        }

        for section in space.sections() {
            let zone = zones
                .get_mut(&section.zone_id)
                .ok_or_else(|| VenueError::UnknownZone(section.zone_id.clone()))?;
            let seats = seats_by_section.get(&section.id).copied().unwrap_or(0);
            zone.seated = zone
                .seated
                .checked_add(seats)
                .ok_or(VenueError::ArithmeticOverflow)?;
        }

        for area in space.standing_areas() {
            let zone = zones
                .get_mut(&area.zone_id)
                .ok_or_else(|| VenueError::UnknownZone(area.zone_id.clone()))?;
            zone.standing = zone
                .standing
                .checked_add(area.capacity)
                .ok_or(VenueError::ArithmeticOverflow)?;
        }

        let mut gates = BTreeMap::new();
        let mut total: u32 = 0;
        for zone in zones.values_mut() {
            zone.total = zone
                .seated
                .checked_add(zone.standing)
                .ok_or(VenueError::ArithmeticOverflow)?;
            total = total
                .checked_add(zone.total)
                .ok_or(VenueError::ArithmeticOverflow)?;

            let gate_ids: Vec<GateId> = topology
                .gates_in_zone(&zone.zone_id)
                .into_iter()
                .map(|gate| gate.id.clone())
                .collect();
            if gate_ids.is_empty() {
                if zone.total > 0 {
                    return Err(VenueError::InvalidCapacity(
                        "zone has capacity but no gates to attribute it to",
                    ));
                }
                continue;
            }

            let gate_count = gate_ids.len() as u32;
            let share = zone.total / gate_count;
            let remainder = zone.total % gate_count;
            for (index, gate_id) in gate_ids.into_iter().enumerate() {
                let extra = if (index as u32) < remainder { 1 } else { 0 };
                let contribution = GateCapacityContribution {
                    gate_id: gate_id.clone(),
                    zone_id: zone.zone_id.clone(),
                    capacity: share + extra,
                };
                gates.insert(gate_id, contribution);
            }
        }

        Ok(Self {
            zones,
            gates,
            total,
        })
    }

    /// Capacity attributed to a zone, if the zone exists in the topology.
    pub fn zone(&self, zone_id: &ZoneId) -> Option<&ZoneCapacity> {
        self.zones.get(zone_id)
    }

    /// Capacity attributed to a gate, if the gate exists in the topology.
    pub fn gate(&self, gate_id: &GateId) -> Option<&GateCapacityContribution> {
        self.gates.get(gate_id)
    }

    /// Zone contributions in deterministic zone-id order.
    pub fn zones(&self) -> impl Iterator<Item = &ZoneCapacity> {
        self.zones.values()
    }

    /// Gate contributions in deterministic gate-id order.
    pub fn gates(&self) -> impl Iterator<Item = &GateCapacityContribution> {
        self.gates.values()
    }

    /// Total seated plus standing capacity across all zones.
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Sum of all gate contributions for a zone.
    pub fn gate_total_for_zone(&self, zone_id: &ZoneId) -> u32 {
        self.gates
            .values()
            .filter(|contribution| &contribution.zone_id == zone_id)
            .fold(0_u32, |acc, contribution| {
                acc.saturating_add(contribution.capacity)
            })
    }
}
