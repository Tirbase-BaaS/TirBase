// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned venue topology: venue → zone → gate → reader → turnstile.
//!
//! A [`TopologyVersion`] is an immutable snapshot of the venue hierarchy with an
//! effective time window. Validation enforces parent/child integrity and unique
//! identifiers within the version.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::VenueError;
use crate::ids::{GateId, ReaderId, TopologyVersionId, TurnstileId, VenueId, ZoneId};

/// Inclusive-exclusive effective window in UTC microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct EffectiveWindow {
    /// Inclusive start, UTC microseconds since Unix epoch.
    pub from_utc_us: i64,
    /// Exclusive end, UTC microseconds since Unix epoch. `None` means open-ended.
    pub until_utc_us: Option<i64>,
}

impl EffectiveWindow {
    /// Create a validated effective window.
    pub fn new(from_utc_us: i64, until_utc_us: Option<i64>) -> Result<Self, VenueError> {
        if let Some(until) = until_utc_us {
            if until <= from_utc_us {
                return Err(VenueError::InvalidEffectiveWindow);
            }
        }
        Ok(Self {
            from_utc_us,
            until_utc_us,
        })
    }

    /// Returns true if `ts_utc_us` is within `[from, until)`.
    pub fn contains(&self, ts_utc_us: i64) -> bool {
        if ts_utc_us < self.from_utc_us {
            return false;
        }
        match self.until_utc_us {
            Some(until) => ts_utc_us < until,
            None => true,
        }
    }

    /// Returns true if two windows overlap.
    pub fn overlaps(&self, other: &Self) -> bool {
        let a_end = self.until_utc_us.unwrap_or(i64::MAX);
        let b_end = other.until_utc_us.unwrap_or(i64::MAX);
        self.from_utc_us < b_end && other.from_utc_us < a_end
    }
}

/// Venue root node.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Venue {
    pub id: VenueId,
    pub name: String,
}

/// A zone within a venue (e.g. bowl, concourse, VIP area).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Zone {
    pub id: ZoneId,
    pub venue_id: VenueId,
    pub name: String,
}

/// A gate within a zone.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Gate {
    pub id: GateId,
    pub zone_id: ZoneId,
    pub name: String,
}

/// A credential reader attached to a gate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Reader {
    pub id: ReaderId,
    pub gate_id: GateId,
    pub name: String,
}

/// A turnstile attached to a gate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Turnstile {
    pub id: TurnstileId,
    pub gate_id: GateId,
    pub name: String,
}

/// An immutable, versioned topology snapshot for one venue.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TopologyVersion {
    pub id: TopologyVersionId,
    pub venue: Venue,
    pub effective: EffectiveWindow,
    zones: BTreeMap<ZoneId, Zone>,
    gates: BTreeMap<GateId, Gate>,
    readers: BTreeMap<ReaderId, Reader>,
    turnstiles: BTreeMap<TurnstileId, Turnstile>,
}

impl TopologyVersion {
    /// Build and validate a topology version.
    ///
    /// Validation enforces: non-empty names, unique ids, and strict parent-child
    /// integrity (zone→venue, gate→zone, reader→gate, turnstile→gate).
    pub fn new(
        id: TopologyVersionId,
        venue: Venue,
        effective: EffectiveWindow,
        zones: Vec<Zone>,
        gates: Vec<Gate>,
        readers: Vec<Reader>,
        turnstiles: Vec<Turnstile>,
    ) -> Result<Self, VenueError> {
        if venue.name.trim().is_empty() {
            return Err(VenueError::InvalidIdentifier("venue name"));
        }

        let mut zone_map = BTreeMap::new();
        for z in zones {
            if z.name.trim().is_empty() {
                return Err(VenueError::InvalidIdentifier("zone name"));
            }
            if z.venue_id != venue.id {
                return Err(VenueError::HierarchyMismatch(
                    "zone venue_id does not match topology venue",
                ));
            }
            if zone_map.insert(z.id.clone(), z).is_some() {
                return Err(VenueError::DuplicateId("zone id"));
            }
        }

        let mut gate_map = BTreeMap::new();
        for g in gates {
            if g.name.trim().is_empty() {
                return Err(VenueError::InvalidIdentifier("gate name"));
            }
            if !zone_map.contains_key(&g.zone_id) {
                return Err(VenueError::HierarchyMismatch(
                    "gate references unknown zone",
                ));
            }
            if gate_map.insert(g.id.clone(), g).is_some() {
                return Err(VenueError::DuplicateId("gate id"));
            }
        }

        let mut reader_map = BTreeMap::new();
        for r in readers {
            if r.name.trim().is_empty() {
                return Err(VenueError::InvalidIdentifier("reader name"));
            }
            if !gate_map.contains_key(&r.gate_id) {
                return Err(VenueError::HierarchyMismatch(
                    "reader references unknown gate",
                ));
            }
            if reader_map.insert(r.id.clone(), r).is_some() {
                return Err(VenueError::DuplicateId("reader id"));
            }
        }

        let mut turnstile_map = BTreeMap::new();
        for t in turnstiles {
            if t.name.trim().is_empty() {
                return Err(VenueError::InvalidIdentifier("turnstile name"));
            }
            if !gate_map.contains_key(&t.gate_id) {
                return Err(VenueError::HierarchyMismatch(
                    "turnstile references unknown gate",
                ));
            }
            if turnstile_map.insert(t.id.clone(), t).is_some() {
                return Err(VenueError::DuplicateId("turnstile id"));
            }
        }

        Ok(Self {
            id,
            venue,
            effective,
            zones: zone_map,
            gates: gate_map,
            readers: reader_map,
            turnstiles: turnstile_map,
        })
    }

    pub fn venue_id(&self) -> &VenueId {
        &self.venue.id
    }

    pub fn zone(&self, id: &ZoneId) -> Option<&Zone> {
        self.zones.get(id)
    }

    pub fn gate(&self, id: &GateId) -> Option<&Gate> {
        self.gates.get(id)
    }

    pub fn reader(&self, id: &ReaderId) -> Option<&Reader> {
        self.readers.get(id)
    }

    pub fn turnstile(&self, id: &TurnstileId) -> Option<&Turnstile> {
        self.turnstiles.get(id)
    }

    pub fn zones(&self) -> impl Iterator<Item = &Zone> {
        self.zones.values()
    }

    pub fn gates(&self) -> impl Iterator<Item = &Gate> {
        self.gates.values()
    }

    pub fn readers(&self) -> impl Iterator<Item = &Reader> {
        self.readers.values()
    }

    pub fn turnstiles(&self) -> impl Iterator<Item = &Turnstile> {
        self.turnstiles.values()
    }

    /// Gates belonging to a zone, in deterministic id order.
    pub fn gates_in_zone(&self, zone_id: &ZoneId) -> Vec<&Gate> {
        self.gates
            .values()
            .filter(|g| &g.zone_id == zone_id)
            .collect()
    }

    /// Readers belonging to a gate, in deterministic id order.
    pub fn readers_in_gate(&self, gate_id: &GateId) -> Vec<&Reader> {
        self.readers
            .values()
            .filter(|r| &r.gate_id == gate_id)
            .collect()
    }

    /// Turnstiles belonging to a gate, in deterministic id order.
    pub fn turnstiles_in_gate(&self, gate_id: &GateId) -> Vec<&Turnstile> {
        self.turnstiles
            .values()
            .filter(|t| &t.gate_id == gate_id)
            .collect()
    }

    /// Resolve the zone for a gate.
    pub fn zone_for_gate(&self, gate_id: &GateId) -> Option<&ZoneId> {
        self.gates.get(gate_id).map(|g| &g.zone_id)
    }

    /// Validate that a gate belongs to a zone in this topology.
    pub fn gate_in_zone(&self, gate_id: &GateId, zone_id: &ZoneId) -> bool {
        self.gates
            .get(gate_id)
            .map(|g| &g.zone_id == zone_id)
            .unwrap_or(false)
    }
}

/// Registry of topology versions for venues, enforcing non-overlapping effective
/// windows per venue.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TopologyRegistry {
    versions: Vec<TopologyVersion>,
}

impl TopologyRegistry {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
        }
    }

    /// Insert a version, rejecting overlaps for the same venue.
    pub fn insert(&mut self, version: TopologyVersion) -> Result<(), VenueError> {
        if self.versions.iter().any(|v| v.id == version.id) {
            return Err(VenueError::DuplicateId("topology version id"));
        }
        for existing in &self.versions {
            if existing.venue_id() == version.venue_id()
                && existing.effective.overlaps(&version.effective)
            {
                return Err(VenueError::OverlappingTopologyVersions {
                    venue_id: version.venue_id().clone(),
                    existing: existing.id.clone(),
                });
            }
        }
        self.versions.push(version);
        // Keep deterministic order: venue, effective_from, id
        self.versions.sort_by(|a, b| {
            a.venue_id()
                .cmp(b.venue_id())
                .then(a.effective.from_utc_us.cmp(&b.effective.from_utc_us))
                .then(a.id.cmp(&b.id))
        });
        Ok(())
    }

    /// Find the effective topology for a venue at a timestamp.
    pub fn effective_for(&self, venue_id: &VenueId, ts_utc_us: i64) -> Option<&TopologyVersion> {
        self.versions
            .iter()
            .find(|v| v.venue_id() == venue_id && v.effective.contains(ts_utc_us))
    }

    /// Get a version by id.
    pub fn get(&self, id: &TopologyVersionId) -> Option<&TopologyVersion> {
        self.versions.iter().find(|v| &v.id == id)
    }

    /// All versions for a venue, in deterministic effective order.
    pub fn versions_for_venue(&self, venue_id: &VenueId) -> Vec<&TopologyVersion> {
        self.versions
            .iter()
            .filter(|v| v.venue_id() == venue_id)
            .collect()
    }
}

/// Helper: collect all gate ids in the topology.
pub fn gate_ids(topology: &TopologyVersion) -> BTreeSet<GateId> {
    topology.gates().map(|g| g.id.clone()).collect()
}

/// Helper: collect all zone ids in the topology.
pub fn zone_ids(topology: &TopologyVersion) -> BTreeSet<ZoneId> {
    topology.zones().map(|z| z.id.clone()).collect()
}
