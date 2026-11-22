// SPDX-License-Identifier: AGPL-3.0-only

//! Venue ingest hub: registers point mappings and folds readings into the venue
//! model, raising health events for stale points and link failures.

use std::collections::BTreeMap;

use tirbase_venue::{GateId, TopologyVersion, ZoneId};

use crate::error::GatewayError;
use crate::health::{BackoffPolicy, ConnectionSupervisor, HealthEvent, HealthEventRecord};
use crate::ids::{EquipmentId, PointId};
use crate::point::{
    DecodedPoint, PointKind, PointMapping, PointTarget, PointUpdate, PointValue, Protocol,
    SafetyClass, VenueSnapshot,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PointState {
    value: Option<PointValue>,
    last_seen_utc_us: Option<i64>,
    stale: bool,
}

/// Ingest gateway for one venue topology version.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VenueGateway {
    topology: TopologyVersion,
    stale_after_us: i64,
    mappings: BTreeMap<PointId, PointMapping>,
    index: BTreeMap<String, PointId>,
    states: BTreeMap<PointId, PointState>,
    supervisors: BTreeMap<Protocol, ConnectionSupervisor>,
    events: Vec<HealthEventRecord>,
}

impl VenueGateway {
    /// Create a gateway for a topology version.
    ///
    /// `stale_after_us` is the age after which a live point without a fresh
    /// reading raises a `PointStale` event.
    pub fn new(topology: TopologyVersion, stale_after_us: i64) -> Result<Self, GatewayError> {
        if stale_after_us <= 0 {
            return Err(GatewayError::InvalidConfig("stale_after_us must be > 0"));
        }
        let supervisors = Protocol::ALL
            .into_iter()
            .map(|protocol| {
                (
                    protocol,
                    ConnectionSupervisor::new(protocol, BackoffPolicy::default()),
                )
            })
            .collect();
        Ok(Self {
            topology,
            stale_after_us,
            mappings: BTreeMap::new(),
            index: BTreeMap::new(),
            states: BTreeMap::new(),
            supervisors,
            events: Vec::new(),
        })
    }

    pub fn topology(&self) -> &TopologyVersion {
        &self.topology
    }

    pub fn stale_after_us(&self) -> i64 {
        self.stale_after_us
    }

    /// Register a point mapping after validating its address and target.
    pub fn register(&mut self, mapping: PointMapping) -> Result<(), GatewayError> {
        mapping.validate()?;
        if self.mappings.contains_key(&mapping.point_id) {
            return Err(GatewayError::DuplicatePoint(mapping.point_id));
        }
        let key = mapping.address.key();
        if self.index.contains_key(&key) {
            return Err(GatewayError::DuplicateAddress(key));
        }
        self.validate_target(&mapping.target)?;

        self.index.insert(key, mapping.point_id.clone());
        self.states
            .insert(mapping.point_id.clone(), PointState::default());
        self.mappings.insert(mapping.point_id.clone(), mapping);
        Ok(())
    }

    fn validate_target(&self, target: &PointTarget) -> Result<(), GatewayError> {
        match target {
            PointTarget::Gate { gate_id } => {
                if self.topology.gate(gate_id).is_none() {
                    return Err(GatewayError::UnknownGate(gate_id.clone()));
                }
            }
            PointTarget::Occupancy { zone_id }
            | PointTarget::Environment { zone_id }
            | PointTarget::Equipment { zone_id, .. } => {
                if self.topology.zone(zone_id).is_none() {
                    return Err(GatewayError::UnknownZone(zone_id.clone()));
                }
            }
        }
        Ok(())
    }

    /// Fold one decoded protocol reading into the venue model.
    pub fn ingest(
        &mut self,
        decoded: DecodedPoint,
        observed_utc_us: i64,
    ) -> Result<PointUpdate, GatewayError> {
        let key = decoded.address.key();
        let point_id = self
            .index
            .get(&key)
            .cloned()
            .ok_or(GatewayError::UnknownPointAddress(key))?;
        let mapping = self
            .mappings
            .get(&point_id)
            .cloned()
            .ok_or_else(|| GatewayError::UnknownPoint(point_id.clone()))?;

        let state = self
            .states
            .get_mut(&point_id)
            .ok_or_else(|| GatewayError::UnknownPoint(point_id.clone()))?;
        let recovered = state.stale;
        state.value = Some(decoded.value.clone());
        state.last_seen_utc_us = Some(observed_utc_us);
        state.stale = false;

        if recovered {
            self.events.push(HealthEventRecord::new(
                observed_utc_us,
                HealthEvent::PointRecovered {
                    point_id: point_id.clone(),
                    last_seen_utc_us: observed_utc_us,
                },
            ));
        }

        Ok(PointUpdate {
            point_id,
            target: mapping.target,
            value: decoded.value,
            recovered,
        })
    }

    /// Advance the stale clock. Each point that crosses the stale threshold
    /// raises exactly one `PointStale` event until it is refreshed.
    pub fn tick(&mut self, now_utc_us: i64) -> Vec<HealthEventRecord> {
        let mut raised = Vec::new();
        for (point_id, state) in self.states.iter_mut() {
            if state.stale {
                continue;
            }
            let Some(last_seen) = state.last_seen_utc_us else {
                continue;
            };
            if now_utc_us.saturating_sub(last_seen) > self.stale_after_us {
                state.stale = true;
                raised.push(HealthEventRecord::new(
                    now_utc_us,
                    HealthEvent::PointStale {
                        point_id: point_id.clone(),
                        last_seen_utc_us: last_seen,
                        stale_after_us: self.stale_after_us,
                    },
                ));
            }
        }
        self.events.extend(raised.iter().cloned());
        raised
    }

    /// Mark a protocol link up, emitting a recovery event when applicable.
    pub fn mark_connected(
        &mut self,
        protocol: Protocol,
        now_utc_us: i64,
    ) -> Option<HealthEventRecord> {
        let supervisor = self.supervisors.get_mut(&protocol)?;
        let event = supervisor.connected()?;
        let record = HealthEventRecord::new(now_utc_us, event);
        self.events.push(record.clone());
        Some(record)
    }

    /// Record a failed connection attempt for a protocol link.
    pub fn mark_failed(
        &mut self,
        protocol: Protocol,
        now_utc_us: i64,
    ) -> Option<HealthEventRecord> {
        let supervisor = self.supervisors.get_mut(&protocol)?;
        let event = supervisor.disconnected(now_utc_us);
        let record = HealthEventRecord::new(now_utc_us, event);
        self.events.push(record.clone());
        Some(record)
    }

    pub fn supervisor(&self, protocol: Protocol) -> Option<&ConnectionSupervisor> {
        self.supervisors.get(&protocol)
    }

    pub fn health_events(&self) -> &[HealthEventRecord] {
        &self.events
    }

    pub fn drain_health_events(&mut self) -> Vec<HealthEventRecord> {
        std::mem::take(&mut self.events)
    }

    pub fn mapping(&self, point_id: &PointId) -> Option<&PointMapping> {
        self.mappings.get(point_id)
    }

    pub fn mappings(&self) -> impl Iterator<Item = &PointMapping> {
        self.mappings.values()
    }

    pub fn point_value(&self, point_id: &PointId) -> Option<&PointValue> {
        self.states.get(point_id)?.value.as_ref()
    }

    pub fn is_stale(&self, point_id: &PointId) -> bool {
        self.states
            .get(point_id)
            .map(|state| state.stale)
            .unwrap_or(false)
    }

    pub fn stale_points(&self) -> Vec<PointId> {
        self.states
            .iter()
            .filter(|(_, state)| state.stale)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Points classified as belonging to a fire/life-safety system.
    pub fn life_safety_points(&self) -> Vec<&PointMapping> {
        self.mappings
            .values()
            .filter(|mapping| mapping.safety == SafetyClass::LifeSafety)
            .collect()
    }

    /// Points grouped by their venue target.
    pub fn snapshot(&self) -> VenueSnapshot {
        let mut snapshot = VenueSnapshot::default();
        for mapping in self.mappings.values() {
            match &mapping.target {
                PointTarget::Gate { gate_id } => snapshot
                    .gates
                    .entry(gate_id.clone())
                    .or_default()
                    .push(mapping.point_id.clone()),
                PointTarget::Occupancy { zone_id } => snapshot
                    .occupancy
                    .entry(zone_id.clone())
                    .or_default()
                    .push(mapping.point_id.clone()),
                PointTarget::Environment { zone_id } => snapshot
                    .environment
                    .entry(zone_id.clone())
                    .or_default()
                    .push(mapping.point_id.clone()),
                PointTarget::Equipment { equipment_id, .. } => snapshot
                    .equipment
                    .entry(equipment_id.clone())
                    .or_default()
                    .push(mapping.point_id.clone()),
            }
        }
        snapshot
    }

    /// Sum of live occupancy points for a zone, saturating at `u32::MAX`.
    pub fn occupancy_total(&self, zone_id: &ZoneId) -> u32 {
        self.mappings
            .values()
            .filter(|mapping| mapping.target.kind() == PointKind::Occupancy)
            .filter(|mapping| mapping.target.zone_id() == Some(zone_id))
            .filter(|mapping| !self.is_stale(&mapping.point_id))
            .filter_map(|mapping| self.point_value(&mapping.point_id))
            .filter_map(PointValue::as_count)
            .fold(0u32, u32::saturating_add)
    }

    /// Gate ids that receive at least one mapped point.
    pub fn gates_with_points(&self) -> Vec<GateId> {
        self.snapshot().gates.into_keys().collect()
    }

    /// Equipment ids that receive at least one mapped point.
    pub fn equipment_with_points(&self) -> Vec<EquipmentId> {
        self.snapshot().equipment.into_keys().collect()
    }
}
