// SPDX-License-Identifier: AGPL-3.0-only

//! Access rules and deterministic policy resolution.
//!
//! A ticket maps to exactly one allowed gate/zone policy for a given scan.

use std::collections::BTreeMap;

use crate::error::VenueError;
use crate::ids::{AccessPolicyId, GateId, TicketId, TicketTypeId, ZoneId};
use crate::space::{TicketClass, TicketType};
use crate::topology::TopologyVersion;

/// Inclusive-exclusive time window in UTC microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TimeWindow {
    pub from_utc_us: i64,
    pub until_utc_us: i64,
}

impl TimeWindow {
    pub fn new(from_utc_us: i64, until_utc_us: i64) -> Result<Self, VenueError> {
        if until_utc_us <= from_utc_us {
            return Err(VenueError::InvalidTimeWindow);
        }
        Ok(Self {
            from_utc_us,
            until_utc_us,
        })
    }

    pub fn contains(&self, ts_utc_us: i64) -> bool {
        ts_utc_us >= self.from_utc_us && ts_utc_us < self.until_utc_us
    }
}

/// Selects which tickets an access policy applies to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketSelector {
    /// Applies to a specific ticket type.
    TicketType(TicketTypeId),
    /// Applies to any ticket of the given class (General/VIP/Staff/ADA/Other).
    TicketClass(TicketClass),
}

impl TicketSelector {
    pub fn matches(&self, ticket_type: &TicketType) -> bool {
        match self {
            TicketSelector::TicketType(id) => &ticket_type.id == id,
            TicketSelector::TicketClass(class) => &ticket_type.class == class,
        }
    }
}

/// An access rule granting entry through a gate into a zone.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessPolicy {
    pub id: AccessPolicyId,
    pub name: String,
    pub selector: TicketSelector,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    pub time_window: TimeWindow,
    pub enabled: bool,
}

impl AccessPolicy {
    pub fn matches(
        &self,
        ticket_type: &TicketType,
        gate_id: &GateId,
        zone_id: &ZoneId,
        ts_utc_us: i64,
    ) -> bool {
        self.enabled
            && &self.gate_id == gate_id
            && &self.zone_id == zone_id
            && self.time_window.contains(ts_utc_us)
            && self.selector.matches(ticket_type)
    }
}

/// A ticket instance presented at a gate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ticket {
    pub id: TicketId,
    pub ticket_type_id: TicketTypeId,
}

impl Ticket {
    /// Create a ticket instance bound to a ticket type.
    pub fn new(id: TicketId, ticket_type_id: TicketTypeId) -> Self {
        Self { id, ticket_type_id }
    }
}

/// Result of resolving access for a ticket at a gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessDecision {
    pub ticket_id: TicketId,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    pub policy_id: AccessPolicyId,
}

/// Detailed resolution outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyResolution {
    /// Exactly one policy allows access.
    Allowed(AccessDecision),
    /// No policy allows access.
    Denied { reason: &'static str },
    /// More than one policy allows access - rejected as ambiguous.
    Ambiguous { policy_ids: Vec<AccessPolicyId> },
}

/// Registry of access policies with deterministic resolution.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessPolicyRegistry {
    policies: BTreeMap<AccessPolicyId, AccessPolicy>,
}

impl AccessPolicyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: AccessPolicy) -> Result<(), VenueError> {
        if policy.name.trim().is_empty() {
            return Err(VenueError::InvalidIdentifier("access policy name"));
        }
        if self.policies.insert(policy.id.clone(), policy).is_some() {
            return Err(VenueError::DuplicateId("access policy id"));
        }
        Ok(())
    }

    pub fn get(&self, id: &AccessPolicyId) -> Option<&AccessPolicy> {
        self.policies.get(id)
    }

    pub fn policies(&self) -> impl Iterator<Item = &AccessPolicy> {
        self.policies.values()
    }

    /// Resolve a ticket scan to exactly one allowed gate/zone policy.
    ///
    /// Checks: gate exists in topology, gate belongs to zone, ticket type is
    /// known, and exactly one enabled policy matches the (ticket, gate, zone,
    /// time) tuple.
    pub fn resolve(
        &self,
        topology: &TopologyVersion,
        ticket_types: &BTreeMap<TicketTypeId, TicketType>,
        ticket: &Ticket,
        gate_id: &GateId,
        ts_utc_us: i64,
    ) -> Result<AccessDecision, VenueError> {
        let gate = topology
            .gate(gate_id)
            .ok_or_else(|| VenueError::UnknownGate(gate_id.clone()))?;
        let zone_id = &gate.zone_id;
        let ticket_type = ticket_types
            .get(&ticket.ticket_type_id)
            .ok_or_else(|| VenueError::UnknownTicketType(ticket.ticket_type_id.clone()))?;

        let mut matches: Vec<&AccessPolicy> = self
            .policies
            .values()
            .filter(|p| p.matches(ticket_type, gate_id, zone_id, ts_utc_us))
            .collect();
        // BTreeMap iteration is deterministic by id; preserve that order.
        matches.sort_by(|a, b| a.id.cmp(&b.id));

        match matches.len() {
            0 => Err(VenueError::AccessDenied(
                "no enabled policy matches ticket, gate, zone and time window",
            )),
            1 => {
                let p = matches[0];
                Ok(AccessDecision {
                    ticket_id: ticket.id.clone(),
                    gate_id: gate_id.clone(),
                    zone_id: zone_id.clone(),
                    policy_id: p.id.clone(),
                })
            }
            _ => Err(VenueError::AmbiguousPolicy {
                ticket_type: ticket.ticket_type_id.clone(),
                gate_id: gate_id.clone(),
                policy_ids: matches.iter().map(|p| p.id.clone()).collect(),
            }),
        }
    }

    /// Resolve using a space model for ticket-type lookup.
    pub fn resolve_in_space(
        &self,
        topology: &TopologyVersion,
        space: &crate::space::SpaceModel,
        ticket: &Ticket,
        gate_id: &GateId,
        ts_utc_us: i64,
    ) -> Result<AccessDecision, VenueError> {
        self.resolve(
            topology,
            space.ticket_types_map(),
            ticket,
            gate_id,
            ts_utc_us,
        )
    }

    /// Resolve with an explicit zone target (must match the gate's zone).
    pub fn resolve_for_zone(
        &self,
        topology: &TopologyVersion,
        ticket_types: &BTreeMap<TicketTypeId, TicketType>,
        ticket: &Ticket,
        gate_id: &GateId,
        zone_id: &ZoneId,
        ts_utc_us: i64,
    ) -> Result<AccessDecision, VenueError> {
        let gate = topology
            .gate(gate_id)
            .ok_or_else(|| VenueError::UnknownGate(gate_id.clone()))?;
        if &gate.zone_id != zone_id {
            return Err(VenueError::HierarchyMismatch(
                "gate does not belong to requested zone",
            ));
        }
        self.resolve(topology, ticket_types, ticket, gate_id, ts_utc_us)
    }
}
