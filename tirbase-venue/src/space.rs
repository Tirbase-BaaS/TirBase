// SPDX-License-Identifier: AGPL-3.0-only

//! Seat, section, standing-area and ticket-type model.

use std::collections::BTreeMap;

use crate::error::VenueError;
use crate::ids::{SeatId, SectionId, StandingAreaId, TicketTypeId, ZoneId};

/// Ticket class used by access rules.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TicketClass {
    General,
    Vip,
    Staff,
    Ada,
    /// Vendor/integrator-defined class.
    Other(String),
}

impl TicketClass {
    pub fn as_str(&self) -> &str {
        match self {
            TicketClass::General => "general",
            TicketClass::Vip => "vip",
            TicketClass::Staff => "staff",
            TicketClass::Ada => "ada",
            TicketClass::Other(s) => s.as_str(),
        }
    }
}

/// Kind of section/area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionKind {
    Seated,
    Standing,
    Mixed,
}

/// A seating section in a zone.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Section {
    pub id: SectionId,
    pub zone_id: ZoneId,
    pub name: String,
    pub kind: SectionKind,
}

/// An individual seat in a seated or mixed section.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Seat {
    pub id: SeatId,
    pub section_id: SectionId,
    pub label: String,
}

/// A standing area in a zone.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StandingArea {
    pub id: StandingAreaId,
    pub zone_id: ZoneId,
    pub name: String,
    /// Maximum occupants for this standing area.
    pub capacity: u32,
}

/// A ticket type offered for the event/venue.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TicketType {
    pub id: TicketTypeId,
    pub name: String,
    pub class: TicketClass,
    /// Optional section binding for seated tickets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<SectionId>,
    /// Optional standing area binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing_area_id: Option<StandingAreaId>,
}

/// Container for space/ticket-type definitions, with basic validation.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpaceModel {
    sections: BTreeMap<SectionId, Section>,
    seats: BTreeMap<SeatId, Seat>,
    standing_areas: BTreeMap<StandingAreaId, StandingArea>,
    ticket_types: BTreeMap<TicketTypeId, TicketType>,
}

impl SpaceModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_section(&mut self, section: Section) -> Result<(), VenueError> {
        if section.name.trim().is_empty() {
            return Err(VenueError::InvalidIdentifier("section name"));
        }
        if self.sections.insert(section.id.clone(), section).is_some() {
            return Err(VenueError::DuplicateId("section id"));
        }
        Ok(())
    }

    pub fn add_seat(&mut self, seat: Seat) -> Result<(), VenueError> {
        if seat.label.trim().is_empty() {
            return Err(VenueError::InvalidIdentifier("seat label"));
        }
        let section = self
            .sections
            .get(&seat.section_id)
            .ok_or_else(|| VenueError::UnknownSection(seat.section_id.clone()))?;
        if matches!(section.kind, SectionKind::Standing) {
            return Err(VenueError::HierarchyMismatch(
                "seat cannot belong to standing-only section",
            ));
        }
        if self.seats.insert(seat.id.clone(), seat).is_some() {
            return Err(VenueError::DuplicateId("seat id"));
        }
        Ok(())
    }

    pub fn add_standing_area(&mut self, area: StandingArea) -> Result<(), VenueError> {
        if area.name.trim().is_empty() {
            return Err(VenueError::InvalidIdentifier("standing area name"));
        }
        if area.capacity == 0 {
            return Err(VenueError::InvalidCapacity(
                "standing area capacity must be > 0",
            ));
        }
        if self.standing_areas.insert(area.id.clone(), area).is_some() {
            return Err(VenueError::DuplicateId("standing area id"));
        }
        Ok(())
    }

    pub fn add_ticket_type(&mut self, ticket_type: TicketType) -> Result<(), VenueError> {
        if ticket_type.name.trim().is_empty() {
            return Err(VenueError::InvalidIdentifier("ticket type name"));
        }
        if let Some(ref section_id) = ticket_type.section_id {
            if !self.sections.contains_key(section_id) {
                return Err(VenueError::UnknownSection(section_id.clone()));
            }
        }
        if let Some(ref area_id) = ticket_type.standing_area_id {
            if !self.standing_areas.contains_key(area_id) {
                return Err(VenueError::UnknownStandingArea(area_id.clone()));
            }
        }
        if self
            .ticket_types
            .insert(ticket_type.id.clone(), ticket_type)
            .is_some()
        {
            return Err(VenueError::DuplicateId("ticket type id"));
        }
        Ok(())
    }

    pub fn section(&self, id: &SectionId) -> Option<&Section> {
        self.sections.get(id)
    }

    pub fn seat(&self, id: &SeatId) -> Option<&Seat> {
        self.seats.get(id)
    }

    pub fn standing_area(&self, id: &StandingAreaId) -> Option<&StandingArea> {
        self.standing_areas.get(id)
    }

    pub fn ticket_type(&self, id: &TicketTypeId) -> Option<&TicketType> {
        self.ticket_types.get(id)
    }

    pub fn ticket_types(&self) -> impl Iterator<Item = &TicketType> {
        self.ticket_types.values()
    }

    pub fn sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.values()
    }

    pub fn standing_areas(&self) -> impl Iterator<Item = &StandingArea> {
        self.standing_areas.values()
    }

    pub fn seats(&self) -> impl Iterator<Item = &Seat> {
        self.seats.values()
    }

    /// Ticket types keyed by id, for access-policy resolution.
    pub fn ticket_types_map(&self) -> &BTreeMap<TicketTypeId, TicketType> {
        &self.ticket_types
    }

    /// Sections assigned to a zone, in deterministic id order.
    pub fn sections_in_zone(&self, zone_id: &ZoneId) -> Vec<&Section> {
        self.sections
            .values()
            .filter(|section| &section.zone_id == zone_id)
            .collect()
    }

    /// Seats in a section, in deterministic id order.
    pub fn seats_in_section(&self, section_id: &SectionId) -> Vec<&Seat> {
        self.seats
            .values()
            .filter(|seat| &seat.section_id == section_id)
            .collect()
    }
}

/// A convenience grouping for area types referenced by capacity/tickets.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceArea {
    Section(SectionId),
    StandingArea(StandingAreaId),
}
