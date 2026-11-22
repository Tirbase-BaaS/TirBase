// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue — Venue topology, access and capacity model
//!
//! ST-01 domain model: venue topology, zones, gates, readers, turnstiles,
//! seats/sections/standing areas, ticket types, access rules, anti-passback,
//! re-entry policy, and deterministic capacity attribution.
//!
//! Depends on F-03 identity/tenancy concepts (tenant levels already include
//! venue/zone/gate). This crate provides the venue-domain model; protocol,
//! gateway, UI and commercial integrations are handled by later ST prompts.

#![forbid(unsafe_code)]

pub mod access;
pub mod capacity;
pub mod error;
pub mod ids;
pub mod passback;
pub mod space;
pub mod topology;

pub use access::{
    AccessDecision, AccessPolicy, AccessPolicyRegistry, PolicyResolution, Ticket, TicketSelector,
    TimeWindow,
};
pub use capacity::{CapacityAttribution, GateCapacityContribution, ZoneCapacity};
pub use error::VenueError;
pub use ids::{
    AccessPolicyId, GateId, ReaderId, SeatId, SectionId, StandingAreaId, TicketId, TicketTypeId,
    TopologyVersionId, TurnstileId, VenueId, ZoneId,
};
pub use passback::{
    AntiPassbackMode, PassbackLedger, PassbackPolicy, ReEntryPolicy, ScanDirection, ScanOutcome,
    ScanRecord,
};
pub use space::{
    Seat, Section, SectionKind, SpaceArea, SpaceModel, StandingArea, TicketClass, TicketType,
};
pub use topology::{
    EffectiveWindow, Gate, Reader, TopologyRegistry, TopologyVersion, Turnstile, Venue, Zone,
};
