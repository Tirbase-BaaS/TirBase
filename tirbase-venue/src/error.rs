// SPDX-License-Identifier: AGPL-3.0-only

//! Errors raised by the venue domain model.

use crate::ids::{
    AccessPolicyId, GateId, ReaderId, SectionId, StandingAreaId, TicketId, TicketTypeId,
    TopologyVersionId, TurnstileId, VenueId, ZoneId,
};

/// A rejected venue-domain operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VenueError {
    /// A required identifier was empty, oversized or contained control characters.
    InvalidIdentifier(&'static str),
    /// An effective window is invalid (end before start).
    InvalidEffectiveWindow,
    /// Two topology versions overlap in effective time for the same venue.
    OverlappingTopologyVersions {
        venue_id: VenueId,
        existing: TopologyVersionId,
    },
    /// The referenced venue was not found.
    UnknownVenue(VenueId),
    /// The referenced zone was not found.
    UnknownZone(ZoneId),
    /// The referenced gate was not found.
    UnknownGate(GateId),
    /// The referenced reader was not found.
    UnknownReader(ReaderId),
    /// The referenced turnstile was not found.
    UnknownTurnstile(TurnstileId),
    /// The referenced section was not found.
    UnknownSection(SectionId),
    /// The referenced standing area was not found.
    UnknownStandingArea(StandingAreaId),
    /// The referenced ticket type was not found.
    UnknownTicketType(TicketTypeId),
    /// The referenced access policy was not found.
    UnknownAccessPolicy(AccessPolicyId),
    /// The referenced topology version was not found.
    UnknownTopologyVersion(TopologyVersionId),
    /// A duplicate entity identifier was supplied.
    DuplicateId(&'static str),
    /// A child entity references a parent that does not match the hierarchy.
    HierarchyMismatch(&'static str),
    /// A capacity value is invalid.
    InvalidCapacity(&'static str),
    /// A time window is invalid (end before start).
    InvalidTimeWindow,
    /// No access policy allows the ticket through the requested gate/zone at the given time.
    AccessDenied(&'static str),
    /// More than one access policy matches; ST-01 requires exactly one.
    AmbiguousPolicy {
        ticket_type: TicketTypeId,
        gate_id: GateId,
        policy_ids: Vec<AccessPolicyId>,
    },
    /// Anti-passback rejected the scan.
    AntiPassbackRejected {
        ticket_id: TicketId,
        reason: &'static str,
    },
    /// Re-entry is not allowed by policy.
    ReEntryRejected {
        ticket_id: TicketId,
        reason: &'static str,
    },
    /// A scan direction is invalid for the current state.
    InvalidScanDirection(&'static str),
    /// A numeric operation overflowed.
    ArithmeticOverflow,
}

impl std::fmt::Display for VenueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VenueError::InvalidIdentifier(what) => {
                write!(f, "invalid identifier: {what}")
            }
            VenueError::InvalidEffectiveWindow => write!(f, "invalid effective window"),
            VenueError::OverlappingTopologyVersions { venue_id, existing } => write!(
                f,
                "topology version overlaps existing version {existing} for venue {venue_id}"
            ),
            VenueError::UnknownVenue(id) => write!(f, "unknown venue: {id}"),
            VenueError::UnknownZone(id) => write!(f, "unknown zone: {id}"),
            VenueError::UnknownGate(id) => write!(f, "unknown gate: {id}"),
            VenueError::UnknownReader(id) => write!(f, "unknown reader: {id}"),
            VenueError::UnknownTurnstile(id) => write!(f, "unknown turnstile: {id}"),
            VenueError::UnknownSection(id) => write!(f, "unknown section: {id}"),
            VenueError::UnknownStandingArea(id) => write!(f, "unknown standing area: {id}"),
            VenueError::UnknownTicketType(id) => write!(f, "unknown ticket type: {id}"),
            VenueError::UnknownAccessPolicy(id) => write!(f, "unknown access policy: {id}"),
            VenueError::UnknownTopologyVersion(id) => {
                write!(f, "unknown topology version: {id}")
            }
            VenueError::DuplicateId(what) => write!(f, "duplicate id: {what}"),
            VenueError::HierarchyMismatch(what) => write!(f, "hierarchy mismatch: {what}"),
            VenueError::InvalidCapacity(what) => write!(f, "invalid capacity: {what}"),
            VenueError::InvalidTimeWindow => write!(f, "invalid time window"),
            VenueError::AccessDenied(reason) => write!(f, "access denied: {reason}"),
            VenueError::AmbiguousPolicy {
                ticket_type,
                gate_id,
                policy_ids,
            } => write!(
                f,
                "ambiguous access policy for ticket type {ticket_type} at gate {gate_id}: {policy_ids:?}"
            ),
            VenueError::AntiPassbackRejected { ticket_id, reason } => {
                write!(f, "anti-passback rejected ticket {ticket_id}: {reason}")
            }
            VenueError::ReEntryRejected { ticket_id, reason } => {
                write!(f, "re-entry rejected ticket {ticket_id}: {reason}")
            }
            VenueError::InvalidScanDirection(reason) => {
                write!(f, "invalid scan direction: {reason}")
            }
            VenueError::ArithmeticOverflow => write!(f, "arithmetic overflow"),
        }
    }
}

impl std::error::Error for VenueError {}
