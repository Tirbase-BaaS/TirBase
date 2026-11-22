// SPDX-License-Identifier: AGPL-3.0-only

//! Typed allow/deny reasons for the offline decision API.

use std::fmt;

use tirbase_venue::{GateId, TicketId, VenueId, ZoneId};

use crate::payload::{EventId, VenueScope};

/// Why a ticket was refused. Every variant is a distinct, testable reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The payload was malformed.
    Malformed(&'static str),
    /// The signing key is not in the verifier's key ring.
    UnknownIssuerKey { key_id: String },
    /// The signing key is not valid yet.
    KeyNotYetValid { key_id: String, not_before_utc_us: i64 },
    /// The signing key's window has ended.
    KeyExpired { key_id: String, not_after_utc_us: i64 },
    /// The signing key was revoked.
    KeyRevoked { key_id: String },
    /// The signature did not verify.
    BadSignature { key_id: String },
    /// The ticket is for another event.
    WrongEvent { expected: EventId, presented: EventId },
    /// The ticket is for another venue.
    WrongVenue { expected: VenueId, presented: VenueId },
    /// The ticket is for another gate.
    WrongGate { expected: GateId, presented: GateId },
    /// The ticket is for another zone.
    WrongZone { expected: ZoneId, presented: ZoneId },
    /// Not valid yet.
    NotYetValid { valid_from_utc_us: i64 },
    /// Past the end of the validity window.
    Expired { valid_until_utc_us: i64 },
    /// Listed in the current revocation list.
    RevokedTicket { ticket_id: TicketId },
    /// The same ticket and nonce were already admitted.
    Replayed { ticket_id: TicketId, nonce: u64 },
    /// The policy requires a holder binding and the ticket has none.
    HolderBindingRequired,
    /// The presented holder binding does not match the ticket.
    HolderMismatch,
    /// No revocation list has been loaded and policy requires one.
    RevocationListMissing,
    /// The loaded revocation list has expired.
    RevocationListExpired {
        version: u64,
        expired_at_utc_us: i64,
    },
    /// A refresh offered a list older than the applied one.
    RevocationListRollback { applied: u64, offered: u64 },
    /// The revocation list's own signature did not verify.
    RevocationListSignature,
}

impl Denial {
    /// Stable machine code for gateway events and guard-console grouping.
    pub fn code(&self) -> &'static str {
        match self {
            Denial::Malformed(_) => "malformed",
            Denial::UnknownIssuerKey { .. } => "unknown_issuer_key",
            Denial::KeyNotYetValid { .. } => "key_not_yet_valid",
            Denial::KeyExpired { .. } => "key_expired",
            Denial::KeyRevoked { .. } => "key_revoked",
            Denial::BadSignature { .. } => "bad_signature",
            Denial::WrongEvent { .. } => "wrong_event",
            Denial::WrongVenue { .. } => "wrong_venue",
            Denial::WrongGate { .. } => "wrong_gate",
            Denial::WrongZone { .. } => "wrong_zone",
            Denial::NotYetValid { .. } => "not_yet_valid",
            Denial::Expired { .. } => "expired",
            Denial::RevokedTicket { .. } => "revoked_ticket",
            Denial::Replayed { .. } => "replayed",
            Denial::HolderBindingRequired => "holder_binding_required",
            Denial::HolderMismatch => "holder_mismatch",
            Denial::RevocationListMissing => "revocation_list_missing",
            Denial::RevocationListExpired { .. } => "revocation_list_expired",
            Denial::RevocationListRollback { .. } => "revocation_list_rollback",
            Denial::RevocationListSignature => "revocation_list_signature",
        }
    }

    /// True when the denial was caused by the revocation list's freshness,
    /// which is always alarm-worthy for an operator.
    pub fn is_revocation_freshness(&self) -> bool {
        matches!(
            self,
            Denial::RevocationListMissing
                | Denial::RevocationListExpired { .. }
                | Denial::RevocationListRollback { .. }
                | Denial::RevocationListSignature
        )
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::Malformed(reason) => write!(f, "malformed ticket: {reason}"),
            Denial::UnknownIssuerKey { key_id } => write!(f, "unknown issuer key: {key_id}"),
            Denial::KeyNotYetValid {
                key_id,
                not_before_utc_us,
            } => write!(f, "issuer key {key_id} is not valid before {not_before_utc_us}"),
            Denial::KeyExpired {
                key_id,
                not_after_utc_us,
            } => write!(f, "issuer key {key_id} expired at {not_after_utc_us}"),
            Denial::KeyRevoked { key_id } => write!(f, "issuer key {key_id} is revoked"),
            Denial::BadSignature { key_id } => {
                write!(f, "signature does not verify for key {key_id}")
            }
            Denial::WrongEvent { expected, presented } => {
                write!(f, "ticket is for event {presented}, not {expected}")
            }
            Denial::WrongVenue { expected, presented } => {
                write!(f, "ticket is for venue {presented}, not {expected}")
            }
            Denial::WrongGate { expected, presented } => {
                write!(f, "ticket is for gate {presented}, not {expected}")
            }
            Denial::WrongZone { expected, presented } => {
                write!(f, "ticket is for zone {presented}, not {expected}")
            }
            Denial::NotYetValid { valid_from_utc_us } => {
                write!(f, "ticket is not valid before {valid_from_utc_us}")
            }
            Denial::Expired { valid_until_utc_us } => {
                write!(f, "ticket expired at {valid_until_utc_us}")
            }
            Denial::RevokedTicket { ticket_id } => write!(f, "ticket {ticket_id} is revoked"),
            Denial::Replayed { ticket_id, nonce } => {
                write!(f, "ticket {ticket_id} nonce {nonce} was already admitted")
            }
            Denial::HolderBindingRequired => write!(f, "ticket has no holder binding"),
            Denial::HolderMismatch => write!(f, "presented holder does not match the ticket"),
            Denial::RevocationListMissing => write!(f, "no revocation list is loaded"),
            Denial::RevocationListExpired {
                version,
                expired_at_utc_us,
            } => write!(
                f,
                "revocation list v{version} expired at {expired_at_utc_us}"
            ),
            Denial::RevocationListRollback { applied, offered } => write!(
                f,
                "revocation list v{offered} would roll back from v{applied}"
            ),
            Denial::RevocationListSignature => {
                write!(f, "revocation list signature does not verify")
            }
        }
    }
}

impl std::error::Error for Denial {}

/// A scope mismatch check producing the specific typed denial.
pub fn scope_denial(expected: &VenueScope, presented: &VenueScope) -> Option<Denial> {
    if presented.event_id != expected.event_id {
        return Some(Denial::WrongEvent {
            expected: expected.event_id.clone(),
            presented: presented.event_id.clone(),
        });
    }
    if presented.venue_id != expected.venue_id {
        return Some(Denial::WrongVenue {
            expected: expected.venue_id.clone(),
            presented: presented.venue_id.clone(),
        });
    }
    if presented.gate_id != expected.gate_id {
        return Some(Denial::WrongGate {
            expected: expected.gate_id.clone(),
            presented: presented.gate_id.clone(),
        });
    }
    if presented.zone_id != expected.zone_id {
        return Some(Denial::WrongZone {
            expected: expected.zone_id.clone(),
            presented: presented.zone_id.clone(),
        });
    }
    None
}
