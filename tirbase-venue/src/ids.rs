// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque string identifiers for the venue domain model.
//!
//! Identifiers are caller-supplied so replayed commands and deterministic tests
//! carry identical values.

use crate::error::VenueError;

/// Maximum accepted identifier length, in bytes.
pub const MAX_ID_LEN: usize = 128;

pub(crate) fn validate_identifier(value: &str, what: &'static str) -> Result<(), VenueError> {
    if value.is_empty() || value.len() > MAX_ID_LEN || value.chars().any(char::is_control) {
        return Err(VenueError::InvalidIdentifier(what));
    }
    Ok(())
}

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an identifier, rejecting empty/oversized/control input.
            pub fn new(value: impl Into<String>) -> Result<Self, VenueError> {
                let value = value.into();
                validate_identifier(&value, $what)?;
                Ok(Self(value))
            }

            /// Borrow the identifier text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = VenueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_newtype!(
    /// Identifies a venue.
    VenueId,
    "venue id"
);
id_newtype!(
    /// Identifies a zone inside a venue.
    ZoneId,
    "zone id"
);
id_newtype!(
    /// Identifies a gate inside a zone.
    GateId,
    "gate id"
);
id_newtype!(
    /// Identifies a reader attached to a gate.
    ReaderId,
    "reader id"
);
id_newtype!(
    /// Identifies a turnstile attached to a gate.
    TurnstileId,
    "turnstile id"
);
id_newtype!(
    /// Identifies a versioned topology snapshot.
    TopologyVersionId,
    "topology version id"
);
id_newtype!(
    /// Identifies a seating section.
    SectionId,
    "section id"
);
id_newtype!(
    /// Identifies an individual seat.
    SeatId,
    "seat id"
);
id_newtype!(
    /// Identifies a standing area.
    StandingAreaId,
    "standing area id"
);
id_newtype!(
    /// Identifies a ticket type.
    TicketTypeId,
    "ticket type id"
);
id_newtype!(
    /// Identifies an access policy.
    AccessPolicyId,
    "access policy id"
);
id_newtype!(
    /// Identifies a ticket instance.
    TicketId,
    "ticket id"
);
