// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque identifiers for venue-gateway points and equipment.

use crate::error::GatewayError;

/// Maximum accepted identifier length, in bytes.
pub const MAX_ID_LEN: usize = 128;

fn validate(value: &str, what: &'static str) -> Result<(), GatewayError> {
    if value.is_empty() || value.len() > MAX_ID_LEN || value.chars().any(char::is_control) {
        return Err(GatewayError::InvalidIdentifier(what));
    }
    Ok(())
}

macro_rules! gateway_id {
    ($name:ident, $what:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an identifier, rejecting empty/oversized/control input.
            pub fn new(value: impl Into<String>) -> Result<Self, GatewayError> {
                let value = value.into();
                validate(&value, $what)?;
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
            type Err = GatewayError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

gateway_id!(PointId, "point id");
gateway_id!(EquipmentId, "equipment id");
