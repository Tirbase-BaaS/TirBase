// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque identifiers for credentials, cardholders and reader keys.

use crate::error::AccessError;

/// Maximum accepted identifier length, in bytes.
pub const MAX_ID_LEN: usize = 128;

pub(crate) fn validate_identifier(value: &str, what: &'static str) -> Result<(), AccessError> {
    if value.is_empty() || value.len() > MAX_ID_LEN || value.chars().any(char::is_control) {
        return Err(AccessError::InvalidIdentifier(what));
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
            pub fn new(value: impl Into<String>) -> Result<Self, AccessError> {
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
            type Err = AccessError;

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
    /// Identifies a credential (a card or fob) without naming its secret.
    CredentialId,
    "credential id"
);
id_newtype!(
    /// Identifies a cardholder.
    CardholderId,
    "cardholder id"
);
id_newtype!(
    /// Identifies a reader key handle (never the key itself).
    ReaderKeyId,
    "reader key id"
);
