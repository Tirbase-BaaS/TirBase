// SPDX-License-Identifier: AGPL-3.0-only

//! Feature-gated protocol ingesters.
//!
//! Every ingester decodes frames produced by a caller-owned transport (or a
//! simulator) into [`crate::point::DecodedPoint`] values. None of them builds a
//! write, command or actuation frame.

#[cfg(feature = "bacnet")]
pub mod bacnet;
#[cfg(feature = "knx")]
pub mod knx;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "mqtt")]
pub mod mqtt;

/// A frame rejected by a protocol ingester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// Malformed or truncated frame.
    InvalidFrame(&'static str),
    /// The frame belongs to a write/command path and is never ingested.
    WritePathRejected(&'static str),
    /// The frame's unit id does not match the configured unit.
    UnitMismatch { expected: u8, actual: u8 },
    /// A protocol feature outside the read-only subset was used.
    Unsupported(&'static str),
    /// A decoded value cannot be represented as a venue point value.
    InvalidValue(&'static str),
    /// Underlying codec error.
    Codec(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::InvalidFrame(reason) => write!(f, "invalid frame: {reason}"),
            ProtocolError::WritePathRejected(reason) => {
                write!(f, "write path rejected (read-only gateway): {reason}")
            }
            ProtocolError::UnitMismatch { expected, actual } => {
                write!(f, "unit id mismatch: expected {expected}, got {actual}")
            }
            ProtocolError::Unsupported(reason) => write!(f, "unsupported: {reason}"),
            ProtocolError::InvalidValue(reason) => write!(f, "invalid value: {reason}"),
            ProtocolError::Codec(message) => write!(f, "codec error: {message}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<tirbase_driver_api::DriverError> for ProtocolError {
    fn from(error: tirbase_driver_api::DriverError) -> Self {
        ProtocolError::Codec(error.to_string())
    }
}
