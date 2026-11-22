// SPDX-License-Identifier: AGPL-3.0-only

//! Errors raised by the venue gateway ingest layer.

use crate::ids::{EquipmentId, PointId};

/// A rejected venue-gateway operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayError {
    /// A required identifier was empty, oversized or contained control characters.
    InvalidIdentifier(&'static str),
    /// A duplicate point id or protocol address was registered.
    DuplicatePoint(PointId),
    /// Two mappings share the same protocol address.
    DuplicateAddress(String),
    /// No mapping exists for the decoded protocol address.
    UnknownPointAddress(String),
    /// The referenced point is not registered.
    UnknownPoint(PointId),
    /// A mapping target is absent from the topology version.
    UnknownTarget(&'static str),
    /// The referenced zone is absent from the topology version.
    UnknownZone(tirbase_venue::ZoneId),
    /// The referenced gate is absent from the topology version.
    UnknownGate(tirbase_venue::GateId),
    /// The referenced equipment is absent from the mapping set.
    UnknownEquipment(EquipmentId),
    /// A write path was attempted. The venue gateway is read-only.
    WritePathRejected(&'static str),
    /// A configuration value is invalid.
    InvalidConfig(&'static str),
    /// A decoded value cannot be represented as a venue point value.
    InvalidValue(&'static str),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayError::InvalidIdentifier(what) => write!(f, "invalid identifier: {what}"),
            GatewayError::DuplicatePoint(id) => write!(f, "duplicate point id: {id}"),
            GatewayError::DuplicateAddress(address) => {
                write!(f, "duplicate point address: {address}")
            }
            GatewayError::UnknownPointAddress(address) => {
                write!(f, "no mapping for point address: {address}")
            }
            GatewayError::UnknownPoint(id) => write!(f, "unknown point: {id}"),
            GatewayError::UnknownTarget(what) => write!(f, "unknown mapping target: {what}"),
            GatewayError::UnknownZone(id) => write!(f, "unknown zone: {id}"),
            GatewayError::UnknownGate(id) => write!(f, "unknown gate: {id}"),
            GatewayError::UnknownEquipment(id) => write!(f, "unknown equipment: {id}"),
            GatewayError::WritePathRejected(reason) => {
                write!(f, "write path rejected (read-only gateway): {reason}")
            }
            GatewayError::InvalidConfig(what) => write!(f, "invalid config: {what}"),
            GatewayError::InvalidValue(what) => write!(f, "invalid value: {what}"),
        }
    }
}

impl std::error::Error for GatewayError {}
