// SPDX-License-Identifier: AGPL-3.0-only

//! Point addresses, mappings, values and venue targets.
//!
//! The gateway ingests **readings** only. There is intentionally no command,
//! actuation or setpoint type in this module: safety systems mapped here are
//! read-only by construction, not by policy check.

use std::collections::BTreeMap;

use crate::error::GatewayError;
use crate::ids::{EquipmentId, PointId};
use tirbase_venue::{GateId, ZoneId};

/// Maximum accepted MQTT topic length.
pub const MAX_TOPIC_LEN: usize = 512;

/// Ingest protocol for one point.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Bacnet,
    Modbus,
    Knx,
    Mqtt,
}

impl Protocol {
    pub const ALL: [Protocol; 4] = [
        Protocol::Bacnet,
        Protocol::Modbus,
        Protocol::Knx,
        Protocol::Mqtt,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Bacnet => "bacnet",
            Protocol::Modbus => "modbus",
            Protocol::Knx => "knx",
            Protocol::Mqtt => "mqtt",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol-specific address of one readable point.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum PointAddress {
    /// BACnet object property (Present-Value by convention).
    Bacnet {
        object_type: u16,
        instance: u32,
        property: u32,
    },
    /// Modbus register read by function 3 or 4.
    Modbus {
        unit_id: u8,
        function: u8,
        register: u16,
    },
    /// KNX group address.
    Knx { group_address: u16 },
    /// MQTT topic.
    Mqtt { topic: String },
}

impl PointAddress {
    pub fn protocol(&self) -> Protocol {
        match self {
            PointAddress::Bacnet { .. } => Protocol::Bacnet,
            PointAddress::Modbus { .. } => Protocol::Modbus,
            PointAddress::Knx { .. } => Protocol::Knx,
            PointAddress::Mqtt { .. } => Protocol::Mqtt,
        }
    }

    /// Canonical, deterministic lookup key.
    pub fn key(&self) -> String {
        match self {
            PointAddress::Bacnet {
                object_type,
                instance,
                property,
            } => format!("bacnet:{object_type}:{instance}:{property}"),
            PointAddress::Modbus {
                unit_id,
                function,
                register,
            } => format!("modbus:{unit_id}:{function}:{register}"),
            PointAddress::Knx { group_address } => format!("knx:{group_address}"),
            PointAddress::Mqtt { topic } => format!("mqtt:{topic}"),
        }
    }

    /// Reject addresses that could only be used for writing.
    pub fn validate(&self) -> Result<(), GatewayError> {
        match self {
            PointAddress::Modbus { function, .. } => {
                if !matches!(function, 0x03 | 0x04) {
                    return Err(GatewayError::WritePathRejected(
                        "only Modbus FC03/FC04 read registers may be mapped",
                    ));
                }
            }
            PointAddress::Mqtt { topic } => {
                if topic.is_empty()
                    || topic.len() > MAX_TOPIC_LEN
                    || topic.chars().any(char::is_control)
                {
                    return Err(GatewayError::InvalidIdentifier("mqtt topic"));
                }
            }
            PointAddress::Bacnet { .. } | PointAddress::Knx { .. } => {}
        }
        Ok(())
    }
}

/// Where a point lands in the venue model.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PointTarget {
    /// A gate mechanism/lane signal (open, occupied, fault).
    Gate { gate_id: GateId },
    /// Live occupancy count for a zone.
    Occupancy { zone_id: ZoneId },
    /// Environment reading for a zone (temperature, humidity, CO2).
    Environment { zone_id: ZoneId },
    /// Venue equipment (turnstile motor, AHU, escalator) inside a zone.
    Equipment {
        equipment_id: EquipmentId,
        zone_id: ZoneId,
    },
}

impl PointTarget {
    pub fn kind(&self) -> PointKind {
        match self {
            PointTarget::Gate { .. } => PointKind::Gate,
            PointTarget::Occupancy { .. } => PointKind::Occupancy,
            PointTarget::Environment { .. } => PointKind::Environment,
            PointTarget::Equipment { .. } => PointKind::Equipment,
        }
    }

    pub fn zone_id(&self) -> Option<&ZoneId> {
        match self {
            PointTarget::Gate { .. } => None,
            PointTarget::Occupancy { zone_id }
            | PointTarget::Environment { zone_id }
            | PointTarget::Equipment { zone_id, .. } => Some(zone_id),
        }
    }
}

/// Point category used for snapshot grouping.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PointKind {
    Gate,
    Occupancy,
    Environment,
    Equipment,
}

/// Whether a system is safety-related.
///
/// Both classes are read-only in this crate; the classification exists so
/// operators can audit which points belong to fire/life-safety systems.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SafetyClass {
    Standard,
    LifeSafety,
}

/// One point mapping from a protocol address into the venue model.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PointMapping {
    pub point_id: PointId,
    pub address: PointAddress,
    pub target: PointTarget,
    pub safety: SafetyClass,
    /// Engineering unit for numeric readings (for example `degC`).
    pub unit: Option<String>,
}

impl PointMapping {
    pub fn new(point_id: PointId, address: PointAddress, target: PointTarget) -> Self {
        Self {
            point_id,
            address,
            target,
            safety: SafetyClass::Standard,
            unit: None,
        }
    }

    /// Mark the mapped system as fire/life-safety. Still read-only.
    pub fn life_safety(mut self) -> Self {
        self.safety = SafetyClass::LifeSafety;
        self
    }

    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    pub fn kind(&self) -> PointKind {
        self.target.kind()
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        self.address.validate()?;
        if let PointTarget::Equipment { equipment_id, .. } = &self.target {
            if equipment_id.as_str().is_empty() {
                return Err(GatewayError::InvalidIdentifier("equipment id"));
            }
        }
        if let Some(unit) = &self.unit {
            if unit.trim().is_empty() || unit.chars().any(char::is_control) {
                return Err(GatewayError::InvalidIdentifier("point unit"));
            }
        }
        Ok(())
    }
}

/// A decoded and typed point value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PointValue {
    Boolean(bool),
    Count(u32),
    /// Decimal number: `mantissa * 10^exponent`.
    Number {
        mantissa: i64,
        exponent: i8,
    },
    Text(String),
}

impl PointValue {
    pub fn number(mantissa: i64, exponent: i8) -> Self {
        Self::Number { mantissa, exponent }
    }

    /// Convert a floating-point decoding into a deterministic decimal value.
    pub fn from_scaled(value: f64, exponent: i8) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        let factor = 10f64.powi(-i32::from(exponent));
        let scaled = (value * factor).round();
        if scaled < i64::MIN as f64 || scaled > i64::MAX as f64 {
            return None;
        }
        Some(Self::Number {
            mantissa: scaled as i64,
            exponent,
        })
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PointValue::Boolean(value) => Some(*value),
            PointValue::Count(value) => Some(*value != 0),
            PointValue::Number { mantissa, .. } => Some(*mantissa != 0),
            PointValue::Text(_) => None,
        }
    }

    /// Exact non-negative integer view, used for occupancy attribution.
    pub fn as_count(&self) -> Option<u32> {
        let scaled: i128 = match self {
            PointValue::Count(value) => i128::from(*value),
            PointValue::Boolean(value) => i128::from(*value),
            PointValue::Number { mantissa, exponent } => {
                if *exponent >= 0 {
                    i128::from(*mantissa)
                        .checked_mul(10i128.checked_pow(u32::from(*exponent as u8))?)?
                } else {
                    let divisor = 10i128.checked_pow(u32::from(exponent.unsigned_abs()))?;
                    let value = i128::from(*mantissa);
                    if value % divisor != 0 {
                        return None;
                    }
                    value / divisor
                }
            }
            PointValue::Text(_) => return None,
        };
        u32::try_from(scaled).ok()
    }
}

/// A point decoded from a protocol frame, before mapping.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecodedPoint {
    pub address: PointAddress,
    pub value: PointValue,
}

impl DecodedPoint {
    pub fn new(address: PointAddress, value: PointValue) -> Self {
        Self { address, value }
    }
}

/// A reading accepted for a registered point.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PointUpdate {
    pub point_id: PointId,
    pub target: PointTarget,
    pub value: PointValue,
    /// True when the point had been stale and is live again.
    pub recovered: bool,
}

/// Venue-model grouping of registered points.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VenueSnapshot {
    pub gates: BTreeMap<GateId, Vec<PointId>>,
    pub occupancy: BTreeMap<ZoneId, Vec<PointId>>,
    pub environment: BTreeMap<ZoneId, Vec<PointId>>,
    pub equipment: BTreeMap<EquipmentId, Vec<PointId>>,
}
