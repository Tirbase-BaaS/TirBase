// SPDX-License-Identifier: Apache-2.0

//! Acme TX-100 vendor example driver.
//!
//! This crate is a worked example for third-party driver authors. It depends
//! only on the Apache-2.0 `tirbase-driver-api` crate, implements
//! [`DriverTrait`], and is validated by the published conformance harness.
//!
//! The TX-100 speaks a small ASCII line protocol over its serial link:
//!
//! | Direction | Frame |
//! |---|---|
//! | read request | `RD <register> <quantity>\n` |
//! | read response | `REGS <parameter> <word> [<word>]\n` |
//! | write/actuation | `WR <register> <word> [<word>]\n` |
//! | read-back | `RB <parameter> <word> [<word>]\n` |
//! | health request | `PING\n` |
//! | health response | `PONG <unit_id>\n` |
//!
//! The driver is a pure codec: it never opens a device, socket, or file. The
//! guard process owns the transport and passes frames across the driver
//! boundary.

use tirbase_driver_api::register_map::{ModbusRegisterMap, RegisterDef, RegisterMapError};
use tirbase_driver_api::tirbase_types::{FixedPointValue, UnitId, UNIT_DESCRIPTORS};
use tirbase_driver_api::{
    ActuationPermitRef, DeviceModel, DriverError, DriverHealth, DriverResult, DriverTrait, Frame,
    ParameterDescriptor,
};

/// Vendor example thermostat driver.
#[derive(Debug, Clone)]
pub struct AcmeThermostatDriver {
    unit_id: u8,
    map: ModbusRegisterMap,
}

impl AcmeThermostatDriver {
    /// The bundled register map (`register-map.toml`).
    pub const REGISTER_MAP: &'static str = include_str!("../register-map.toml");

    /// Builds the driver with the bundled register map.
    pub fn new(unit_id: u8) -> Result<Self, RegisterMapError> {
        Self::from_map(unit_id, Self::REGISTER_MAP)
    }

    /// Builds the driver from a register-map document.
    pub fn from_map(unit_id: u8, register_map: &str) -> Result<Self, RegisterMapError> {
        Ok(Self {
            unit_id,
            map: ModbusRegisterMap::parse(register_map)?,
        })
    }

    /// Configured Modbus unit id.
    pub fn unit_id(&self) -> u8 {
        self.unit_id
    }

    /// Register map used by this driver.
    pub fn map(&self) -> &ModbusRegisterMap {
        &self.map
    }

    /// Looks up a parameter definition by name.
    pub fn parameter(&self, name: &str) -> Option<&RegisterDef> {
        self.map.registers.iter().find(|def| def.name == name)
    }

    fn def(&self, name: &str) -> DriverResult<&RegisterDef> {
        self.parameter(name)
            .ok_or_else(|| DriverError::UnsupportedParam(name.into()))
    }

    fn decode_named(&self, frame: &[u8], prefix: &str) -> DriverResult<FixedPointValue> {
        let (name, words) = parse_named_frame(frame, prefix)?;
        let def = self.def(&name)?;
        let scaled = def
            .decode_to_scaled_i64(&words)
            .map_err(|e| DriverError::Codec(e.to_string()))?;
        Ok(FixedPointValue::new(
            scaled,
            def.scale_exponent,
            def.unit_id,
        ))
    }
}

impl DriverTrait for AcmeThermostatDriver {
    fn capability_discovery(&self) -> DriverResult<DeviceModel> {
        let parameters = self
            .map
            .registers
            .iter()
            .map(|def| {
                let (min, max) = raw_bounds(def);
                ParameterDescriptor {
                    name: def.name.clone(),
                    unit_id: def.unit_id,
                    unit_label: unit_label(def.unit_id),
                    range: [scaled_fpv(def, min), scaled_fpv(def, max)],
                    writable: def.writable,
                }
            })
            .collect();
        DeviceModel::try_new(self.map.device_class.clone(), parameters)
            .map_err(|e| DriverError::Capability(e.to_string()))
    }

    fn encode_read(&self, param: &str) -> DriverResult<Frame> {
        let def = self.def(param)?;
        Ok(format!("RD {} {}\n", def.register, def.quantity).into_bytes())
    }

    fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        self.decode_named(frame, "REGS")
    }

    fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame> {
        let def = self.def(&permit.param)?;
        if !def.writable {
            return Err(DriverError::Capability(format!(
                "{} is read-only",
                def.name
            )));
        }
        if permit.value.exponent != def.scale_exponent {
            return Err(DriverError::Codec(format!(
                "value exponent {} does not match register exponent {}",
                permit.value.exponent, def.scale_exponent
            )));
        }
        let words = def
            .encode_scaled_i64(permit.value.mantissa)
            .map_err(|e| DriverError::Codec(e.to_string()))?;
        Ok(format_frame("WR", def.register.to_string(), &words))
    }

    fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        self.decode_named(frame, "RB")
    }

    fn encode_health_check(&self) -> DriverResult<Frame> {
        Ok(b"PING\n".to_vec())
    }

    fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
        let text = std::str::from_utf8(frame)
            .map_err(|e| DriverError::InvalidFrame(format!("health frame is not UTF-8: {e}")))?;
        let rest = text
            .trim_end()
            .strip_prefix("PONG ")
            .ok_or_else(|| DriverError::InvalidFrame("expected 'PONG <unit_id>'".into()))?;
        let unit_ok = rest
            .trim()
            .parse::<u8>()
            .map(|unit| unit == self.unit_id)
            .unwrap_or(false);
        Ok(DriverHealth {
            healthy: unit_ok,
            detail: format!("health response for unit {rest}"),
        })
    }
}

fn format_frame(prefix: &str, header: String, words: &[u16]) -> Frame {
    let words: Vec<String> = words.iter().map(u16::to_string).collect();
    format!("{prefix} {header} {}\n", words.join(" ")).into_bytes()
}

fn parse_named_frame(frame: &[u8], prefix: &str) -> DriverResult<(String, Vec<u16>)> {
    let text = std::str::from_utf8(frame)
        .map_err(|e| DriverError::InvalidFrame(format!("frame is not UTF-8: {e}")))?;
    let body = text.trim_end_matches('\n');
    let rest = body
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| DriverError::InvalidFrame(format!("expected '{prefix}' frame")))?;
    let mut tokens = rest.split_whitespace();
    let name = tokens
        .next()
        .ok_or_else(|| DriverError::InvalidFrame("missing parameter name".into()))?
        .to_string();
    let mut words = Vec::new();
    for token in tokens {
        words.push(token.parse::<u16>().map_err(|_| {
            DriverError::InvalidFrame(format!("'{token}' is not a 16-bit register word"))
        })?);
    }
    if words.is_empty() {
        return Err(DriverError::InvalidFrame(
            "frame carries no register words".into(),
        ));
    }
    Ok((name, words))
}

fn raw_bounds(def: &RegisterDef) -> (i128, i128) {
    match def.data_type_normalized().as_str() {
        "bool" => (0, 1),
        "i16" | "int16" => (i16::MIN as i128, i16::MAX as i128),
        "u16" | "uint16" => (0, u16::MAX as i128),
        "i32" | "int32" => (i32::MIN as i128, i32::MAX as i128),
        "u32" | "uint32" => (0, u32::MAX as i128),
        _ => (0, u16::MAX as i128),
    }
}

fn scaled_fpv(def: &RegisterDef, raw: i128) -> FixedPointValue {
    let scaled = def
        .encode_raw_i128(raw)
        .ok()
        .and_then(|words| def.decode_to_scaled_i64(&words).ok())
        .unwrap_or(0);
    FixedPointValue::new(scaled, def.scale_exponent, def.unit_id)
}

fn unit_label(unit_id: UnitId) -> String {
    UNIT_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.id == unit_id)
        .map(|descriptor| descriptor.label.to_string())
        .unwrap_or_else(|| format!("unit_{unit_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_map_parses_and_advertises_parameters() {
        let driver = AcmeThermostatDriver::new(7).unwrap();
        let model = driver.capability_discovery().unwrap();
        assert_eq!(model.device_class, "acme_tx100_thermostat");
        let names: Vec<&str> = model
            .parameters
            .iter()
            .map(|parameter| parameter.name.as_str())
            .collect();
        assert_eq!(names, ["temperature_c", "setpoint_c", "energy_kwh"]);
        assert!(model.parameters[1].writable);
        assert_eq!(model.parameters[0].unit_id, 1);
    }

    #[test]
    fn read_only_parameter_rejects_actuation() {
        let driver = AcmeThermostatDriver::new(7).unwrap();
        let permit = ActuationPermitRef {
            target_id: tirbase_driver_api::tirbase_types::TargetId::new("t1"),
            param: "temperature_c".into(),
            value: FixedPointValue::new(250, -1, 1),
            entry_id: [0u8; 16],
        };
        assert!(matches!(
            driver.encode_actuation(&permit),
            Err(DriverError::Capability(_))
        ));
    }
}
