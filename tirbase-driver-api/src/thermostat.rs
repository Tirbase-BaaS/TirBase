// SPDX-License-Identifier: Apache-2.0

//! Reusable Modbus thermostat profiles (CC-03).
//!
//! A [`ThermostatProfile`] is a validated [`ModbusRegisterMap`] with six
//! semantic fields: current temperature, setpoint, mode, fan, alarm, and fault.
//! The [two built-in profiles](generic_thermostat_a) use original register
//! layouts, not vendor documentation.
//!
//! This module is pure: it validates maps, decodes/encodes register values, and
//! converts mode/fan codes. Transport I/O lives in `tirbase-drivers`.

use std::fmt;

use tirbase_types::FixedPointValue;

use crate::register_map::{ModbusRegisterMap, RegisterDef, RegisterMapError};

/// Canonical register names used by a thermostat profile.
pub const REG_CURRENT_TEMPERATURE: &str = "current_temperature";
pub const REG_SETPOINT: &str = "setpoint";
pub const REG_MODE: &str = "mode";
pub const REG_FAN: &str = "fan";
pub const REG_ALARM: &str = "alarm";
pub const REG_FAULT: &str = "fault";

/// Semantic thermostat field mapped to one register definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThermostatField {
    CurrentTemperature,
    Setpoint,
    Mode,
    Fan,
    Alarm,
    Fault,
}

impl ThermostatField {
    /// All fields, in reading order.
    pub const ALL: [Self; 6] = [
        Self::CurrentTemperature,
        Self::Setpoint,
        Self::Mode,
        Self::Fan,
        Self::Alarm,
        Self::Fault,
    ];

    /// Register name used in the profile document.
    pub const fn register_name(self) -> &'static str {
        match self {
            Self::CurrentTemperature => REG_CURRENT_TEMPERATURE,
            Self::Setpoint => REG_SETPOINT,
            Self::Mode => REG_MODE,
            Self::Fan => REG_FAN,
            Self::Alarm => REG_ALARM,
            Self::Fault => REG_FAULT,
        }
    }

    /// Whether the field is written by the controller.
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::Setpoint | Self::Mode | Self::Fan)
    }
}

/// Thermostat operating mode (original encoding, not vendor-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum ThermostatMode {
    #[default]
    Off = 0,
    Heat = 1,
    Cool = 2,
    Auto = 3,
}

impl ThermostatMode {
    /// Wire value.
    pub const fn as_raw(self) -> u16 {
        self as u16
    }

    /// Decodes a wire value.
    pub fn from_raw(raw: u16) -> Result<Self, ThermostatError> {
        match raw {
            0 => Ok(Self::Off),
            1 => Ok(Self::Heat),
            2 => Ok(Self::Cool),
            3 => Ok(Self::Auto),
            other => Err(ThermostatError::UnknownMode(other)),
        }
    }
}

/// Thermostat fan speed (original encoding, not vendor-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum ThermostatFan {
    #[default]
    Off = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl ThermostatFan {
    /// Wire value.
    pub const fn as_raw(self) -> u16 {
        self as u16
    }

    /// Decodes a wire value.
    pub fn from_raw(raw: u16) -> Result<Self, ThermostatError> {
        match raw {
            0 => Ok(Self::Off),
            1 => Ok(Self::Low),
            2 => Ok(Self::Medium),
            3 => Ok(Self::High),
            other => Err(ThermostatError::UnknownFan(other)),
        }
    }
}

/// A validated thermostat register map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermostatProfile {
    /// Maps to `ModbusRegisterMap::device_class`.
    pub device_class: String,
    registers: ModbusRegisterMap,
}

impl ThermostatProfile {
    /// Parses and validates a register-map document.
    pub fn parse(input: &str) -> Result<Self, ThermostatError> {
        Self::new(ModbusRegisterMap::parse(input)?)
    }

    /// Validates a register map as a thermostat profile.
    pub fn new(registers: ModbusRegisterMap) -> Result<Self, ThermostatError> {
        if registers.device_class.trim().is_empty() {
            return Err(ThermostatError::InvalidProfile(
                "device_class must not be empty".into(),
            ));
        }
        let mut unit_id = None;
        for field in ThermostatField::ALL {
            let def = registers
                .registers
                .iter()
                .find(|def| def.name == field.register_name())
                .ok_or(ThermostatError::MissingField(field))?;
            def.validate()?;
            if def.unit_id > u16::from(u8::MAX) {
                return Err(field_error(
                    field,
                    format!("unit_id {} does not fit Modbus unit id", def.unit_id),
                ));
            }
            if def.quantity != 1 {
                return Err(field_error(field, "quantity must be 1"));
            }
            let data_type = def.data_type_normalized();
            let expected_read = matches!(field, ThermostatField::CurrentTemperature)
                || matches!(field, ThermostatField::Alarm | ThermostatField::Fault);
            if expected_read {
                if !matches!(def.function, 3 | 4) {
                    return Err(field_error(
                        field,
                        format!("read field requires FC 3 or 4, got FC {}", def.function),
                    ));
                }
                if def.writable {
                    return Err(field_error(field, "read field must not be writable"));
                }
            } else {
                if !matches!(def.function, 6 | 16) {
                    return Err(field_error(
                        field,
                        format!("write field requires FC 6 or 16, got FC {}", def.function),
                    ));
                }
                if !def.writable {
                    return Err(field_error(field, "write field must be writable"));
                }
            }
            match field {
                ThermostatField::CurrentTemperature | ThermostatField::Setpoint => {
                    if !matches!(data_type.as_str(), "i16" | "int16") {
                        return Err(field_error(
                            field,
                            format!("temperature field requires i16, got '{data_type}'"),
                        ));
                    }
                }
                _ => {
                    if data_type != "u16" && data_type != "uint16" {
                        return Err(field_error(
                            field,
                            format!("status/control field requires u16, got '{data_type}'"),
                        ));
                    }
                    if def.scale_mantissa != 1
                        || def.scale_exponent != 0
                        || def.offset_mantissa != 0
                        || def.offset_exponent != 0
                    {
                        return Err(field_error(
                            field,
                            "status/control field must be unscaled with zero offset",
                        ));
                    }
                }
            }
            match unit_id {
                Some(expected) if expected != def.unit_id => {
                    return Err(field_error(
                        field,
                        format!(
                            "unit_id {} differs from profile unit_id {expected}",
                            def.unit_id
                        ),
                    ));
                }
                None => unit_id = Some(def.unit_id),
                _ => {}
            }
        }
        Ok(Self {
            device_class: registers.device_class.clone(),
            registers,
        })
    }

    /// Underlying register map.
    pub fn register_map(&self) -> &ModbusRegisterMap {
        &self.registers
    }

    /// Definition for a semantic field.
    pub fn field(&self, field: ThermostatField) -> Option<&RegisterDef> {
        self.registers
            .registers
            .iter()
            .find(|def| def.name == field.register_name())
    }

    /// Single Modbus unit id shared by every field.
    pub fn unit_id(&self) -> Option<u8> {
        self.field(ThermostatField::CurrentTemperature)
            .and_then(|def| u8::try_from(def.unit_id).ok())
    }

    /// Reads a temperature-family field from register words.
    pub fn decode_temperature(
        &self,
        field: ThermostatField,
        words: &[u16],
    ) -> Result<FixedPointValue, ThermostatError> {
        let def = self
            .field(field)
            .ok_or(ThermostatError::MissingField(field))?;
        let scaled = def.decode_to_scaled_i64(words)?;
        Ok(FixedPointValue::new(
            scaled,
            def.scale_exponent,
            tirbase_types::UNIT_DEG_C,
        ))
    }

    /// Encodes a temperature-family field to register words.
    pub fn encode_temperature(
        &self,
        field: ThermostatField,
        value: &FixedPointValue,
    ) -> Result<Vec<u16>, ThermostatError> {
        let def = self
            .field(field)
            .ok_or(ThermostatError::MissingField(field))?;
        let scaled = normalize_exponent(value.mantissa, value.exponent, def.scale_exponent)
            .ok_or_else(|| field_error(field, "temperature value cannot be scaled"))?;
        Ok(def.encode_scaled_i64(scaled)?)
    }

    /// Decodes an unscaled status/control field.
    pub fn decode_raw(
        &self,
        field: ThermostatField,
        words: &[u16],
    ) -> Result<u16, ThermostatError> {
        let def = self
            .field(field)
            .ok_or(ThermostatError::MissingField(field))?;
        let raw = def.decode_raw_i128(words)?;
        u16::try_from(raw).map_err(|_| field_error(field, "value does not fit u16"))
    }

    /// Encodes an unscaled status/control field.
    pub fn encode_raw(
        &self,
        field: ThermostatField,
        value: u16,
    ) -> Result<Vec<u16>, ThermostatError> {
        let def = self
            .field(field)
            .ok_or(ThermostatError::MissingField(field))?;
        Ok(def.encode_raw_i128(i128::from(value))?)
    }
}

/// A complete thermostat reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermostatReading {
    pub current_temperature: FixedPointValue,
    pub setpoint: FixedPointValue,
    pub mode: ThermostatMode,
    pub fan: ThermostatFan,
    pub alarm: u16,
    pub fault: u16,
}

/// Original generic profile A: inputs 0–2, holding registers 0–2, unit 1.
///
/// Current temperature/setpoint use 0.1 °C (`i16`); mode, fan, alarm, and fault
/// are unscaled `u16`. Setpoint is written with FC 06.
pub fn generic_thermostat_a() -> Result<ThermostatProfile, ThermostatError> {
    ThermostatProfile::new(ModbusRegisterMap {
        device_class: "generic_thermostat_a".into(),
        registers: vec![
            thermostat_def(REG_CURRENT_TEMPERATURE, 0, 4, "i16", false, 1, -1),
            thermostat_def(REG_ALARM, 1, 4, "u16", false, 1, 0),
            thermostat_def(REG_FAULT, 2, 4, "u16", false, 1, 0),
            thermostat_def(REG_SETPOINT, 0, 6, "i16", true, 1, -1),
            thermostat_def(REG_MODE, 1, 6, "u16", true, 1, 0),
            thermostat_def(REG_FAN, 2, 6, "u16", true, 1, 0),
        ],
    })
}

/// Original generic profile B: inputs 100–102, holding registers 200–202,
/// unit 2. Setpoint is written with FC 16; mode and fan use FC 06.
pub fn generic_thermostat_b() -> Result<ThermostatProfile, ThermostatError> {
    ThermostatProfile::new(ModbusRegisterMap {
        device_class: "generic_thermostat_b".into(),
        registers: vec![
            thermostat_def(REG_CURRENT_TEMPERATURE, 100, 4, "i16", false, 2, -1),
            thermostat_def(REG_ALARM, 101, 4, "u16", false, 2, 0),
            thermostat_def(REG_FAULT, 102, 4, "u16", false, 2, 0),
            thermostat_def(REG_SETPOINT, 200, 16, "i16", true, 2, -1),
            thermostat_def(REG_MODE, 201, 6, "u16", true, 2, 0),
            thermostat_def(REG_FAN, 202, 6, "u16", true, 2, 0),
        ],
    })
}

fn thermostat_def(
    name: &str,
    register: u16,
    function: u8,
    data_type: &str,
    writable: bool,
    unit_id: u16,
    scale_exponent: i8,
) -> RegisterDef {
    RegisterDef {
        name: name.into(),
        register,
        function,
        data_type: data_type.into(),
        scale_mantissa: 1,
        scale_exponent,
        offset_mantissa: 0,
        offset_exponent: 0,
        word_order: crate::register_map::RegisterWordOrder::BigEndian,
        unit_id,
        writable,
        quantity: 1,
    }
}

fn normalize_exponent(mantissa: i64, exponent: i8, target: i8) -> Option<i64> {
    let mut value = i128::from(mantissa);
    let mut exponent = exponent;
    while exponent > target {
        value = value.checked_mul(10)?;
        exponent -= 1;
    }
    while exponent < target {
        value /= 10;
        exponent += 1;
    }
    i64::try_from(value).ok()
}

fn field_error(field: ThermostatField, message: impl Into<String>) -> ThermostatError {
    ThermostatError::InvalidField {
        field,
        message: message.into(),
    }
}

/// Thermostat profile/value error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThermostatError {
    RegisterMap(RegisterMapError),
    InvalidProfile(String),
    MissingField(ThermostatField),
    InvalidField {
        field: ThermostatField,
        message: String,
    },
    UnknownMode(u16),
    UnknownFan(u16),
}

impl fmt::Display for ThermostatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterMap(error) => write!(f, "{error}"),
            Self::InvalidProfile(message) => write!(f, "invalid thermostat profile: {message}"),
            Self::MissingField(field) => {
                write!(
                    f,
                    "thermostat profile is missing '{}'",
                    field.register_name()
                )
            }
            Self::InvalidField { field, message } => {
                write!(f, "thermostat field '{}': {message}", field.register_name())
            }
            Self::UnknownMode(raw) => write!(f, "unknown thermostat mode {raw}"),
            Self::UnknownFan(raw) => write!(f, "unknown thermostat fan {raw}"),
        }
    }
}

impl std::error::Error for ThermostatError {}

impl From<RegisterMapError> for ThermostatError {
    fn from(error: RegisterMapError) -> Self {
        Self::RegisterMap(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_built_in_profiles_validate() {
        for profile in [
            generic_thermostat_a().unwrap(),
            generic_thermostat_b().unwrap(),
        ] {
            assert!(profile.unit_id().is_some());
            for field in ThermostatField::ALL {
                assert!(profile.field(field).is_some(), "{field:?}");
            }
        }
    }

    #[test]
    fn mode_and_fan_codes_roundtrip() {
        for mode in [
            ThermostatMode::Off,
            ThermostatMode::Heat,
            ThermostatMode::Cool,
            ThermostatMode::Auto,
        ] {
            assert_eq!(ThermostatMode::from_raw(mode.as_raw()).unwrap(), mode);
        }
        for fan in [
            ThermostatFan::Off,
            ThermostatFan::Low,
            ThermostatFan::Medium,
            ThermostatFan::High,
        ] {
            assert_eq!(ThermostatFan::from_raw(fan.as_raw()).unwrap(), fan);
        }
        assert!(ThermostatMode::from_raw(9).is_err());
        assert!(ThermostatFan::from_raw(9).is_err());
    }
}
