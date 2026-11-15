// SPDX-License-Identifier: AGPL-3.0-only

//! Reusable Modbus thermostat runtime (CC-03).
//!
//! [`ThermostatDevice`] installs a validated
//! [`ThermostatProfile`](tirbase_driver_api::thermostat::ThermostatProfile) on
//! either the TCP or RTU Modbus client. It reads current temperature, setpoint,
//! mode, fan, alarm, and fault registers, writes setpoint/mode/fan, surfaces
//! device exception PDUs as [`DriverError::Exception`], and retries bounded
//! timeouts according to [`ThermostatDevice::with_retries`].
//!
//! The pure profile, decoding, and mode/fan types live in the Apache-2.0
//! `tirbase_driver_api::thermostat` module.

use tirbase_driver_api::driver_trait::{DriverError, DriverResult};
use tirbase_driver_api::register_map::RegisterDef;
use tirbase_types::FixedPointValue;

use crate::modbus::{ModbusRtuClient, ModbusTcpClient};

pub use tirbase_driver_api::thermostat::*;

/// Common register operations used by [`ThermostatDevice`].
pub trait ModbusClient {
    fn read_holding_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>>;
    fn read_input_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>>;
    fn write_single_register(&mut self, address: u16, value: u16) -> DriverResult<()>;
    fn write_multiple_registers(&mut self, address: u16, values: &[u16]) -> DriverResult<()>;
}

impl<T: std::io::Read + std::io::Write> ModbusClient for ModbusTcpClient<T> {
    fn read_holding_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>> {
        ModbusTcpClient::read_holding_registers(self, address, quantity)
    }

    fn read_input_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>> {
        ModbusTcpClient::read_input_registers(self, address, quantity)
    }

    fn write_single_register(&mut self, address: u16, value: u16) -> DriverResult<()> {
        ModbusTcpClient::write_single_register(self, address, value)
    }

    fn write_multiple_registers(&mut self, address: u16, values: &[u16]) -> DriverResult<()> {
        ModbusTcpClient::write_multiple_registers(self, address, values)
    }
}

impl<T: std::io::Read + std::io::Write> ModbusClient for ModbusRtuClient<T> {
    fn read_holding_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>> {
        ModbusRtuClient::read_holding_registers(self, address, quantity)
    }

    fn read_input_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>> {
        ModbusRtuClient::read_input_registers(self, address, quantity)
    }

    fn write_single_register(&mut self, address: u16, value: u16) -> DriverResult<()> {
        ModbusRtuClient::write_single_register(self, address, value)
    }

    fn write_multiple_registers(&mut self, address: u16, values: &[u16]) -> DriverResult<()> {
        ModbusRtuClient::write_multiple_registers(self, address, values)
    }
}

/// Thermostat installed on a Modbus client.
#[derive(Debug, Clone)]
pub struct ThermostatDevice<C: ModbusClient> {
    client: C,
    profile: ThermostatProfile,
    retries: u8,
}

impl<C: ModbusClient> ThermostatDevice<C> {
    /// Installs a validated profile on a Modbus client. No I/O is performed.
    pub fn install(client: C, profile: ThermostatProfile) -> Result<Self, ThermostatError> {
        // Re-validate so a profile cannot be mutated into an invalid shape.
        let profile = ThermostatProfile::new(profile.register_map().clone())?;
        Ok(Self {
            client,
            profile,
            retries: 0,
        })
    }

    /// Number of retries after a bounded timeout (default 0).
    pub fn with_retries(mut self, retries: u8) -> Self {
        self.retries = retries;
        self
    }

    /// Installed profile.
    pub fn profile(&self) -> &ThermostatProfile {
        &self.profile
    }

    /// Underlying client.
    pub fn client(&self) -> &C {
        &self.client
    }

    /// Mutable underlying client.
    pub fn client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    /// Consumes the device and returns the client.
    pub fn into_inner(self) -> C {
        self.client
    }

    /// Reads a temperature-family field.
    pub fn read_temperature(&mut self, field: ThermostatField) -> DriverResult<FixedPointValue> {
        let def = self.definition(field)?;
        let words = self.read_words(&def)?;
        self.profile
            .decode_temperature(field, &words)
            .map_err(profile_error)
    }

    /// Reads the current temperature.
    pub fn read_current_temperature(&mut self) -> DriverResult<FixedPointValue> {
        self.read_temperature(ThermostatField::CurrentTemperature)
    }

    /// Reads the configured setpoint.
    pub fn read_setpoint(&mut self) -> DriverResult<FixedPointValue> {
        self.read_temperature(ThermostatField::Setpoint)
    }

    /// Writes the setpoint.
    pub fn write_setpoint(&mut self, value: &FixedPointValue) -> DriverResult<()> {
        let def = self.definition(ThermostatField::Setpoint)?;
        let words = self
            .profile
            .encode_temperature(ThermostatField::Setpoint, value)
            .map_err(profile_error)?;
        self.write_words(&def, &words)
    }

    /// Reads the operating mode.
    pub fn read_mode(&mut self) -> DriverResult<ThermostatMode> {
        let raw = self.read_raw(ThermostatField::Mode)?;
        ThermostatMode::from_raw(raw).map_err(profile_error)
    }

    /// Writes the operating mode.
    pub fn write_mode(&mut self, mode: ThermostatMode) -> DriverResult<()> {
        self.write_raw(ThermostatField::Mode, mode.as_raw())
    }

    /// Reads the fan speed.
    pub fn read_fan(&mut self) -> DriverResult<ThermostatFan> {
        let raw = self.read_raw(ThermostatField::Fan)?;
        ThermostatFan::from_raw(raw).map_err(profile_error)
    }

    /// Writes the fan speed.
    pub fn write_fan(&mut self, fan: ThermostatFan) -> DriverResult<()> {
        self.write_raw(ThermostatField::Fan, fan.as_raw())
    }

    /// Reads the alarm register.
    pub fn read_alarm(&mut self) -> DriverResult<u16> {
        self.read_raw(ThermostatField::Alarm)
    }

    /// Reads the fault register.
    pub fn read_fault(&mut self) -> DriverResult<u16> {
        self.read_raw(ThermostatField::Fault)
    }

    /// Reads every semantic field.
    pub fn read_all(&mut self) -> DriverResult<ThermostatReading> {
        Ok(ThermostatReading {
            current_temperature: self.read_current_temperature()?,
            setpoint: self.read_setpoint()?,
            mode: self.read_mode()?,
            fan: self.read_fan()?,
            alarm: self.read_alarm()?,
            fault: self.read_fault()?,
        })
    }

    fn read_raw(&mut self, field: ThermostatField) -> DriverResult<u16> {
        let def = self.definition(field)?;
        let words = self.read_words(&def)?;
        self.profile
            .decode_raw(field, &words)
            .map_err(profile_error)
    }

    fn write_raw(&mut self, field: ThermostatField, value: u16) -> DriverResult<()> {
        let def = self.definition(field)?;
        let words = self
            .profile
            .encode_raw(field, value)
            .map_err(profile_error)?;
        self.write_words(&def, &words)
    }

    fn definition(&self, field: ThermostatField) -> DriverResult<RegisterDef> {
        self.profile
            .field(field)
            .cloned()
            .ok_or_else(|| profile_error(ThermostatError::MissingField(field)))
    }

    fn read_words(&mut self, def: &RegisterDef) -> DriverResult<Vec<u16>> {
        let function = def.function;
        let address = def.register;
        let quantity = def.quantity;
        self.with_retry(|client| match function {
            // Writable holding registers (FC 06/16) are read back with FC 03.
            3 | 6 | 16 => client.read_holding_registers(address, quantity),
            4 => client.read_input_registers(address, quantity),
            other => Err(DriverError::UnsupportedParam(format!(
                "thermostat read uses unsupported FC {other}"
            ))),
        })
    }

    fn write_words(&mut self, def: &RegisterDef, words: &[u16]) -> DriverResult<()> {
        let function = def.function;
        let address = def.register;
        self.with_retry(|client| match function {
            6 => match words {
                [value] => client.write_single_register(address, *value),
                _ => Err(DriverError::Codec(
                    "FC 06 requires exactly one register word".into(),
                )),
            },
            16 => client.write_multiple_registers(address, words),
            other => Err(DriverError::UnsupportedParam(format!(
                "thermostat write uses unsupported FC {other}"
            ))),
        })
    }

    fn with_retry<T>(
        &mut self,
        mut operation: impl FnMut(&mut C) -> DriverResult<T>,
    ) -> DriverResult<T> {
        let attempts = u16::from(self.retries) + 1;
        let mut last_error = None;
        for attempt in 0..attempts {
            match operation(&mut self.client) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let retryable = matches!(error, DriverError::Timeout(_));
                    if !retryable || attempt + 1 == attempts {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| DriverError::Codec("thermostat retry failed".into())))
    }
}

fn profile_error(error: ThermostatError) -> DriverError {
    DriverError::Codec(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_expose_expected_functions() {
        let profile = generic_thermostat_a().unwrap();
        assert_eq!(
            profile.field(ThermostatField::Setpoint).unwrap().function,
            6
        );
        let profile = generic_thermostat_b().unwrap();
        assert_eq!(
            profile.field(ThermostatField::Setpoint).unwrap().function,
            16
        );
    }
}
