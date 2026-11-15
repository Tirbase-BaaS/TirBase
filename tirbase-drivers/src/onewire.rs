// SPDX-License-Identifier: AGPL-3.0-only

//! DS18B20 1-Wire reference driver (CC-02, CLAIM-34.x/PV-10).
//!
//! This module owns the bus-facing half of CC-02:
//! * [`Ds18b20Bus`] — the byte-level bus contract implemented by the guard
//!   transport (`tirbase-guard`) and the simulator (`tirbase-sim`).
//! * [`Ds18b20Sensor`] — reset/presence, Convert T, conversion wait, Read
//!   Scratchpad, CRC/range validation, and health/fault accounting.
//! * [`Ds18b20Codec`] — a pure [`DriverTrait`] codec over recorded frames.
//!
//! The protocol codec (CRC-8, scratchpad parsing, resolution decode, command
//! frames) lives in the Apache-2.0 `tirbase_driver_api::ds18b20` module and is
//! re-exported here. All device I/O is bounded: buses must implement
//! [`Ds18b20Bus`] without unbounded blocking reads.

use std::fmt;

use tirbase_driver_api::driver_trait::{
    ActuationPermitRef, DeviceModel, DriverError, DriverHealth, DriverResult, DriverTrait, Frame,
    ParameterDescriptor,
};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

pub use tirbase_driver_api::ds18b20::*;

/// Byte-level DS18B20 bus, implemented by the guard transport and simulator.
///
/// Every method must return within the transport's configured timeout; a bus may
/// not block indefinitely on a disconnected or contended line.
pub trait Ds18b20Bus {
    /// Issue a reset pulse and report whether a device answered with presence.
    fn reset_presence(&mut self) -> Result<bool, OneWireError>;
    /// Write command bytes (ROM command + function command) to the bus.
    fn write(&mut self, bytes: &[u8]) -> Result<(), OneWireError>;
    /// Read `len` bytes from the bus. Returning fewer bytes is a short read and
    /// must be rejected by the caller as [`Ds18b20Error::ShortScratchpad`].
    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, OneWireError>;
    /// Wait for a conversion to finish, bounded by the resolution's conversion
    /// time. A bus that already blocks until the conversion completes (Linux
    /// `w1_therm`) may return immediately.
    fn wait_conversion(&mut self, resolution: Ds18b20Resolution) -> Result<(), OneWireError>;
}

/// Typed bus/transport error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneWireError {
    /// No presence pulse: the probe is absent or the line is broken.
    Disconnected,
    /// Another master is driving the bus.
    BusContention,
    /// The transport exceeded its bounded deadline.
    Timeout { operation: &'static str },
    /// A conversion was read before it completed.
    ConversionIncomplete,
    /// Low-level I/O failure (message is diagnostic only).
    Io(String),
    /// The bus returned bytes that do not form a valid transaction.
    Protocol(String),
}

impl fmt::Display for OneWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OneWireError::Disconnected => write!(f, "no presence pulse: probe disconnected"),
            OneWireError::BusContention => write!(f, "1-Wire bus contention detected"),
            OneWireError::Timeout { operation } => {
                write!(f, "1-Wire operation '{operation}' timed out")
            }
            OneWireError::ConversionIncomplete => {
                write!(f, "temperature conversion still in progress")
            }
            OneWireError::Io(message) => write!(f, "1-Wire I/O error: {message}"),
            OneWireError::Protocol(message) => write!(f, "1-Wire protocol error: {message}"),
        }
    }
}

impl std::error::Error for OneWireError {}

/// Fault state surfaced to the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ds18b20Fault {
    /// No presence pulse.
    Disconnected,
    /// CRC-8 mismatch on the scratchpad.
    BadCrc { computed: u8, received: u8 },
    /// Scratchpad shorter than 9 bytes.
    ShortScratchpad { len: usize },
    /// Raw temperature outside the sensor range.
    ImpossibleTemperature { raw: i16 },
    /// Sensor returned its 85 °C power-on value.
    PowerOnReset,
    /// Another master is driving the bus.
    BusContention,
    /// A bounded transport deadline expired.
    Timeout { operation: &'static str },
    /// Conversion read before completion.
    ConversionIncomplete,
    /// Config register is invalid.
    InvalidConfig { config: u8 },
    /// Low-level I/O failure.
    Io(String),
    /// Unparseable bus/transport response.
    Protocol(String),
}

impl fmt::Display for Ds18b20Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ds18b20Fault::Disconnected => write!(f, "probe disconnected"),
            Ds18b20Fault::BadCrc { computed, received } => write!(
                f,
                "bad scratchpad CRC: computed 0x{computed:02x}, received 0x{received:02x}"
            ),
            Ds18b20Fault::ShortScratchpad { len } => {
                write!(f, "short scratchpad: {len} of {SCRATCHPAD_LEN} bytes")
            }
            Ds18b20Fault::ImpossibleTemperature { raw } => {
                write!(f, "impossible temperature raw value {raw}")
            }
            Ds18b20Fault::PowerOnReset => write!(f, "power-on reset value (85 C)"),
            Ds18b20Fault::BusContention => write!(f, "bus contention"),
            Ds18b20Fault::Timeout { operation } => write!(f, "timeout during '{operation}'"),
            Ds18b20Fault::ConversionIncomplete => write!(f, "conversion incomplete"),
            Ds18b20Fault::InvalidConfig { config } => {
                write!(f, "invalid config register 0x{config:02x}")
            }
            Ds18b20Fault::Io(message) => write!(f, "I/O error: {message}"),
            Ds18b20Fault::Protocol(message) => write!(f, "protocol error: {message}"),
        }
    }
}

impl std::error::Error for Ds18b20Fault {}

impl From<Ds18b20Error> for Ds18b20Fault {
    fn from(error: Ds18b20Error) -> Self {
        match error {
            Ds18b20Error::ShortScratchpad { len } => Ds18b20Fault::ShortScratchpad { len },
            Ds18b20Error::BadCrc { computed, received } => {
                Ds18b20Fault::BadCrc { computed, received }
            }
            Ds18b20Error::ImpossibleTemperature { raw } => {
                Ds18b20Fault::ImpossibleTemperature { raw }
            }
            Ds18b20Error::PowerOnReset => Ds18b20Fault::PowerOnReset,
            Ds18b20Error::InvalidConfig { config } => Ds18b20Fault::InvalidConfig { config },
            Ds18b20Error::InvalidRomId { family } => {
                Ds18b20Fault::Protocol(format!("invalid ROM family 0x{family:02x}"))
            }
            Ds18b20Error::BadRomCrc { computed, received } => Ds18b20Fault::Protocol(format!(
                "ROM CRC mismatch: computed 0x{computed:02x}, received 0x{received:02x}"
            )),
            Ds18b20Error::MalformedRomId => Ds18b20Fault::Protocol("malformed ROM id".into()),
            Ds18b20Error::MalformedW1Slave(message) => {
                Ds18b20Fault::Protocol(format!("malformed w1_slave: {message}"))
            }
        }
    }
}

impl From<OneWireError> for Ds18b20Fault {
    fn from(error: OneWireError) -> Self {
        match error {
            OneWireError::Disconnected => Ds18b20Fault::Disconnected,
            OneWireError::BusContention => Ds18b20Fault::BusContention,
            OneWireError::Timeout { operation } => Ds18b20Fault::Timeout { operation },
            OneWireError::ConversionIncomplete => Ds18b20Fault::ConversionIncomplete,
            OneWireError::Io(message) => Ds18b20Fault::Io(message),
            OneWireError::Protocol(message) => Ds18b20Fault::Protocol(message),
        }
    }
}

/// Health/fault state exposed to the guard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ds18b20Health {
    /// Last observed presence state.
    pub present: bool,
    /// Last fault, cleared by the next successful read.
    pub last_fault: Option<Ds18b20Fault>,
    /// Consecutive failed reads since the last success.
    pub consecutive_failures: u32,
    /// Successful reads since construction.
    pub successful_reads: u64,
    /// Last successfully decoded temperature.
    pub last_temperature: Option<FixedPointValue>,
}

impl Ds18b20Health {
    /// Healthy when the probe was present, the last read succeeded, and there
    /// are no consecutive failures.
    pub fn is_healthy(&self) -> bool {
        self.present && self.last_fault.is_none() && self.consecutive_failures == 0
    }
}

/// Bus-backed DS18B20 sensor with bounded transactions and health accounting.
#[derive(Debug, Clone)]
pub struct Ds18b20Sensor<B: Ds18b20Bus> {
    bus: B,
    rom: Option<Ds18b20RomId>,
    resolution: Ds18b20Resolution,
    health: Ds18b20Health,
}

impl<B: Ds18b20Bus> Ds18b20Sensor<B> {
    /// Creates a sensor. `rom = None` addresses the bus with Skip ROM; a ROM id
    /// switches to Match ROM for multi-drop buses.
    pub fn new(bus: B, rom: Option<Ds18b20RomId>, resolution: Ds18b20Resolution) -> Self {
        Self {
            bus,
            rom,
            resolution,
            health: Ds18b20Health::default(),
        }
    }

    /// Bus access for transports that need to change mode or inspect counters.
    pub fn bus(&self) -> &B {
        &self.bus
    }

    /// Mutable bus access.
    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }

    /// Configured ROM id, if Match ROM addressing is used.
    pub fn rom(&self) -> Option<Ds18b20RomId> {
        self.rom
    }

    /// Configured conversion resolution.
    pub fn resolution(&self) -> Ds18b20Resolution {
        self.resolution
    }

    /// Current health/fault snapshot.
    pub fn health(&self) -> Ds18b20Health {
        self.health.clone()
    }

    /// Last fault, if any.
    pub fn fault_state(&self) -> Option<Ds18b20Fault> {
        self.health.last_fault.clone()
    }

    /// True when the last transaction succeeded and presence was observed.
    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    /// Reset + Read Scratchpad + CRC/range validation.
    pub fn read_scratchpad(&mut self) -> Result<Ds18b20Scratchpad, Ds18b20Fault> {
        let result = self.read_scratchpad_inner();
        self.finish(result)
    }

    /// Read the current scratchpad temperature.
    pub fn read_temperature(&mut self) -> Result<FixedPointValue, Ds18b20Fault> {
        let result = self
            .read_scratchpad_inner()
            .and_then(|pad| pad.temperature().map_err(Ds18b20Fault::from));
        let temperature = self.finish(result)?;
        self.health.last_temperature = Some(temperature);
        Ok(temperature)
    }

    /// Reset, issue Convert T, wait the resolution's maximum conversion time,
    /// then read and decode the scratchpad.
    pub fn convert_and_read(&mut self) -> Result<FixedPointValue, Ds18b20Fault> {
        let result = self.convert_and_read_inner();
        let temperature = self.finish(result)?;
        self.health.last_temperature = Some(temperature);
        Ok(temperature)
    }

    fn convert_and_read_inner(&mut self) -> Result<FixedPointValue, Ds18b20Fault> {
        let present = self.bus.reset_presence().map_err(Ds18b20Fault::from)?;
        if !present {
            return Err(Ds18b20Fault::Disconnected);
        }
        self.health.present = true;
        let command = self.addressed_command(CMD_CONVERT_T);
        self.bus.write(&command).map_err(Ds18b20Fault::from)?;
        self.bus
            .wait_conversion(self.resolution)
            .map_err(Ds18b20Fault::from)?;
        let pad = self.read_scratchpad_inner()?;
        pad.temperature().map_err(Ds18b20Fault::from)
    }

    fn read_scratchpad_inner(&mut self) -> Result<Ds18b20Scratchpad, Ds18b20Fault> {
        let present = self.bus.reset_presence().map_err(Ds18b20Fault::from)?;
        if !present {
            return Err(Ds18b20Fault::Disconnected);
        }
        self.health.present = true;
        let command = self.addressed_command(CMD_READ_SCRATCHPAD);
        self.bus.write(&command).map_err(Ds18b20Fault::from)?;
        let bytes = self
            .bus
            .read_bytes(SCRATCHPAD_LEN)
            .map_err(Ds18b20Fault::from)?;
        parse_scratchpad(&bytes).map_err(Ds18b20Fault::from)
    }

    fn addressed_command(&self, command: u8) -> Vec<u8> {
        match self.rom {
            Some(rom) => match_rom_command(rom, command).to_vec(),
            None => vec![CMD_SKIP_ROM, command],
        }
    }

    fn finish<T>(&mut self, result: Result<T, Ds18b20Fault>) -> Result<T, Ds18b20Fault> {
        match &result {
            Ok(_) => {
                self.health.present = true;
                self.health.last_fault = None;
                self.health.consecutive_failures = 0;
                self.health.successful_reads = self.health.successful_reads.saturating_add(1);
            }
            Err(fault) => {
                if matches!(fault, Ds18b20Fault::Disconnected) {
                    self.health.present = false;
                }
                self.health.last_fault = Some(fault.clone());
                self.health.consecutive_failures =
                    self.health.consecutive_failures.saturating_add(1);
            }
        }
        result
    }
}

/// Codec-only DS18B20 driver for recorded scratchpad frames.
///
/// This implements [`DriverTrait`] and performs no bus I/O. Use
/// [`Ds18b20Sensor`] when a transport is available.
#[derive(Debug, Clone, Default)]
pub struct Ds18b20Codec {
    resolution: Ds18b20Resolution,
}

impl Ds18b20Codec {
    /// Creates a codec with the given configured resolution.
    pub fn new(resolution: Ds18b20Resolution) -> Self {
        Self { resolution }
    }

    /// Configured resolution.
    pub fn resolution(&self) -> Ds18b20Resolution {
        self.resolution
    }

    fn decode(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let pad = parse_scratchpad(frame).map_err(codec_error)?;
        pad.temperature().map_err(codec_error)
    }
}

fn codec_error(error: Ds18b20Error) -> DriverError {
    match error {
        Ds18b20Error::ShortScratchpad { len } => {
            DriverError::InvalidFrame(format!("short scratchpad: {len} of 9 bytes"))
        }
        Ds18b20Error::BadCrc { computed, received } => DriverError::InvalidFrame(format!(
            "bad scratchpad CRC: computed 0x{computed:02x}, received 0x{received:02x}"
        )),
        other => DriverError::Codec(other.to_string()),
    }
}

impl DriverTrait for Ds18b20Codec {
    fn capability_discovery(&self) -> DriverResult<DeviceModel> {
        let min = decode_temperature(MIN_TEMPERATURE_RAW, Ds18b20Resolution::Bits12)
            .map_err(codec_error)?;
        let max = decode_temperature(MAX_TEMPERATURE_RAW, Ds18b20Resolution::Bits12)
            .map_err(codec_error)?;
        DeviceModel::try_new(
            "ds18b20".into(),
            vec![ParameterDescriptor {
                name: "temperature_c".into(),
                unit_id: UNIT_DEG_C,
                unit_label: "degC".into(),
                range: [min, max],
                writable: false,
            }],
        )
        .map_err(|error| DriverError::Capability(error.to_string()))
    }

    fn encode_read(&self, param: &str) -> DriverResult<Frame> {
        if param != "temperature_c" {
            return Err(DriverError::UnsupportedParam(param.into()));
        }
        Ok(read_scratchpad_command().to_vec())
    }

    fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        self.decode(frame)
    }

    fn encode_actuation(&self, _permit: &ActuationPermitRef) -> DriverResult<Frame> {
        Err(DriverError::Capability(
            "DS18B20 is a read-only temperature sensor".into(),
        ))
    }

    fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        self.decode(frame)
    }

    fn encode_health_check(&self) -> DriverResult<Frame> {
        Ok(read_scratchpad_command().to_vec())
    }

    fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
        match parse_scratchpad(frame)
            .and_then(|pad| pad.temperature().map(|temperature| (pad, temperature)))
        {
            Ok((pad, temperature)) => Ok(DriverHealth {
                healthy: true,
                detail: format!(
                    "resolution={} bits, raw={}, temperature={:?}",
                    pad.resolution().map(|r| r.bits()).unwrap_or(0),
                    pad.temperature_raw,
                    temperature
                ),
            }),
            Err(error) => Ok(DriverHealth {
                healthy: false,
                detail: error.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_encodes_read_and_decodes_recorded_frame() {
        let codec = Ds18b20Codec::default();
        assert_eq!(
            codec.encode_read("temperature_c").unwrap(),
            vec![0xCC, 0xBE]
        );
        let frame = [0x72, 0x01, 0x4b, 0x46, 0x7f, 0xff, 0x0e, 0x10, 0x57];
        assert_eq!(
            codec.decode_read_response(&frame).unwrap(),
            FixedPointValue::new(231250, -4, UNIT_DEG_C)
        );
        assert!(matches!(
            codec.encode_actuation(&ActuationPermitRef {
                target_id: tirbase_types::TargetId::new("t"),
                param: "temperature_c".into(),
                value: FixedPointValue::new(0, 0, UNIT_DEG_C),
                entry_id: [0; 16],
            }),
            Err(DriverError::Capability(_))
        ));
    }

    #[test]
    fn codec_rejects_bad_crc_as_typed_error() {
        let codec = Ds18b20Codec::default();
        let mut frame = [0x72, 0x01, 0x4b, 0x46, 0x7f, 0xff, 0x0e, 0x10, 0x57];
        frame[8] ^= 0xFF;
        assert!(matches!(
            codec.decode_read_response(&frame),
            Err(DriverError::InvalidFrame(_))
        ));
        assert!(!codec.decode_health_response(&frame).unwrap().healthy);
    }
}
