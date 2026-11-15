// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic simulated DS18B20 1-Wire bus (CC-02, F-13 `OneWire`).
//!
//! The simulator implements [`Ds18b20Bus`] with no real I/O and no wall clock:
//! conversions advance a virtual millisecond counter by the datasheet maximum.
//! It supports presence/disconnect, bad CRC, short scratchpad reads, impossible
//! temperatures, bus contention, transport timeouts, and reading recorded Linux
//! `w1_slave` frames.

use tirbase_drivers::onewire::{
    crc8, parse_w1_slave, Ds18b20Bus, Ds18b20Error, Ds18b20Resolution, OneWireError, CMD_CONVERT_T,
    CMD_READ_SCRATCHPAD, SCRATCHPAD_LEN,
};

/// Simulated DS18B20 bus with injectable faults.
#[derive(Debug, Clone)]
pub struct SimOneWireBus {
    present: bool,
    scratchpad: [u8; SCRATCHPAD_LEN],
    conversion_required: bool,
    conversion_pending: bool,
    conversion_waits_ms: Vec<u64>,
    short_read: Option<usize>,
    contention: bool,
    timeout: bool,
    writes: Vec<Vec<u8>>,
    virtual_time_ms: u64,
}

impl SimOneWireBus {
    /// Creates a present 12-bit sensor reporting `raw` (0.0625 °C per count).
    pub fn new(raw: i16, resolution: Ds18b20Resolution) -> Self {
        let mut scratchpad = [0u8; SCRATCHPAD_LEN];
        scratchpad[0..2].copy_from_slice(&raw.to_le_bytes());
        scratchpad[2] = 0x4B;
        scratchpad[3] = 0x46;
        scratchpad[4] = resolution.config_bits() | 0x1F;
        scratchpad[5] = 0xFF;
        scratchpad[6] = 0x0E;
        scratchpad[7] = 0x10;
        scratchpad[8] = crc8(&scratchpad[..8]);
        Self {
            present: true,
            scratchpad,
            conversion_required: true,
            conversion_pending: false,
            conversion_waits_ms: Vec::new(),
            short_read: None,
            contention: false,
            timeout: false,
            writes: Vec::new(),
            virtual_time_ms: 0,
        }
    }

    /// Creates a simulated bus from a recorded Linux `w1_slave` document.
    pub fn from_w1_slave(document: &str) -> Result<Self, Ds18b20Error> {
        let reading = parse_w1_slave(document)?;
        let mut scratchpad = [0u8; SCRATCHPAD_LEN];
        scratchpad.copy_from_slice(&reading.scratchpad[..SCRATCHPAD_LEN]);
        let mut bus = Self::new(0, Ds18b20Resolution::Bits12);
        bus.scratchpad = scratchpad;
        Ok(bus)
    }

    /// Creates a simulated bus from raw scratchpad bytes.
    pub fn with_scratchpad(scratchpad: [u8; SCRATCHPAD_LEN]) -> Self {
        let mut bus = Self::new(0, Ds18b20Resolution::Bits12);
        bus.scratchpad = scratchpad;
        bus
    }

    /// Current simulated scratchpad.
    pub fn scratchpad(&self) -> [u8; SCRATCHPAD_LEN] {
        self.scratchpad
    }

    /// Command frames written to the bus, in order.
    pub fn writes(&self) -> &[Vec<u8>] {
        &self.writes
    }

    /// Conversion waits requested by the driver, in milliseconds.
    pub fn conversion_waits_ms(&self) -> &[u64] {
        &self.conversion_waits_ms
    }

    /// Virtual elapsed time.
    pub fn virtual_time_ms(&self) -> u64 {
        self.virtual_time_ms
    }

    /// Sets presence (false simulates a disconnected probe).
    pub fn set_present(&mut self, present: bool) -> &mut Self {
        self.present = present;
        self
    }

    /// Truncates scratchpad reads to `len` bytes (short-read fault).
    pub fn set_short_read(&mut self, len: Option<usize>) -> &mut Self {
        self.short_read = len;
        self
    }

    /// Corrupts the scratchpad CRC byte.
    pub fn set_bad_crc(&mut self) -> &mut Self {
        self.scratchpad[8] ^= 0xFF;
        self
    }

    /// Replaces the raw temperature and recomputes the CRC (impossible-value
    /// and power-on faults).
    pub fn set_temperature_raw(&mut self, raw: i16) -> &mut Self {
        self.scratchpad[0..2].copy_from_slice(&raw.to_le_bytes());
        self.scratchpad[8] = crc8(&self.scratchpad[..8]);
        self
    }

    /// Requires a completed conversion wait before a scratchpad read.
    pub fn set_conversion_required(&mut self, required: bool) -> &mut Self {
        self.conversion_required = required;
        self
    }

    /// Simulates another master driving the bus.
    pub fn set_contention(&mut self, contention: bool) -> &mut Self {
        self.contention = contention;
        self
    }

    /// Simulates a transport timeout.
    pub fn set_timeout(&mut self, timeout: bool) -> &mut Self {
        self.timeout = timeout;
        self
    }

    fn fault(&self, operation: &'static str) -> Result<(), OneWireError> {
        if self.timeout {
            return Err(OneWireError::Timeout { operation });
        }
        if self.contention {
            return Err(OneWireError::BusContention);
        }
        Ok(())
    }
}

impl Ds18b20Bus for SimOneWireBus {
    fn reset_presence(&mut self) -> Result<bool, OneWireError> {
        self.fault("reset_presence")?;
        Ok(self.present)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), OneWireError> {
        self.fault("write")?;
        self.writes.push(bytes.to_vec());
        if bytes.last() == Some(&CMD_CONVERT_T) {
            self.conversion_pending = self.conversion_required;
        } else if bytes.last() == Some(&CMD_READ_SCRATCHPAD) {
            // A read does not start a conversion.
        } else {
            return Err(OneWireError::Protocol(format!(
                "unexpected 1-Wire command frame {bytes:02x?}"
            )));
        }
        Ok(())
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, OneWireError> {
        self.fault("read_bytes")?;
        let command = self.writes.last().and_then(|frame| frame.last()).copied();
        if command != Some(CMD_READ_SCRATCHPAD) {
            return Err(OneWireError::Protocol(
                "read attempted without a Read Scratchpad command".into(),
            ));
        }
        if self.conversion_pending {
            return Err(OneWireError::ConversionIncomplete);
        }
        let available = self
            .short_read
            .unwrap_or(SCRATCHPAD_LEN)
            .min(SCRATCHPAD_LEN);
        let count = len.min(available);
        Ok(self.scratchpad[..count].to_vec())
    }

    fn wait_conversion(&mut self, resolution: Ds18b20Resolution) -> Result<(), OneWireError> {
        self.fault("wait_conversion")?;
        let wait_ms = u64::from(resolution.conversion_time_ms());
        self.conversion_waits_ms.push(wait_ms);
        self.virtual_time_ms = self.virtual_time_ms.saturating_add(wait_ms);
        self.conversion_pending = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDED: &str = "72 01 4b 46 7f ff 0e 10 57 : crc=57 YES\n\
                            72 01 4b 46 7f ff 0e 10 57 t=23125\n";

    #[test]
    fn recorded_frame_roundtrips() {
        let bus = SimOneWireBus::from_w1_slave(RECORDED).unwrap();
        assert_eq!(
            bus.scratchpad(),
            [0x72, 0x01, 0x4b, 0x46, 0x7f, 0xff, 0x0e, 0x10, 0x57]
        );
        assert_eq!(bus.conversion_waits_ms().len(), 0);
    }

    #[test]
    fn bad_crc_is_injectable() {
        let mut bus = SimOneWireBus::from_w1_slave(RECORDED).unwrap();
        bus.set_bad_crc();
        assert_ne!(crc8(&bus.scratchpad()[..8]), bus.scratchpad()[8]);
    }
}
