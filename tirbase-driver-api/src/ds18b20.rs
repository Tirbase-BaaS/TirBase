// SPDX-License-Identifier: Apache-2.0

//! DS18B20 1-Wire temperature sensor codec (CC-02).
//!
//! Pure protocol helpers: reset/presence framing, Skip ROM / Match ROM /
//! Convert T / Read Scratchpad commands, Dallas/Maxim CRC-8, scratchpad
//! validation, resolution handling, temperature decoding, and conversion
//! timing. No bus or device I/O happens here; the guard-owned transport and the
//! driver implement the byte movement.
//!
//! ## Wire protocol (DS18B20)
//! 1. Reset pulse, then sample presence (bus pulls low).
//! 2. ROM command: `SKIP ROM (0xCC)` / `MATCH ROM (0x55)` + 8-byte ROM id.
//! 3. Function command: `CONVERT T (0x44)` or `READ SCRATCHPAD (0xBE)`.
//! 4. Scratchpad: 9 bytes, little-endian temperature in bytes 0..2, config in
//!    byte 4, CRC-8 in byte 8 over bytes 0..8.
//!
//! ## Conversion timing (datasheet maxima)
//! | Resolution | Bits | Conversion |
//! |---|---:|---:|
//! | `Bits9` | 9 | 93.75 ms |
//! | `Bits10` | 10 | 187.5 ms |
//! | `Bits11` | 11 | 375 ms |
//! | `Bits12` | 12 | 750 ms |

use std::fmt;
use std::time::Duration;

use tirbase_types::{FixedPointValue, UNIT_DEG_C};

/// DS18B20 family code (first ROM byte).
pub const DS18B20_FAMILY_CODE: u8 = 0x28;
/// Skip ROM: address every device on the bus.
pub const CMD_SKIP_ROM: u8 = 0xCC;
/// Match ROM: address one device by its 64-bit ROM id.
pub const CMD_MATCH_ROM: u8 = 0x55;
/// Convert T: start a temperature conversion.
pub const CMD_CONVERT_T: u8 = 0x44;
/// Read Scratchpad: read 9 bytes (8 data + CRC).
pub const CMD_READ_SCRATCHPAD: u8 = 0xBE;
/// Scratchpad length in bytes.
pub const SCRATCHPAD_LEN: usize = 9;
/// Power-on default scratchpad config (12-bit resolution, alarm defaults).
pub const SCRATCHPAD_CONFIG_DEFAULT: u8 = 0x7F;
/// Power-on default temperature raw value (85.0 °C).
pub const POWER_ON_TEMPERATURE_RAW: i16 = 0x0550;
/// Lowest raw value in the DS18B20 measurement range (-55 °C).
pub const MIN_TEMPERATURE_RAW: i16 = -880;
/// Highest raw value in the DS18B20 measurement range (125 °C).
pub const MAX_TEMPERATURE_RAW: i16 = 2000;

/// Programmable conversion resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Ds18b20Resolution {
    Bits9,
    Bits10,
    Bits11,
    #[default]
    Bits12,
}

impl Ds18b20Resolution {
    /// Resolution in bits.
    pub const fn bits(self) -> u8 {
        match self {
            Self::Bits9 => 9,
            Self::Bits10 => 10,
            Self::Bits11 => 11,
            Self::Bits12 => 12,
        }
    }

    /// Maximum conversion time in whole milliseconds (rounded up from the
    /// datasheet value: 93.75, 187.5, 375, 750 ms).
    pub const fn conversion_time_ms(self) -> u16 {
        match self {
            Self::Bits9 => 94,
            Self::Bits10 => 188,
            Self::Bits11 => 375,
            Self::Bits12 => 750,
        }
    }

    /// Bounded wait for a conversion at this resolution.
    pub const fn conversion_time(self) -> Duration {
        Duration::from_millis(self.conversion_time_ms() as u64)
    }

    /// Config-register bits 6:5 for this resolution.
    pub const fn config_bits(self) -> u8 {
        match self {
            Self::Bits9 => 0b0000_0000,
            Self::Bits10 => 0b0010_0000,
            Self::Bits11 => 0b0100_0000,
            Self::Bits12 => 0b0110_0000,
        }
    }

    /// Decodes the resolution from a scratchpad config byte.
    ///
    /// Valid config bytes have bit 7 clear and bits 4:0 set (0x1F); bits 6:5
    /// select the resolution.
    pub fn from_config(config: u8) -> Result<Self, Ds18b20Error> {
        if config & 0x80 != 0 || config & 0x1F != 0x1F {
            return Err(Ds18b20Error::InvalidConfig { config });
        }
        Ok(match (config >> 5) & 0x03 {
            0 => Self::Bits9,
            1 => Self::Bits10,
            2 => Self::Bits11,
            _ => Self::Bits12,
        })
    }

    /// Masks the bits that are undefined at this resolution.
    ///
    /// Two's-complement raw values are quantised toward zero on the positive
    /// side and toward the next representable value on the negative side, which
    /// is how the DS18B20 reports partial conversions.
    pub fn quantize_raw(self, raw: i16) -> i16 {
        let mask: u16 = match self {
            Self::Bits9 => 0xFFF8,
            Self::Bits10 => 0xFFFC,
            Self::Bits11 => 0xFFFE,
            Self::Bits12 => 0xFFFF,
        };
        ((raw as u16) & mask) as i16
    }
}

/// A validated 64-bit DS18B20 ROM id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ds18b20RomId([u8; 8]);

impl Ds18b20RomId {
    /// Builds a ROM id from all 8 bytes, validating family code and CRC.
    pub fn new(bytes: [u8; 8]) -> Result<Self, Ds18b20Error> {
        if bytes[0] != DS18B20_FAMILY_CODE {
            return Err(Ds18b20Error::InvalidRomId { family: bytes[0] });
        }
        let computed = crc8(&bytes[..7]);
        if computed != bytes[7] {
            return Err(Ds18b20Error::BadRomCrc {
                computed,
                received: bytes[7],
            });
        }
        Ok(Self(bytes))
    }

    /// Builds a ROM id from the sysfs device name (`28-000006b4a69b`), which
    /// carries family + 6 serial bytes; the CRC byte is computed.
    pub fn from_sysfs_name(name: &str) -> Result<Self, Ds18b20Error> {
        let (family, serial) = name.split_once('-').ok_or(Ds18b20Error::MalformedRomId)?;
        if family.len() != 2 || serial.len() != 12 {
            return Err(Ds18b20Error::MalformedRomId);
        }
        let mut bytes = [0u8; 8];
        bytes[0] = parse_hex_byte(family)?;
        for (index, pair) in serial.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| Ds18b20Error::MalformedRomId)?;
            bytes[index + 1] = parse_hex_byte(pair)?;
        }
        bytes[7] = crc8(&bytes[..7]);
        Self::new(bytes)
    }

    /// Builds a ROM id from 16 hex characters (family + serial + CRC).
    pub fn from_hex(value: &str) -> Result<Self, Ds18b20Error> {
        let value = value.trim().replace('-', "");
        if value.len() != 16 {
            return Err(Ds18b20Error::MalformedRomId);
        }
        let mut bytes = [0u8; 8];
        for (index, pair) in value.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| Ds18b20Error::MalformedRomId)?;
            bytes[index] = parse_hex_byte(pair)?;
        }
        Self::new(bytes)
    }

    /// All 8 ROM bytes.
    pub const fn bytes(self) -> [u8; 8] {
        self.0
    }

    /// Family code (always [`DS18B20_FAMILY_CODE`] for this type).
    pub const fn family_code(self) -> u8 {
        self.0[0]
    }
}

impl fmt::Display for Ds18b20RomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Parsed DS18B20 scratchpad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ds18b20Scratchpad {
    /// Raw signed 16-bit temperature (byte 0 LSB, byte 1 MSB).
    pub temperature_raw: i16,
    /// High alarm threshold.
    pub th: u8,
    /// Low alarm threshold.
    pub tl: u8,
    /// Config register.
    pub config: u8,
    /// Received CRC byte.
    pub crc: u8,
}

impl Ds18b20Scratchpad {
    /// Resolution encoded in the config register.
    pub fn resolution(&self) -> Result<Ds18b20Resolution, Ds18b20Error> {
        Ds18b20Resolution::from_config(self.config)
    }

    /// Decodes the temperature at the scratchpad's configured resolution.
    pub fn temperature(&self) -> Result<FixedPointValue, Ds18b20Error> {
        decode_temperature(self.temperature_raw, self.resolution()?)
    }
}

/// Parses a 9-byte scratchpad frame, rejecting short frames and bad CRCs.
pub fn parse_scratchpad(frame: &[u8]) -> Result<Ds18b20Scratchpad, Ds18b20Error> {
    if frame.len() < SCRATCHPAD_LEN {
        return Err(Ds18b20Error::ShortScratchpad { len: frame.len() });
    }
    let computed = crc8(&frame[..8]);
    if computed != frame[8] {
        return Err(Ds18b20Error::BadCrc {
            computed,
            received: frame[8],
        });
    }
    let config = frame[4];
    // Validate the config register even though the caller may not use it.
    Ds18b20Resolution::from_config(config)?;
    Ok(Ds18b20Scratchpad {
        temperature_raw: i16::from_le_bytes([frame[0], frame[1]]),
        th: frame[2],
        tl: frame[3],
        config,
        crc: frame[8],
    })
}

/// Decodes a raw temperature at `resolution` into a fixed-point °C value.
///
/// Rejects the power-on reset value (85 °C) and raw values outside the DS18B20
/// range (-55…+125 °C).
pub fn decode_temperature(
    raw: i16,
    resolution: Ds18b20Resolution,
) -> Result<FixedPointValue, Ds18b20Error> {
    let raw = resolution.quantize_raw(raw);
    if raw == POWER_ON_TEMPERATURE_RAW {
        return Err(Ds18b20Error::PowerOnReset);
    }
    if !(MIN_TEMPERATURE_RAW..=MAX_TEMPERATURE_RAW).contains(&raw) {
        return Err(Ds18b20Error::ImpossibleTemperature { raw });
    }
    // 1 raw count = 0.0625 °C = 625 × 10^-4 °C.
    Ok(FixedPointValue::new(i64::from(raw) * 625, -4, UNIT_DEG_C))
}

/// Dallas/Maxim CRC-8 (reflected polynomial 0x8C, init 0).
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8C
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Skip ROM + Convert T.
pub const fn convert_t_command() -> [u8; 2] {
    [CMD_SKIP_ROM, CMD_CONVERT_T]
}

/// Skip ROM + Read Scratchpad.
pub const fn read_scratchpad_command() -> [u8; 2] {
    [CMD_SKIP_ROM, CMD_READ_SCRATCHPAD]
}

/// Match ROM + id + command.
pub fn match_rom_command(rom: Ds18b20RomId, command: u8) -> [u8; 10] {
    let mut frame = [0u8; 10];
    frame[0] = CMD_MATCH_ROM;
    frame[1..9].copy_from_slice(&rom.bytes());
    frame[9] = command;
    frame
}

/// A parsed Linux `w1_slave` reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W1SlaveReading {
    /// The 9 scratchpad bytes reported by the kernel.
    pub scratchpad: Vec<u8>,
    /// Whether the computed CRC matches the received CRC byte.
    pub crc_ok: bool,
    /// The `t=` millidegree value, when present.
    pub temperature_millidegrees: Option<i32>,
}

/// Parses the two-line Linux `w1_slave` format:
///
/// ```text
/// 72 01 4b 46 7f ff 0e 10 57 : crc=57 YES
/// 72 01 4b 46 7f ff 0e 10 57 t=23125
/// ```
pub fn parse_w1_slave(document: &str) -> Result<W1SlaveReading, Ds18b20Error> {
    let mut lines = document.lines();
    let first = lines
        .next()
        .ok_or_else(|| Ds18b20Error::MalformedW1Slave("empty document".into()))?;
    let (hex_part, status_part) = first
        .split_once(':')
        .ok_or_else(|| Ds18b20Error::MalformedW1Slave("missing ':'".into()))?;

    let mut scratchpad = Vec::new();
    for token in hex_part.split_whitespace() {
        let byte = u8::from_str_radix(token.trim(), 16)
            .map_err(|_| Ds18b20Error::MalformedW1Slave(format!("invalid hex byte '{token}'")))?;
        scratchpad.push(byte);
    }
    if scratchpad.len() < SCRATCHPAD_LEN {
        return Err(Ds18b20Error::ShortScratchpad {
            len: scratchpad.len(),
        });
    }
    scratchpad.truncate(SCRATCHPAD_LEN);
    let computed = crc8(&scratchpad[..8]);
    let crc_ok = computed == scratchpad[8];
    let _kernel_verdict = status_part.contains("YES");

    let temperature_millidegrees = lines
        .find_map(|line| line.split_once("t="))
        .and_then(|(_, value)| value.trim().parse::<i32>().ok());

    Ok(W1SlaveReading {
        scratchpad,
        crc_ok,
        temperature_millidegrees,
    })
}

fn parse_hex_byte(token: &str) -> Result<u8, Ds18b20Error> {
    u8::from_str_radix(token.trim(), 16).map_err(|_| Ds18b20Error::MalformedRomId)
}

/// Typed DS18B20 codec error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ds18b20Error {
    /// Scratchpad or slave frame shorter than 9 bytes.
    ShortScratchpad { len: usize },
    /// Dallas/Maxim CRC mismatch.
    BadCrc { computed: u8, received: u8 },
    /// Config register has reserved bits set or cleared incorrectly.
    InvalidConfig { config: u8 },
    /// Raw temperature outside the sensor's physical range.
    ImpossibleTemperature { raw: i16 },
    /// Raw temperature is the power-on default (85 °C): no conversion ran.
    PowerOnReset,
    /// ROM family code is not a DS18B20.
    InvalidRomId { family: u8 },
    /// ROM id CRC mismatch.
    BadRomCrc { computed: u8, received: u8 },
    /// ROM id string was not family-serial or 16 hex characters.
    MalformedRomId,
    /// `w1_slave` document could not be parsed.
    MalformedW1Slave(String),
}

impl fmt::Display for Ds18b20Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ds18b20Error::ShortScratchpad { len } => {
                write!(
                    f,
                    "short DS18B20 scratchpad: {len} of {SCRATCHPAD_LEN} bytes"
                )
            }
            Ds18b20Error::BadCrc { computed, received } => write!(
                f,
                "DS18B20 CRC mismatch: computed 0x{computed:02x}, received 0x{received:02x}"
            ),
            Ds18b20Error::InvalidConfig { config } => {
                write!(f, "invalid DS18B20 config register 0x{config:02x}")
            }
            Ds18b20Error::ImpossibleTemperature { raw } => {
                write!(f, "impossible DS18B20 temperature raw value {raw}")
            }
            Ds18b20Error::PowerOnReset => {
                write!(f, "DS18B20 returned its power-on reset value (85 C)")
            }
            Ds18b20Error::InvalidRomId { family } => {
                write!(f, "invalid DS18B20 ROM family code 0x{family:02x}")
            }
            Ds18b20Error::BadRomCrc { computed, received } => write!(
                f,
                "DS18B20 ROM CRC mismatch: computed 0x{computed:02x}, received 0x{received:02x}"
            ),
            Ds18b20Error::MalformedRomId => write!(f, "malformed DS18B20 ROM id"),
            Ds18b20Error::MalformedW1Slave(message) => {
                write!(f, "malformed w1_slave document: {message}")
            }
        }
    }
}

impl std::error::Error for Ds18b20Error {}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDED_SCRATCHPAD: [u8; 9] = [0x72, 0x01, 0x4b, 0x46, 0x7f, 0xff, 0x0e, 0x10, 0x57];

    #[test]
    fn crc8_matches_recorded_kernel_frame() {
        assert_eq!(crc8(&RECORDED_SCRATCHPAD[..8]), 0x57);
        assert_eq!(crc8(&[0x00]), 0x00);
    }

    #[test]
    fn parses_recorded_scratchpad() {
        let pad = parse_scratchpad(&RECORDED_SCRATCHPAD).unwrap();
        assert_eq!(pad.temperature_raw, 0x0172);
        assert_eq!(pad.resolution().unwrap(), Ds18b20Resolution::Bits12);
        assert_eq!(
            pad.temperature().unwrap(),
            FixedPointValue::new(231250, -4, UNIT_DEG_C)
        );
    }

    #[test]
    fn rejects_bad_crc_and_short_frames() {
        let mut corrupt = RECORDED_SCRATCHPAD;
        corrupt[0] ^= 0x01;
        assert!(matches!(
            parse_scratchpad(&corrupt),
            Err(Ds18b20Error::BadCrc { .. })
        ));
        assert_eq!(
            parse_scratchpad(&[0x72, 0x01]),
            Err(Ds18b20Error::ShortScratchpad { len: 2 })
        );
    }

    #[test]
    fn decodes_positive_negative_and_resolution_values() {
        assert_eq!(
            decode_temperature(2000, Ds18b20Resolution::Bits12).unwrap(),
            FixedPointValue::new(1_250_000, -4, UNIT_DEG_C)
        );
        assert_eq!(
            decode_temperature(-400, Ds18b20Resolution::Bits12).unwrap(),
            FixedPointValue::new(-250_000, -4, UNIT_DEG_C)
        );
        // 9-bit quantisation clears the three low bits.
        assert_eq!(
            decode_temperature(401, Ds18b20Resolution::Bits9).unwrap(),
            FixedPointValue::new(250_000, -4, UNIT_DEG_C)
        );
    }

    #[test]
    fn rejects_power_on_and_impossible_temperatures() {
        assert_eq!(
            decode_temperature(POWER_ON_TEMPERATURE_RAW, Ds18b20Resolution::Bits12),
            Err(Ds18b20Error::PowerOnReset)
        );
        assert!(matches!(
            decode_temperature(3000, Ds18b20Resolution::Bits12),
            Err(Ds18b20Error::ImpossibleTemperature { raw: 3000 })
        ));
        assert!(matches!(
            decode_temperature(-1000, Ds18b20Resolution::Bits12),
            Err(Ds18b20Error::ImpossibleTemperature { raw: -1000 })
        ));
    }

    #[test]
    fn conversion_times_match_datasheet() {
        assert_eq!(Ds18b20Resolution::Bits9.conversion_time_ms(), 94);
        assert_eq!(Ds18b20Resolution::Bits10.conversion_time_ms(), 188);
        assert_eq!(Ds18b20Resolution::Bits11.conversion_time_ms(), 375);
        assert_eq!(Ds18b20Resolution::Bits12.conversion_time_ms(), 750);
        assert_eq!(
            Ds18b20Resolution::Bits12.conversion_time(),
            Duration::from_millis(750)
        );
    }

    #[test]
    fn config_roundtrip() {
        for resolution in [
            Ds18b20Resolution::Bits9,
            Ds18b20Resolution::Bits10,
            Ds18b20Resolution::Bits11,
            Ds18b20Resolution::Bits12,
        ] {
            let config = resolution.config_bits() | 0x1F;
            assert_eq!(Ds18b20Resolution::from_config(config).unwrap(), resolution);
        }
        assert!(matches!(
            Ds18b20Resolution::from_config(0x00),
            Err(Ds18b20Error::InvalidConfig { .. })
        ));
    }

    #[test]
    fn rom_id_validation_and_sysfs_name() {
        let mut bytes = [0u8; 8];
        bytes[..7].copy_from_slice(&[0x28, 0x00, 0x00, 0x06, 0xB4, 0xA6, 0x9B]);
        bytes[7] = crc8(&bytes[..7]);
        let rom = Ds18b20RomId::new(bytes).unwrap();
        assert_eq!(
            Ds18b20RomId::from_sysfs_name("28-000006b4a69b").unwrap(),
            rom
        );
        assert_eq!(Ds18b20RomId::from_hex(&rom.to_string()).unwrap(), rom);
        assert!(matches!(
            Ds18b20RomId::from_sysfs_name("10-000006b4a69b"),
            Err(Ds18b20Error::InvalidRomId { family: 0x10 })
        ));
    }

    #[test]
    fn parses_w1_slave_document() {
        let document = "72 01 4b 46 7f ff 0e 10 57 : crc=57 YES\n\
                        72 01 4b 46 7f ff 0e 10 57 t=23125\n";
        let reading = parse_w1_slave(document).unwrap();
        assert!(reading.crc_ok);
        assert_eq!(reading.temperature_millidegrees, Some(23125));
        assert_eq!(reading.scratchpad, RECORDED_SCRATCHPAD);

        let corrupt = "72 01 4b 46 7f ff 0e 10 57 : crc=57 YES\n\
                       72 01 4b 46 7f ff 0e 10 57 t=23125\n"
            .replace("72 01", "73 01");
        let reading = parse_w1_slave(&corrupt).unwrap();
        assert!(!reading.crc_ok);
    }

    #[test]
    fn match_rom_frame_layout() {
        let mut bytes = [0u8; 8];
        bytes[..7].copy_from_slice(&[0x28, 1, 2, 3, 4, 5, 6]);
        bytes[7] = crc8(&bytes[..7]);
        let rom = Ds18b20RomId::new(bytes).unwrap();
        let frame = match_rom_command(rom, CMD_READ_SCRATCHPAD);
        assert_eq!(frame[0], CMD_MATCH_ROM);
        assert_eq!(&frame[1..9], &rom.bytes());
        assert_eq!(frame[9], CMD_READ_SCRATCHPAD);
    }
}
