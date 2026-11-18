// SPDX-License-Identifier: AGPL-3.0-only

//! POS-08 — serial scale codec, stable-weight detection and guard-owned endpoint.
//!
//! The crate models two public serial protocols:
//!
//! - [`ScaleProtocol::MettlerToledo`] — a text frame modelled on the
//!   Mettler-Toledo continuous output:
//!   `ST,GS,+001.234,kg\r\n`. Status tokens are `ST` (stable) and `US`
//!   (unstable); `OL` and `UL` report overflow and underload. The second field
//!   is `GS` (gross) or `NT` (net).
//! - [`ScaleProtocol::CasBinary`] — a 12-byte binary frame with `STX`, a status
//!   byte, sign, six weight digits (thousandths of the displayed unit), unit
//!   code, `ETX` and an XOR checksum.
//!
//! The codec is pure: it reads no clock and owns no port. [`ScaleEndpoint`]
//! owns the transport, keeps a fixed-size receive buffer, rejects truncated or
//! checksum-failed frames, requires consecutive identical stable samples before
//! exposing a weight, sends the protocol tare command, and reports a stall as a
//! timeout. [`SimulatedScale`] implements the transport for tests and HIL
//! rehearsals.
//!
//! Weights are exact integer nanograms internally. Kilo, gram and pound
//! factors are exact; ounce is represented to the nearest nanogram.

use std::fmt;

use crate::device::DeviceTransport;
use crate::money::Quantity;
use crate::printer::TransportError;

/// Maximum bytes in one scale frame.
pub const MAX_SCALE_FRAME_BYTES: usize = 32;
/// Maximum bytes buffered between frames.
pub const MAX_SCALE_BUFFER_BYTES: usize = 128;
/// Maximum bytes requested in one transport read.
pub const MAX_SCALE_READ_BYTES: usize = 64;
/// Default number of consecutive identical stable samples.
pub const DEFAULT_STABLE_SAMPLES: u8 = 3;
/// Default stall deadline for a scale that stops producing frames.
pub const DEFAULT_SCALE_TIMEOUT_MS: u64 = 2_000;
/// Maximum magnitude of a weight, in thousandths of its unit.
pub const MAX_WEIGHT_THOUSANDTHS: i64 = 1_000_000_000;

/// A supported serial scale protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScaleProtocol {
    /// Mettler-Toledo-style ASCII continuous output.
    MettlerToledo,
    /// Compact binary frame with an XOR checksum.
    CasBinary,
}

impl ScaleProtocol {
    /// Stable protocol code for logs and policy.
    pub fn code(self) -> &'static str {
        match self {
            ScaleProtocol::MettlerToledo => "scale.protocol.mettler_toledo",
            ScaleProtocol::CasBinary => "scale.protocol.cas_binary",
        }
    }

    /// The command that tares the device at its current gross weight.
    pub fn tare_command(self) -> &'static [u8] {
        match self {
            ScaleProtocol::MettlerToledo => b"T\r\n",
            ScaleProtocol::CasBinary => &[0x05],
        }
    }
}

/// A display/count unit reported by a scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WeightUnit {
    /// Grams.
    Gram,
    /// Kilograms.
    Kilogram,
    /// Avoirdupois pounds.
    Pound,
    /// Avoirdupois ounces.
    Ounce,
}

impl WeightUnit {
    /// Unit symbol as printed by a scale.
    pub fn symbol(self) -> &'static str {
        match self {
            WeightUnit::Gram => "g",
            WeightUnit::Kilogram => "kg",
            WeightUnit::Pound => "lb",
            WeightUnit::Ounce => "oz",
        }
    }

    /// Parse a scale unit symbol.
    pub fn from_symbol(value: &str) -> Option<Self> {
        match value.trim() {
            "g" => Some(WeightUnit::Gram),
            "kg" => Some(WeightUnit::Kilogram),
            "lb" => Some(WeightUnit::Pound),
            "oz" => Some(WeightUnit::Ounce),
            _ => None,
        }
    }

    /// Binary protocol unit code (`0` kg, `1` g, `2` lb, `3` oz).
    pub fn code(self) -> u8 {
        match self {
            WeightUnit::Kilogram => b'0',
            WeightUnit::Gram => b'1',
            WeightUnit::Pound => b'2',
            WeightUnit::Ounce => b'3',
        }
    }

    /// Parse a binary protocol unit code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            b'0' => Some(WeightUnit::Kilogram),
            b'1' => Some(WeightUnit::Gram),
            b'2' => Some(WeightUnit::Pound),
            b'3' => Some(WeightUnit::Ounce),
            _ => None,
        }
    }

    fn nanograms_per_unit(self) -> i128 {
        match self {
            WeightUnit::Gram => 1_000_000_000,
            WeightUnit::Kilogram => 1_000_000_000_000,
            WeightUnit::Pound => 453_592_370_000,
            WeightUnit::Ounce => 28_349_523_125,
        }
    }
}

/// An exact weight, held as thousandths of its display unit.
#[derive(Clone, Copy, Debug)]
pub struct Weight {
    unit: WeightUnit,
    thousandths: i64,
}

impl Weight {
    /// Construct from thousandths of `unit` (for example `1234` kg = 1.234 kg).
    pub fn new(unit: WeightUnit, thousandths: i64) -> Result<Self, ScaleError> {
        if thousandths.unsigned_abs() > MAX_WEIGHT_THOUSANDTHS as u64 {
            return Err(ScaleError::WeightOutOfRange);
        }
        Ok(Self { unit, thousandths })
    }

    /// A zero weight in the given unit.
    pub fn zero(unit: WeightUnit) -> Self {
        Self {
            unit,
            thousandths: 0,
        }
    }

    /// The display unit.
    pub fn unit(self) -> WeightUnit {
        self.unit
    }

    /// Thousandths of the display unit.
    pub fn thousandths(self) -> i64 {
        self.thousandths
    }

    /// Exact weight in nanograms (nearest nanogram for ounces).
    pub fn nanograms(self) -> i128 {
        div_round_half_away(
            self.thousandths as i128 * self.unit.nanograms_per_unit(),
            1000,
        )
    }

    /// This weight converted to another display unit, rounded half away from
    /// zero to the nearest thousandth.
    pub fn to_unit(self, unit: WeightUnit) -> Result<Self, ScaleError> {
        let nanograms = self.nanograms();
        let scaled = nanograms * 1000;
        let divisor = unit.nanograms_per_unit();
        let rounded = div_round_half_away(scaled, divisor);
        Self::new(
            unit,
            i64::try_from(rounded).map_err(|_| ScaleError::WeightOutOfRange)?,
        )
    }

    /// This weight as a POS-01 quantity in kilograms, thousandths precise.
    /// A zero or negative weight is not a sellable quantity.
    pub fn to_quantity(self) -> Result<Quantity, ScaleError> {
        if self.thousandths <= 0 || self.nanograms() <= 0 {
            return Err(ScaleError::InvalidWeight);
        }
        let kilograms = self.to_unit(WeightUnit::Kilogram)?;
        Quantity::from_thousandths(kilograms.thousandths).map_err(|_| ScaleError::WeightOutOfRange)
    }

    /// Add two weights, preserving the left operand's display unit.
    pub fn checked_add(self, other: Weight) -> Result<Self, ScaleError> {
        let sum = self.nanograms() + other.nanograms();
        Self::from_nanograms(self.unit, sum)
    }

    /// Subtract two weights, preserving the left operand's display unit.
    pub fn checked_sub(self, other: Weight) -> Result<Self, ScaleError> {
        let difference = self.nanograms() - other.nanograms();
        Self::from_nanograms(self.unit, difference)
    }

    /// Whether the weight is exactly zero.
    pub fn is_zero(self) -> bool {
        self.thousandths == 0
    }

    fn from_nanograms(unit: WeightUnit, nanograms: i128) -> Result<Self, ScaleError> {
        let thousandths = div_round_half_away(nanograms * 1000, unit.nanograms_per_unit());
        Self::new(
            unit,
            i64::try_from(thousandths).map_err(|_| ScaleError::WeightOutOfRange)?,
        )
    }
}

fn div_round_half_away(numerator: i128, denominator: i128) -> i128 {
    debug_assert!(denominator > 0);
    let sign = if numerator < 0 { -1 } else { 1 };
    let magnitude = numerator.unsigned_abs();
    let denominator = denominator as u128;
    let quotient = magnitude / denominator;
    let remainder = magnitude % denominator;
    let rounded = if remainder * 2 >= denominator {
        quotient + 1
    } else {
        quotient
    };
    sign * rounded as i128
}

impl PartialEq for Weight {
    fn eq(&self, other: &Self) -> bool {
        self.nanograms() == other.nanograms()
    }
}

impl Eq for Weight {}

impl PartialOrd for Weight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Weight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.nanograms().cmp(&other.nanograms())
    }
}

impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.thousandths < 0 { "-" } else { "" };
        let magnitude = self.thousandths.unsigned_abs();
        write!(
            f,
            "{sign}{}.{:03} {}",
            magnitude / 1000,
            magnitude % 1000,
            self.unit.symbol()
        )
    }
}

/// Gross or net indication from a scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScaleMode {
    /// The weight includes the tare.
    Gross,
    /// The tare has been cancelled by the device.
    Net,
}

impl ScaleMode {
    fn text_token(self) -> &'static str {
        match self {
            ScaleMode::Gross => "GS",
            ScaleMode::Net => "NT",
        }
    }
}

/// A scale fault reported by the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScaleFault {
    /// The weight exceeds the scale's capacity.
    Overflow,
    /// The weight is below the zero/underload limit.
    Underload,
}

impl ScaleFault {
    /// Stable fault code.
    pub fn code(self) -> &'static str {
        match self {
            ScaleFault::Overflow => "scale.fault.overflow",
            ScaleFault::Underload => "scale.fault.underload",
        }
    }
}

impl fmt::Display for ScaleFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScaleFault::Overflow => "scale overflow",
            ScaleFault::Underload => "scale underload",
        })
    }
}

/// One decoded scale frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleReading {
    /// The reported weight (gross or net according to `mode`).
    pub weight: Weight,
    /// Whether the device reports the weight as stable.
    pub stable: bool,
    /// Gross or net.
    pub mode: ScaleMode,
    /// A device fault, if the frame reports one.
    pub fault: Option<ScaleFault>,
}

/// A malformed frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScaleFrameError {
    /// The frame ended before a complete command/checksum.
    Truncated,
    /// The binary checksum did not match.
    Checksum,
    /// The frame did not match the selected protocol.
    Malformed,
    /// The frame exceeded [`MAX_SCALE_FRAME_BYTES`].
    TooLong,
    /// The unit symbol or code is not supported.
    UnknownUnit,
    /// The weight field is not a valid number.
    InvalidWeight,
}

impl ScaleFrameError {
    /// Stable reason code.
    pub fn code(self) -> &'static str {
        match self {
            ScaleFrameError::Truncated => "scale.frame.truncated",
            ScaleFrameError::Checksum => "scale.frame.checksum",
            ScaleFrameError::Malformed => "scale.frame.malformed",
            ScaleFrameError::TooLong => "scale.frame.too_long",
            ScaleFrameError::UnknownUnit => "scale.frame.unknown_unit",
            ScaleFrameError::InvalidWeight => "scale.frame.invalid_weight",
        }
    }
}

impl fmt::Display for ScaleFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScaleFrameError::Truncated => "scale frame truncated",
            ScaleFrameError::Checksum => "scale frame checksum mismatch",
            ScaleFrameError::Malformed => "malformed scale frame",
            ScaleFrameError::TooLong => "scale frame too long",
            ScaleFrameError::UnknownUnit => "unsupported scale unit",
            ScaleFrameError::InvalidWeight => "invalid scale weight",
        })
    }
}

/// A scale operation or device failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScaleError {
    /// The frame was malformed.
    Frame(ScaleFrameError),
    /// The device reported overflow or underload.
    Fault(ScaleFault),
    /// The transport failed or timed out.
    Transport(TransportError),
    /// No complete frame has arrived inside the stall deadline.
    Timeout,
    /// The transport had no bytes available.
    NoData,
    /// The tare command could not be written.
    TareFailed,
    /// The weight is outside the representable range.
    WeightOutOfRange,
    /// The weight is zero or negative and cannot be sold.
    InvalidWeight,
    /// The endpoint configuration is invalid.
    InvalidConfig,
}

impl ScaleError {
    /// Stable reason code.
    pub fn code(&self) -> &'static str {
        match self {
            ScaleError::Frame(error) => error.code(),
            ScaleError::Fault(fault) => fault.code(),
            ScaleError::Transport(error) => error.code(),
            ScaleError::Timeout => "scale.timeout",
            ScaleError::NoData => "scale.no_data",
            ScaleError::TareFailed => "scale.tare_failed",
            ScaleError::WeightOutOfRange => "scale.weight_out_of_range",
            ScaleError::InvalidWeight => "scale.invalid_weight",
            ScaleError::InvalidConfig => "scale.invalid_config",
        }
    }
}

impl From<ScaleFrameError> for ScaleError {
    fn from(value: ScaleFrameError) -> Self {
        ScaleError::Frame(value)
    }
}

impl From<TransportError> for ScaleError {
    fn from(value: TransportError) -> Self {
        ScaleError::Transport(value)
    }
}

impl fmt::Display for ScaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScaleError::Frame(error) => write!(f, "{error}"),
            ScaleError::Fault(fault) => write!(f, "{fault}"),
            ScaleError::Transport(error) => write!(f, "{error}"),
            ScaleError::Timeout => f.write_str("scale did not produce a frame in time"),
            ScaleError::NoData => f.write_str("scale has no data"),
            ScaleError::TareFailed => f.write_str("scale tare command failed"),
            ScaleError::WeightOutOfRange => f.write_str("scale weight out of range"),
            ScaleError::InvalidWeight => f.write_str("scale weight is not sellable"),
            ScaleError::InvalidConfig => f.write_str("invalid scale configuration"),
        }
    }
}

impl std::error::Error for ScaleError {}

/// Pure codec for the two public scale protocols.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScaleCodec;

impl ScaleCodec {
    /// Decode exactly one complete frame.
    pub fn decode(protocol: ScaleProtocol, frame: &[u8]) -> Result<ScaleReading, ScaleError> {
        if frame.is_empty() {
            return Err(ScaleFrameError::Truncated.into());
        }
        if frame.len() > MAX_SCALE_FRAME_BYTES {
            return Err(ScaleFrameError::TooLong.into());
        }
        match protocol {
            ScaleProtocol::MettlerToledo => Self::decode_text(frame),
            ScaleProtocol::CasBinary => Self::decode_binary(frame),
        }
    }

    /// Encode one reading. The result is always at most
    /// [`MAX_SCALE_FRAME_BYTES`].
    pub fn encode(protocol: ScaleProtocol, reading: &ScaleReading) -> Result<Vec<u8>, ScaleError> {
        let abs = reading.weight.thousandths.unsigned_abs();
        if abs > 999_999 {
            return Err(ScaleError::WeightOutOfRange);
        }
        match protocol {
            ScaleProtocol::MettlerToledo => {
                let status = match reading.fault {
                    Some(ScaleFault::Overflow) => "OL",
                    Some(ScaleFault::Underload) => "UL",
                    None if reading.stable => "ST",
                    None => "US",
                };
                let sign = if reading.weight.thousandths < 0 {
                    '-'
                } else {
                    '+'
                };
                let whole = abs / 1000;
                let fraction = abs % 1000;
                Ok(format!(
                    "{status},{},{sign}{whole:03}.{fraction:03},{}\r\n",
                    reading.mode.text_token(),
                    reading.weight.unit.symbol()
                )
                .into_bytes())
            }
            ScaleProtocol::CasBinary => {
                let mut status = 0_u8;
                if reading.stable {
                    status |= 0b0000_0001;
                }
                if reading.mode == ScaleMode::Net {
                    status |= 0b0000_0010;
                }
                match reading.fault {
                    Some(ScaleFault::Overflow) => status |= 0b0000_0100,
                    Some(ScaleFault::Underload) => status |= 0b0000_1000,
                    None => {}
                }
                let sign = if reading.weight.thousandths < 0 {
                    b'-'
                } else {
                    b'+'
                };
                let mut frame = Vec::with_capacity(12);
                frame.push(0x02);
                frame.push(status);
                frame.push(sign);
                let digits = abs;
                frame.push(b'0' + ((digits / 100_000) % 10) as u8);
                frame.push(b'0' + ((digits / 10_000) % 10) as u8);
                frame.push(b'0' + ((digits / 1_000) % 10) as u8);
                frame.push(b'0' + ((digits / 100) % 10) as u8);
                frame.push(b'0' + ((digits / 10) % 10) as u8);
                frame.push(b'0' + (digits % 10) as u8);
                frame.push(reading.weight.unit.code());
                frame.push(0x03);
                let checksum = frame[1..].iter().fold(0_u8, |acc, byte| acc ^ byte);
                frame.push(checksum);
                Ok(frame)
            }
        }
    }

    fn decode_text(frame: &[u8]) -> Result<ScaleReading, ScaleError> {
        let Some(body) = frame.strip_suffix(b"\r\n") else {
            return Err(ScaleFrameError::Truncated.into());
        };
        let text = std::str::from_utf8(body).map_err(|_| ScaleFrameError::Malformed)?;
        let mut fields = text.split(',');
        let status = fields.next().ok_or(ScaleFrameError::Malformed)?;
        let mode = fields.next().ok_or(ScaleFrameError::Malformed)?;
        let weight = fields.next().ok_or(ScaleFrameError::Malformed)?;
        let unit = fields.next().ok_or(ScaleFrameError::Malformed)?;
        if fields.next().is_some() {
            return Err(ScaleFrameError::Malformed.into());
        }
        let fault = match status {
            "ST" | "US" => None,
            "OL" => Some(ScaleFault::Overflow),
            "UL" => Some(ScaleFault::Underload),
            _ => return Err(ScaleFrameError::Malformed.into()),
        };
        let mode = match mode {
            "GS" => ScaleMode::Gross,
            "NT" => ScaleMode::Net,
            _ => return Err(ScaleFrameError::Malformed.into()),
        };
        let stable = status == "ST";
        let unit = WeightUnit::from_symbol(unit).ok_or(ScaleFrameError::UnknownUnit)?;
        if weight.len() != 8 {
            return Err(ScaleFrameError::InvalidWeight.into());
        }
        let bytes = weight.as_bytes();
        let sign = match bytes[0] {
            b'+' => 1_i64,
            b'-' => -1_i64,
            _ => return Err(ScaleFrameError::InvalidWeight.into()),
        };
        if bytes[4] != b'.'
            || !bytes[1..4].iter().all(u8::is_ascii_digit)
            || !bytes[5..8].iter().all(u8::is_ascii_digit)
        {
            return Err(ScaleFrameError::InvalidWeight.into());
        }
        let whole = parse_digits(&bytes[1..4])?;
        let fraction = parse_digits(&bytes[5..8])?;
        let thousandths = sign * (whole * 1000 + fraction);
        let weight = Weight::new(unit, thousandths)?;
        Ok(ScaleReading {
            weight,
            stable,
            mode,
            fault,
        })
    }

    fn decode_binary(frame: &[u8]) -> Result<ScaleReading, ScaleError> {
        if frame.len() < 12 {
            return Err(ScaleFrameError::Truncated.into());
        }
        if frame.len() > 12 {
            return Err(ScaleFrameError::TooLong.into());
        }
        if frame[0] != 0x02 {
            return Err(ScaleFrameError::Malformed.into());
        }
        if frame[10] != 0x03 {
            return Err(ScaleFrameError::Truncated.into());
        }
        let checksum = frame[1..11].iter().fold(0_u8, |acc, byte| acc ^ byte);
        if checksum != frame[11] {
            return Err(ScaleFrameError::Checksum.into());
        }
        let status = frame[1];
        let overflow = status & 0b0000_0100 != 0;
        let underload = status & 0b0000_1000 != 0;
        let fault = match (overflow, underload) {
            (true, true) => return Err(ScaleFrameError::Malformed.into()),
            (true, false) => Some(ScaleFault::Overflow),
            (false, true) => Some(ScaleFault::Underload),
            (false, false) => None,
        };
        let stable = status & 0b0000_0001 != 0;
        let mode = if status & 0b0000_0010 != 0 {
            ScaleMode::Net
        } else {
            ScaleMode::Gross
        };
        let sign = match frame[2] {
            b'+' => 1_i64,
            b'-' => -1_i64,
            _ => return Err(ScaleFrameError::Malformed.into()),
        };
        if !frame[3..9].iter().all(u8::is_ascii_digit) {
            return Err(ScaleFrameError::InvalidWeight.into());
        }
        let digits = parse_digits(&frame[3..9])?;
        let unit = WeightUnit::from_code(frame[9]).ok_or(ScaleFrameError::UnknownUnit)?;
        let weight = Weight::new(unit, sign * digits)?;
        Ok(ScaleReading {
            weight,
            stable,
            mode,
            fault,
        })
    }
}

fn parse_digits(bytes: &[u8]) -> Result<i64, ScaleFrameError> {
    let mut value = 0_i64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(ScaleFrameError::InvalidWeight);
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Ok(value)
}

/// Stable-weight policy and stall deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleConfig {
    /// Consecutive identical stable frames required before a weight is stable.
    pub stable_samples: u8,
    /// Milliseconds without a frame before a stall is reported.
    pub stall_timeout_ms: u64,
}

impl Default for ScaleConfig {
    fn default() -> Self {
        Self {
            stable_samples: DEFAULT_STABLE_SAMPLES,
            stall_timeout_ms: DEFAULT_SCALE_TIMEOUT_MS,
        }
    }
}

impl ScaleConfig {
    /// Validate the configuration.
    pub fn validate(self) -> Result<Self, ScaleError> {
        if self.stable_samples == 0 {
            return Err(ScaleError::InvalidConfig);
        }
        Ok(self)
    }
}

/// One poll result. `stable_weight` is set once the configured number of
/// identical stable samples has been seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleUpdate {
    /// The decoded reading.
    pub reading: ScaleReading,
    /// A confirmed stable weight, if the stability threshold was reached.
    pub stable_weight: Option<Weight>,
}

/// Guard-owned scale endpoint.
///
/// The transport is private. The endpoint buffers at most
/// [`MAX_SCALE_BUFFER_BYTES`], decodes one bounded frame at a time, counts
/// consecutive stable samples, rejects faults and reports a stall once
/// [`ScaleConfig::stall_timeout_ms`] passes without a frame.
pub struct ScaleEndpoint<T: DeviceTransport> {
    transport: T,
    protocol: ScaleProtocol,
    config: ScaleConfig,
    buffer: [u8; MAX_SCALE_BUFFER_BYTES],
    filled: usize,
    candidate: Option<Weight>,
    consecutive: u8,
    last_frame_ms: Option<u64>,
    frames: u64,
    stable_readings: u64,
    tare_commands: u64,
}

impl<T: DeviceTransport> ScaleEndpoint<T> {
    /// Wrap a transport. The configuration is validated here.
    pub fn new(
        transport: T,
        protocol: ScaleProtocol,
        config: ScaleConfig,
    ) -> Result<Self, ScaleError> {
        let config = config.validate()?;
        Ok(Self {
            transport,
            protocol,
            config,
            buffer: [0; MAX_SCALE_BUFFER_BYTES],
            filled: 0,
            candidate: None,
            consecutive: 0,
            last_frame_ms: None,
            frames: 0,
            stable_readings: 0,
            tare_commands: 0,
        })
    }

    /// The configured protocol.
    pub fn protocol(&self) -> ScaleProtocol {
        self.protocol
    }

    /// Poll for one frame. `now_ms` is caller-supplied time; the guard never
    /// reads a clock.
    ///
    /// Returns `Ok(None)` when no complete frame is buffered or available yet.
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<ScaleUpdate>, ScaleError> {
        if let Some(last) = self.last_frame_ms {
            if now_ms.saturating_sub(last) > self.config.stall_timeout_ms {
                return Err(ScaleError::Timeout);
            }
        }
        if let Some((frame, length)) = self.extract_frame()? {
            return self.process_frame(&frame[..length], now_ms).map(Some);
        }
        let mut chunk = [0_u8; MAX_SCALE_READ_BYTES];
        let read = self.transport.read(&mut chunk)?;
        if read == 0 {
            return Ok(None);
        }
        if read > chunk.len() {
            return Err(ScaleError::Transport(TransportError::ReadFailed));
        }
        if self.filled + read > self.buffer.len() {
            self.filled = 0;
            self.candidate = None;
            self.consecutive = 0;
            return Err(ScaleFrameError::TooLong.into());
        }
        self.buffer[self.filled..self.filled + read].copy_from_slice(&chunk[..read]);
        self.filled += read;
        match self.extract_frame()? {
            Some((frame, length)) => self.process_frame(&frame[..length], now_ms).map(Some),
            None => Ok(None),
        }
    }

    /// Send the protocol tare command. Stability is reset; the device reports
    /// net weight from the next frame.
    pub fn tare(&mut self, now_ms: u64) -> Result<(), ScaleError> {
        let command = self.protocol.tare_command();
        self.transport
            .write_all(command)
            .map_err(|_| ScaleError::TareFailed)?;
        self.transport.flush()?;
        self.tare_commands = self.tare_commands.saturating_add(1);
        self.candidate = None;
        self.consecutive = 0;
        self.last_frame_ms = Some(now_ms);
        Ok(())
    }

    /// Number of decoded frames.
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// Number of confirmed stable readings.
    pub fn stable_readings(&self) -> u64 {
        self.stable_readings
    }

    /// Number of tare commands sent.
    pub fn tare_commands(&self) -> u64 {
        self.tare_commands
    }

    /// Bytes currently buffered between frames.
    pub fn buffered_bytes(&self) -> usize {
        self.filled
    }

    /// Consume the guard and recover the transport for inspection.
    pub fn into_transport(self) -> T {
        self.transport
    }

    fn process_frame(&mut self, frame: &[u8], now_ms: u64) -> Result<ScaleUpdate, ScaleError> {
        let reading = ScaleCodec::decode(self.protocol, frame)?;
        self.frames = self.frames.saturating_add(1);
        self.last_frame_ms = Some(now_ms);
        let mut stable_weight = None;
        if reading.stable && reading.fault.is_none() {
            if self.candidate == Some(reading.weight) {
                self.consecutive = self.consecutive.saturating_add(1);
            } else {
                self.candidate = Some(reading.weight);
                self.consecutive = 1;
            }
            if self.consecutive >= self.config.stable_samples {
                stable_weight = Some(reading.weight);
                self.stable_readings = self.stable_readings.saturating_add(1);
            }
        } else {
            self.candidate = None;
            self.consecutive = 0;
        }
        Ok(ScaleUpdate {
            reading,
            stable_weight,
        })
    }

    fn extract_frame(
        &mut self,
    ) -> Result<Option<([u8; MAX_SCALE_FRAME_BYTES], usize)>, ScaleError> {
        let boundary = match self.protocol {
            ScaleProtocol::MettlerToledo => self
                .buffer
                .get(..self.filled)
                .and_then(|bytes| bytes.windows(2).position(|pair| pair == b"\r\n"))
                .map(|position| position + 2),
            ScaleProtocol::CasBinary => {
                if self.filled < 12 {
                    None
                } else {
                    Some(12)
                }
            }
        };
        let Some(boundary) = boundary else {
            if self.filled >= self.buffer.len() {
                self.filled = 0;
                return Err(ScaleFrameError::TooLong.into());
            }
            return Ok(None);
        };
        if boundary > MAX_SCALE_FRAME_BYTES {
            self.drain(boundary);
            return Err(ScaleFrameError::TooLong.into());
        }
        let mut frame = [0_u8; MAX_SCALE_FRAME_BYTES];
        frame[..boundary].copy_from_slice(&self.buffer[..boundary]);
        self.drain(boundary);
        Ok(Some((frame, boundary)))
    }

    fn drain(&mut self, count: usize) {
        self.buffer.copy_within(count..self.filled, 0);
        self.filled -= count;
    }
}

/// In-process scale simulator for tests and HIL rehearsals.
///
/// It answers every read with a frame for its current gross weight, applies a
/// tare command by recording the current gross as tare and reporting net
/// weight, and can hold an unstable or faulted reading.
#[derive(Clone, Debug)]
pub struct SimulatedScale {
    protocol: ScaleProtocol,
    gross: Weight,
    tare: Weight,
    mode: ScaleMode,
    stable: bool,
    fault: Option<ScaleFault>,
    writes: Vec<Vec<u8>>,
    tare_count: u64,
}

impl SimulatedScale {
    /// A stable zero scale speaking `protocol`.
    pub fn new(protocol: ScaleProtocol) -> Self {
        Self {
            protocol,
            gross: Weight::zero(WeightUnit::Kilogram),
            tare: Weight::zero(WeightUnit::Kilogram),
            mode: ScaleMode::Gross,
            stable: true,
            fault: None,
            writes: Vec::new(),
            tare_count: 0,
        }
    }

    /// Set the gross weight and stability.
    pub fn set_weight(&mut self, weight: Weight, stable: bool) {
        self.gross = weight;
        self.stable = stable;
    }

    /// Set the stability flag without changing the weight.
    pub fn set_stable(&mut self, stable: bool) {
        self.stable = stable;
    }

    /// Set or clear an overflow/underload fault.
    pub fn set_fault(&mut self, fault: Option<ScaleFault>) {
        self.fault = fault;
    }

    /// The current net weight after any tare.
    pub fn net_weight(&self) -> Weight {
        self.gross
            .checked_sub(self.tare)
            .unwrap_or_else(|_| Weight::zero(self.gross.unit()))
    }

    /// Commands written by the endpoint.
    pub fn writes(&self) -> &[Vec<u8>] {
        &self.writes
    }

    /// Number of tare commands applied.
    pub fn tare_count(&self) -> u64 {
        self.tare_count
    }

    fn reading(&self) -> ScaleReading {
        let weight = if self.mode == ScaleMode::Net {
            self.net_weight()
        } else {
            self.gross
        };
        ScaleReading {
            weight,
            stable: self.stable,
            mode: self.mode,
            fault: self.fault,
        }
    }
}

impl DeviceTransport for SimulatedScale {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.writes.push(bytes.to_vec());
        if bytes == self.protocol.tare_command() {
            self.tare = self.gross;
            self.mode = ScaleMode::Net;
            self.tare_count = self.tare_count.saturating_add(1);
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let frame = ScaleCodec::encode(self.protocol, &self.reading())
            .map_err(|_| TransportError::ReadFailed)?;
        if buf.len() < frame.len() {
            return Err(TransportError::ReadFailed);
        }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }
}
