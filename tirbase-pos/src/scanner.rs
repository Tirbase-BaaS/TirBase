// SPDX-License-Identifier: AGPL-3.0-only

//! POS-08 — barcode scanner framing, GS1 application identifiers and guards.
//!
//! Three pieces are modelled:
//!
//! - [`ScannerCodec`] validates a serial frame (prefix, suffix, checksum,
//!   bounded payload) and decodes plain or GS1 element strings. A frame without
//!   its closing suffix is truncated and rejected.
//! - [`HidScanner`] owns a keyboard-wedge transport. It accumulates bounded
//!   characters and terminates a scan on Enter or Tab.
//! - [`SerialScanner`] owns a byte transport, reassembles frames across reads
//!   with a fixed buffer, and enforces a read budget.
//!
//! GS1 parsing covers the common retail identifier set: GTIN (00/01/02),
//! dates (11/12/13/15/16/17), batch/serial/count (10/21/22/30/37), net weight
//! (3100–3699) and price/amount (3900–3959). Unknown AIs are rejected rather
//! than guessed. Simulators for both transports are provided.
//!
//! The codecs are pure. No endpoint exposes its transport, so framing,
//! checksum, GS1 validation and payload bounds cannot be skipped.

use std::collections::VecDeque;
use std::fmt;

use crate::device::DeviceTransport;
use crate::printer::TransportError;
use crate::scale::{Weight, WeightUnit};

/// Maximum barcode payload, in bytes.
pub const MAX_SCAN_PAYLOAD_BYTES: usize = 256;
/// Maximum serial frame, including prefix, checksum and suffix.
pub const MAX_SCAN_FRAME_BYTES: usize = MAX_SCAN_PAYLOAD_BYTES + 8;
/// Maximum keyboard events consumed by one HID scan.
pub const MAX_SCAN_KEYS: usize = 256;
/// Maximum decoded GS1 elements.
pub const MAX_GS1_ELEMENTS: usize = 32;
/// Maximum bytes in one GS1 AI or value.
pub const MAX_GS1_ELEMENT_BYTES: usize = 40;
/// Default read attempts for one serial scan.
pub const DEFAULT_SCAN_READS: u8 = 8;

/// ASCII group separator used as the GS1 FNC1 separator.
pub const GS1_SEPARATOR: u8 = 0x1D;

/// Whether a payload is a plain barcode or a GS1 element string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symbology {
    /// A plain, printable ASCII payload.
    Plain,
    /// A GS1 element string with application identifiers.
    Gs1,
}

impl Symbology {
    /// Stable code for logs and policy.
    pub fn code(self) -> &'static str {
        match self {
            Symbology::Plain => "scanner.symbology.plain",
            Symbology::Gs1 => "scanner.symbology.gs1",
        }
    }
}

/// Serial frame checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScannerChecksum {
    /// No checksum byte.
    None,
    /// XOR of all payload bytes.
    Xor,
    /// Sum of all payload bytes modulo 256.
    Sum8,
}

impl ScannerChecksum {
    fn length(self) -> usize {
        match self {
            ScannerChecksum::None => 0,
            ScannerChecksum::Xor | ScannerChecksum::Sum8 => 1,
        }
    }

    fn compute(self, payload: &[u8]) -> u8 {
        match self {
            ScannerChecksum::None => 0,
            ScannerChecksum::Xor => payload.iter().fold(0, |acc, byte| acc ^ byte),
            ScannerChecksum::Sum8 => payload
                .iter()
                .fold(0_u8, |acc, byte| acc.wrapping_add(*byte)),
        }
    }
}

/// Prefix, suffix and checksum used by a serial scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScannerFraming {
    /// First byte of a frame.
    pub prefix: u8,
    /// Last byte of a frame.
    pub suffix: u8,
    /// Checksum byte between payload and suffix.
    pub checksum: ScannerChecksum,
}

impl ScannerFraming {
    /// The common `STX payload ETX` framing with no checksum.
    pub const fn stx_etx() -> Self {
        Self {
            prefix: 0x02,
            suffix: 0x03,
            checksum: ScannerChecksum::None,
        }
    }

    /// The common `STX payload XOR ETX` framing.
    pub const fn stx_etx_xor() -> Self {
        Self {
            prefix: 0x02,
            suffix: 0x03,
            checksum: ScannerChecksum::Xor,
        }
    }

    /// Maximum complete frame length under this framing.
    pub fn max_frame_bytes(self) -> usize {
        1 + MAX_SCAN_PAYLOAD_BYTES + self.checksum.length() + 1
    }
}

/// A malformed serial frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScannerFrameError {
    /// The closing suffix or checksum is missing.
    Truncated,
    /// The frame does not start with the configured prefix.
    BadPrefix,
    /// The frame does not end with the configured suffix.
    BadSuffix,
    /// The checksum byte did not match.
    Checksum,
    /// The payload is empty.
    EmptyPayload,
    /// The payload exceeds [`MAX_SCAN_PAYLOAD_BYTES`].
    TooLong,
    /// The payload contains a control character other than GS.
    ControlCharacter,
}

impl ScannerFrameError {
    /// Stable reason code.
    pub fn code(self) -> &'static str {
        match self {
            ScannerFrameError::Truncated => "scanner.frame.truncated",
            ScannerFrameError::BadPrefix => "scanner.frame.bad_prefix",
            ScannerFrameError::BadSuffix => "scanner.frame.bad_suffix",
            ScannerFrameError::Checksum => "scanner.frame.checksum",
            ScannerFrameError::EmptyPayload => "scanner.frame.empty_payload",
            ScannerFrameError::TooLong => "scanner.frame.too_long",
            ScannerFrameError::ControlCharacter => "scanner.frame.control_character",
        }
    }
}

impl fmt::Display for ScannerFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScannerFrameError::Truncated => "scanner frame truncated",
            ScannerFrameError::BadPrefix => "scanner frame has the wrong prefix",
            ScannerFrameError::BadSuffix => "scanner frame has the wrong suffix",
            ScannerFrameError::Checksum => "scanner frame checksum mismatch",
            ScannerFrameError::EmptyPayload => "scanner frame has no payload",
            ScannerFrameError::TooLong => "scanner frame too long",
            ScannerFrameError::ControlCharacter => "scanner payload has a control character",
        })
    }
}

/// A GS1 parse failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gs1Error {
    /// No element strings were supplied.
    Empty,
    /// An application identifier or value ended early.
    Truncated,
    /// The AI is not in the supported set.
    UnknownAi,
    /// The AI is not numeric or has the wrong digit count.
    InvalidAi,
    /// A fixed-length field has the wrong length, or a variable field is empty.
    InvalidLength,
    /// A numeric field contains a non-digit.
    InvalidDigit,
    /// A GTIN check digit is wrong.
    InvalidGtinCheckDigit,
    /// A date field is not a valid YYMMDD date.
    InvalidDate,
    /// More than [`MAX_GS1_ELEMENTS`] elements were supplied.
    TooManyElements,
}

impl Gs1Error {
    /// Stable reason code.
    pub fn code(self) -> &'static str {
        match self {
            Gs1Error::Empty => "gs1.empty",
            Gs1Error::Truncated => "gs1.truncated",
            Gs1Error::UnknownAi => "gs1.unknown_ai",
            Gs1Error::InvalidAi => "gs1.invalid_ai",
            Gs1Error::InvalidLength => "gs1.invalid_length",
            Gs1Error::InvalidDigit => "gs1.invalid_digit",
            Gs1Error::InvalidGtinCheckDigit => "gs1.invalid_gtin_check_digit",
            Gs1Error::InvalidDate => "gs1.invalid_date",
            Gs1Error::TooManyElements => "gs1.too_many_elements",
        }
    }
}

impl fmt::Display for Gs1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Gs1Error::Empty => "empty GS1 element string",
            Gs1Error::Truncated => "truncated GS1 element string",
            Gs1Error::UnknownAi => "unsupported GS1 application identifier",
            Gs1Error::InvalidAi => "invalid GS1 application identifier",
            Gs1Error::InvalidLength => "invalid GS1 value length",
            Gs1Error::InvalidDigit => "non-digit in a numeric GS1 value",
            Gs1Error::InvalidGtinCheckDigit => "GS1 GTIN check digit mismatch",
            Gs1Error::InvalidDate => "invalid GS1 date",
            Gs1Error::TooManyElements => "too many GS1 elements",
        })
    }
}

/// A scanner operation, framing, GS1 or transport failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScannerError {
    /// The serial frame was malformed.
    Frame(ScannerFrameError),
    /// The GS1 element string was malformed.
    Gs1(Gs1Error),
    /// The transport failed.
    Transport(TransportError),
    /// The scan did not terminate within the read/key budget.
    Timeout,
    /// No bytes or keys were available.
    NoData,
    /// The payload exceeds the endpoint's configured bound.
    PayloadTooLong { len: usize, limit: usize },
    /// A non-ASCII character arrived from a keyboard wedge.
    NonAscii,
    /// The barcode payload is not printable ASCII (plain symbology).
    NonPrintable,
    /// A scan was terminated without a payload.
    EmptyScan,
}

impl ScannerError {
    /// Stable reason code.
    pub fn code(&self) -> &'static str {
        match self {
            ScannerError::Frame(error) => error.code(),
            ScannerError::Gs1(error) => error.code(),
            ScannerError::Transport(error) => error.code(),
            ScannerError::Timeout => "scanner.timeout",
            ScannerError::NoData => "scanner.no_data",
            ScannerError::PayloadTooLong { .. } => "scanner.payload_too_long",
            ScannerError::NonAscii => "scanner.non_ascii",
            ScannerError::NonPrintable => "scanner.non_printable",
            ScannerError::EmptyScan => "scanner.empty_scan",
        }
    }
}

impl From<ScannerFrameError> for ScannerError {
    fn from(value: ScannerFrameError) -> Self {
        ScannerError::Frame(value)
    }
}

impl From<Gs1Error> for ScannerError {
    fn from(value: Gs1Error) -> Self {
        ScannerError::Gs1(value)
    }
}

impl From<TransportError> for ScannerError {
    fn from(value: TransportError) -> Self {
        ScannerError::Transport(value)
    }
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::Frame(error) => write!(f, "{error}"),
            ScannerError::Gs1(error) => write!(f, "{error}"),
            ScannerError::Transport(error) => write!(f, "{error}"),
            ScannerError::Timeout => f.write_str("scanner timed out"),
            ScannerError::NoData => f.write_str("scanner has no data"),
            ScannerError::PayloadTooLong { len, limit } => {
                write!(f, "scanner payload is {len} bytes; the limit is {limit}")
            }
            ScannerError::NonAscii => f.write_str("scanner sent a non-ASCII character"),
            ScannerError::NonPrintable => f.write_str("barcode payload is not printable ASCII"),
            ScannerError::EmptyScan => f.write_str("scan contained no payload"),
        }
    }
}

impl std::error::Error for ScannerError {}

/// One GS1 application identifier and value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gs1Element {
    ai: String,
    value: String,
}

impl Gs1Element {
    /// The application identifier (for example `01` or `3103`).
    pub fn ai(&self) -> &str {
        &self.ai
    }

    /// The element value, without any FNC1 separator.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A parsed GS1 element string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gs1Data {
    elements: Vec<Gs1Element>,
}

impl Gs1Data {
    /// Parse a GS1 element string. FNC1 is ASCII GS (`0x1D`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Gs1Error> {
        if bytes.is_empty() {
            return Err(Gs1Error::Empty);
        }
        let mut elements = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == GS1_SEPARATOR {
                index += 1;
                continue;
            }
            if elements.len() >= MAX_GS1_ELEMENTS {
                return Err(Gs1Error::TooManyElements);
            }
            let ai_len = ai_length(&bytes[index..])?;
            if index + ai_len > bytes.len() {
                return Err(Gs1Error::Truncated);
            }
            let ai = std::str::from_utf8(&bytes[index..index + ai_len])
                .map_err(|_| Gs1Error::InvalidAi)?;
            if !ai.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Gs1Error::InvalidAi);
            }
            index += ai_len;
            let spec = ai_spec(ai)?;
            let value = match spec {
                AiSpec::Fixed(length) => {
                    if index + length > bytes.len() {
                        return Err(Gs1Error::Truncated);
                    }
                    let value = &bytes[index..index + length];
                    index += length;
                    value
                }
                AiSpec::Variable(maximum) => {
                    let start = index;
                    while index < bytes.len() && bytes[index] != GS1_SEPARATOR {
                        index += 1;
                    }
                    let length = index - start;
                    if length == 0 || length > maximum {
                        return Err(Gs1Error::InvalidLength);
                    }
                    if index < bytes.len() {
                        index += 1;
                    }
                    &bytes[start..start + length]
                }
            };
            validate_ai_value(ai, value)?;
            if value.len() > MAX_GS1_ELEMENT_BYTES {
                return Err(Gs1Error::InvalidLength);
            }
            let value = std::str::from_utf8(value).map_err(|_| Gs1Error::InvalidDigit)?;
            elements.push(Gs1Element {
                ai: ai.to_owned(),
                value: value.to_owned(),
            });
        }
        if elements.is_empty() {
            return Err(Gs1Error::Empty);
        }
        Ok(Self { elements })
    }

    /// All elements in wire order.
    pub fn elements(&self) -> &[Gs1Element] {
        &self.elements
    }

    /// The first value for `ai`, if present.
    pub fn get(&self, ai: &str) -> Option<&str> {
        self.elements
            .iter()
            .find(|element| element.ai == ai)
            .map(Gs1Element::value)
    }

    /// The GTIN-14 value from AI 01 or 02, if present.
    pub fn gtin(&self) -> Option<&str> {
        self.get("01").or_else(|| self.get("02"))
    }

    /// Net weight in kilograms from a 310n element, if present.
    pub fn net_weight(&self) -> Option<Weight> {
        self.elements
            .iter()
            .find(|element| element.ai.starts_with("310") && element.ai.len() == 4)
            .and_then(|element| {
                let decimals = element.ai.as_bytes()[3] - b'0';
                let value = element.value.parse::<i64>().ok()?;
                let thousandths = scale_weight_thousandths(value, decimals)?;
                Weight::new(WeightUnit::Kilogram, thousandths).ok()
            })
    }
}

enum AiSpec {
    Fixed(usize),
    Variable(usize),
}

fn ai_length(bytes: &[u8]) -> Result<usize, Gs1Error> {
    if bytes.len() < 2 {
        return Err(Gs1Error::Truncated);
    }
    if !bytes[..2].iter().all(u8::is_ascii_digit) {
        return Err(Gs1Error::InvalidAi);
    }
    if bytes.len() >= 4 && bytes[..4].iter().all(u8::is_ascii_digit) {
        let first_three = &bytes[..3];
        let weight = first_three >= b"310" && first_three <= b"369";
        let price = first_three >= b"390" && first_three <= b"395";
        if weight || price {
            return Ok(4);
        }
    }
    Ok(2)
}

fn ai_spec(ai: &str) -> Result<AiSpec, Gs1Error> {
    let spec = match ai {
        "00" => AiSpec::Fixed(18),
        "01" | "02" => AiSpec::Fixed(14),
        "11" | "12" | "13" | "15" | "16" | "17" => AiSpec::Fixed(6),
        "20" => AiSpec::Fixed(2),
        "10" | "21" | "22" => AiSpec::Variable(20),
        "30" => AiSpec::Variable(8),
        "37" => AiSpec::Variable(8),
        "90" | "91" | "92" | "93" | "94" | "95" | "96" | "97" | "98" | "99" => AiSpec::Variable(30),
        _ if ai.len() == 4 && ai.starts_with('3') => {
            let first_three = &ai[..3];
            let last = ai.as_bytes()[3];
            if !last.is_ascii_digit() {
                return Err(Gs1Error::InvalidAi);
            }
            if ("310"..="369").contains(&first_three) {
                AiSpec::Fixed(6)
            } else if ("390"..="395").contains(&first_three) {
                AiSpec::Variable(15)
            } else {
                return Err(Gs1Error::UnknownAi);
            }
        }
        _ => return Err(Gs1Error::UnknownAi),
    };
    Ok(spec)
}

fn validate_ai_value(ai: &str, value: &[u8]) -> Result<(), Gs1Error> {
    let alphanumeric = matches!(ai, "10" | "21" | "22") || ai.starts_with("9") && ai.len() == 2;
    if !alphanumeric {
        if !value.iter().all(u8::is_ascii_digit) {
            return Err(Gs1Error::InvalidDigit);
        }
    } else if value.is_empty() || !value.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(Gs1Error::InvalidDigit);
    }
    match ai {
        "00" => {
            // SSCC-18: eighteen digits, no GTIN check digit.
            if value.len() != 18 {
                return Err(Gs1Error::InvalidLength);
            }
        }
        "01" | "02" => {
            if value.len() != 14 {
                return Err(Gs1Error::InvalidLength);
            }
            if !gtin_check_digit_valid(value) {
                return Err(Gs1Error::InvalidGtinCheckDigit);
            }
        }
        "11" | "12" | "13" | "15" | "16" | "17" if value.len() != 6 || !valid_date(value) => {
            return Err(Gs1Error::InvalidDate);
        }
        _ => {}
    }
    Ok(())
}

fn gtin_check_digit_valid(value: &[u8]) -> bool {
    if value.len() != 14 || !value.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut sum = 0_u32;
    for (index, byte) in value[..13].iter().enumerate() {
        let digit = u32::from(byte - b'0');
        sum += if index % 2 == 0 { digit * 3 } else { digit };
    }
    let expected = (10 - sum % 10) % 10;
    u32::from(value[13] - b'0') == expected
}

fn valid_date(value: &[u8]) -> bool {
    let year = u32::from(value[0] - b'0') * 10 + u32::from(value[1] - b'0');
    let month = u32::from(value[2] - b'0') * 10 + u32::from(value[3] - b'0');
    let day = u32::from(value[4] - b'0') * 10 + u32::from(value[5] - b'0');
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn scale_weight_thousandths(value: i64, decimals: u8) -> Option<i64> {
    if decimals <= 3 {
        let factor = 10_i64.checked_pow(u32::from(3 - decimals))?;
        value.checked_mul(factor)
    } else {
        let divisor = 10_i64.checked_pow(u32::from(decimals - 3))?;
        Some((value + divisor / 2) / divisor)
    }
}

/// A decoded barcode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedCode {
    raw: Vec<u8>,
    gs1: Option<Gs1Data>,
}

impl ScannedCode {
    /// The raw payload bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The payload as text when every byte is printable ASCII.
    pub fn text(&self) -> Option<&str> {
        if self.raw.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
            std::str::from_utf8(&self.raw).ok()
        } else {
            None
        }
    }

    /// The parsed GS1 data, when the scan used the GS1 symbology.
    pub fn gs1(&self) -> Option<&Gs1Data> {
        self.gs1.as_ref()
    }

    /// The GTIN-14 value from a GS1 scan.
    pub fn gtin(&self) -> Option<&str> {
        self.gs1.as_ref().and_then(Gs1Data::gtin)
    }

    /// The net weight from a GS1 scan.
    pub fn net_weight(&self) -> Option<Weight> {
        self.gs1.as_ref().and_then(Gs1Data::net_weight)
    }
}

/// Pure barcode and serial-framing codec.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScannerCodec;

impl ScannerCodec {
    /// Decode a payload under the selected symbology.
    pub fn decode_payload(
        payload: &[u8],
        symbology: Symbology,
    ) -> Result<ScannedCode, ScannerError> {
        if payload.is_empty() {
            return Err(ScannerError::EmptyScan);
        }
        if payload.len() > MAX_SCAN_PAYLOAD_BYTES {
            return Err(ScannerError::PayloadTooLong {
                len: payload.len(),
                limit: MAX_SCAN_PAYLOAD_BYTES,
            });
        }
        match symbology {
            Symbology::Plain => {
                if !payload.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
                    return Err(ScannerError::NonPrintable);
                }
                Ok(ScannedCode {
                    raw: payload.to_vec(),
                    gs1: None,
                })
            }
            Symbology::Gs1 => {
                let gs1 = Gs1Data::parse(payload)?;
                Ok(ScannedCode {
                    raw: payload.to_vec(),
                    gs1: Some(gs1),
                })
            }
        }
    }

    /// Validate and extract the payload of one framed serial message.
    ///
    /// A frame missing its suffix is [`ScannerFrameError::Truncated`], never a
    /// short payload.
    pub fn decode_serial(frame: &[u8], framing: ScannerFraming) -> Result<&[u8], ScannerError> {
        let checksum_len = framing.checksum.length();
        if frame.len() < 2 + checksum_len {
            return Err(ScannerFrameError::Truncated.into());
        }
        if frame[frame.len() - 1] != framing.suffix {
            return Err(ScannerFrameError::Truncated.into());
        }
        if frame[0] != framing.prefix {
            return Err(ScannerFrameError::BadPrefix.into());
        }
        let payload_end = frame.len() - 1 - checksum_len;
        if payload_end <= 1 {
            return Err(ScannerFrameError::EmptyPayload.into());
        }
        let payload = &frame[1..payload_end];
        if payload.len() > MAX_SCAN_PAYLOAD_BYTES {
            return Err(ScannerFrameError::TooLong.into());
        }
        if checksum_len == 1 {
            let expected = framing.checksum.compute(payload);
            if frame[payload_end] != expected {
                return Err(ScannerFrameError::Checksum.into());
            }
        }
        if payload
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != GS1_SEPARATOR) || *byte == 0x7F)
        {
            return Err(ScannerFrameError::ControlCharacter.into());
        }
        Ok(payload)
    }

    /// Frame a payload for a serial scanner.
    pub fn encode_serial(payload: &[u8], framing: ScannerFraming) -> Result<Vec<u8>, ScannerError> {
        if payload.is_empty() {
            return Err(ScannerError::EmptyScan);
        }
        if payload.len() > MAX_SCAN_PAYLOAD_BYTES {
            return Err(ScannerError::PayloadTooLong {
                len: payload.len(),
                limit: MAX_SCAN_PAYLOAD_BYTES,
            });
        }
        if payload
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != GS1_SEPARATOR) || *byte == 0x7F)
        {
            return Err(ScannerFrameError::ControlCharacter.into());
        }
        let mut frame = Vec::with_capacity(2 + payload.len() + framing.checksum.length());
        frame.push(framing.prefix);
        frame.extend_from_slice(payload);
        if framing.checksum.length() == 1 {
            frame.push(framing.checksum.compute(payload));
        }
        frame.push(framing.suffix);
        Ok(frame)
    }
}

/// One keyboard-wedge event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidKey {
    /// A printable character.
    Character(char),
    /// The configured terminator.
    Enter,
    /// An alternate terminator.
    Tab,
}

/// Keyboard-wedge transport.
pub trait HidTransport {
    /// Read one key, `None` when no key is available, or a transport failure.
    fn read_key(&mut self) -> Result<Option<HidKey>, TransportError>;
}

/// Guard-owned keyboard-wedge scanner.
pub struct HidScanner<T: HidTransport> {
    transport: T,
    symbology: Symbology,
    max_bytes: usize,
    buffer: Vec<u8>,
    keys_read: u64,
    scans: u64,
}

impl<T: HidTransport> HidScanner<T> {
    /// Wrap a HID transport. `max_bytes` must be in `1..=MAX_SCAN_PAYLOAD_BYTES`.
    pub fn new(transport: T, symbology: Symbology, max_bytes: usize) -> Result<Self, ScannerError> {
        if max_bytes == 0 || max_bytes > MAX_SCAN_PAYLOAD_BYTES {
            return Err(ScannerError::PayloadTooLong {
                len: max_bytes,
                limit: MAX_SCAN_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            transport,
            symbology,
            max_bytes,
            buffer: Vec::with_capacity(max_bytes),
            keys_read: 0,
            scans: 0,
        })
    }

    /// Read keys until Enter/Tab and decode one barcode.
    pub fn scan(&mut self) -> Result<ScannedCode, ScannerError> {
        let mut keys = 0;
        loop {
            if keys >= MAX_SCAN_KEYS {
                self.buffer.clear();
                return Err(ScannerError::Timeout);
            }
            let key = match self.transport.read_key() {
                Ok(Some(key)) => key,
                Ok(None) => return Err(ScannerError::NoData),
                Err(TransportError::Timeout) => return Err(ScannerError::Timeout),
                Err(error) => return Err(ScannerError::Transport(error)),
            };
            keys += 1;
            self.keys_read = self.keys_read.saturating_add(1);
            match key {
                HidKey::Enter | HidKey::Tab => {
                    if self.buffer.is_empty() {
                        return Err(ScannerError::EmptyScan);
                    }
                    let code = ScannerCodec::decode_payload(&self.buffer, self.symbology)?;
                    self.buffer.clear();
                    self.scans = self.scans.saturating_add(1);
                    return Ok(code);
                }
                HidKey::Character(character) => {
                    if !character.is_ascii() {
                        self.buffer.clear();
                        return Err(ScannerError::NonAscii);
                    }
                    if character.is_ascii_control() {
                        self.buffer.clear();
                        return Err(ScannerError::NonPrintable);
                    }
                    if self.buffer.len() >= self.max_bytes {
                        let len = self.buffer.len() + 1;
                        self.buffer.clear();
                        return Err(ScannerError::PayloadTooLong {
                            len,
                            limit: self.max_bytes,
                        });
                    }
                    self.buffer.push(character as u8);
                }
            }
        }
    }

    /// Bytes accumulated for the current scan.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Number of terminated scans.
    pub fn scans(&self) -> u64 {
        self.scans
    }

    /// Consume the guard and recover the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// Guard-owned serial scanner.
pub struct SerialScanner<T: DeviceTransport> {
    transport: T,
    framing: ScannerFraming,
    symbology: Symbology,
    buffer: [u8; MAX_SCAN_FRAME_BYTES * 2],
    filled: usize,
    max_reads: u8,
    scans: u64,
}

impl<T: DeviceTransport> SerialScanner<T> {
    /// Wrap a serial transport.
    pub fn new(
        transport: T,
        framing: ScannerFraming,
        symbology: Symbology,
        max_reads: u8,
    ) -> Result<Self, ScannerError> {
        if max_reads == 0 {
            return Err(ScannerError::Timeout);
        }
        Ok(Self {
            transport,
            framing,
            symbology,
            buffer: [0; MAX_SCAN_FRAME_BYTES * 2],
            filled: 0,
            max_reads,
            scans: 0,
        })
    }

    /// Wrap a transport with [`DEFAULT_SCAN_READS`] read attempts.
    pub fn with_default_reads(
        transport: T,
        framing: ScannerFraming,
        symbology: Symbology,
    ) -> Result<Self, ScannerError> {
        Self::new(transport, framing, symbology, DEFAULT_SCAN_READS)
    }

    /// Reassemble and decode one frame. Reads at most `max_reads` chunks.
    pub fn scan(&mut self) -> Result<ScannedCode, ScannerError> {
        let mut attempts = 0;
        loop {
            if let Some(length) = self.frame_length()? {
                let payload = ScannerCodec::decode_serial(&self.buffer[..length], self.framing)?;
                let code = ScannerCodec::decode_payload(payload, self.symbology)?;
                self.drain(length);
                self.scans = self.scans.saturating_add(1);
                return Ok(code);
            }
            if attempts >= self.max_reads {
                return Err(ScannerError::Timeout);
            }
            attempts += 1;
            let mut chunk = [0_u8; 64];
            let read = self.transport.read(&mut chunk)?;
            if read == 0 {
                return Err(ScannerError::NoData);
            }
            if read > chunk.len() {
                return Err(ScannerError::Transport(TransportError::ReadFailed));
            }
            if self.filled + read > self.buffer.len() {
                self.filled = 0;
                return Err(ScannerFrameError::TooLong.into());
            }
            self.buffer[self.filled..self.filled + read].copy_from_slice(&chunk[..read]);
            self.filled += read;
        }
    }

    /// Bytes buffered between frames.
    pub fn buffered_bytes(&self) -> usize {
        self.filled
    }

    /// Number of decoded scans.
    pub fn scans(&self) -> u64 {
        self.scans
    }

    /// Consume the guard and recover the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    fn frame_length(&mut self) -> Result<Option<usize>, ScannerError> {
        if self.filled == 0 {
            return Ok(None);
        }
        let Some(position) = self.buffer[..self.filled]
            .iter()
            .position(|byte| *byte == self.framing.suffix)
        else {
            if self.filled >= self.framing.max_frame_bytes() {
                self.filled = 0;
                return Err(ScannerFrameError::TooLong.into());
            }
            return Ok(None);
        };
        Ok(Some(position + 1))
    }

    fn drain(&mut self, count: usize) {
        self.buffer.copy_within(count..self.filled, 0);
        self.filled -= count;
    }
}

/// In-process scanner simulator for both HID and serial transports.
#[derive(Clone, Debug, Default)]
pub struct SimulatedScanner {
    keys: VecDeque<HidKey>,
    chunks: VecDeque<Vec<u8>>,
    serial_reads: u64,
}

impl SimulatedScanner {
    /// A keyboard wedge that will deliver `keys`.
    pub fn hid(keys: Vec<HidKey>) -> Self {
        Self {
            keys: keys.into(),
            chunks: VecDeque::new(),
            serial_reads: 0,
        }
    }

    /// A serial scanner that will deliver `chunks` in order.
    pub fn serial(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            keys: VecDeque::new(),
            chunks: chunks.into(),
            serial_reads: 0,
        }
    }

    /// Queue another serial chunk.
    pub fn feed_serial(&mut self, chunk: Vec<u8>) {
        self.chunks.push_back(chunk);
    }

    /// Number of serial reads served.
    pub fn serial_reads(&self) -> u64 {
        self.serial_reads
    }
}

impl HidTransport for SimulatedScanner {
    fn read_key(&mut self) -> Result<Option<HidKey>, TransportError> {
        Ok(self.keys.pop_front())
    }
}

impl DeviceTransport for SimulatedScanner {
    fn write_all(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Unavailable)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let Some(chunk) = self.chunks.pop_front() else {
            return Ok(0);
        };
        if chunk.len() > buf.len() {
            self.chunks.push_front(chunk);
            return Err(TransportError::ReadFailed);
        }
        buf[..chunk.len()].copy_from_slice(&chunk);
        self.serial_reads = self.serial_reads.saturating_add(1);
        Ok(chunk.len())
    }
}
