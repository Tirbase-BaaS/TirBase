// SPDX-License-Identifier: AGPL-3.0-only

//! POS-07 — pure ESC/POS command codec.
//!
//! This module is a **codec only**. It builds command byte vectors and decodes
//! printer status bytes; it owns no transport, opens no device, reads no clock
//! and cannot block. The guard-owned writer lives in [`crate::printer`], which
//! builds a whole receipt job through [`EscPosCodec`] before handing any bytes
//! to a transport.
//!
//! ## Supported command set
//!
//! | Operation | Wire command |
//! |---|---|
//! | Initialise | `ESC @` |
//! | Alignment | `ESC a n` |
//! | Emphasis | `ESC E n` |
//! | Feed *n* lines | `ESC d n` |
//! | Select code page | `ESC t n` |
//! | Text | encoded bytes |
//! | CODE128 barcode | `GS k 0x49 len data` |
//! | EAN-13 barcode | `GS k 0x43 d1..d12` |
//! | QR model/size/ECC/store/print | `GS ( k ...` |
//! | Cut | `GS V 0` / `GS V 1` |
//! | Cash-drawer kick | `ESC p m t1 t2` |
//! | Real-time status query | `DLE EOT n` |
//!
//! ## Bounded work
//!
//! A codec is created with an explicit byte capacity, capped at
//! [`MAX_JOB_BYTES`]. Every builder checks the remaining capacity **before**
//! extending the buffer and returns [`EscPosError::BufferFull`] instead of
//! growing it. Text, barcode and QR inputs have their own limits:
//! [`MAX_TEXT_BYTES`], [`MAX_BARCODE_BYTES`] and [`MAX_QR_DATA_BYTES`]. No
//! operation allocates from untrusted length fields, and status decoding looks
//! at one byte of a caller-supplied bounded slice.

use std::fmt;

/// Largest print job a single codec may build.
pub const MAX_JOB_BYTES: usize = 64 * 1024;
/// Largest single text run accepted by [`EscPosCodec::text`].
pub const MAX_TEXT_BYTES: usize = 4 * 1024;
/// Largest CODE128 payload accepted (the length byte is one byte).
pub const MAX_BARCODE_BYTES: usize = 255;
/// Largest QR payload accepted.
pub const MAX_QR_DATA_BYTES: usize = 1_024;
/// Largest status response a decoder will consider; only the first byte is
/// interpreted, so a device cannot grow work by replying with a long burst.
pub const MAX_STATUS_RESPONSE_BYTES: usize = 8;

const ESC: u8 = 0x1B;
const GS: u8 = 0x1D;
const DLE: u8 = 0x10;

/// A codec or status-decoding failure. These are protocol errors, not device or
/// transport failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscPosError {
    /// The requested capacity is zero or above [`MAX_JOB_BYTES`].
    InvalidCapacity,
    /// The command would exceed the codec's fixed capacity.
    BufferFull { capacity: usize },
    /// A text run is empty or longer than [`MAX_TEXT_BYTES`].
    InvalidTextLength,
    /// A text run contains a control character other than the implicit newline
    /// added by [`EscPosCodec::line`].
    ControlCharacter,
    /// A character is not representable in the selected code page.
    UnencodableCharacter(char),
    /// A barcode payload is empty or longer than [`MAX_BARCODE_BYTES`].
    InvalidBarcodeLength,
    /// A barcode payload contains a character the symbology cannot encode.
    InvalidBarcodeData,
    /// An EAN-13 payload is not 12 or 13 ASCII digits.
    InvalidEan13(&'static str),
    /// A QR payload is empty or longer than [`MAX_QR_DATA_BYTES`].
    InvalidQrData,
    /// A QR option is outside the values the command set permits.
    InvalidQrOption,
    /// The status response was empty.
    EmptyStatusResponse,
    /// The status response was longer than [`MAX_STATUS_RESPONSE_BYTES`].
    OversizedStatusResponse,
    /// The requested status kind is not one of `1..=4`.
    InvalidStatusKind(u8),
}

impl EscPosError {
    /// Stable reason code for logs and policy.
    pub fn code(self) -> &'static str {
        match self {
            EscPosError::InvalidCapacity => "escpos.invalid_capacity",
            EscPosError::BufferFull { .. } => "escpos.buffer_full",
            EscPosError::InvalidTextLength => "escpos.invalid_text_length",
            EscPosError::ControlCharacter => "escpos.control_character",
            EscPosError::UnencodableCharacter(_) => "escpos.unencodable_character",
            EscPosError::InvalidBarcodeLength => "escpos.invalid_barcode_length",
            EscPosError::InvalidBarcodeData => "escpos.invalid_barcode_data",
            EscPosError::InvalidEan13(_) => "escpos.invalid_ean13",
            EscPosError::InvalidQrData => "escpos.invalid_qr_data",
            EscPosError::InvalidQrOption => "escpos.invalid_qr_option",
            EscPosError::EmptyStatusResponse => "escpos.empty_status_response",
            EscPosError::OversizedStatusResponse => "escpos.oversized_status_response",
            EscPosError::InvalidStatusKind(_) => "escpos.invalid_status_kind",
        }
    }
}

impl fmt::Display for EscPosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscPosError::InvalidCapacity => write!(
                f,
                "codec capacity must be between 1 and {MAX_JOB_BYTES} bytes"
            ),
            EscPosError::BufferFull { capacity } => {
                write!(f, "print job exceeds the {capacity}-byte capacity")
            }
            EscPosError::InvalidTextLength => {
                write!(
                    f,
                    "text must be non-empty and at most {MAX_TEXT_BYTES} bytes"
                )
            }
            EscPosError::ControlCharacter => {
                write!(f, "text contains a control character; use feed()")
            }
            EscPosError::UnencodableCharacter(ch) => {
                write!(f, "character {ch:?} is not representable in this code page")
            }
            EscPosError::InvalidBarcodeLength => write!(
                f,
                "barcode payload must be non-empty and at most {MAX_BARCODE_BYTES} bytes"
            ),
            EscPosError::InvalidBarcodeData => {
                write!(
                    f,
                    "barcode payload contains a character the symbology cannot encode"
                )
            }
            EscPosError::InvalidEan13(reason) => write!(f, "invalid EAN-13 payload: {reason}"),
            EscPosError::InvalidQrData => write!(
                f,
                "QR payload must be non-empty and at most {MAX_QR_DATA_BYTES} bytes"
            ),
            EscPosError::InvalidQrOption => write!(f, "QR option is outside the permitted range"),
            EscPosError::EmptyStatusResponse => write!(f, "printer returned no status byte"),
            EscPosError::OversizedStatusResponse => write!(
                f,
                "status response exceeds {MAX_STATUS_RESPONSE_BYTES} bytes"
            ),
            EscPosError::InvalidStatusKind(kind) => {
                write!(f, "status kind {kind} is not in 1..=4")
            }
        }
    }
}

impl std::error::Error for EscPosError {}

/// Text justification (`ESC a n`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Alignment {
    /// Left aligned (0).
    Left = 0,
    /// Centred (1).
    Center = 1,
    /// Right aligned (2).
    Right = 2,
}

/// Paper cut (`GS V`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CutMode {
    /// Full cut after the current job (0).
    Full = 0,
    /// Partial cut (1).
    Partial = 1,
}

/// Cash-drawer kick pin (`ESC p m`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DrawerPin {
    /// Pin 2 (m = 0), the usual drawer connector.
    Pin2 = 0,
    /// Pin 5 (m = 1).
    Pin5 = 1,
}

/// Barcode symbologies supported by [`EscPosCodec::barcode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarcodeType {
    /// CODE128 (`GS k 0x49`), printable ASCII payload of 1..=255 bytes.
    Code128,
    /// EAN-13 (`GS k 0x43`), exactly 12 or 13 ASCII digits.
    Ean13,
}

/// Error-correction level for QR symbols (`GS ( k 0x31 0x45`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QrEcc {
    /// Level L (7% recovery).
    Low = 48,
    /// Level M (15% recovery).
    Medium = 49,
    /// Level Q (25% recovery).
    Quartile = 50,
    /// Level H (30% recovery).
    High = 51,
}

/// QR symbol parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QrOptions {
    /// Model 1 or 2 (typically 2).
    pub model: u8,
    /// Module size 1..=16.
    pub module_size: u8,
    /// Error-correction level.
    pub ecc: QrEcc,
}

impl Default for QrOptions {
    fn default() -> Self {
        Self {
            model: 2,
            module_size: 6,
            ecc: QrEcc::Medium,
        }
    }
}

/// Real-time status register (`DLE EOT n`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusKind {
    /// Printer status (n = 1).
    Printer = 1,
    /// Offline status (n = 2).
    Offline = 2,
    /// Error status (n = 3).
    Error = 3,
    /// Paper sensor status (n = 4).
    Paper = 4,
}

impl StatusKind {
    fn from_number(value: u8) -> Result<Self, EscPosError> {
        match value {
            1 => Ok(StatusKind::Printer),
            2 => Ok(StatusKind::Offline),
            3 => Ok(StatusKind::Error),
            4 => Ok(StatusKind::Paper),
            other => Err(EscPosError::InvalidStatusKind(other)),
        }
    }
}

/// The most severe condition reported by a status byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrinterErrorCode {
    /// The printer is offline.
    Offline,
    /// Paper is near the end of the roll.
    PaperNearEnd,
    /// The cover is open.
    CoverOpen,
    /// The printer reports a recoverable error.
    RecoverableError,
    /// No paper in the print path.
    PaperOut,
    /// The cutter is jammed.
    CutterError,
    /// The printer reports an unrecoverable error.
    UnrecoverableError,
}

impl PrinterErrorCode {
    /// Stable reason code for logs and policy.
    pub fn code(self) -> &'static str {
        match self {
            PrinterErrorCode::Offline => "printer.offline",
            PrinterErrorCode::PaperNearEnd => "printer.paper_near_end",
            PrinterErrorCode::CoverOpen => "printer.cover_open",
            PrinterErrorCode::RecoverableError => "printer.recoverable_error",
            PrinterErrorCode::PaperOut => "printer.paper_out",
            PrinterErrorCode::CutterError => "printer.cutter_error",
            PrinterErrorCode::UnrecoverableError => "printer.unrecoverable_error",
        }
    }
}

impl fmt::Display for PrinterErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Decoded bits of one status byte.
///
/// Bits the selected register does not define are ignored, never treated as an
/// error. A device therefore cannot make decoding panic by returning an
/// unexpected byte value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusFlags {
    /// No offline condition is reported.
    pub online: bool,
    /// The drawer connector signal is low (bit 0 set, active-low signal).
    pub drawer_signal: bool,
    /// The cover is open.
    pub cover_open: bool,
    /// Paper is near the end.
    pub paper_near_end: bool,
    /// No paper is present.
    pub paper_out: bool,
    /// The cutter failed.
    pub cutter_error: bool,
    /// A recoverable error is present.
    pub recoverable_error: bool,
    /// An unrecoverable error is present.
    pub unrecoverable_error: bool,
}

impl StatusFlags {
    /// The most severe reported condition, if any.
    pub fn error_code(&self) -> Option<PrinterErrorCode> {
        if self.unrecoverable_error {
            Some(PrinterErrorCode::UnrecoverableError)
        } else if self.cutter_error {
            Some(PrinterErrorCode::CutterError)
        } else if self.paper_out {
            Some(PrinterErrorCode::PaperOut)
        } else if self.cover_open {
            Some(PrinterErrorCode::CoverOpen)
        } else if !self.online {
            Some(PrinterErrorCode::Offline)
        } else if self.recoverable_error {
            Some(PrinterErrorCode::RecoverableError)
        } else if self.paper_near_end {
            Some(PrinterErrorCode::PaperNearEnd)
        } else {
            None
        }
    }

    /// `true` when no error condition is set. A near-end paper warning alone
    /// still allows printing.
    pub fn is_ready(&self) -> bool {
        self.error_code().is_none()
    }
}

/// One decoded status response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrinterStatus {
    kind: StatusKind,
    raw: u8,
    flags: StatusFlags,
}

impl PrinterStatus {
    /// The register that was queried.
    pub fn kind(self) -> StatusKind {
        self.kind
    }

    /// The raw byte, for diagnostics and recorded evidence.
    pub fn raw(self) -> u8 {
        self.raw
    }

    /// Decoded flags.
    pub fn flags(self) -> StatusFlags {
        self.flags
    }

    /// The most severe reported condition.
    pub fn error_code(self) -> Option<PrinterErrorCode> {
        self.flags.error_code()
    }

    /// `true` when the printer reports no error.
    pub fn is_ready(self) -> bool {
        self.flags.is_ready()
    }
}

/// Decode a bounded real-time status response.
///
/// An empty response is an error and so is a burst longer than
/// [`MAX_STATUS_RESPONSE_BYTES`]; otherwise only the first byte is interpreted.
/// Undefined bits are ignored.
pub fn decode_status_response(
    kind: StatusKind,
    response: &[u8],
) -> Result<PrinterStatus, EscPosError> {
    if response.is_empty() {
        return Err(EscPosError::EmptyStatusResponse);
    }
    if response.len() > MAX_STATUS_RESPONSE_BYTES {
        return Err(EscPosError::OversizedStatusResponse);
    }
    Ok(decode_status(kind, response[0]))
}

/// Decode one status byte for a register.
///
/// Bit assignments follow the common Epson `DLE EOT` layout:
///
/// - printer (1): bit 3 offline, bit 5 waiting for recovery, bit 0 drawer;
/// - offline (2): bit 2 cover open, bit 5 waiting for recovery, bit 0 drawer;
/// - error (3): bit 2 cutter, bit 3 unrecoverable, bit 5 recoverable, bit 6
///   paper out;
/// - paper (4): bit 2 near end, bit 3 paper end.
pub fn decode_status(kind: StatusKind, byte: u8) -> PrinterStatus {
    let bit = |index: u8| (byte >> index) & 1 == 1;
    let mut flags = StatusFlags {
        online: true,
        ..StatusFlags::default()
    };
    match kind {
        StatusKind::Printer => {
            flags.online = !bit(3);
            flags.drawer_signal = bit(0);
            flags.recoverable_error = bit(5);
        }
        StatusKind::Offline => {
            flags.online = !bit(3);
            flags.drawer_signal = bit(0);
            flags.cover_open = bit(2);
            flags.recoverable_error = bit(5);
        }
        StatusKind::Error => {
            flags.cutter_error = bit(2);
            flags.unrecoverable_error = bit(3);
            flags.recoverable_error = bit(5);
            flags.paper_out = bit(6);
        }
        StatusKind::Paper => {
            flags.paper_near_end = bit(2);
            flags.paper_out = bit(3);
        }
    }
    PrinterStatus {
        kind,
        raw: byte,
        flags,
    }
}

/// A supported single-byte code page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CodePage {
    /// PC437 (Epson page 0).
    Cp437 = 0,
    /// PC850 (Epson page 2).
    Cp850 = 2,
    /// Windows-1252 (Epson page 16).
    Cp1252 = 16,
}

impl CodePage {
    /// The Epson page number sent with `ESC t`.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Encode one character, or `None` when the code page has no byte for it.
    pub fn encode(self, ch: char) -> Option<u8> {
        let code = ch as u32;
        if (0x20..=0x7E).contains(&code) {
            return Some(code as u8);
        }
        let high = match self {
            CodePage::Cp437 => &CP437_HIGH,
            CodePage::Cp850 => &CP850_HIGH,
            CodePage::Cp1252 => &CP1252_HIGH,
        };
        high.iter()
            .position(|candidate| *candidate != '\0' && *candidate == ch)
            .map(|index| 0x80 + index as u8)
    }
}

#[rustfmt::skip]
const CP437_HIGH: [char; 128] = [
    'Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å',
    'É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','¢','£','¥','₧','ƒ',
    'á','í','ó','ú','ñ','Ñ','ª','º','¿','⌐','¬','½','¼','¡','«','»',
    '░','▒','▓','│','┤','╡','╢','╖','╕','╣','║','╗','╝','╜','╛','┐',
    '└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','╧',
    '╨','╤','╥','╙','╘','╒','╓','╫','╪','┘','┌','█','▄','▌','▐','▀',
    'α','ß','Γ','π','Σ','σ','µ','τ','Φ','Θ','Ω','δ','∞','φ','ε','∩',
    '≡','±','≥','≤','⌠','⌡','÷','≈','°','∙','·','√','ⁿ','²','■','\u{00A0}',
];

#[rustfmt::skip]
const CP850_HIGH: [char; 128] = [
    'Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å',
    'É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','ø','£','Ø','×','ƒ',
    'á','í','ó','ú','ñ','Ñ','ª','º','¿','®','¬','½','¼','¡','«','»',
    '░','▒','▓','│','┤','Á','Â','À','©','╣','║','╗','╝','¢','¥','┐',
    '└','┴','┬','├','─','┼','ã','Ã','╚','╔','╩','╦','╠','═','╬','¤',
    'ð','Ð','Ê','Ë','È','ı','Í','Î','Ï','┘','┌','█','▄','¦','Ì','▀',
    'Ó','ß','Ô','Ò','õ','Õ','µ','þ','Þ','Ú','Û','Ù','ý','Ý','¯','´',
    '\u{00AD}','±','‗','¾','¶','§','÷','¸','°','¨','·','¹','³','²','■','\u{00A0}',
];

#[rustfmt::skip]
const CP1252_HIGH: [char; 128] = [
    '€','\0','‚','ƒ','„','…','†','‡','ˆ','‰','Š','‹','Œ','\0','Ž','\0',
    '\0','‘','’','“','”','•','–','—','˜','™','š','›','œ','\0','ž','Ÿ',
    '\u{00A0}','¡','¢','£','¤','¥','¦','§','¨','©','ª','«','¬','\u{00AD}','®','¯',
    '°','±','²','³','´','µ','¶','·','¸','¹','º','»','¼','½','¾','¿',
    'À','Á','Â','Ã','Ä','Å','Æ','Ç','È','É','Ê','Ë','Ì','Í','Î','Ï',
    'Ð','Ñ','Ò','Ó','Ô','Õ','Ö','×','Ø','Ù','Ú','Û','Ü','Ý','Þ','ß',
    'à','á','â','ã','ä','å','æ','ç','è','é','ê','ë','ì','í','î','ï',
    'ð','ñ','ò','ó','ô','õ','ö','÷','ø','ù','ú','û','ü','ý','þ','ÿ',
];

/// A bounded ESC/POS command builder.
///
/// The buffer has a fixed capacity chosen at construction; it never grows.
/// `into_bytes` hands the completed job to the guard-owned writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscPosCodec {
    capacity: usize,
    buffer: Vec<u8>,
    page: CodePage,
}

impl EscPosCodec {
    /// Create a codec with a fixed capacity in `1..=MAX_JOB_BYTES`.
    pub fn new(capacity: usize) -> Result<Self, EscPosError> {
        if capacity == 0 || capacity > MAX_JOB_BYTES {
            return Err(EscPosError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            buffer: Vec::with_capacity(capacity),
            page: CodePage::Cp437,
        })
    }

    /// The fixed capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes built so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Number of bytes built so far.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// `true` when no command has been written.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Finish the job.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Discard all buffered commands and reset the selected code page.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.page = CodePage::Cp437;
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), EscPosError> {
        let new_len =
            self.buffer
                .len()
                .checked_add(bytes.len())
                .ok_or(EscPosError::BufferFull {
                    capacity: self.capacity,
                })?;
        if new_len > self.capacity {
            return Err(EscPosError::BufferFull {
                capacity: self.capacity,
            });
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// `ESC @` — reset the printer. Also resets the codec's selected page.
    pub fn initialize(&mut self) -> Result<(), EscPosError> {
        self.push(&[ESC, b'@'])?;
        self.page = CodePage::Cp437;
        Ok(())
    }

    /// `ESC a n` — set justification.
    pub fn align(&mut self, alignment: Alignment) -> Result<(), EscPosError> {
        self.push(&[ESC, b'a', alignment as u8])
    }

    /// `ESC E n` — enable or disable emphasised text.
    pub fn bold(&mut self, enabled: bool) -> Result<(), EscPosError> {
        self.push(&[ESC, b'E', u8::from(enabled)])
    }

    /// `ESC d n` — feed *n* lines.
    pub fn feed(&mut self, lines: u8) -> Result<(), EscPosError> {
        self.push(&[ESC, b'd', lines])
    }

    /// `ESC t n` — select a code page.
    pub fn code_page(&mut self, page: CodePage) -> Result<(), EscPosError> {
        self.push(&[ESC, b't', page.number()])?;
        self.page = page;
        Ok(())
    }

    /// Encode printable text in the currently selected code page.
    ///
    /// The text must be non-empty, at most [`MAX_TEXT_BYTES`], and contain no
    /// control characters. A character the page cannot represent is rejected
    /// rather than replaced, so a receipt never silently loses data.
    pub fn text(&mut self, text: &str) -> Result<(), EscPosError> {
        if text.is_empty() || text.len() > MAX_TEXT_BYTES {
            return Err(EscPosError::InvalidTextLength);
        }
        if text.chars().any(char::is_control) {
            return Err(EscPosError::ControlCharacter);
        }
        let mut encoded = [0_u8; 4];
        for ch in text.chars() {
            let byte = self
                .page
                .encode(ch)
                .ok_or(EscPosError::UnencodableCharacter(ch))?;
            encoded[0] = byte;
            self.push(&encoded[..1])?;
        }
        Ok(())
    }

    /// Encode text and append a line feed.
    pub fn line(&mut self, text: &str) -> Result<(), EscPosError> {
        self.text(text)?;
        self.push(b"\n")
    }

    /// `GS k` — print a barcode.
    ///
    /// CODE128 accepts 1..=255 printable ASCII bytes. EAN-13 accepts exactly 12
    /// or 13 ASCII digits; a 13-digit payload is checked for an all-digit body
    /// only (the check digit is left to the printer).
    pub fn barcode(&mut self, data: &str, kind: BarcodeType) -> Result<(), EscPosError> {
        match kind {
            BarcodeType::Code128 => {
                if data.is_empty() || data.len() > MAX_BARCODE_BYTES {
                    return Err(EscPosError::InvalidBarcodeLength);
                }
                if !data.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
                    return Err(EscPosError::InvalidBarcodeData);
                }
                self.push(&[GS, b'k', 0x49, data.len() as u8])?;
                self.push(data.as_bytes())
            }
            BarcodeType::Ean13 => {
                if data.len() != 12 && data.len() != 13 {
                    return Err(EscPosError::InvalidEan13(
                        "payload must have 12 or 13 digits",
                    ));
                }
                if !data.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(EscPosError::InvalidEan13(
                        "payload must contain digits only",
                    ));
                }
                self.push(&[GS, b'k', 0x43])?;
                self.push(data.as_bytes())
            }
        }
    }

    /// Build a complete QR symbol: model, module size, error correction, data
    /// store and print (`GS ( k`).
    pub fn qr_code(&mut self, data: &str, options: QrOptions) -> Result<(), EscPosError> {
        if data.is_empty() || data.len() > MAX_QR_DATA_BYTES {
            return Err(EscPosError::InvalidQrData);
        }
        if !matches!(options.model, 1 | 2) || !(1..=16).contains(&options.module_size) {
            return Err(EscPosError::InvalidQrOption);
        }

        // Model: pL = 4, pH = 0, cn = 0x31, fn = 0x41.
        self.push(&[GS, b'(', b'k', 4, 0, 0x31, 0x41, options.model, 0])?;
        // Module size: pL = 3.
        self.push(&[GS, b'(', b'k', 3, 0, 0x31, b'C', options.module_size])?;
        // Error correction: pL = 3.
        self.push(&[GS, b'(', b'k', 3, 0, 0x31, b'E', options.ecc as u8])?;

        let payload_len = data.len() + 3;
        if payload_len > u16::MAX as usize {
            return Err(EscPosError::InvalidQrData);
        }
        let p_l = (payload_len & 0xFF) as u8;
        let p_h = (payload_len >> 8) as u8;
        self.push(&[GS, b'(', b'k', p_l, p_h, 0x31, b'P', 0x30])?;
        self.push(data.as_bytes())?;
        // Print the stored symbol: pL = 3.
        self.push(&[GS, b'(', b'k', 3, 0, 0x31, b'Q', 0x30])
    }

    /// `GS V m` — cut the paper.
    pub fn cut(&mut self, mode: CutMode) -> Result<(), EscPosError> {
        self.push(&[GS, b'V', mode as u8])
    }

    /// `ESC p m t1 t2` — pulse the cash-drawer kick line.
    ///
    /// The pulse is 50 ms on and 500 ms off (t1 = 25, t2 = 250 in 2 ms units),
    /// a common drawer-safe default. The guard-owned writer is the only caller
    /// in the production path and permits one pulse per sale.
    pub fn drawer_kick(&mut self, pin: DrawerPin) -> Result<(), EscPosError> {
        self.push(&[ESC, b'p', pin as u8, 25, 250])
    }

    /// `DLE EOT n` — request one real-time status register.
    pub fn status_query(&mut self, kind: StatusKind) -> Result<(), EscPosError> {
        self.push(&[DLE, 0x04, kind as u8])
    }

    /// Build a status query as a standalone two-byte command.
    pub fn status_query_bytes(kind: StatusKind) -> [u8; 3] {
        [DLE, 0x04, kind as u8]
    }
}

/// Convenience: decode a status response after validating the kind number.
impl TryFrom<u8> for StatusKind {
    type Error = EscPosError;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        StatusKind::from_number(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_page_tables_are_well_formed() {
        for page in [CodePage::Cp437, CodePage::Cp850, CodePage::Cp1252] {
            for byte in 0x20_u8..=0x7E {
                assert_eq!(page.encode(byte as char), Some(byte));
            }
            assert_eq!(page.encode('\0'), None, "{page:?} must not encode NUL");
        }
        assert_eq!(CodePage::Cp437.encode('é'), Some(0x82));
        assert_eq!(CodePage::Cp850.encode('ø'), Some(0x9B));
        assert_eq!(CodePage::Cp1252.encode('€'), Some(0x80));
    }

    #[test]
    fn command_vectors_are_exact() {
        let mut codec = EscPosCodec::new(64).unwrap();
        codec.initialize().unwrap();
        codec.align(Alignment::Center).unwrap();
        codec.bold(true).unwrap();
        codec.feed(2).unwrap();
        codec.cut(CutMode::Partial).unwrap();
        assert_eq!(
            codec.as_bytes(),
            &[0x1B, 0x40, 0x1B, 0x61, 1, 0x1B, 0x45, 1, 0x1B, 0x64, 2, 0x1D, 0x56, 1]
        );
    }

    #[test]
    fn drawer_and_status_vectors_are_exact() {
        let mut codec = EscPosCodec::new(64).unwrap();
        codec.drawer_kick(DrawerPin::Pin2).unwrap();
        codec.status_query(StatusKind::Error).unwrap();
        codec.status_query(StatusKind::Paper).unwrap();
        assert_eq!(
            codec.as_bytes(),
            &[0x1B, 0x70, 0, 25, 250, 0x10, 0x04, 3, 0x10, 0x04, 4]
        );
    }

    #[test]
    fn status_bits_are_decoded_without_panicking() {
        for kind in [
            StatusKind::Printer,
            StatusKind::Offline,
            StatusKind::Error,
            StatusKind::Paper,
        ] {
            for byte in 0..=u8::MAX {
                let _ = decode_status(kind, byte);
            }
        }
        let error = decode_status(StatusKind::Error, 0b0000_1000);
        assert_eq!(
            error.error_code(),
            Some(PrinterErrorCode::UnrecoverableError)
        );
        assert_eq!(
            decode_status(StatusKind::Paper, 0b0000_1000).error_code(),
            Some(PrinterErrorCode::PaperOut)
        );
        assert!(decode_status(StatusKind::Printer, 0).is_ready());
    }

    #[test]
    fn status_response_length_is_bounded() {
        assert_eq!(
            decode_status_response(StatusKind::Printer, &[]),
            Err(EscPosError::EmptyStatusResponse)
        );
        let oversized = [0_u8; MAX_STATUS_RESPONSE_BYTES + 1];
        assert_eq!(
            decode_status_response(StatusKind::Printer, &oversized),
            Err(EscPosError::OversizedStatusResponse)
        );
        let ok = [0_u8; MAX_STATUS_RESPONSE_BYTES];
        assert!(decode_status_response(StatusKind::Printer, &ok).is_ok());
    }

    #[test]
    fn capacity_is_fixed_and_checked_before_writing() {
        let mut codec = EscPosCodec::new(3).unwrap();
        assert!(codec.initialize().is_ok());
        assert_eq!(
            codec.initialize().unwrap_err(),
            EscPosError::BufferFull { capacity: 3 }
        );
        assert_eq!(codec.as_bytes(), &[0x1B, 0x40]);
        assert_eq!(
            EscPosCodec::new(0).unwrap_err(),
            EscPosError::InvalidCapacity
        );
        assert_eq!(
            EscPosCodec::new(MAX_JOB_BYTES + 1).unwrap_err(),
            EscPosError::InvalidCapacity
        );
    }
}
