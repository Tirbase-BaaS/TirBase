// SPDX-License-Identifier: AGPL-3.0-only

//! POS-07 — receipt job, guard-owned printer transport and simulator.
//!
//! The ESC/POS codec in [`crate::escpos`] is pure. This module owns the device:
//! [`ReceiptPrinter`] takes exclusive ownership of a [`PrinterTransport`], builds
//! a complete bounded job through the codec, and writes it only after every
//! command has been encoded. There is no public access to the transport, so a
//! caller cannot bypass the codec, the status check or the per-sale drawer
//! rule.
//!
//! ## Sale flow
//!
//! ```text
//! print_sale(receipt, tender)
//!   |
//!   +-- validate receipt (currency, line count, exact totals)
//!   +-- query the printer status (DLE EOT 1) into a fixed 8-byte buffer
//!   |     offline / paper out / cover open / cutter error -> typed error
//!   +-- encode text, totals, payment line, footer, cut
//!   +-- cash tender only: one ESC p drawer pulse
//!   +-- one write_all of the finished job
//!   |
//!   +-- PrintOutcome { bytes_written, cash_drawer_opened }
//! ```
//!
//! A failed build writes nothing, so a partially encoded receipt can never
//! reach paper. Device status is read into a caller-supplied fixed-size slice,
//! never into a buffer sized by the device.
//!
//! [`SimulatedPrinter`] implements the transport for tests and HIL dry runs
//! (F-13). It records every write and answers status queries from a caller-set
//! script.

use std::collections::VecDeque;
use std::fmt;

use crate::check::Check;
use crate::check::PaymentMethod;
use crate::error::PosError;
use crate::escpos::{
    decode_status_response, BarcodeType, CodePage, CutMode, DrawerPin, EscPosCodec, EscPosError,
    PrinterErrorCode, PrinterStatus, StatusKind, MAX_STATUS_RESPONSE_BYTES,
};
use crate::money::Money;

/// Maximum number of item lines on one receipt.
pub const MAX_RECEIPT_LINES: usize = 256;
/// Maximum byte length of a receipt title, footer, description or quantity.
pub const MAX_RECEIPT_TEXT_BYTES: usize = 128;
/// Character columns assumed for receipt layout.
pub const RECEIPT_WIDTH: usize = 32;

/// A transport failure. The transport reports facts; policy lives in the guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The device is closed, unplugged or otherwise unavailable.
    Unavailable,
    /// The write was rejected or short.
    WriteFailed,
    /// No status response could be read.
    ReadFailed,
    /// The device did not respond in the caller's deadline.
    Timeout,
}

impl TransportError {
    /// Stable reason code for logs and policy.
    pub fn code(self) -> &'static str {
        match self {
            TransportError::Unavailable => "printer.transport.unavailable",
            TransportError::WriteFailed => "printer.transport.write_failed",
            TransportError::ReadFailed => "printer.transport.read_failed",
            TransportError::Timeout => "printer.transport.timeout",
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportError::Unavailable => "printer transport unavailable",
            TransportError::WriteFailed => "printer write failed",
            TransportError::ReadFailed => "printer status read failed",
            TransportError::Timeout => "printer transport timed out",
        })
    }
}

impl std::error::Error for TransportError {}

/// A rejected print, drawer or status operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrinterError {
    /// The command could not be encoded within the job capacity.
    Codec(EscPosError),
    /// The transport failed.
    Transport(TransportError),
    /// Receipt construction used invalid POS data.
    Pos(PosError),
    /// A receipt must carry at least one line.
    EmptyReceipt,
    /// The receipt exceeds [`MAX_RECEIPT_LINES`].
    TooManyLines { lines: usize, limit: usize },
    /// A title, footer, description or quantity is empty or too long.
    InvalidText(&'static str),
    /// Receipt amounts do not share one currency.
    CurrencyMismatch,
    /// The receipt's stated total disagrees with its components.
    InvalidTotals,
    /// The printer reported a condition that stops the job.
    Device(PrinterErrorCode),
    /// The status read returned zero bytes.
    EmptyStatusResponse,
}

impl PrinterError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            PrinterError::Codec(error) => error.code(),
            PrinterError::Transport(error) => error.code(),
            PrinterError::Pos(_) => "printer.pos_error",
            PrinterError::EmptyReceipt => "printer.empty_receipt",
            PrinterError::TooManyLines { .. } => "printer.too_many_lines",
            PrinterError::InvalidText(_) => "printer.invalid_text",
            PrinterError::CurrencyMismatch => "printer.currency_mismatch",
            PrinterError::InvalidTotals => "printer.invalid_totals",
            PrinterError::Device(error) => error.code(),
            PrinterError::EmptyStatusResponse => "printer.empty_status_response",
        }
    }

    /// The device condition, when the printer itself refused the job.
    pub fn device_error(&self) -> Option<PrinterErrorCode> {
        match self {
            PrinterError::Device(code) => Some(*code),
            _ => None,
        }
    }
}

impl From<EscPosError> for PrinterError {
    fn from(value: EscPosError) -> Self {
        PrinterError::Codec(value)
    }
}

impl From<TransportError> for PrinterError {
    fn from(value: TransportError) -> Self {
        PrinterError::Transport(value)
    }
}

impl From<PosError> for PrinterError {
    fn from(value: PosError) -> Self {
        PrinterError::Pos(value)
    }
}

impl fmt::Display for PrinterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrinterError::Codec(error) => write!(f, "ESC/POS codec error: {error}"),
            PrinterError::Transport(error) => write!(f, "{error}"),
            PrinterError::Pos(error) => write!(f, "invalid receipt data: {error}"),
            PrinterError::EmptyReceipt => write!(f, "receipt has no item lines"),
            PrinterError::TooManyLines { lines, limit } => {
                write!(f, "receipt has {lines} lines; the limit is {limit}")
            }
            PrinterError::InvalidText(what) => write!(f, "invalid {what}"),
            PrinterError::CurrencyMismatch => write!(f, "receipt amounts use different currencies"),
            PrinterError::InvalidTotals => write!(f, "receipt total does not match its components"),
            PrinterError::Device(error) => write!(f, "printer reported {error}"),
            PrinterError::EmptyStatusResponse => write!(f, "printer returned no status byte"),
        }
    }
}

impl std::error::Error for PrinterError {}

/// One printed item line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptLine {
    description: String,
    quantity: String,
    amount: Money,
}

impl ReceiptLine {
    /// Construct a line. The description is the item label; quantity is a
    /// pre-formatted display value (for example `2` or `1.5`).
    pub fn new(
        description: impl Into<String>,
        quantity: impl Into<String>,
        amount: Money,
    ) -> Result<Self, PrinterError> {
        let description = description.into();
        let quantity = quantity.into();
        validate_text(&description, "line description")?;
        validate_text(&quantity, "line quantity")?;
        if amount.is_negative() {
            return Err(PrinterError::Pos(PosError::NegativeAmount));
        }
        Ok(Self {
            description,
            quantity,
            amount,
        })
    }

    /// The item label.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The display quantity.
    pub fn quantity(&self) -> &str {
        &self.quantity
    }

    /// The line amount.
    pub fn amount(&self) -> Money {
        self.amount
    }
}

/// A printable sale receipt built from exact POS-01 money.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    title: String,
    lines: Vec<ReceiptLine>,
    subtotal: Money,
    discount_total: Money,
    tax_total: Money,
    tip: Money,
    total: Money,
    footer: Option<String>,
}

impl Receipt {
    /// Start a receipt with exact components. `total` must equal
    /// `subtotal - discount_total + tax_total + tip`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: impl Into<String>,
        subtotal: Money,
        discount_total: Money,
        tax_total: Money,
        tip: Money,
        total: Money,
    ) -> Result<Self, PrinterError> {
        let receipt = Self {
            title: title.into(),
            lines: Vec::new(),
            subtotal,
            discount_total,
            tax_total,
            tip,
            total,
            footer: None,
        };
        receipt.validate_components()?;
        Ok(receipt)
    }

    /// Build a receipt for a POS-01 check from its active lines and totals.
    ///
    /// Voided lines are excluded. The check rounding mode is used for each
    /// line's exact amount.
    pub fn from_check(check: &Check, title: impl Into<String>) -> Result<Self, PrinterError> {
        let totals = check.totals()?;
        let mut receipt = Self::new(
            title,
            totals.subtotal,
            totals.discount_total,
            totals.tax_total,
            totals.tip,
            totals.grand_total,
        )?;
        for (line, line_totals) in check.active_line_items().zip(totals.line_totals.iter()) {
            receipt.push_line(ReceiptLine::new(
                line.name(),
                format_quantity(line.quantity()),
                line_totals.total,
            )?)?;
        }
        Ok(receipt)
    }

    /// Append an item line.
    pub fn push_line(&mut self, line: ReceiptLine) -> Result<(), PrinterError> {
        if self.lines.len() == MAX_RECEIPT_LINES {
            return Err(PrinterError::TooManyLines {
                lines: self.lines.len() + 1,
                limit: MAX_RECEIPT_LINES,
            });
        }
        if line.amount.currency() != self.subtotal.currency() {
            return Err(PrinterError::CurrencyMismatch);
        }
        self.lines.push(line);
        Ok(())
    }

    /// Set the centred footer.
    pub fn with_footer(mut self, footer: impl Into<String>) -> Result<Self, PrinterError> {
        let footer = footer.into();
        validate_text(&footer, "footer")?;
        self.footer = Some(footer);
        Ok(self)
    }

    /// The receipt title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Item lines.
    pub fn lines(&self) -> &[ReceiptLine] {
        &self.lines
    }

    /// Subtotal.
    pub fn subtotal(&self) -> Money {
        self.subtotal
    }

    /// Total discount.
    pub fn discount_total(&self) -> Money {
        self.discount_total
    }

    /// Total tax.
    pub fn tax_total(&self) -> Money {
        self.tax_total
    }

    /// Tip.
    pub fn tip(&self) -> Money {
        self.tip
    }

    /// Grand total.
    pub fn total(&self) -> Money {
        self.total
    }

    /// The optional footer.
    pub fn footer(&self) -> Option<&str> {
        self.footer.as_deref()
    }

    fn validate_components(&self) -> Result<(), PrinterError> {
        validate_text(&self.title, "receipt title")?;
        let currency = self.subtotal.currency();
        for component in [self.discount_total, self.tax_total, self.tip, self.total] {
            if component.currency() != currency {
                return Err(PrinterError::CurrencyMismatch);
            }
        }
        if self.subtotal.is_negative()
            || self.discount_total.is_negative()
            || self.tax_total.is_negative()
            || self.tip.is_negative()
        {
            return Err(PrinterError::Pos(PosError::NegativeAmount));
        }
        let total = self.subtotal.minor() as i128 - self.discount_total.minor() as i128
            + self.tax_total.minor() as i128
            + self.tip.minor() as i128;
        if total != self.total.minor() as i128 {
            return Err(PrinterError::InvalidTotals);
        }
        Ok(())
    }

    /// Validate the whole receipt before it reaches the codec.
    pub fn validate(&self) -> Result<(), PrinterError> {
        self.validate_components()?;
        if self.lines.is_empty() {
            return Err(PrinterError::EmptyReceipt);
        }
        if self.lines.len() > MAX_RECEIPT_LINES {
            return Err(PrinterError::TooManyLines {
                lines: self.lines.len(),
                limit: MAX_RECEIPT_LINES,
            });
        }
        if let Some(footer) = &self.footer {
            validate_text(footer, "footer")?;
        }
        for line in &self.lines {
            validate_text(&line.description, "line description")?;
            validate_text(&line.quantity, "line quantity")?;
            if line.amount.currency() != self.subtotal.currency() {
                return Err(PrinterError::CurrencyMismatch);
            }
        }
        Ok(())
    }
}

fn validate_text(value: &str, what: &'static str) -> Result<(), PrinterError> {
    if value.trim().is_empty() || value.len() > MAX_RECEIPT_TEXT_BYTES {
        return Err(PrinterError::InvalidText(what));
    }
    Ok(())
}

fn format_quantity(quantity: crate::money::Quantity) -> String {
    let thousandths = quantity.thousandths();
    if thousandths % 1_000 == 0 {
        format!("{}", thousandths / 1_000)
    } else {
        let text = format!("{quantity}");
        text.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

fn format_money(amount: Money) -> String {
    let currency = amount.currency();
    let digits = currency.minor_units() as usize;
    let units = currency.minor_units_per_major();
    let minor = amount.minor();
    let sign = if minor < 0 { "-" } else { "" };
    let magnitude = minor.unsigned_abs();
    let major = magnitude / units as u64;
    if digits == 0 {
        format!("{sign}{major}")
    } else {
        let fraction = magnitude % units as u64;
        format!("{sign}{major}.{fraction:0width$}", width = digits)
    }
}

fn format_amount(amount: Money) -> String {
    format!("{} {}", format_money(amount), amount.currency().code())
}

/// A two-column receipt row, wrapping the amount to its own right-aligned line
/// when the pair does not fit.
fn push_row(codec: &mut EscPosCodec, left: &str, right: &str) -> Result<(), PrinterError> {
    let combined = left.len() + 1 + right.len();
    if combined <= RECEIPT_WIDTH {
        let padding = RECEIPT_WIDTH - left.len() - right.len();
        codec.text(left)?;
        codec.text(&" ".repeat(padding))?;
        codec.line(right)?;
    } else {
        codec.line(left)?;
        let padding = RECEIPT_WIDTH.saturating_sub(right.len());
        codec.text(&" ".repeat(padding))?;
        codec.line(right)?;
    }
    Ok(())
}

/// The result of a successful print job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrintOutcome {
    /// Bytes handed to the transport in one write.
    pub bytes_written: usize,
    /// `true` when the job included a cash-drawer pulse.
    pub cash_drawer_opened: bool,
    /// Receipts printed by this guard, including this one.
    pub receipts_printed: u64,
}

/// A physical printer connection owned by the guard.
///
/// Implementations write bytes and fill a caller-supplied buffer. `read_status`
/// must not allocate from a device-supplied length: the guard passes a fixed
/// `MAX_STATUS_RESPONSE_BYTES` slice.
pub trait PrinterTransport {
    /// Write a complete command job.
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// Read a status response into `buffer`, returning the byte count.
    fn read_status(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError>;

    /// Flush buffered bytes, when the transport has a flush boundary.
    fn flush(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// A guard-owned printer: the transport is private and every byte passes
/// through [`EscPosCodec`] and the receipt rules.
pub struct ReceiptPrinter<T: PrinterTransport> {
    transport: T,
    capacity: usize,
    receipts_printed: u64,
    drawer_kicks: u64,
}

impl<T: PrinterTransport> ReceiptPrinter<T> {
    /// Take ownership of a transport and fix the maximum job size.
    pub fn new(transport: T, capacity: usize) -> Result<Self, PrinterError> {
        let capacity = {
            let codec = EscPosCodec::new(capacity)?;
            codec.capacity()
        };
        Ok(Self {
            transport,
            capacity,
            receipts_printed: 0,
            drawer_kicks: 0,
        })
    }

    /// Receipts printed through this guard.
    pub fn receipts_printed(&self) -> u64 {
        self.receipts_printed
    }

    /// Drawer pulses emitted through this guard.
    pub fn drawer_kicks(&self) -> u64 {
        self.drawer_kicks
    }

    /// Build one receipt job and identify whether it opens the drawer.
    fn build_receipt_job(
        &self,
        receipt: &Receipt,
        tender: PaymentMethod,
    ) -> Result<(Vec<u8>, bool), PrinterError> {
        receipt.validate()?;
        let cash = tender == PaymentMethod::Cash;
        let mut codec = EscPosCodec::new(self.capacity)?;
        codec.initialize()?;
        codec.code_page(CodePage::Cp437)?;

        codec.align(crate::escpos::Alignment::Center)?;
        codec.bold(true)?;
        codec.line(receipt.title())?;
        codec.bold(false)?;
        codec.line(&"-".repeat(RECEIPT_WIDTH))?;
        codec.align(crate::escpos::Alignment::Left)?;

        for line in &receipt.lines {
            let left = format!("{} x {}", line.quantity, line.description);
            push_row(&mut codec, &left, &format_amount(line.amount))?;
        }

        codec.feed(1)?;
        push_row(&mut codec, "Subtotal", &format_amount(receipt.subtotal))?;
        if !receipt.discount_total.is_zero() {
            push_row(
                &mut codec,
                "Discount",
                &format!("-{}", format_amount(receipt.discount_total)),
            )?;
        }
        if !receipt.tax_total.is_zero() {
            push_row(&mut codec, "Tax", &format_amount(receipt.tax_total))?;
        }
        if !receipt.tip.is_zero() {
            push_row(&mut codec, "Tip", &format_amount(receipt.tip))?;
        }
        codec.bold(true)?;
        push_row(&mut codec, "TOTAL", &format_amount(receipt.total))?;
        codec.bold(false)?;

        let tender_label = match tender {
            PaymentMethod::Cash => "CASH",
            PaymentMethod::Card => "CARD",
            PaymentMethod::Voucher => "VOUCHER",
            PaymentMethod::Other => "OTHER",
        };
        push_row(&mut codec, "Tender", tender_label)?;

        if let Some(footer) = &receipt.footer {
            codec.feed(1)?;
            codec.align(crate::escpos::Alignment::Center)?;
            codec.line(footer)?;
            codec.align(crate::escpos::Alignment::Left)?;
        }

        codec.feed(1)?;
        if cash {
            codec.drawer_kick(DrawerPin::Pin2)?;
        }
        codec.cut(CutMode::Partial)?;
        Ok((codec.into_bytes(), cash))
    }

    /// Print a non-sale receipt. The drawer is not pulsed.
    pub fn print_receipt(&mut self, receipt: &Receipt) -> Result<PrintOutcome, PrinterError> {
        self.print_with_tender(receipt, PaymentMethod::Other)
    }

    /// Print a sale receipt; a cash tender pulses the drawer exactly once.
    pub fn print_sale(
        &mut self,
        receipt: &Receipt,
        tender: PaymentMethod,
    ) -> Result<PrintOutcome, PrinterError> {
        self.print_with_tender(receipt, tender)
    }

    fn print_with_tender(
        &mut self,
        receipt: &Receipt,
        tender: PaymentMethod,
    ) -> Result<PrintOutcome, PrinterError> {
        // Build first: an encoding failure must write nothing.
        let (job, cash_drawer_opened) = self.build_receipt_job(receipt, tender)?;
        let status = self.query_status(StatusKind::Printer)?;
        if let Some(error) = status.error_code() {
            return Err(PrinterError::Device(error));
        }
        self.transport.write_all(&job)?;
        self.transport.flush()?;
        self.receipts_printed = self.receipts_printed.saturating_add(1);
        if cash_drawer_opened {
            self.drawer_kicks = self.drawer_kicks.saturating_add(1);
        }
        Ok(PrintOutcome {
            bytes_written: job.len(),
            cash_drawer_opened,
            receipts_printed: self.receipts_printed,
        })
    }

    /// Pulse the cash drawer without printing a sale.
    ///
    /// This is an explicit drawer operation (for example a manager no-sale
    /// open); it is counted separately from sale pulses.
    pub fn pulse_drawer(&mut self) -> Result<(), PrinterError> {
        let mut codec = EscPosCodec::new(self.capacity)?;
        codec.drawer_kick(DrawerPin::Pin2)?;
        let job = codec.into_bytes();
        self.transport.write_all(&job)?;
        self.transport.flush()?;
        self.drawer_kicks = self.drawer_kicks.saturating_add(1);
        Ok(())
    }

    /// Query one real-time status register. The read buffer is fixed-size.
    pub fn query_status(&mut self, kind: StatusKind) -> Result<PrinterStatus, PrinterError> {
        let query = EscPosCodec::status_query_bytes(kind);
        self.transport.write_all(&query)?;
        self.transport.flush()?;
        let mut buffer = [0_u8; MAX_STATUS_RESPONSE_BYTES];
        let read = self.transport.read_status(&mut buffer)?;
        if read == 0 {
            return Err(PrinterError::EmptyStatusResponse);
        }
        if read > buffer.len() {
            return Err(PrinterError::Transport(TransportError::ReadFailed));
        }
        decode_status_response(kind, &buffer[..read]).map_err(PrinterError::Codec)
    }

    /// Consume the guard and recover the transport, for reconfiguration or
    /// inspection in tests. No other method exposes it.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// In-process printer and drawer simulator for tests and HIL rehearsals.
///
/// Every `write_all` is journaled in order. Status queries are answered from a
/// scripted queue; when the queue is empty a ready byte (`0x00`) is returned so
/// an ordinary sale needs no setup. Scripted bytes are bounded by
/// `MAX_STATUS_RESPONSE_BYTES`.
#[derive(Clone, Debug, Default)]
pub struct SimulatedPrinter {
    writes: Vec<Vec<u8>>,
    statuses: VecDeque<Vec<u8>>,
    status_queries: Vec<StatusKind>,
    fail_next_write: bool,
    offline: bool,
}

impl SimulatedPrinter {
    /// A ready simulator with no scripted conditions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script one status response for the next query. Responses longer than the
    /// guard's read buffer are truncated at the buffer boundary.
    pub fn push_status(&mut self, response: impl Into<Vec<u8>>) {
        self.statuses.push_back(response.into());
    }

    /// Script a status byte for a register.
    pub fn push_status_byte(&mut self, byte: u8) {
        self.push_status(vec![byte]);
    }

    /// Make the transport unavailable for the next write.
    pub fn fail_next_write(&mut self) {
        self.fail_next_write = true;
    }

    /// Record and answer every write with `TransportError::Unavailable`.
    pub fn set_offline(&mut self, offline: bool) {
        self.offline = offline;
    }

    /// Journaled writes in order.
    pub fn writes(&self) -> &[Vec<u8>] {
        &self.writes
    }

    /// Every byte written, concatenated. The simulator journal is host memory,
    /// not device input; it is bounded by the guard's job capacity per write.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for write in &self.writes {
            out.extend_from_slice(write);
        }
        out
    }

    /// Registers queried, in order.
    pub fn status_queries(&self) -> &[StatusKind] {
        &self.status_queries
    }

    /// `true` when any write contains the cash-drawer pulse command.
    pub fn drawer_pulsed(&self) -> bool {
        self.writes
            .iter()
            .any(|write| write.windows(3).any(|window| window == [0x1B, b'p', 0x00]))
    }

    /// Count cash-drawer pulse commands across all writes.
    pub fn drawer_pulse_count(&self) -> usize {
        self.writes
            .iter()
            .map(|write| {
                write
                    .windows(3)
                    .filter(|window| *window == [0x1B, b'p', 0x00])
                    .count()
            })
            .sum()
    }

    /// `true` when any write contains a paper-cut command.
    pub fn cut_issued(&self) -> bool {
        self.writes
            .iter()
            .any(|write| write.windows(2).any(|window| window == [0x1D, b'V']))
    }

    /// Extract printable ASCII runs from the journal, one per line, so a test
    /// can assert what a customer would see without parsing ESC/POS.
    pub fn receipt_text(&self) -> String {
        let mut out = String::new();
        let mut line = String::new();
        for byte in self.bytes() {
            if (0x20..=0x7E).contains(&byte) {
                line.push(byte as char);
            } else {
                if !line.trim().is_empty() {
                    out.push_str(line.trim_end());
                    out.push('\n');
                }
                line.clear();
            }
        }
        if !line.trim().is_empty() {
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

impl PrinterTransport for SimulatedPrinter {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.offline {
            return Err(TransportError::Unavailable);
        }
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(TransportError::WriteFailed);
        }
        self.writes.push(bytes.to_vec());
        Ok(())
    }

    fn read_status(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        if self.offline {
            return Err(TransportError::ReadFailed);
        }
        // Remember which register was requested when the query write is seen.
        if let Some(last) = self.writes.last() {
            if last.len() == 3 && last[0] == 0x10 && last[1] == 0x04 {
                if let Ok(kind) = StatusKind::try_from(last[2]) {
                    self.status_queries.push(kind);
                }
            }
        }
        let response = self.statuses.pop_front().unwrap_or_else(|| vec![0x00]);
        let copied = response.len().min(buffer.len());
        buffer[..copied].copy_from_slice(&response[..copied]);
        Ok(copied)
    }
}

/// Convenience constructor for the ready simulator (clippy prefers `Default`).
impl SimulatedPrinter {
    /// A ready simulator, equivalent to `SimulatedPrinter::default()`.
    pub fn ready() -> Self {
        Self::new()
    }
}

/// Encode a barcode standalone, for tests and operators that print labels
/// without a sale. Output is bounded by [`crate::escpos::MAX_JOB_BYTES`].
pub fn barcode_bytes(
    data: &str,
    kind: BarcodeType,
    capacity: usize,
) -> Result<Vec<u8>, PrinterError> {
    let mut codec = EscPosCodec::new(capacity)?;
    codec.barcode(data, kind)?;
    Ok(codec.into_bytes())
}
