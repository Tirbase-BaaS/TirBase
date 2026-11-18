// SPDX-License-Identifier: AGPL-3.0-only

//! POS-08 — kitchen display ticket codec, idempotent ticket IDs and ack/retry.
//!
//! [`KdsCodec`] is a bounded text codec for one ticket, its lines and their
//! preparation status, plus an acknowledgement frame. Text fields are
//! percent-escaped, so a name can contain spaces or any UTF-8 byte without
//! changing the line structure. Decoding requires the closing `END` marker; a
//! truncated ticket is rejected.
//!
//! [`KdsEndpoint`] owns the transport and the ticket journal. A ticket ID is
//! idempotent: retrying the exact same ticket returns
//! [`KdsSubmitOutcome::Duplicate`] without writing anything, while reusing the
//! ID for different content is a conflict. Delivery retries a bounded number of
//! times when the transport fails or the acknowledgement does not arrive, and
//! every acknowledgement is checked against the ticket ID and sequence.
//!
//! [`SimulatedKds`] records tickets, drops acknowledgements and fails sends for
//! tests and HIL rehearsals.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use crate::ids::{CheckId, KdsTicketId, LineItemId, OrderId};
use crate::money::Quantity;
use crate::printer::TransportError;

/// Maximum encoded ticket size.
pub const MAX_KDS_TICKET_BYTES: usize = 32 * 1024;
/// Maximum lines in one ticket.
pub const MAX_KDS_LINES: usize = 128;
/// Maximum bytes in a ticket, line or station label.
pub const MAX_KDS_TEXT_BYTES: usize = 64;
/// Maximum acknowledgement frame size.
pub const MAX_KDS_ACK_BYTES: usize = 256;
/// Default delivery attempts before retry exhaustion.
pub const DEFAULT_KDS_ATTEMPTS: u8 = 3;

/// Where a line is prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Station {
    /// Grill station.
    Grill,
    /// Fry station.
    Fry,
    /// Cold pantry.
    Cold,
    /// Bar.
    Bar,
    /// Pass / expeditor.
    Expo,
}

impl Station {
    /// Wire token.
    pub fn code(self) -> &'static str {
        match self {
            Station::Grill => "grill",
            Station::Fry => "fry",
            Station::Cold => "cold",
            Station::Bar => "bar",
            Station::Expo => "expo",
        }
    }

    /// Parse a wire token.
    pub fn from_code(value: &str) -> Option<Self> {
        match value {
            "grill" => Some(Station::Grill),
            "fry" => Some(Station::Fry),
            "cold" => Some(Station::Cold),
            "bar" => Some(Station::Bar),
            "expo" => Some(Station::Expo),
            _ => None,
        }
    }
}

/// Preparation status of one ticket line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LineStatus {
    /// Waiting for a station.
    Queued,
    /// Being prepared.
    Preparing,
    /// Ready for the pass.
    Ready,
    /// Delivered to the guest.
    Served,
}

impl LineStatus {
    /// Wire token.
    pub fn code(self) -> &'static str {
        match self {
            LineStatus::Queued => "queued",
            LineStatus::Preparing => "preparing",
            LineStatus::Ready => "ready",
            LineStatus::Served => "served",
        }
    }

    /// Parse a wire token.
    pub fn from_code(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(LineStatus::Queued),
            "preparing" => Some(LineStatus::Preparing),
            "ready" => Some(LineStatus::Ready),
            "served" => Some(LineStatus::Served),
            _ => None,
        }
    }
}

/// Derived status of a whole ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TicketStatus {
    /// Every line is queued.
    Queued,
    /// At least one line is in preparation or ready.
    InProgress,
    /// Every line is ready or served.
    Ready,
    /// Every line is served.
    Served,
}

/// One line on a kitchen ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdsLine {
    id: LineItemId,
    name: String,
    quantity: Quantity,
    station: Station,
    status: LineStatus,
}

impl KdsLine {
    /// Construct and validate a line.
    pub fn new(
        id: LineItemId,
        name: impl Into<String>,
        quantity: Quantity,
        station: Station,
        status: LineStatus,
    ) -> Result<Self, KdsCodecError> {
        let name = name.into();
        validate_text(&name, "line name")?;
        Ok(Self {
            id,
            name,
            quantity,
            station,
            status,
        })
    }

    /// Line identifier.
    pub fn id(&self) -> &LineItemId {
        &self.id
    }

    /// Item label.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ordered quantity.
    pub fn quantity(&self) -> Quantity {
        self.quantity
    }

    /// Preparation station.
    pub fn station(&self) -> Station {
        self.station
    }

    /// Preparation status.
    pub fn status(&self) -> LineStatus {
        self.status
    }

    /// A copy of this line with a new status.
    pub fn with_status(mut self, status: LineStatus) -> Self {
        self.status = status;
        self
    }
}

/// One kitchen-display ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdsTicket {
    id: KdsTicketId,
    order_id: OrderId,
    check_id: CheckId,
    sequence: u64,
    lines: Vec<KdsLine>,
}

impl KdsTicket {
    /// Construct and validate a ticket.
    pub fn new(
        id: KdsTicketId,
        order_id: OrderId,
        check_id: CheckId,
        sequence: u64,
        lines: Vec<KdsLine>,
    ) -> Result<Self, KdsCodecError> {
        if lines.is_empty() {
            return Err(KdsCodecError::EmptyTicket);
        }
        if lines.len() > MAX_KDS_LINES {
            return Err(KdsCodecError::TooManyLines {
                lines: lines.len(),
                limit: MAX_KDS_LINES,
            });
        }
        let mut seen = BTreeMap::new();
        for line in &lines {
            if seen.insert(line.id.as_str(), ()).is_some() {
                return Err(KdsCodecError::DuplicateLine);
            }
        }
        Ok(Self {
            id,
            order_id,
            check_id,
            sequence,
            lines,
        })
    }

    /// Idempotent ticket identifier.
    pub fn id(&self) -> &KdsTicketId {
        &self.id
    }

    /// Owning order.
    pub fn order_id(&self) -> &OrderId {
        &self.order_id
    }

    /// Owning check.
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    /// Caller-supplied ticket sequence/revision.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Ticket lines.
    pub fn lines(&self) -> &[KdsLine] {
        &self.lines
    }

    /// Derived ticket status.
    pub fn status(&self) -> TicketStatus {
        if self
            .lines
            .iter()
            .all(|line| line.status == LineStatus::Served)
        {
            TicketStatus::Served
        } else if self
            .lines
            .iter()
            .all(|line| matches!(line.status, LineStatus::Ready | LineStatus::Served))
        {
            TicketStatus::Ready
        } else if self
            .lines
            .iter()
            .any(|line| line.status != LineStatus::Queued)
        {
            TicketStatus::InProgress
        } else {
            TicketStatus::Queued
        }
    }
}

fn validate_text(value: &str, what: &'static str) -> Result<(), KdsCodecError> {
    if value.is_empty() || value.len() > MAX_KDS_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(KdsCodecError::InvalidText(what));
    }
    Ok(())
}

/// A malformed KDS frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdsCodecError {
    /// The frame is missing its header or `END` marker.
    Truncated,
    /// The frame exceeds [`MAX_KDS_TICKET_BYTES`] or an ack exceeds
    /// [`MAX_KDS_ACK_BYTES`].
    TooLong,
    /// A key, separator or escape is malformed.
    Malformed(&'static str),
    /// A ticket has no lines.
    EmptyTicket,
    /// A ticket exceeds [`MAX_KDS_LINES`].
    TooManyLines { lines: usize, limit: usize },
    /// Two lines share an identifier.
    DuplicateLine,
    /// A name, station label or identifier is empty, too long or has a control.
    InvalidText(&'static str),
    /// A quantity is not a positive thousandth count.
    InvalidQuantity,
    /// A station or line status token is unknown.
    UnknownStatus(&'static str),
    /// A required field appeared more than once.
    DuplicateField(&'static str),
    /// A required field is missing.
    MissingField(&'static str),
}

impl KdsCodecError {
    /// Stable reason code.
    pub fn code(self) -> &'static str {
        match self {
            KdsCodecError::Truncated => "kds.codec.truncated",
            KdsCodecError::TooLong => "kds.codec.too_long",
            KdsCodecError::Malformed(_) => "kds.codec.malformed",
            KdsCodecError::EmptyTicket => "kds.codec.empty_ticket",
            KdsCodecError::TooManyLines { .. } => "kds.codec.too_many_lines",
            KdsCodecError::DuplicateLine => "kds.codec.duplicate_line",
            KdsCodecError::InvalidText(_) => "kds.codec.invalid_text",
            KdsCodecError::InvalidQuantity => "kds.codec.invalid_quantity",
            KdsCodecError::UnknownStatus(_) => "kds.codec.unknown_status",
            KdsCodecError::DuplicateField(_) => "kds.codec.duplicate_field",
            KdsCodecError::MissingField(_) => "kds.codec.missing_field",
        }
    }
}

impl fmt::Display for KdsCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdsCodecError::Truncated => f.write_str("truncated KDS frame"),
            KdsCodecError::TooLong => f.write_str("KDS frame too long"),
            KdsCodecError::Malformed(what) => write!(f, "malformed KDS {what}"),
            KdsCodecError::EmptyTicket => f.write_str("KDS ticket has no lines"),
            KdsCodecError::TooManyLines { lines, limit } => {
                write!(f, "KDS ticket has {lines} lines; the limit is {limit}")
            }
            KdsCodecError::DuplicateLine => f.write_str("duplicate KDS line id"),
            KdsCodecError::InvalidText(what) => write!(f, "invalid KDS {what}"),
            KdsCodecError::InvalidQuantity => f.write_str("invalid KDS quantity"),
            KdsCodecError::UnknownStatus(what) => write!(f, "unknown KDS {what}"),
            KdsCodecError::DuplicateField(field) => write!(f, "duplicate KDS field {field}"),
            KdsCodecError::MissingField(field) => write!(f, "missing KDS field {field}"),
        }
    }
}

impl std::error::Error for KdsCodecError {}

/// A KDS delivery or codec failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KdsError {
    /// The frame was malformed.
    Codec(KdsCodecError),
    /// The transport failed.
    Transport(TransportError),
    /// Every delivery attempt failed or timed out.
    RetryExhausted { attempts: u8 },
    /// The ticket ID is already in use for different content.
    TicketConflict,
    /// The acknowledgement names a different ticket or sequence.
    AckMismatch,
    /// A zero delivery-attempt budget was supplied.
    InvalidAttempts,
}

impl KdsError {
    /// Stable reason code.
    pub fn code(&self) -> &'static str {
        match self {
            KdsError::Codec(error) => error.code(),
            KdsError::Transport(error) => error.code(),
            KdsError::RetryExhausted { .. } => "kds.retry_exhausted",
            KdsError::TicketConflict => "kds.ticket_conflict",
            KdsError::AckMismatch => "kds.ack_mismatch",
            KdsError::InvalidAttempts => "kds.invalid_attempts",
        }
    }
}

impl From<KdsCodecError> for KdsError {
    fn from(value: KdsCodecError) -> Self {
        KdsError::Codec(value)
    }
}

impl From<TransportError> for KdsError {
    fn from(value: TransportError) -> Self {
        KdsError::Transport(value)
    }
}

impl fmt::Display for KdsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdsError::Codec(error) => write!(f, "{error}"),
            KdsError::Transport(error) => write!(f, "{error}"),
            KdsError::RetryExhausted { attempts } => {
                write!(f, "KDS delivery failed after {attempts} attempts")
            }
            KdsError::TicketConflict => f.write_str("KDS ticket id reused for different content"),
            KdsError::AckMismatch => f.write_str("KDS acknowledgement does not match the ticket"),
            KdsError::InvalidAttempts => f.write_str("KDS attempt budget must be positive"),
        }
    }
}

impl std::error::Error for KdsError {}

/// One acknowledgement from the kitchen display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdsAck {
    ticket_id: KdsTicketId,
    sequence: u64,
}

impl KdsAck {
    /// Construct an acknowledgement.
    pub fn new(ticket_id: KdsTicketId, sequence: u64) -> Self {
        Self {
            ticket_id,
            sequence,
        }
    }

    /// Acknowledged ticket.
    pub fn ticket_id(&self) -> &KdsTicketId {
        &self.ticket_id
    }

    /// Acknowledged sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Pure ticket and acknowledgement codec.
#[derive(Clone, Copy, Debug, Default)]
pub struct KdsCodec;

impl KdsCodec {
    /// Encode one ticket.
    pub fn encode_ticket(ticket: &KdsTicket) -> Result<Vec<u8>, KdsError> {
        if ticket.lines.is_empty() {
            return Err(KdsCodecError::EmptyTicket.into());
        }
        if ticket.lines.len() > MAX_KDS_LINES {
            return Err(KdsCodecError::TooManyLines {
                lines: ticket.lines.len(),
                limit: MAX_KDS_LINES,
            }
            .into());
        }
        let mut encoded = String::with_capacity(128);
        encoded.push_str("KDS1\n");
        encoded.push_str("I ");
        escape_into(ticket.id.as_str(), &mut encoded);
        encoded.push('\n');
        encoded.push_str("O ");
        escape_into(ticket.order_id.as_str(), &mut encoded);
        encoded.push('\n');
        encoded.push_str("C ");
        escape_into(ticket.check_id.as_str(), &mut encoded);
        encoded.push('\n');
        encoded.push_str(&format!("S {}\n", ticket.sequence));
        for line in &ticket.lines {
            encoded.push_str("L ");
            escape_into(line.id.as_str(), &mut encoded);
            encoded.push_str(&format!(
                " {} {} {} ",
                line.quantity.thousandths(),
                line.station.code(),
                line.status.code()
            ));
            escape_into(&line.name, &mut encoded);
            encoded.push('\n');
        }
        encoded.push_str("END\n");
        if encoded.len() > MAX_KDS_TICKET_BYTES {
            return Err(KdsCodecError::TooLong.into());
        }
        Ok(encoded.into_bytes())
    }

    /// Decode exactly one ticket frame.
    pub fn decode_ticket(bytes: &[u8]) -> Result<KdsTicket, KdsError> {
        if bytes.len() > MAX_KDS_TICKET_BYTES {
            return Err(KdsCodecError::TooLong.into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| KdsCodecError::Malformed("utf-8"))?;
        let lines: Vec<&str> = text.split_terminator('\n').collect();
        if lines.len() < 6 || lines.last() != Some(&"END") {
            return Err(KdsCodecError::Truncated.into());
        }
        if lines[0] != "KDS1" {
            return Err(KdsCodecError::Malformed("header").into());
        }
        let mut id = None;
        let mut order_id = None;
        let mut check_id = None;
        let mut sequence = None;
        let mut ticket_lines = Vec::new();
        for line in &lines[1..lines.len() - 1] {
            if let Some(value) = line.strip_prefix("I ") {
                set_once(&mut id, value, "ticket id")?;
            } else if let Some(value) = line.strip_prefix("O ") {
                set_once(&mut order_id, value, "order id")?;
            } else if let Some(value) = line.strip_prefix("C ") {
                set_once(&mut check_id, value, "check id")?;
            } else if let Some(value) = line.strip_prefix("S ") {
                set_once(&mut sequence, value, "sequence")?;
            } else if let Some(value) = line.strip_prefix("L ") {
                ticket_lines.push(parse_line(value)?);
            } else {
                return Err(KdsCodecError::Malformed("field").into());
            }
        }
        let id = KdsTicketId::new(unescape(
            id.ok_or(KdsCodecError::MissingField("ticket id"))?,
        )?)
        .map_err(|_| KdsCodecError::InvalidText("ticket id"))?;
        let order_id = OrderId::new(unescape(
            order_id.ok_or(KdsCodecError::MissingField("order id"))?,
        )?)
        .map_err(|_| KdsCodecError::InvalidText("order id"))?;
        let check_id = CheckId::new(unescape(
            check_id.ok_or(KdsCodecError::MissingField("check id"))?,
        )?)
        .map_err(|_| KdsCodecError::InvalidText("check id"))?;
        let sequence = sequence
            .ok_or(KdsCodecError::MissingField("sequence"))?
            .parse::<u64>()
            .map_err(|_| KdsCodecError::Malformed("sequence"))?;
        KdsTicket::new(id, order_id, check_id, sequence, ticket_lines).map_err(KdsError::from)
    }

    /// Encode an acknowledgement.
    pub fn encode_ack(ack: &KdsAck) -> Result<Vec<u8>, KdsError> {
        let mut encoded = String::with_capacity(64);
        encoded.push_str("ACK ");
        escape_into(ack.ticket_id.as_str(), &mut encoded);
        encoded.push_str(&format!(" {}\n", ack.sequence));
        if encoded.len() > MAX_KDS_ACK_BYTES {
            return Err(KdsCodecError::TooLong.into());
        }
        Ok(encoded.into_bytes())
    }

    /// Decode one acknowledgement frame.
    pub fn decode_ack(bytes: &[u8]) -> Result<KdsAck, KdsError> {
        if bytes.len() > MAX_KDS_ACK_BYTES {
            return Err(KdsCodecError::TooLong.into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| KdsCodecError::Malformed("utf-8"))?;
        let text = text.strip_suffix('\n').ok_or(KdsCodecError::Truncated)?;
        let mut parts = text.split(' ');
        if parts.next() != Some("ACK") {
            return Err(KdsCodecError::Malformed("ack header").into());
        }
        let id = parts.next().ok_or(KdsCodecError::MissingField("ack id"))?;
        let sequence = parts
            .next()
            .ok_or(KdsCodecError::MissingField("ack sequence"))?;
        if parts.next().is_some() {
            return Err(KdsCodecError::Malformed("ack").into());
        }
        let ticket_id =
            KdsTicketId::new(unescape(id)?).map_err(|_| KdsCodecError::InvalidText("ack id"))?;
        let sequence = sequence
            .parse::<u64>()
            .map_err(|_| KdsCodecError::Malformed("ack sequence"))?;
        Ok(KdsAck::new(ticket_id, sequence))
    }
}

fn set_once<'a>(
    slot: &mut Option<&'a str>,
    value: &'a str,
    field: &'static str,
) -> Result<(), KdsCodecError> {
    if slot.is_some() {
        return Err(KdsCodecError::DuplicateField(field));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_line(value: &str) -> Result<KdsLine, KdsCodecError> {
    let mut parts = value.splitn(5, ' ');
    let id = parts.next().ok_or(KdsCodecError::Malformed("line"))?;
    let quantity = parts
        .next()
        .ok_or(KdsCodecError::Malformed("line quantity"))?;
    let station = parts
        .next()
        .ok_or(KdsCodecError::Malformed("line station"))?;
    let status = parts
        .next()
        .ok_or(KdsCodecError::Malformed("line status"))?;
    let name = parts.next().ok_or(KdsCodecError::Malformed("line name"))?;
    let quantity = quantity
        .parse::<i64>()
        .ok()
        .and_then(|value| Quantity::from_thousandths(value).ok())
        .ok_or(KdsCodecError::InvalidQuantity)?;
    let station = Station::from_code(station).ok_or(KdsCodecError::UnknownStatus("station"))?;
    let status =
        LineStatus::from_code(status).ok_or(KdsCodecError::UnknownStatus("line status"))?;
    let id = LineItemId::new(unescape(id)?).map_err(|_| KdsCodecError::InvalidText("line id"))?;
    KdsLine::new(id, unescape(name)?, quantity, station, status)
}

fn escape_into(value: &str, out: &mut String) {
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'/') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
}

fn unescape(value: &str) -> Result<String, KdsCodecError> {
    let mut bytes = Vec::with_capacity(value.len());
    let input = value.as_bytes();
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            if index + 2 >= input.len() {
                return Err(KdsCodecError::Malformed("escape"));
            }
            let high = hex_value(input[index + 1]).ok_or(KdsCodecError::Malformed("escape"))?;
            let low = hex_value(input[index + 2]).ok_or(KdsCodecError::Malformed("escape"))?;
            bytes.push(high * 16 + low);
            index += 3;
        } else {
            bytes.push(input[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(bytes).map_err(|_| KdsCodecError::Malformed("utf-8"))?;
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        return Err(KdsCodecError::InvalidText("field"));
    }
    Ok(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Ticket delivery transport.
pub trait KdsTransport {
    /// Send one complete frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError>;

    /// Receive one acknowledgement frame into the fixed-size buffer.
    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;
}

/// Result of submitting a ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdsSubmitOutcome {
    /// Delivered and acknowledged on this attempt.
    Created { attempts: u8 },
    /// The exact ticket was already delivered; nothing was written.
    Duplicate,
}

/// Guard-owned kitchen-display endpoint.
pub struct KdsEndpoint<T: KdsTransport> {
    transport: T,
    tickets: BTreeMap<String, KdsTicket>,
    acknowledgements: BTreeMap<String, u64>,
    max_attempts: u8,
    sends: u64,
    retries: u64,
}

impl<T: KdsTransport> KdsEndpoint<T> {
    /// Wrap a transport. `max_attempts` must be greater than zero.
    pub fn new(transport: T, max_attempts: u8) -> Result<Self, KdsError> {
        if max_attempts == 0 {
            return Err(KdsError::InvalidAttempts);
        }
        Ok(Self {
            transport,
            tickets: BTreeMap::new(),
            acknowledgements: BTreeMap::new(),
            max_attempts,
            sends: 0,
            retries: 0,
        })
    }

    /// Wrap a transport with [`DEFAULT_KDS_ATTEMPTS`] delivery attempts.
    pub fn with_defaults(transport: T) -> Result<Self, KdsError> {
        Self::new(transport, DEFAULT_KDS_ATTEMPTS)
    }

    /// Submit a ticket exactly once by its ID.
    ///
    /// Re-submitting identical content returns [`KdsSubmitOutcome::Duplicate`]
    /// without touching the transport. Reusing the ID for different content is
    /// [`KdsError::TicketConflict`].
    pub fn submit(&mut self, ticket: &KdsTicket) -> Result<KdsSubmitOutcome, KdsError> {
        let key = ticket.id.as_str().to_owned();
        if let Some(existing) = self.tickets.get(&key) {
            if existing == ticket {
                return Ok(KdsSubmitOutcome::Duplicate);
            }
            return Err(KdsError::TicketConflict);
        }
        let frame = KdsCodec::encode_ticket(ticket)?;
        let expected = KdsAck::new(ticket.id.clone(), ticket.sequence);
        for attempt in 1..=self.max_attempts {
            if self.transport.send(&frame).is_ok() {
                self.sends = self.sends.saturating_add(1);
                let mut buffer = [0_u8; MAX_KDS_ACK_BYTES];
                match self.transport.receive(&mut buffer) {
                    Ok(0) => {}
                    Ok(read) if read <= buffer.len() => {
                        let ack = KdsCodec::decode_ack(&buffer[..read])?;
                        if ack != expected {
                            return Err(KdsError::AckMismatch);
                        }
                        self.acknowledgements.insert(key.clone(), ack.sequence);
                        self.tickets.insert(key, ticket.clone());
                        return Ok(KdsSubmitOutcome::Created { attempts: attempt });
                    }
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
            if attempt < self.max_attempts {
                self.retries = self.retries.saturating_add(1);
            }
        }
        Err(KdsError::RetryExhausted {
            attempts: self.max_attempts,
        })
    }

    /// Acknowledged sequence for a ticket, if delivered.
    pub fn acknowledged(&self, id: &KdsTicketId) -> Option<u64> {
        self.acknowledgements.get(id.as_str()).copied()
    }

    /// Delivered tickets.
    pub fn tickets(&self) -> impl Iterator<Item = &KdsTicket> {
        self.tickets.values()
    }

    /// Frames written to the display.
    pub fn sends(&self) -> u64 {
        self.sends
    }

    /// Delivery attempts after the first.
    pub fn retries(&self) -> u64 {
        self.retries
    }

    /// Consume the guard and recover the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// In-process kitchen-display simulator.
///
/// It deduplicates tickets by ID, queues an acknowledgement for each accepted
/// ticket, and can drop acknowledgements or fail sends.
#[derive(Clone, Debug, Default)]
pub struct SimulatedKds {
    tickets: Vec<KdsTicket>,
    frames: Vec<Vec<u8>>,
    duplicate_frames: u64,
    acks: VecDeque<Vec<u8>>,
    drop_acks: u8,
    fail_sends: u8,
}

impl SimulatedKds {
    /// An empty display.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop the next `count` acknowledgements.
    pub fn drop_next_acks(&mut self, count: u8) {
        self.drop_acks = count;
    }

    /// Fail the next `count` sends.
    pub fn fail_next_sends(&mut self, count: u8) {
        self.fail_sends = count;
    }

    /// Accepted tickets, in delivery order.
    pub fn tickets(&self) -> &[KdsTicket] {
        &self.tickets
    }

    /// Every ticket frame received.
    pub fn frames(&self) -> &[Vec<u8>] {
        &self.frames
    }

    /// Repeated frames for an already-known ticket ID.
    pub fn duplicate_frames(&self) -> u64 {
        self.duplicate_frames
    }
}

impl KdsTransport for SimulatedKds {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if self.fail_sends > 0 {
            self.fail_sends -= 1;
            return Err(TransportError::WriteFailed);
        }
        let ticket = KdsCodec::decode_ticket(frame).map_err(|_| TransportError::WriteFailed)?;
        self.frames.push(frame.to_vec());
        if self.tickets.iter().any(|known| known.id == ticket.id) {
            self.duplicate_frames = self.duplicate_frames.saturating_add(1);
        } else {
            let ack = KdsAck::new(ticket.id.clone(), ticket.sequence);
            if let Ok(frame) = KdsCodec::encode_ack(&ack) {
                self.acks.push_back(frame);
            }
            self.tickets.push(ticket);
        }
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if self.drop_acks > 0 {
            self.drop_acks -= 1;
            return Err(TransportError::Timeout);
        }
        let Some(ack) = self.acks.pop_front() else {
            return Err(TransportError::ReadFailed);
        };
        if ack.len() > buf.len() {
            return Err(TransportError::ReadFailed);
        }
        buf[..ack.len()].copy_from_slice(&ack);
        Ok(ack.len())
    }
}
