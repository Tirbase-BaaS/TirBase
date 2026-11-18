// SPDX-License-Identifier: AGPL-3.0-only

//! POS-10 — append-only invoice numbering.
//!
//! The register allocates monotonically increasing numbers and records either
//! an issued invoice or an explicit, reasoned gap. There is no "set next
//! number" and no rollback: a number handed out by [`InvoiceRegister::issue`]
//! can never be handed out again. A reprint calls
//! [`InvoiceRegister::mark_reprinted`] on the existing number and does not
//! allocate.
//!
//! Two gap policies are available:
//!
//! - [`InvoiceGapPolicy::Gapless`] rejects [`InvoiceRegister::record_gap`], so
//!   a deployment that cannot guarantee atomic document creation does not use
//!   it. This module does not pretend that an in-memory increment is durable.
//! - [`InvoiceGapPolicy::Documented`] consumes the number and records the
//!   required reason, timestamp and number. The ledger audit rejects holes
//!   that have no matching gap record.
//!
//! [`InvoiceRegister::from_ledger`] restores a persisted ledger and derives the
//! next sequence from it, rejecting duplicates, overlapping issued/gap entries
//! and undocumented holes. That makes restart/replay safe when the caller
//! actually persists the returned records atomically.

use std::collections::BTreeMap;

use crate::audit::Timestamp;
use crate::error::PosError;
use crate::ids::validate_identifier;

/// Maximum supported sequence digits.
pub const MAX_INVOICE_WIDTH: u8 = 18;

/// A series prefix such as `TILL1`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvoiceSeries(String);

impl InvoiceSeries {
    /// Construct a series. It uses the same identifier rules as other POS ids.
    pub fn new(series: impl Into<String>) -> Result<Self, InvoiceError> {
        let series = series.into();
        validate_identifier(&series, "invoice series").map_err(|_| InvoiceError::InvalidSeries)?;
        Ok(Self(series))
    }

    /// The series text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A formatted invoice number.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvoiceNumber {
    series: InvoiceSeries,
    sequence: u64,
    width: u8,
}

impl InvoiceNumber {
    fn new(series: &InvoiceSeries, sequence: u64, width: u8) -> Self {
        Self {
            series: series.clone(),
            sequence,
            width,
        }
    }

    /// The series prefix.
    pub fn series(&self) -> &InvoiceSeries {
        &self.series
    }

    /// The numeric sequence, starting at the register's configured start.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The zero-padding width for the sequence.
    pub fn width(&self) -> u8 {
        self.width
    }
}

impl std::fmt::Display for InvoiceNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-{:0width$}",
            self.series.as_str(),
            self.sequence,
            width = usize::from(self.width)
        )
    }
}

/// What to do when a number cannot become an invoice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvoiceGapPolicy {
    /// Do not allow gaps at all; refuse to consume a number without issuing it.
    Gapless,
    /// Consume the number and record an explicit reason.
    Documented,
}

/// One successfully issued invoice number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedInvoice {
    number: InvoiceNumber,
    issued_at: Timestamp,
}

impl IssuedInvoice {
    /// The allocated number.
    pub fn number(&self) -> &InvoiceNumber {
        &self.number
    }

    /// When the invoice was issued.
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
}

/// One explicitly abandoned number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceGap {
    number: InvoiceNumber,
    recorded_at: Timestamp,
    reason: String,
}

impl InvoiceGap {
    /// The consumed number. It must not be used for an invoice.
    pub fn number(&self) -> &InvoiceNumber {
        &self.number
    }

    /// When the gap was recorded.
    pub fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// The operator-visible reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// An append-only invoice-number ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceRegister {
    series: InvoiceSeries,
    policy: InvoiceGapPolicy,
    width: u8,
    start_sequence: u64,
    next_sequence: u64,
    issued: Vec<IssuedInvoice>,
    gaps: Vec<InvoiceGap>,
    reprints: BTreeMap<InvoiceNumber, u64>,
}

impl InvoiceRegister {
    /// Create an empty register. `start_sequence` is the first number that may
    /// be issued; it is normally 1.
    pub fn new(
        series: InvoiceSeries,
        policy: InvoiceGapPolicy,
        width: u8,
        start_sequence: u64,
    ) -> Result<Self, InvoiceError> {
        validate_width(width)?;
        if start_sequence == 0 || start_sequence > max_sequence(width) {
            return Err(InvoiceError::InvalidStart);
        }
        Ok(Self {
            series,
            policy,
            width,
            start_sequence,
            next_sequence: start_sequence,
            issued: Vec::new(),
            gaps: Vec::new(),
            reprints: BTreeMap::new(),
        })
    }

    /// Restore a persisted ledger.
    ///
    /// The next sequence is derived, not supplied. Duplicate issued numbers,
    /// an issued number that also has a gap, numbers outside the configured
    /// series/width, and holes without a gap record are rejected.
    pub fn from_ledger(
        series: InvoiceSeries,
        policy: InvoiceGapPolicy,
        width: u8,
        start_sequence: u64,
        mut issued: Vec<IssuedInvoice>,
        mut gaps: Vec<InvoiceGap>,
    ) -> Result<Self, InvoiceError> {
        validate_width(width)?;
        if start_sequence == 0 || start_sequence > max_sequence(width) {
            return Err(InvoiceError::InvalidStart);
        }
        issued.sort_by_key(|entry| entry.number.sequence);
        gaps.sort_by_key(|entry| entry.number.sequence);

        let mut states: BTreeMap<u64, bool> = BTreeMap::new();
        for entry in &issued {
            validate_number(&entry.number, &series, width, start_sequence)?;
            if states.insert(entry.number.sequence, true).is_some() {
                return Err(InvoiceError::DuplicateNumber(entry.number.clone()));
            }
        }
        for entry in &gaps {
            validate_number(&entry.number, &series, width, start_sequence)?;
            if entry.reason.is_empty()
                || entry.reason.len() > 256
                || entry.reason.chars().any(char::is_control)
            {
                return Err(InvoiceError::InvalidGapReason);
            }
            if states.insert(entry.number.sequence, false).is_some() {
                return Err(InvoiceError::DuplicateNumber(entry.number.clone()));
            }
        }
        if policy == InvoiceGapPolicy::Gapless && !gaps.is_empty() {
            return Err(InvoiceError::GapNotAllowed);
        }

        // Walk the sorted keys rather than every sequence in the range: a
        // ledger with a valid but very large number must not turn restore into
        // an enormous loop.
        let mut next_sequence = start_sequence;
        for sequence in states.keys() {
            if *sequence != next_sequence {
                return Err(InvoiceError::UndocumentedGap(next_sequence));
            }
            next_sequence = sequence
                .checked_add(1)
                .ok_or(InvoiceError::SequenceExhausted)?;
        }

        let mut register = Self::new(series, policy, width, start_sequence)?;
        register.issued = issued;
        register.gaps = gaps;
        register.next_sequence = next_sequence;
        Ok(register)
    }

    /// The series prefix.
    pub fn series(&self) -> &InvoiceSeries {
        &self.series
    }

    /// The configured gap policy.
    pub fn policy(&self) -> InvoiceGapPolicy {
        self.policy
    }

    /// The zero-padding width.
    pub fn width(&self) -> u8 {
        self.width
    }

    /// The first sequence this register may ever issue.
    pub fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    /// The next sequence that will be issued or abandoned.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// All issued invoices, in issue order.
    pub fn issued(&self) -> &[IssuedInvoice] {
        &self.issued
    }

    /// All documented gaps, in recording order.
    pub fn gaps(&self) -> &[InvoiceGap] {
        &self.gaps
    }

    /// `true` when `number` was issued by this ledger.
    pub fn was_issued(&self, number: &InvoiceNumber) -> bool {
        self.issued.iter().any(|entry| &entry.number == number)
    }

    /// Allocate an invoice number and append it to the issued ledger.
    pub fn issue(&mut self, issued_at: Timestamp) -> Result<InvoiceNumber, InvoiceError> {
        let number = self.take_next()?;
        self.issued.push(IssuedInvoice {
            number: number.clone(),
            issued_at,
        });
        Ok(number)
    }

    /// Abandon the next number and record why. Under
    /// [`InvoiceGapPolicy::Gapless`] this consumes nothing and returns
    /// [`InvoiceError::GapNotAllowed`].
    pub fn record_gap(
        &mut self,
        recorded_at: Timestamp,
        reason: impl Into<String>,
    ) -> Result<InvoiceGap, InvoiceError> {
        if self.policy == InvoiceGapPolicy::Gapless {
            return Err(InvoiceError::GapNotAllowed);
        }
        let reason = reason.into();
        if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
            return Err(InvoiceError::InvalidGapReason);
        }
        let number = self.take_next()?;
        let gap = InvoiceGap {
            number,
            recorded_at,
            reason,
        };
        self.gaps.push(gap.clone());
        Ok(gap)
    }

    /// Record a reprint of an existing invoice and return that invoice's
    /// reprint count. This never allocates a new number and rejects a number
    /// that is not in the issued ledger.
    pub fn mark_reprinted(&mut self, number: &InvoiceNumber) -> Result<u64, InvoiceError> {
        if !self.was_issued(number) {
            return Err(InvoiceError::UnknownInvoice(number.clone()));
        }
        let count = self.reprints.entry(number.clone()).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or(InvoiceError::SequenceExhausted)?;
        Ok(*count)
    }

    /// Number of times `number` has been marked reprinted.
    pub fn reprint_count(&self, number: &InvoiceNumber) -> u64 {
        self.reprints.get(number).copied().unwrap_or(0)
    }

    fn take_next(&mut self) -> Result<InvoiceNumber, InvoiceError> {
        if self.next_sequence > max_sequence(self.width) {
            return Err(InvoiceError::SequenceExhausted);
        }
        let number = InvoiceNumber::new(&self.series, self.next_sequence, self.width);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(InvoiceError::SequenceExhausted)?;
        Ok(number)
    }
}

fn validate_width(width: u8) -> Result<(), InvoiceError> {
    if !(1..=MAX_INVOICE_WIDTH).contains(&width) {
        return Err(InvoiceError::InvalidWidth);
    }
    Ok(())
}

fn max_sequence(width: u8) -> u64 {
    10_u64.pow(u32::from(width)) - 1
}

fn validate_number(
    number: &InvoiceNumber,
    series: &InvoiceSeries,
    width: u8,
    start_sequence: u64,
) -> Result<(), InvoiceError> {
    if &number.series != series || number.width != width {
        return Err(InvoiceError::LedgerSeriesMismatch);
    }
    if number.sequence < start_sequence || number.sequence > max_sequence(width) {
        return Err(InvoiceError::InvalidStart);
    }
    Ok(())
}

/// A rejected numbering operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvoiceError {
    /// The invoice series was empty or malformed.
    InvalidSeries,
    /// The width was outside 1 through [`MAX_INVOICE_WIDTH`].
    InvalidWidth,
    /// The start sequence was zero or outside the width's range.
    InvalidStart,
    /// The sequence range is exhausted.
    SequenceExhausted,
    /// A gap had no reason or an unsafe reason.
    InvalidGapReason,
    /// A gapless register was asked to create a gap.
    GapNotAllowed,
    /// A reprint referenced an invoice that was never issued.
    UnknownInvoice(InvoiceNumber),
    /// A restored ledger contained the same number twice.
    DuplicateNumber(InvoiceNumber),
    /// A restored ledger had a number for a different series or width.
    LedgerSeriesMismatch,
    /// A restored ledger skipped a sequence without a gap record.
    UndocumentedGap(u64),
}

impl InvoiceError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            InvoiceError::InvalidSeries => "numbering.invalid_series",
            InvoiceError::InvalidWidth => "numbering.invalid_width",
            InvoiceError::InvalidStart => "numbering.invalid_start",
            InvoiceError::SequenceExhausted => "numbering.sequence_exhausted",
            InvoiceError::InvalidGapReason => "numbering.invalid_gap_reason",
            InvoiceError::GapNotAllowed => "numbering.gap_not_allowed",
            InvoiceError::UnknownInvoice(_) => "numbering.unknown_invoice",
            InvoiceError::DuplicateNumber(_) => "numbering.duplicate_number",
            InvoiceError::LedgerSeriesMismatch => "numbering.ledger_series_mismatch",
            InvoiceError::UndocumentedGap(_) => "numbering.undocumented_gap",
        }
    }
}

impl From<PosError> for InvoiceError {
    fn from(_: PosError) -> Self {
        InvoiceError::InvalidSeries
    }
}

impl std::fmt::Display for InvoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvoiceError::InvalidSeries => f.write_str("invalid invoice series"),
            InvoiceError::InvalidWidth => f.write_str("invalid invoice number width"),
            InvoiceError::InvalidStart => f.write_str("invalid invoice start sequence"),
            InvoiceError::SequenceExhausted => f.write_str("invoice sequence exhausted"),
            InvoiceError::InvalidGapReason => f.write_str("invalid invoice gap reason"),
            InvoiceError::GapNotAllowed => f.write_str("gapless policy does not allow a gap"),
            InvoiceError::UnknownInvoice(number) => write!(f, "unknown invoice: {number}"),
            InvoiceError::DuplicateNumber(number) => {
                write!(f, "duplicate invoice number: {number}")
            }
            InvoiceError::LedgerSeriesMismatch => {
                f.write_str("invoice ledger series or width mismatch")
            }
            InvoiceError::UndocumentedGap(sequence) => {
                write!(f, "undocumented invoice gap at sequence {sequence}")
            }
        }
    }
}

impl std::error::Error for InvoiceError {}
