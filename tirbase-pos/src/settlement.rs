// SPDX-License-Identifier: AGPL-3.0-only

//! POS-12 — settlement batches, processor reconciliation and chargebacks.
//!
//! POS-03 records what the POS *intended* to charge. This module records what a
//! processor says it *did*, compares the two, and keeps every disagreement in a
//! durable exception queue instead of dropping it.
//!
//! # Batches
//!
//! A [`SettlementBatch`] is identified by processor, terminal and settlement
//! day. [`SettlementBook::ingest`] merges a [`ProcessorBatchFile`] into that
//! batch, so a continuation file for the same day appends records instead of
//! creating a second batch. A closed batch accepts nothing more.
//!
//! ```text
//! net = captures − refunds − chargebacks + chargeback_reversals
//! ```
//!
//! Adjustments and tips are reported separately and are never netted into
//! `net`, so a processor fee cannot silently change a captured total.
//!
//! # Reconciliation
//!
//! [`SettlementBook::reconcile`] walks every intent the POS captured and
//! decides, for each one, whether the processor records agree:
//!
//! | Processor records for one captured intent | Result |
//! |---|---|
//! | exactly one capture equal to the captured amount | reconciled |
//! | none | `MissingRecord` |
//! | more than one capture | `DuplicateRecord` |
//! | one capture below the captured amount | `PartialSettlement` |
//! | one capture above the captured amount | `OverSettlement` |
//! | refund records disagree with the intent | `RefundMismatch` |
//! | different currency | `CurrencyMismatch` |
//!
//! Everything else — a record naming an intent the POS never captured, a record
//! with no intent that is not an adjustment, a repeated record identifier — also
//! becomes an exception. An intent is therefore *either* in
//! [`SettlementReconciliation::reconciled`] *or* in
//! [`SettlementReconciliation::exceptions`]; there is no third outcome and no
//! silent drop.
//!
//! # Exception queue
//!
//! [`ExceptionQueue`] is keyed by a deterministic [`ExceptionKey`] built from the
//! category, intent and record. Raising the same problem twice is a no-op, so
//! re-running reconciliation does not multiply entries, and resolving an entry
//! is recorded with an operator, a time and an optional note. Resolving is an
//! explicit act: reconciliation never clears a queue entry by itself.
//!
//! # Chargebacks
//!
//! A [`Chargeback`] moves through `Opened → UnderReview → Lost → Paid`, or
//! `Opened`/`UnderReview` → `Won` when the issuer reverses it. Evidence links
//! are attached while the case is still being worked, a case can only be won
//! with evidence, and only a lost case can be paid. Once paid the case is
//! terminal and a second payment is refused with
//! [`SettlementError::ChargebackAlreadyPaid`] rather than treated as a replay,
//! so one chargeback can never be debited twice.

use std::collections::BTreeMap;

use crate::audit::Timestamp;
use crate::error::PosError;
use crate::guard::MILLIS_PER_DAY;
use crate::ids::{
    validate_identifier, ChargebackId, CheckId, EmployeeId, PaymentIntentId, ProcessorRecordId,
    SettlementBatchId, StoreId, TerminalId,
};
use crate::intent::PaymentIntentStore;
use crate::money::{Currency, Money};
use crate::staff::{Permission, StaffSession};

/// Maximum records accepted in one processor batch file.
pub const MAX_BATCH_RECORDS: usize = 5_000;

/// Maximum evidence links attached to one chargeback.
pub const MAX_CHARGEBACK_EVIDENCE: usize = 64;

/// Maximum length of a chargeback reason or an evidence note, in bytes.
pub const MAX_SETTLEMENT_TEXT_LEN: usize = 256;

/// The acquiring processor a batch belongs to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Processor(String);

impl Processor {
    /// Construct a processor identity. Empty, oversized or control-bearing
    /// names are rejected.
    pub fn new(name: impl Into<String>) -> Result<Self, SettlementError> {
        let name = name.into();
        validate_identifier(&name, "processor").map_err(|_| SettlementError::InvalidProcessor)?;
        Ok(Self(name))
    }

    /// The processor name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Processor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One calendar day used to group settlement batches.
///
/// A day is a civil date (`YYYY-MM-DD`), not a time zone or a business-day
/// cut-off. The crate has no jurisdiction default and no local-time rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettlementDay {
    year: i32,
    month: u8,
    day: u8,
    index: i64,
}

impl SettlementDay {
    /// Parse an ISO `YYYY-MM-DD` date.
    pub fn parse(text: &str) -> Result<Self, SettlementError> {
        parse_day(text.trim()).ok_or(SettlementError::InvalidSettlementDay)
    }

    /// The UTC day containing `at`.
    pub fn from_timestamp(at: Timestamp) -> Self {
        Self::from_index(at.millis().div_euclid(MILLIS_PER_DAY))
    }

    /// The day with a given index since the Unix epoch.
    pub fn from_index(index: i64) -> Self {
        let (year, month, day) = civil_from_days(index);
        Self {
            year,
            month,
            day,
            index,
        }
    }

    /// The day index since 1970-01-01.
    pub fn index(self) -> i64 {
        self.index
    }

    /// The civil year.
    pub fn year(self) -> i32 {
        self.year
    }

    /// The civil month, `1..=12`.
    pub fn month(self) -> u8 {
        self.month
    }

    /// The civil day of month, `1..=31`.
    pub fn day(self) -> u8 {
        self.day
    }
}

impl std::fmt::Display for SettlementDay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl PartialOrd for SettlementDay {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SettlementDay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

fn parse_day(text: &str) -> Option<SettlementDay> {
    let mut parts = text.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some(SettlementDay {
        year,
        month,
        day,
        index: days_from_civil(year, month, day),
    })
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

// Howard Hinnant's civil-date conversions. Both are exact integer arithmetic
// with no time-zone or leap-second input.
fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let year = i64::from(if month <= 2 { year - 1 } else { year });
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(index: i64) -> (i32, u8, u8) {
    let shifted = index + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (
        (if month <= 2 { year + 1 } else { year }) as i32,
        month as u8,
        day as u8,
    )
}

/// What one processor record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessorRecordKind {
    /// The processor captured money for an intent.
    Capture,
    /// The processor refunded a captured intent.
    Refund,
    /// The processor debited a captured intent after a chargeback.
    Chargeback,
    /// The processor reversed a chargeback it had previously debited.
    ChargebackReversal,
    /// A processor fee or a tip adjustment that changes no captured total.
    Adjustment,
}

impl ProcessorRecordKind {
    /// Parse the wire label used by processor files.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "capture" => ProcessorRecordKind::Capture,
            "refund" => ProcessorRecordKind::Refund,
            "chargeback" => ProcessorRecordKind::Chargeback,
            "chargeback_reversal" => ProcessorRecordKind::ChargebackReversal,
            "adjustment" => ProcessorRecordKind::Adjustment,
            _ => return None,
        })
    }

    /// Stable label for files, logs and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            ProcessorRecordKind::Capture => "capture",
            ProcessorRecordKind::Refund => "refund",
            ProcessorRecordKind::Chargeback => "chargeback",
            ProcessorRecordKind::ChargebackReversal => "chargeback_reversal",
            ProcessorRecordKind::Adjustment => "adjustment",
        }
    }

    /// `true` when the record moves money back to the merchant.
    pub fn is_credit(self) -> bool {
        matches!(
            self,
            ProcessorRecordKind::Refund
                | ProcessorRecordKind::Chargeback
                | ProcessorRecordKind::Adjustment
        )
    }
}

impl std::fmt::Display for ProcessorRecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One line of a processor settlement file.
///
/// `amount` and `tip` are non-negative magnitudes in the batch currency. A tip
/// is the portion of `amount` the processor reports as a tip, so it can never
/// exceed the amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessorRecord {
    id: ProcessorRecordId,
    intent: Option<PaymentIntentId>,
    kind: ProcessorRecordKind,
    amount: Money,
    tip: Money,
    at: Timestamp,
}

impl ProcessorRecord {
    /// Build one record. Amounts are validated by
    /// [`ProcessorRecord::validate`] and again on ingest.
    pub fn new(
        id: ProcessorRecordId,
        intent: Option<PaymentIntentId>,
        kind: ProcessorRecordKind,
        amount: Money,
        tip: Money,
        at: Timestamp,
    ) -> Result<Self, SettlementError> {
        let record = Self {
            id,
            intent,
            kind,
            amount,
            tip,
            at,
        };
        record.validate()?;
        Ok(record)
    }

    /// Reject a negative amount, a mixed currency or a tip above the amount.
    pub fn validate(&self) -> Result<(), SettlementError> {
        if self.amount.is_negative() || self.tip.is_negative() {
            return Err(SettlementError::NegativeAmount);
        }
        if self.amount.currency() != self.tip.currency() {
            return Err(SettlementError::CurrencyMismatch);
        }
        if self.tip > self.amount {
            return Err(SettlementError::TipExceedsAmount);
        }
        Ok(())
    }

    /// The processor's record reference.
    pub fn id(&self) -> &ProcessorRecordId {
        &self.id
    }

    /// The POS intent this record settles, if it names one.
    pub fn intent(&self) -> Option<&PaymentIntentId> {
        self.intent.as_ref()
    }

    /// What the record did.
    pub fn kind(&self) -> ProcessorRecordKind {
        self.kind
    }

    /// The processed amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The tip portion of the amount.
    pub fn tip(&self) -> Money {
        self.tip
    }

    /// The processor's event time.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}

/// One processor settlement file: a batch header plus its records.
///
/// # Format
///
/// Line-oriented CSV. Blank lines and lines starting with `#` are ignored.
/// Field values are trimmed and must not contain a comma.
///
/// ```text
/// batch,<batch-id>,<processor>,<terminal>,<YYYY-MM-DD>,<CUR>
/// capture,<record-id>,<intent-id>,<amount-minor>,<tip-minor>,<unix-millis>
/// refund,<record-id>,<intent-id>,<amount-minor>,<tip-minor>,<unix-millis>
/// chargeback,<record-id>,<intent-id>,<amount-minor>,<tip-minor>,<unix-millis>
/// chargeback_reversal,<record-id>,<intent-id>,<amount-minor>,<tip-minor>,<unix-millis>
/// adjustment,<record-id>,-,<amount-minor>,<tip-minor>,<unix-millis>
/// ```
///
/// A record may use `-` instead of an intent identifier for a processor event
/// that names none; only an adjustment is meaningful without one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessorBatchFile {
    id: SettlementBatchId,
    processor: Processor,
    terminal_id: TerminalId,
    day: SettlementDay,
    currency: Currency,
    records: Vec<ProcessorRecord>,
}

impl ProcessorBatchFile {
    /// Parse a processor file.
    ///
    /// Every line is validated; the first malformed line is reported with its
    /// 1-based line number. A file without a header, or a record before the
    /// header, is rejected.
    pub fn parse(input: &str) -> Result<Self, SettlementError> {
        let mut header: Option<(
            SettlementBatchId,
            Processor,
            TerminalId,
            SettlementDay,
            Currency,
        )> = None;
        let mut records: Vec<ProcessorRecord> = Vec::new();

        for (index, raw) in input.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = trimmed.split(',').map(str::trim).collect();
            match fields[0] {
                "batch" => {
                    if header.is_some() {
                        return Err(malformed(line, "duplicate batch header"));
                    }
                    if fields.len() != 6 {
                        return Err(malformed(
                            line,
                            "batch header needs batch,id,processor,terminal,day,currency",
                        ));
                    }
                    let id = SettlementBatchId::new(fields[1])
                        .map_err(|_| malformed(line, "invalid batch id"))?;
                    let processor = Processor::new(fields[2])
                        .map_err(|_| malformed(line, "invalid processor"))?;
                    let terminal_id = TerminalId::new(fields[3])
                        .map_err(|_| malformed(line, "invalid terminal id"))?;
                    let day = parse_day(fields[4])
                        .ok_or_else(|| malformed(line, "invalid settlement day"))?;
                    let currency = Currency::from_code(fields[5])
                        .map_err(|_| malformed(line, "unknown currency"))?;
                    header = Some((id, processor, terminal_id, day, currency));
                }
                kind => {
                    let Some((_, _, _, _, currency)) = header.as_ref() else {
                        return Err(malformed(line, "record before the batch header"));
                    };
                    let kind = ProcessorRecordKind::parse(kind)
                        .ok_or_else(|| malformed(line, "unknown record kind"))?;
                    if fields.len() != 6 {
                        return Err(malformed(line, "record needs kind,id,intent,amount,tip,at"));
                    }
                    let id = ProcessorRecordId::new(fields[1])
                        .map_err(|_| malformed(line, "invalid record id"))?;
                    let intent = if fields[2] == "-" || fields[2].is_empty() {
                        None
                    } else {
                        Some(
                            PaymentIntentId::new(fields[2])
                                .map_err(|_| malformed(line, "invalid intent id"))?,
                        )
                    };
                    let amount =
                        parse_minor(fields[3]).ok_or_else(|| malformed(line, "invalid amount"))?;
                    let tip =
                        parse_minor(fields[4]).ok_or_else(|| malformed(line, "invalid tip"))?;
                    let at = fields[5]
                        .parse::<i64>()
                        .map_err(|_| malformed(line, "invalid timestamp"))?;
                    let record = ProcessorRecord {
                        id,
                        intent,
                        kind,
                        amount: Money::new(*currency, amount),
                        tip: Money::new(*currency, tip),
                        at: Timestamp::from_millis(at),
                    };
                    record
                        .validate()
                        .map_err(|_| malformed(line, "inconsistent record amounts"))?;
                    if records.len() >= MAX_BATCH_RECORDS {
                        return Err(malformed(line, "batch file exceeds the record limit"));
                    }
                    records.push(record);
                }
            }
        }

        let Some((id, processor, terminal_id, day, currency)) = header else {
            return Err(malformed(1, "missing batch header"));
        };
        Ok(Self {
            id,
            processor,
            terminal_id,
            day,
            currency,
            records,
        })
    }

    /// Build a file from records that are already parsed.
    pub fn from_records(
        id: SettlementBatchId,
        processor: Processor,
        terminal_id: TerminalId,
        day: SettlementDay,
        currency: Currency,
        records: Vec<ProcessorRecord>,
    ) -> Result<Self, SettlementError> {
        if records.len() > MAX_BATCH_RECORDS {
            return Err(SettlementError::BatchTooLarge);
        }
        for record in &records {
            record.validate()?;
            if record.amount.currency() != currency {
                return Err(SettlementError::CurrencyMismatch);
            }
        }
        Ok(Self {
            id,
            processor,
            terminal_id,
            day,
            currency,
            records,
        })
    }

    /// The batch identifier the file claims.
    pub fn id(&self) -> &SettlementBatchId {
        &self.id
    }

    /// The processor the file came from.
    pub fn processor(&self) -> &Processor {
        &self.processor
    }

    /// The terminal the file settles.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The settlement day.
    pub fn day(&self) -> SettlementDay {
        self.day
    }

    /// The batch currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The records, in file order.
    pub fn records(&self) -> &[ProcessorRecord] {
        &self.records
    }
}

fn parse_minor(text: &str) -> Option<i64> {
    let value = text.parse::<i64>().ok()?;
    if value < 0 {
        None
    } else {
        Some(value)
    }
}

fn malformed(line: usize, reason: &'static str) -> SettlementError {
    SettlementError::MalformedFile { line, reason }
}

/// Whether a batch still accepts records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BatchStatus {
    /// Records may still be ingested.
    Open,
    /// The batch was closed; nothing more can be ingested.
    Closed,
}

/// The totals of one settlement batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchTotals {
    /// The batch currency.
    pub currency: Currency,
    /// Number of records in the batch.
    pub record_count: u64,
    /// Number of capture records.
    pub capture_count: u64,
    /// Sum of captured amounts.
    pub captured: Money,
    /// Sum of refunded amounts.
    pub refunded: Money,
    /// Sum of chargeback debits.
    pub chargebacks: Money,
    /// Sum of chargeback reversals.
    pub reversals: Money,
    /// Sum of adjustments (fees and corrections).
    pub adjustments: Money,
    /// Sum of tips reported on capture records.
    pub tips: Money,
}

impl BatchTotals {
    /// `captured − refunded − chargebacks + reversals`.
    pub fn net(&self) -> Result<Money, PosError> {
        self.captured
            .checked_sub(self.refunded)?
            .checked_sub(self.chargebacks)?
            .checked_add(self.reversals)
    }
}

/// One settlement batch: a processor, a terminal and one day.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementBatch {
    id: SettlementBatchId,
    key: SettlementKey,
    currency: Currency,
    status: BatchStatus,
    records: BTreeMap<ProcessorRecordId, ProcessorRecord>,
    closed_at: Option<Timestamp>,
}

impl SettlementBatch {
    fn new(id: SettlementBatchId, key: SettlementKey, currency: Currency) -> Self {
        Self {
            id,
            key,
            currency,
            status: BatchStatus::Open,
            records: BTreeMap::new(),
            closed_at: None,
        }
    }

    /// The batch identifier taken from the processor file.
    pub fn id(&self) -> &SettlementBatchId {
        &self.id
    }

    /// The processor, terminal and day this batch settles.
    pub fn key(&self) -> &SettlementKey {
        &self.key
    }

    /// The processor.
    pub fn processor(&self) -> &Processor {
        self.key.processor()
    }

    /// The terminal.
    pub fn terminal_id(&self) -> &TerminalId {
        self.key.terminal_id()
    }

    /// The settlement day.
    pub fn day(&self) -> SettlementDay {
        self.key.day()
    }

    /// The batch currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The batch status.
    pub fn status(&self) -> BatchStatus {
        self.status
    }

    /// `true` while the batch accepts records.
    pub fn is_open(&self) -> bool {
        self.status == BatchStatus::Open
    }

    /// `true` once the batch is closed.
    pub fn is_closed(&self) -> bool {
        self.status == BatchStatus::Closed
    }

    /// When the batch was closed.
    pub fn closed_at(&self) -> Option<Timestamp> {
        self.closed_at
    }

    /// Number of records in the batch.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` when the batch holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// One record by identifier.
    pub fn record(&self, id: &ProcessorRecordId) -> Option<&ProcessorRecord> {
        self.records.get(id)
    }

    /// Every record, in identifier order.
    pub fn records(&self) -> impl Iterator<Item = &ProcessorRecord> {
        self.records.values()
    }

    /// The batch totals.
    pub fn totals(&self) -> Result<BatchTotals, SettlementError> {
        let zero = Money::zero(self.currency);
        let mut captured = zero;
        let mut refunded = zero;
        let mut chargebacks = zero;
        let mut reversals = zero;
        let mut adjustments = zero;
        let mut tips = zero;
        let mut capture_count = 0_u64;
        for record in self.records.values() {
            match record.kind {
                ProcessorRecordKind::Capture => {
                    captured = captured.checked_add(record.amount)?;
                    tips = tips.checked_add(record.tip)?;
                    capture_count += 1;
                }
                ProcessorRecordKind::Refund => refunded = refunded.checked_add(record.amount)?,
                ProcessorRecordKind::Chargeback => {
                    chargebacks = chargebacks.checked_add(record.amount)?
                }
                ProcessorRecordKind::ChargebackReversal => {
                    reversals = reversals.checked_add(record.amount)?
                }
                ProcessorRecordKind::Adjustment => {
                    adjustments = adjustments.checked_add(record.amount)?
                }
            }
        }
        Ok(BatchTotals {
            currency: self.currency,
            record_count: self.records.len() as u64,
            capture_count,
            captured,
            refunded,
            chargebacks,
            reversals,
            adjustments,
            tips,
        })
    }

    /// Close the batch. A second close is refused.
    pub fn close(&mut self, at: Timestamp) -> Result<(), SettlementError> {
        if self.status == BatchStatus::Closed {
            return Err(SettlementError::BatchClosed(self.key.clone()));
        }
        self.status = BatchStatus::Closed;
        self.closed_at = Some(at);
        Ok(())
    }
}

/// The identity of a settlement batch: processor, terminal and day.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettlementKey {
    processor: Processor,
    terminal_id: TerminalId,
    day: SettlementDay,
}

impl SettlementKey {
    /// Build a batch key.
    pub fn new(processor: Processor, terminal_id: TerminalId, day: SettlementDay) -> Self {
        Self {
            processor,
            terminal_id,
            day,
        }
    }

    /// The processor.
    pub fn processor(&self) -> &Processor {
        &self.processor
    }

    /// The terminal.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The settlement day.
    pub fn day(&self) -> SettlementDay {
        self.day
    }
}

impl std::fmt::Display for SettlementKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.processor.as_str(),
            self.terminal_id.as_str(),
            self.day
        )
    }
}

/// The result of ingesting one processor file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestOutcome {
    /// Records added to the batch.
    pub added: usize,
    /// Records already present with identical content.
    pub replayed: usize,
    /// Record identifiers repeated inside the file.
    pub duplicates: Vec<ProcessorRecordId>,
    /// Record identifiers already present with different content.
    pub conflicts: Vec<ProcessorRecordId>,
}

impl IngestOutcome {
    /// `true` when no record was duplicated or conflicting.
    pub fn is_clean(&self) -> bool {
        self.duplicates.is_empty() && self.conflicts.is_empty()
    }
}

/// Why one POS intent and the processor do not agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExceptionCategory {
    /// A captured intent has no processor capture.
    MissingRecord,
    /// A record identifier was repeated, or one intent has several captures.
    DuplicateRecord,
    /// The processor settled less than the intent.
    PartialSettlement,
    /// The processor settled more than the intent.
    OverSettlement,
    /// The processor event names an intent the POS never captured.
    UnmatchedRecord,
    /// One record identifier carried different content.
    RecordConflict,
    /// Refund records disagree with the intent's refund.
    RefundMismatch,
    /// Amounts use a different currency.
    CurrencyMismatch,
}

impl ExceptionCategory {
    /// Stable reason code for logs and policy.
    pub fn code(self) -> &'static str {
        match self {
            ExceptionCategory::MissingRecord => "settlement.missing_record",
            ExceptionCategory::DuplicateRecord => "settlement.duplicate_record",
            ExceptionCategory::PartialSettlement => "settlement.partial_settlement",
            ExceptionCategory::OverSettlement => "settlement.over_settlement",
            ExceptionCategory::UnmatchedRecord => "settlement.unmatched_record",
            ExceptionCategory::RecordConflict => "settlement.record_conflict",
            ExceptionCategory::RefundMismatch => "settlement.refund_mismatch",
            ExceptionCategory::CurrencyMismatch => "settlement.currency_mismatch",
        }
    }
}

impl std::fmt::Display for ExceptionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// The deterministic identity of an exception-queue entry.
///
/// Two reconciliation passes that find the same problem produce the same key, so
/// the queue holds one entry rather than a new one per pass.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExceptionKey {
    category: ExceptionCategory,
    intent: Option<PaymentIntentId>,
    record: Option<ProcessorRecordId>,
}

impl ExceptionKey {
    fn new(
        category: ExceptionCategory,
        intent: Option<PaymentIntentId>,
        record: Option<ProcessorRecordId>,
    ) -> Self {
        Self {
            category,
            intent,
            record,
        }
    }

    /// The problem category.
    pub fn category(&self) -> ExceptionCategory {
        self.category
    }

    /// The POS intent involved, if any.
    pub fn intent(&self) -> Option<&PaymentIntentId> {
        self.intent.as_ref()
    }

    /// The processor record involved, if any.
    pub fn record(&self) -> Option<&ProcessorRecordId> {
        self.record.as_ref()
    }
}

impl std::fmt::Display for ExceptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.category.code())?;
        if let Some(intent) = &self.intent {
            write!(f, " intent={intent}")?;
        }
        if let Some(record) = &self.record {
            write!(f, " record={record}")?;
        }
        Ok(())
    }
}

/// Whether an exception has been dealt with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExceptionState {
    /// Still needs an operator.
    Open,
    /// Resolved by an operator.
    Resolved {
        /// When it was resolved.
        at: Timestamp,
        /// Optional resolution note.
        note: Option<String>,
    },
}

impl ExceptionState {
    /// `true` while the entry is unresolved.
    pub fn is_open(&self) -> bool {
        matches!(self, ExceptionState::Open)
    }
}

/// One entry in the exception queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementException {
    /// The deterministic identity of this problem.
    pub key: ExceptionKey,
    /// What is wrong.
    pub category: ExceptionCategory,
    /// The POS intent involved, if any.
    pub intent: Option<PaymentIntentId>,
    /// The processor records involved, in identifier order.
    pub records: Vec<ProcessorRecordId>,
    /// The amount the POS expected, when one can be named.
    pub expected: Option<Money>,
    /// The amount the processor reported, when one can be named.
    pub actual: Option<Money>,
    /// When the entry was first queued.
    pub queued_at: Timestamp,
    /// Whether an operator has resolved it.
    pub state: ExceptionState,
}

impl SettlementException {
    fn new(
        category: ExceptionCategory,
        intent: Option<PaymentIntentId>,
        records: Vec<ProcessorRecordId>,
        expected: Option<Money>,
        actual: Option<Money>,
        at: Timestamp,
    ) -> Self {
        let key = ExceptionKey::new(category, intent.clone(), records.first().cloned());
        Self {
            key,
            category,
            intent,
            records,
            expected,
            actual,
            queued_at: at,
            state: ExceptionState::Open,
        }
    }

    /// `true` while the entry needs an operator.
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }
}

/// A queue of settlement problems that need an operator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExceptionQueue {
    entries: BTreeMap<ExceptionKey, SettlementException>,
}

impl ExceptionQueue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries, resolved or not.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the queue holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry unless its key is already present.
    ///
    /// Returns `true` when the entry was added, `false` when the queue already
    /// had it. An already-resolved entry is never reopened by a later pass.
    pub fn raise(&mut self, exception: SettlementException) -> bool {
        if self.entries.contains_key(&exception.key) {
            return false;
        }
        self.entries.insert(exception.key.clone(), exception);
        true
    }

    /// Look up one entry by key.
    pub fn get(&self, key: &ExceptionKey) -> Option<&SettlementException> {
        self.entries.get(key)
    }

    /// Every entry, in key order.
    pub fn entries(&self) -> impl Iterator<Item = &SettlementException> {
        self.entries.values()
    }

    /// Every unresolved entry, in key order.
    pub fn open(&self) -> impl Iterator<Item = &SettlementException> {
        self.entries.values().filter(|entry| entry.is_open())
    }

    /// Number of unresolved entries.
    pub fn open_len(&self) -> usize {
        self.open().count()
    }

    /// `true` when an entry with this key exists.
    pub fn contains(&self, key: &ExceptionKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Mark one entry resolved.
    ///
    /// A missing key is [`SettlementError::UnknownException`]; a second
    /// resolution is [`SettlementError::AlreadyResolved`].
    pub fn resolve(
        &mut self,
        key: &ExceptionKey,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<(), SettlementError> {
        let note = validate_note(note)?;
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| SettlementError::UnknownException(key.clone()))?;
        if !entry.is_open() {
            return Err(SettlementError::AlreadyResolved(key.clone()));
        }
        entry.state = ExceptionState::Resolved { at, note };
        Ok(())
    }
}

/// One captured intent that agrees with the processor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementMatch {
    /// The POS intent.
    pub intent: PaymentIntentId,
    /// The check the intent paid.
    pub check_id: CheckId,
    /// The terminal that made the request.
    pub terminal_id: TerminalId,
    /// The intent currency.
    pub currency: Currency,
    /// The amount the POS captured.
    pub captured: Money,
    /// The amount the processor settled.
    pub settled: Money,
    /// Refund records attached to the intent.
    pub refunded: Money,
    /// Chargeback records attached to the intent.
    pub chargebacks: Money,
    /// The tip the processor reported on the capture.
    pub tip: Money,
    /// The capture record that settled the intent.
    pub records: Vec<ProcessorRecordId>,
}

/// The outcome of one reconciliation pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettlementReconciliation {
    /// Captured intents the processor agrees with, in intent order.
    pub reconciled: Vec<SettlementMatch>,
    /// Problems found in this pass, in key order.
    pub exceptions: Vec<SettlementException>,
}

impl SettlementReconciliation {
    /// `true` when every captured intent reconciled.
    pub fn is_clean(&self) -> bool {
        self.exceptions.is_empty()
    }

    /// The match for one intent, if it reconciled.
    pub fn match_for(&self, intent: &PaymentIntentId) -> Option<&SettlementMatch> {
        self.reconciled.iter().find(|entry| &entry.intent == intent)
    }

    /// The exception recorded for one intent, if any.
    pub fn exception_for(&self, intent: &PaymentIntentId) -> Option<&SettlementException> {
        self.exceptions
            .iter()
            .find(|entry| entry.intent.as_ref() == Some(intent))
    }

    /// `true` when the intent either reconciled or has a queued exception.
    pub fn accounts_for(&self, intent: &PaymentIntentId) -> bool {
        self.match_for(intent).is_some() || self.exception_for(intent).is_some()
    }
}

/// A rejected settlement or chargeback operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementError {
    /// The processor name was empty, oversized or control-bearing.
    InvalidProcessor,
    /// The evidence reference was empty, oversized or control-bearing.
    InvalidEvidenceRef,
    /// A chargeback reason or note was empty, oversized or control-bearing.
    InvalidNote,
    /// The settlement day is not an ISO `YYYY-MM-DD` date.
    InvalidSettlementDay,
    /// A processor file line could not be parsed.
    MalformedFile {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        reason: &'static str,
    },
    /// The file carries more records than [`MAX_BATCH_RECORDS`].
    BatchTooLarge,
    /// An amount was negative.
    NegativeAmount,
    /// A processor-reported tip was larger than the amount it belongs to.
    TipExceedsAmount,
    /// Two amounts use different currencies.
    CurrencyMismatch,
    /// The batch is closed and accepts no more records.
    BatchClosed(SettlementKey),
    /// No batch exists for this key.
    UnknownBatch(SettlementKey),
    /// The file names a different batch identifier than the open batch.
    BatchIdConflict {
        /// The identifier already in use.
        expected: SettlementBatchId,
        /// The identifier the file claims.
        actual: SettlementBatchId,
    },
    /// A record identifier was repeated with different content.
    RecordConflict(ProcessorRecordId),
    /// The session belongs to a different store.
    StoreMismatch,
    /// The session lacks the required permission.
    NotPermitted(Permission),
    /// No exception with this key exists.
    UnknownException(ExceptionKey),
    /// The exception was already resolved.
    AlreadyResolved(ExceptionKey),
    /// No chargeback with this identifier exists.
    UnknownChargeback(ChargebackId),
    /// The chargeback identifier is already used by a different case.
    DuplicateChargeback(ChargebackId),
    /// The chargeback was already paid; it cannot be paid twice.
    ChargebackAlreadyPaid(ChargebackId),
    /// The chargeback was won and is not a debit.
    ChargebackAlreadyWon(ChargebackId),
    /// The chargeback has not been lost, so there is nothing to pay.
    ChargebackNotLost(ChargebackId),
    /// A case cannot be won without attached evidence.
    EvidenceRequired(ChargebackId),
    /// The evidence reference is already attached to the case.
    DuplicateEvidence(ChargebackId),
    /// The case is closed and accepts no more evidence.
    ChargebackClosed(ChargebackId),
    /// The state machine does not allow this transition.
    InvalidChargebackTransition {
        /// State before the attempted transition.
        from: ChargebackState,
        /// State after the attempted transition.
        to: ChargebackState,
    },
    /// Money arithmetic failed.
    Pos(PosError),
}

impl SettlementError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            SettlementError::InvalidProcessor => "settlement.invalid_processor",
            SettlementError::InvalidEvidenceRef => "settlement.invalid_evidence_ref",
            SettlementError::InvalidNote => "settlement.invalid_note",
            SettlementError::InvalidSettlementDay => "settlement.invalid_day",
            SettlementError::MalformedFile { .. } => "settlement.malformed_file",
            SettlementError::BatchTooLarge => "settlement.batch_too_large",
            SettlementError::NegativeAmount => "settlement.negative_amount",
            SettlementError::TipExceedsAmount => "settlement.tip_exceeds_amount",
            SettlementError::CurrencyMismatch => "settlement.currency_mismatch",
            SettlementError::BatchClosed(_) => "settlement.batch_closed",
            SettlementError::UnknownBatch(_) => "settlement.unknown_batch",
            SettlementError::BatchIdConflict { .. } => "settlement.batch_id_conflict",
            SettlementError::RecordConflict(_) => "settlement.record_conflict",
            SettlementError::StoreMismatch => "settlement.store_mismatch",
            SettlementError::NotPermitted(_) => "settlement.not_permitted",
            SettlementError::UnknownException(_) => "settlement.unknown_exception",
            SettlementError::AlreadyResolved(_) => "settlement.already_resolved",
            SettlementError::UnknownChargeback(_) => "settlement.unknown_chargeback",
            SettlementError::DuplicateChargeback(_) => "settlement.duplicate_chargeback",
            SettlementError::ChargebackAlreadyPaid(_) => "settlement.already_paid",
            SettlementError::ChargebackAlreadyWon(_) => "settlement.already_won",
            SettlementError::ChargebackNotLost(_) => "settlement.not_lost",
            SettlementError::EvidenceRequired(_) => "settlement.evidence_required",
            SettlementError::DuplicateEvidence(_) => "settlement.duplicate_evidence",
            SettlementError::ChargebackClosed(_) => "settlement.chargeback_closed",
            SettlementError::InvalidChargebackTransition { .. } => {
                "settlement.invalid_chargeback_transition"
            }
            SettlementError::Pos(_) => "settlement.pos",
        }
    }
}

impl std::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettlementError::InvalidProcessor => f.write_str("invalid processor name"),
            SettlementError::InvalidEvidenceRef => f.write_str("invalid evidence reference"),
            SettlementError::InvalidNote => f.write_str("invalid note"),
            SettlementError::InvalidSettlementDay => f.write_str("invalid settlement day"),
            SettlementError::MalformedFile { line, reason } => {
                write!(f, "processor file line {line}: {reason}")
            }
            SettlementError::BatchTooLarge => f.write_str("batch exceeds the record limit"),
            SettlementError::NegativeAmount => f.write_str("amount must not be negative"),
            SettlementError::TipExceedsAmount => f.write_str("tip exceeds the captured amount"),
            SettlementError::CurrencyMismatch => f.write_str("currency mismatch"),
            SettlementError::BatchClosed(key) => write!(f, "batch {key} is closed"),
            SettlementError::UnknownBatch(key) => write!(f, "unknown batch {key}"),
            SettlementError::BatchIdConflict { expected, actual } => {
                write!(
                    f,
                    "batch id conflict: expected {expected}, file says {actual}"
                )
            }
            SettlementError::RecordConflict(id) => {
                write!(f, "processor record {id} was already ingested differently")
            }
            SettlementError::StoreMismatch => f.write_str("session belongs to another store"),
            SettlementError::NotPermitted(permission) => {
                write!(f, "permission denied: {permission}")
            }
            SettlementError::UnknownException(key) => write!(f, "unknown exception {key}"),
            SettlementError::AlreadyResolved(key) => write!(f, "exception {key} is resolved"),
            SettlementError::UnknownChargeback(id) => write!(f, "unknown chargeback {id}"),
            SettlementError::DuplicateChargeback(id) => write!(f, "duplicate chargeback {id}"),
            SettlementError::ChargebackAlreadyPaid(id) => {
                write!(f, "chargeback {id} was already paid")
            }
            SettlementError::ChargebackAlreadyWon(id) => {
                write!(f, "chargeback {id} was won")
            }
            SettlementError::ChargebackNotLost(id) => {
                write!(f, "chargeback {id} has not been lost")
            }
            SettlementError::EvidenceRequired(id) => {
                write!(f, "chargeback {id} needs evidence before it can be won")
            }
            SettlementError::DuplicateEvidence(id) => {
                write!(f, "evidence is already attached to chargeback {id}")
            }
            SettlementError::ChargebackClosed(id) => {
                write!(f, "chargeback {id} no longer accepts changes")
            }
            SettlementError::InvalidChargebackTransition { from, to } => {
                write!(f, "chargeback cannot move from {from} to {to}")
            }
            SettlementError::Pos(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SettlementError {}

impl From<PosError> for SettlementError {
    fn from(error: PosError) -> Self {
        SettlementError::Pos(error)
    }
}

/// A settlement book: batches keyed by processor, terminal and day.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettlementBook {
    batches: BTreeMap<SettlementKey, SettlementBatch>,
    exceptions: ExceptionQueue,
}

impl SettlementBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of batches.
    pub fn len(&self) -> usize {
        self.batches.len()
    }

    /// `true` when no batch exists.
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// One batch by key.
    pub fn batch(&self, key: &SettlementKey) -> Option<&SettlementBatch> {
        self.batches.get(key)
    }

    /// Every batch, in key order.
    pub fn batches(&self) -> impl Iterator<Item = &SettlementBatch> {
        self.batches.values()
    }

    /// The exception queue.
    pub fn exceptions(&self) -> &ExceptionQueue {
        &self.exceptions
    }

    /// Ingest one processor file into its batch.
    ///
    /// The batch is created on the first file for a processor/terminal/day and
    /// merged on later ones. A file whose batch identifier disagrees with the
    /// existing batch is refused rather than silently mixed. Records already
    /// present with the same content are replays; a repeated identifier inside
    /// the file is a duplicate; a repeated identifier with different content is
    /// a conflict. Duplicates and conflicts are queued as exceptions and never
    /// overwrite what the book already holds.
    pub fn ingest(
        &mut self,
        session: &StaffSession,
        file: ProcessorBatchFile,
        at: Timestamp,
    ) -> Result<IngestOutcome, SettlementError> {
        require(session, Permission::SettleBatch)?;
        if file.records.len() > MAX_BATCH_RECORDS {
            return Err(SettlementError::BatchTooLarge);
        }
        let key = SettlementKey::new(file.processor.clone(), file.terminal_id.clone(), file.day);

        let missing = match self.batches.get(&key) {
            Some(existing) => {
                if existing.currency != file.currency {
                    return Err(SettlementError::CurrencyMismatch);
                }
                if existing.id != file.id {
                    return Err(SettlementError::BatchIdConflict {
                        expected: existing.id.clone(),
                        actual: file.id.clone(),
                    });
                }
                if existing.is_closed() {
                    return Err(SettlementError::BatchClosed(key));
                }
                false
            }
            None => true,
        };
        if missing {
            self.batches.insert(
                key.clone(),
                SettlementBatch::new(file.id.clone(), key.clone(), file.currency),
            );
        }

        let mut outcome = IngestOutcome::default();
        let mut seen: BTreeMap<ProcessorRecordId, ProcessorRecord> = BTreeMap::new();
        for record in file.records {
            record.validate()?;
            if record.amount.currency() != file.currency {
                return Err(SettlementError::CurrencyMismatch);
            }
            if let Some(previous) = seen.get(&record.id) {
                if previous != &record {
                    return Err(SettlementError::RecordConflict(record.id));
                }
                outcome.duplicates.push(record.id.clone());
                self.exceptions.raise(SettlementException::new(
                    ExceptionCategory::DuplicateRecord,
                    record.intent.clone(),
                    vec![record.id.clone()],
                    None,
                    Some(record.amount),
                    at,
                ));
                continue;
            }
            seen.insert(record.id.clone(), record.clone());

            let existing = self
                .batches
                .get(&key)
                .and_then(|batch| batch.records.get(&record.id).cloned());
            match existing {
                Some(existing) if existing == record => outcome.replayed += 1,
                Some(existing) => {
                    outcome.conflicts.push(record.id.clone());
                    self.exceptions.raise(SettlementException::new(
                        ExceptionCategory::RecordConflict,
                        record.intent.clone(),
                        vec![record.id.clone()],
                        Some(existing.amount),
                        Some(record.amount),
                        at,
                    ));
                }
                None => {
                    let batch = self
                        .batches
                        .get_mut(&key)
                        .ok_or_else(|| SettlementError::UnknownBatch(key.clone()))?;
                    batch.records.insert(record.id.clone(), record);
                    outcome.added += 1;
                }
            }
        }
        Ok(outcome)
    }

    /// Close one batch so it accepts no further records.
    pub fn close_batch(
        &mut self,
        session: &StaffSession,
        key: &SettlementKey,
        at: Timestamp,
    ) -> Result<(), SettlementError> {
        require(session, Permission::SettleBatch)?;
        let batch = self
            .batches
            .get_mut(key)
            .ok_or_else(|| SettlementError::UnknownBatch(key.clone()))?;
        batch.close(at)
    }

    /// Compare every captured POS intent with the ingested processor records.
    ///
    /// Each captured intent ends up either in
    /// [`SettlementReconciliation::reconciled`] or in
    /// [`SettlementReconciliation::exceptions`]. The pass is idempotent: keys
    /// are deterministic, so running it again adds no queue entries, and an
    /// entry an operator already resolved stays resolved.
    pub fn reconcile(
        &mut self,
        session: &StaffSession,
        intents: &PaymentIntentStore,
        at: Timestamp,
    ) -> Result<SettlementReconciliation, SettlementError> {
        require(session, Permission::SettleBatch)?;

        // Snapshot the records first: the queue is mutated below, and a reader
        // borrowing the batches would conflict with that.
        let records: Vec<ProcessorRecord> = self
            .batches
            .values()
            .flat_map(|batch| batch.records.values().cloned())
            .collect();

        let mut by_intent: BTreeMap<PaymentIntentId, Vec<ProcessorRecord>> = BTreeMap::new();
        for record in &records {
            if let Some(intent) = record.intent.clone() {
                by_intent.entry(intent).or_default().push(record.clone());
            }
        }

        let mut collected: BTreeMap<ExceptionKey, SettlementException> = BTreeMap::new();
        let raise =
            |exception: SettlementException, queue: &mut ExceptionQueue| -> SettlementException {
                let key = exception.key.clone();
                let fallback = exception.clone();
                queue.raise(exception);
                queue.get(&key).cloned().unwrap_or(fallback)
            };

        // A record with no intent only makes sense as an adjustment.
        for record in records.iter().filter(|record| {
            record.intent.is_none() && record.kind != ProcessorRecordKind::Adjustment
        }) {
            let exception = raise(
                SettlementException::new(
                    ExceptionCategory::UnmatchedRecord,
                    None,
                    vec![record.id.clone()],
                    None,
                    Some(record.amount),
                    at,
                ),
                &mut self.exceptions,
            );
            collected.insert(exception.key.clone(), exception);
        }

        // A record naming an intent the POS never captured is unmatched too.
        for (intent, attached) in &by_intent {
            let known = intents
                .intent(intent)
                .is_some_and(|intent| intent.captured_amount().is_some());
            if known {
                continue;
            }
            for record in attached {
                let exception = raise(
                    SettlementException::new(
                        ExceptionCategory::UnmatchedRecord,
                        Some(intent.clone()),
                        vec![record.id.clone()],
                        None,
                        Some(record.amount),
                        at,
                    ),
                    &mut self.exceptions,
                );
                collected.insert(exception.key.clone(), exception);
            }
        }

        let mut reconciled: Vec<SettlementMatch> = Vec::new();
        for intent in intents.intents() {
            let Some(captured) = intent.captured_amount() else {
                continue;
            };
            let empty: Vec<ProcessorRecord> = Vec::new();
            let attached = by_intent.get(intent.id()).unwrap_or(&empty);
            let captures: Vec<&ProcessorRecord> = attached
                .iter()
                .filter(|record| record.kind == ProcessorRecordKind::Capture)
                .collect();
            let refunds: Vec<&ProcessorRecord> = attached
                .iter()
                .filter(|record| record.kind == ProcessorRecordKind::Refund)
                .collect();
            let chargebacks: Vec<&ProcessorRecord> = attached
                .iter()
                .filter(|record| record.kind == ProcessorRecordKind::Chargeback)
                .collect();
            let refunded = Money::checked_sum(intent.currency(), refunds.iter().map(|r| r.amount))?;
            let chargeback_total =
                Money::checked_sum(intent.currency(), chargebacks.iter().map(|r| r.amount))?;

            let problem = if captures.is_empty() {
                Some(SettlementException::new(
                    ExceptionCategory::MissingRecord,
                    Some(intent.id().clone()),
                    Vec::new(),
                    Some(captured),
                    Some(Money::zero(captured.currency())),
                    at,
                ))
            } else if captures.len() > 1 {
                Some(SettlementException::new(
                    ExceptionCategory::DuplicateRecord,
                    Some(intent.id().clone()),
                    captures.iter().map(|record| record.id.clone()).collect(),
                    Some(captured),
                    None,
                    at,
                ))
            } else if captures[0].amount.currency() != captured.currency() {
                Some(SettlementException::new(
                    ExceptionCategory::CurrencyMismatch,
                    Some(intent.id().clone()),
                    vec![captures[0].id.clone()],
                    Some(captured),
                    Some(captures[0].amount),
                    at,
                ))
            } else if captures[0].amount < captured {
                Some(SettlementException::new(
                    ExceptionCategory::PartialSettlement,
                    Some(intent.id().clone()),
                    vec![captures[0].id.clone()],
                    Some(captured),
                    Some(captures[0].amount),
                    at,
                ))
            } else if captures[0].amount > captured {
                Some(SettlementException::new(
                    ExceptionCategory::OverSettlement,
                    Some(intent.id().clone()),
                    vec![captures[0].id.clone()],
                    Some(captured),
                    Some(captures[0].amount),
                    at,
                ))
            } else if refunded
                != intent
                    .refunded_amount()
                    .unwrap_or(Money::zero(intent.currency()))
            {
                Some(SettlementException::new(
                    ExceptionCategory::RefundMismatch,
                    Some(intent.id().clone()),
                    refunds.iter().map(|record| record.id.clone()).collect(),
                    Some(
                        intent
                            .refunded_amount()
                            .unwrap_or(Money::zero(intent.currency())),
                    ),
                    Some(refunded),
                    at,
                ))
            } else {
                None
            };

            match problem {
                Some(exception) => {
                    let exception = raise(exception, &mut self.exceptions);
                    collected.insert(exception.key.clone(), exception);
                }
                None => reconciled.push(SettlementMatch {
                    intent: intent.id().clone(),
                    check_id: intent.check_id().clone(),
                    terminal_id: intent.terminal_id().clone(),
                    currency: intent.currency(),
                    captured,
                    settled: captures[0].amount,
                    refunded,
                    chargebacks: chargeback_total,
                    tip: captures[0].tip,
                    records: vec![captures[0].id.clone()],
                }),
            }
        }

        Ok(SettlementReconciliation {
            reconciled,
            exceptions: collected.into_values().collect(),
        })
    }
}

/// A reference to evidence held outside the POS.
///
/// This is a link such as a document identifier or an archive path. It is not
/// the evidence itself, and this crate neither fetches nor stores it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceRef(String);

impl EvidenceRef {
    /// Validate an evidence reference.
    pub fn new(reference: impl Into<String>) -> Result<Self, SettlementError> {
        let reference = reference.into();
        validate_identifier(&reference, "evidence reference")
            .map_err(|_| SettlementError::InvalidEvidenceRef)?;
        // An evidence reference is a link: whitespace would make it unusable in
        // the systems that hold the document.
        if reference.chars().any(char::is_whitespace) {
            return Err(SettlementError::InvalidEvidenceRef);
        }
        Ok(Self(reference))
    }

    /// The reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EvidenceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What kind of evidence a reference points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    /// A signed receipt or invoice.
    Receipt,
    /// A captured signature.
    Signature,
    /// A terminal, printer or drawer log excerpt.
    TerminalLog,
    /// A delivery or service-completion proof.
    DeliveryProof,
    /// Correspondence with the customer or issuer.
    Correspondence,
    /// Anything else the deployment records.
    Other,
}

impl EvidenceKind {
    /// Every kind, in stable order.
    pub const ALL: [EvidenceKind; 6] = [
        EvidenceKind::Receipt,
        EvidenceKind::Signature,
        EvidenceKind::TerminalLog,
        EvidenceKind::DeliveryProof,
        EvidenceKind::Correspondence,
        EvidenceKind::Other,
    ];

    /// Stable label for logs and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Receipt => "receipt",
            EvidenceKind::Signature => "signature",
            EvidenceKind::TerminalLog => "terminal_log",
            EvidenceKind::DeliveryProof => "delivery_proof",
            EvidenceKind::Correspondence => "correspondence",
            EvidenceKind::Other => "other",
        }
    }
}

impl std::fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One evidence link attached to a chargeback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    reference: EvidenceRef,
    kind: EvidenceKind,
    note: Option<String>,
    at: Timestamp,
}

impl Evidence {
    /// Attach a link to a case. The reference is unique within the case.
    pub fn new(
        reference: EvidenceRef,
        kind: EvidenceKind,
        note: Option<&str>,
        at: Timestamp,
    ) -> Result<Self, SettlementError> {
        Ok(Self {
            reference,
            kind,
            note: validate_note(note)?,
            at,
        })
    }

    /// The reference.
    pub fn reference(&self) -> &EvidenceRef {
        &self.reference
    }

    /// What the evidence is.
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// The optional note.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// When it was attached.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}

/// Where a chargeback is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChargebackState {
    /// The processor reported the chargeback; no evidence has been reviewed.
    Opened,
    /// The merchant is preparing or has submitted evidence.
    UnderReview,
    /// The issuer reversed the chargeback; nothing is owed.
    Won,
    /// The merchant lost; the amount is owed.
    Lost,
    /// The owed amount was settled; the case is closed.
    Paid,
}

impl ChargebackState {
    /// Stable label for logs and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            ChargebackState::Opened => "opened",
            ChargebackState::UnderReview => "under_review",
            ChargebackState::Won => "won",
            ChargebackState::Lost => "lost",
            ChargebackState::Paid => "paid",
        }
    }

    /// `true` when no further transition is allowed.
    pub fn is_terminal(self) -> bool {
        matches!(self, ChargebackState::Won | ChargebackState::Paid)
    }

    /// `true` when the merchant still owes the amount.
    pub fn is_debit(self) -> bool {
        matches!(self, ChargebackState::Lost | ChargebackState::Paid)
    }
}

impl std::fmt::Display for ChargebackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a chargeback open request did anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargebackChange {
    /// The case was created.
    Created,
    /// An identical case already existed.
    Replayed,
}

/// The parameters of a new chargeback case.
///
/// Scope and amounts are validated by [`ChargebackBook::open`], matching the
/// `ShiftSpec` pattern POS-11 uses for shifts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChargebackSpec {
    id: ChargebackId,
    intent: PaymentIntentId,
    check_id: Option<CheckId>,
    amount: Money,
    reason: String,
    opened_at: Timestamp,
}

impl ChargebackSpec {
    /// Describe a case. The reason is trimmed and validated on open.
    pub fn new(
        id: ChargebackId,
        intent: PaymentIntentId,
        check_id: Option<CheckId>,
        amount: Money,
        reason: impl Into<String>,
        opened_at: Timestamp,
    ) -> Self {
        Self {
            id,
            intent,
            check_id,
            amount,
            reason: reason.into(),
            opened_at,
        }
    }

    /// The case identifier.
    pub fn id(&self) -> &ChargebackId {
        &self.id
    }

    /// The disputed intent.
    pub fn intent(&self) -> &PaymentIntentId {
        &self.intent
    }

    /// The check the intent paid, when known.
    pub fn check_id(&self) -> Option<&CheckId> {
        self.check_id.as_ref()
    }

    /// The disputed amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The processor's reason text.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// When the case opened.
    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }
}

/// One chargeback case and its evidence trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chargeback {
    id: ChargebackId,
    store_id: StoreId,
    intent: PaymentIntentId,
    check_id: Option<CheckId>,
    amount: Money,
    reason: String,
    opened_by: EmployeeId,
    opened_at: Timestamp,
    state: ChargebackState,
    evidence: Vec<Evidence>,
    reviewed_by: Option<EmployeeId>,
    reviewed_at: Option<Timestamp>,
    lost_by: Option<EmployeeId>,
    lost_at: Option<Timestamp>,
    paid_by: Option<EmployeeId>,
    paid_at: Option<Timestamp>,
}

impl Chargeback {
    /// The case identifier.
    pub fn id(&self) -> &ChargebackId {
        &self.id
    }

    /// The store that took the sale.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The disputed intent.
    pub fn intent(&self) -> &PaymentIntentId {
        &self.intent
    }

    /// The check the intent paid, when known.
    pub fn check_id(&self) -> Option<&CheckId> {
        self.check_id.as_ref()
    }

    /// The disputed amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The processor's reason text.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Who opened the case.
    pub fn opened_by(&self) -> &EmployeeId {
        &self.opened_by
    }

    /// When the case was opened.
    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }

    /// The current state.
    pub fn state(&self) -> ChargebackState {
        self.state
    }

    /// `true` once the case is won or paid.
    pub fn is_closed(&self) -> bool {
        self.state.is_terminal()
    }

    /// Every evidence link, in attachment order.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Who moved the case to review.
    pub fn reviewed_by(&self) -> Option<&EmployeeId> {
        self.reviewed_by.as_ref()
    }

    /// When the case moved to review.
    pub fn reviewed_at(&self) -> Option<Timestamp> {
        self.reviewed_at
    }

    /// Who recorded the loss.
    pub fn lost_by(&self) -> Option<&EmployeeId> {
        self.lost_by.as_ref()
    }

    /// When the loss was recorded.
    pub fn lost_at(&self) -> Option<Timestamp> {
        self.lost_at
    }

    /// Who paid the case.
    pub fn paid_by(&self) -> Option<&EmployeeId> {
        self.paid_by.as_ref()
    }

    /// When the case was paid.
    pub fn paid_at(&self) -> Option<Timestamp> {
        self.paid_at
    }

    /// The debit this case represents: the amount once lost or paid.
    pub fn debit(&self) -> Option<Money> {
        if self.state.is_debit() {
            Some(self.amount)
        } else {
            None
        }
    }

    fn transition(&mut self, to: ChargebackState) -> Result<(), SettlementError> {
        if !chargeback_can_transition(self.state, to) {
            return Err(SettlementError::InvalidChargebackTransition {
                from: self.state,
                to,
            });
        }
        self.state = to;
        Ok(())
    }
}

fn chargeback_can_transition(from: ChargebackState, to: ChargebackState) -> bool {
    matches!(
        (from, to),
        (ChargebackState::Opened, ChargebackState::UnderReview)
            | (ChargebackState::Opened, ChargebackState::Won)
            | (ChargebackState::Opened, ChargebackState::Lost)
            | (ChargebackState::UnderReview, ChargebackState::Won)
            | (ChargebackState::UnderReview, ChargebackState::Lost)
            | (ChargebackState::Lost, ChargebackState::Paid)
    )
}

/// Every chargeback case in one deployment, keyed by case identifier.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChargebackBook {
    cases: BTreeMap<ChargebackId, Chargeback>,
}

impl ChargebackBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cases.
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    /// `true` when no case exists.
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    /// One case by identifier.
    pub fn chargeback(&self, id: &ChargebackId) -> Option<&Chargeback> {
        self.cases.get(id)
    }

    /// Every case, in identifier order.
    pub fn chargebacks(&self) -> impl Iterator<Item = &Chargeback> {
        self.cases.values()
    }

    /// Every case still awaiting a decision.
    pub fn open_cases(&self) -> impl Iterator<Item = &Chargeback> {
        self.cases.values().filter(|case| !case.is_closed())
    }

    /// The total actually paid in one currency.
    ///
    /// Only `Paid` cases count. A `Lost` case is owed but not yet paid, and a
    /// `Won` case is not a debit at all.
    pub fn paid_total(&self, currency: Currency) -> Result<Money, SettlementError> {
        let mut total = Money::zero(currency);
        for case in self
            .cases
            .values()
            .filter(|case| case.state == ChargebackState::Paid)
        {
            total = total.checked_add(case.amount)?;
        }
        Ok(total)
    }

    /// The total owed but not yet paid in one currency.
    pub fn outstanding_total(&self, currency: Currency) -> Result<Money, SettlementError> {
        let mut total = Money::zero(currency);
        for case in self
            .cases
            .values()
            .filter(|case| case.state == ChargebackState::Lost)
        {
            total = total.checked_add(case.amount)?;
        }
        Ok(total)
    }

    /// Open a case.
    ///
    /// The same identifier with identical content is an idempotent replay. The
    /// same identifier with different content is refused.
    pub fn open(
        &mut self,
        session: &StaffSession,
        spec: ChargebackSpec,
    ) -> Result<ChargebackChange, SettlementError> {
        require(session, Permission::ManageChargebacks)?;
        let ChargebackSpec {
            id,
            intent,
            check_id,
            amount,
            reason,
            opened_at,
        } = spec;
        if !amount.is_positive() {
            return Err(SettlementError::NegativeAmount);
        }
        let reason = validate_reason(&reason)?;
        if let Some(existing) = self.cases.get(&id) {
            let same = existing.store_id == *session.store_id()
                && existing.intent == intent
                && existing.check_id == check_id
                && existing.amount == amount
                && existing.reason == reason;
            return if same {
                Ok(ChargebackChange::Replayed)
            } else {
                Err(SettlementError::DuplicateChargeback(id))
            };
        }
        self.cases.insert(
            id.clone(),
            Chargeback {
                id,
                store_id: session.store_id().clone(),
                intent,
                check_id,
                amount,
                reason,
                opened_by: session.employee_id().clone(),
                opened_at,
                state: ChargebackState::Opened,
                evidence: Vec::new(),
                reviewed_by: None,
                reviewed_at: None,
                lost_by: None,
                lost_at: None,
                paid_by: None,
                paid_at: None,
            },
        );
        Ok(ChargebackChange::Created)
    }

    /// Attach one evidence link to an open case.
    ///
    /// Evidence is accepted while the case is `Opened` or `UnderReview`. A
    /// reference already attached to the case is refused, so the trail cannot
    /// claim the same document twice.
    pub fn attach_evidence(
        &mut self,
        session: &StaffSession,
        id: &ChargebackId,
        evidence: Evidence,
    ) -> Result<(), SettlementError> {
        require(session, Permission::ManageChargebacks)?;
        let case = self.case_mut(session, id)?;
        if case.is_closed() {
            return Err(SettlementError::ChargebackClosed(id.clone()));
        }
        if case.evidence.len() >= MAX_CHARGEBACK_EVIDENCE {
            return Err(SettlementError::ChargebackClosed(id.clone()));
        }
        if case
            .evidence
            .iter()
            .any(|existing| existing.reference == evidence.reference)
        {
            return Err(SettlementError::DuplicateEvidence(id.clone()));
        }
        case.evidence.push(evidence);
        Ok(())
    }

    /// Move an opened case to review.
    pub fn review(
        &mut self,
        session: &StaffSession,
        id: &ChargebackId,
        at: Timestamp,
    ) -> Result<&Chargeback, SettlementError> {
        require(session, Permission::ManageChargebacks)?;
        let operator = session.employee_id().clone();
        let case = self.case_mut(session, id)?;
        match case.state {
            ChargebackState::Opened => {
                case.transition(ChargebackState::UnderReview)?;
                case.reviewed_by = Some(operator);
                case.reviewed_at = Some(at);
            }
            ChargebackState::UnderReview => {}
            ChargebackState::Won => return Err(SettlementError::ChargebackAlreadyWon(id.clone())),
            ChargebackState::Lost | ChargebackState::Paid => {
                return Err(SettlementError::ChargebackClosed(id.clone()))
            }
        }
        Ok(case)
    }

    /// Record that the issuer reversed the chargeback.
    ///
    /// At least one evidence link is required; a case cannot be recorded as won
    /// with nothing behind it.
    pub fn win(
        &mut self,
        session: &StaffSession,
        id: &ChargebackId,
        at: Timestamp,
    ) -> Result<&Chargeback, SettlementError> {
        require(session, Permission::ManageChargebacks)?;
        let case = self.case_mut(session, id)?;
        match case.state {
            ChargebackState::Won => return Ok(case),
            ChargebackState::Lost | ChargebackState::Paid => {
                return Err(SettlementError::ChargebackClosed(id.clone()))
            }
            ChargebackState::Opened | ChargebackState::UnderReview => {
                if case.evidence.is_empty() {
                    return Err(SettlementError::EvidenceRequired(id.clone()));
                }
                case.transition(ChargebackState::Won)?;
                case.reviewed_at.get_or_insert(at);
                case.reviewed_by
                    .get_or_insert_with(|| session.employee_id().clone());
            }
        }
        Ok(case)
    }

    /// Record that the merchant lost the case and owes the amount.
    pub fn lose(
        &mut self,
        session: &StaffSession,
        id: &ChargebackId,
        at: Timestamp,
    ) -> Result<&Chargeback, SettlementError> {
        require(session, Permission::ManageChargebacks)?;
        let operator = session.employee_id().clone();
        let case = self.case_mut(session, id)?;
        match case.state {
            ChargebackState::Lost | ChargebackState::Paid => {}
            ChargebackState::Won => return Err(SettlementError::ChargebackAlreadyWon(id.clone())),
            ChargebackState::Opened | ChargebackState::UnderReview => {
                case.transition(ChargebackState::Lost)?;
                case.lost_by = Some(operator);
                case.lost_at = Some(at);
            }
        }
        Ok(case)
    }

    /// Pay a lost case exactly once.
    ///
    /// The second payment is refused with
    /// [`SettlementError::ChargebackAlreadyPaid`]; it is not treated as a
    /// replay, because a second debit of the same case would move money twice.
    pub fn pay(
        &mut self,
        session: &StaffSession,
        id: &ChargebackId,
        at: Timestamp,
    ) -> Result<&Chargeback, SettlementError> {
        require(session, Permission::ManageChargebacks)?;
        let operator = session.employee_id().clone();
        let case = self.case_mut(session, id)?;
        match case.state {
            ChargebackState::Paid => {
                return Err(SettlementError::ChargebackAlreadyPaid(id.clone()))
            }
            ChargebackState::Won => return Err(SettlementError::ChargebackAlreadyWon(id.clone())),
            ChargebackState::Opened | ChargebackState::UnderReview => {
                return Err(SettlementError::ChargebackNotLost(id.clone()))
            }
            ChargebackState::Lost => {
                case.transition(ChargebackState::Paid)?;
                case.paid_by = Some(operator);
                case.paid_at = Some(at);
            }
        }
        Ok(case)
    }

    fn case_mut(
        &mut self,
        session: &StaffSession,
        id: &ChargebackId,
    ) -> Result<&mut Chargeback, SettlementError> {
        let case = self
            .cases
            .get_mut(id)
            .ok_or_else(|| SettlementError::UnknownChargeback(id.clone()))?;
        if case.store_id != *session.store_id() {
            return Err(SettlementError::StoreMismatch);
        }
        Ok(case)
    }
}

fn require(session: &StaffSession, permission: Permission) -> Result<(), SettlementError> {
    if session.can(permission) {
        Ok(())
    } else {
        Err(SettlementError::NotPermitted(permission))
    }
}

fn validate_reason(reason: &str) -> Result<String, SettlementError> {
    let reason = reason.trim();
    if reason.is_empty()
        || reason.len() > MAX_SETTLEMENT_TEXT_LEN
        || reason.chars().any(char::is_control)
    {
        return Err(SettlementError::InvalidNote);
    }
    Ok(reason.to_owned())
}

fn validate_note(note: Option<&str>) -> Result<Option<String>, SettlementError> {
    match note {
        None => Ok(None),
        Some(note) => {
            let note = note.trim();
            if note.is_empty() {
                return Ok(None);
            }
            if note.len() > MAX_SETTLEMENT_TEXT_LEN || note.chars().any(char::is_control) {
                return Err(SettlementError::InvalidNote);
            }
            Ok(Some(note.to_owned()))
        }
    }
}
