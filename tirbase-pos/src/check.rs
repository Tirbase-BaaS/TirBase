// SPDX-License-Identifier: AGPL-3.0-only

//! Checks: the payable bill, its state machine, payment links and totals.
//!
//! # State machine
//!
//! ```text
//!            hold               close
//!   Open ──────────► Held ──────────────► Closed ──► Refunded
//!     │  ◄──────────  │                     ▲
//!     │    resume     │                     │
//!     └───────────────┴──── void ──► Voided │
//!                          close ───────────┘
//! ```
//!
//! `Open` and `Held` are the only mutable states. `Closed`, `Voided`,
//! `Refunded` and `Merged` are terminal for content: every mutator calls
//! [`Check::ensure_mutable`] first, so a closed check cannot be silently
//! changed. Closing also freezes the line-derived totals in
//! [`Check::sealed`], so even a defect that bypassed the guard could not alter
//! the historical bill; [`Check::sealed_totals_are_consistent`] checks the
//! frozen copy against a fresh recomputation.
//!
//! POS-02 adds void records for individual lines and payments, plus an
//! atomic `Merged` terminal state. A voided line stays in the check for audit
//! but is excluded from totals; a voided payment stays linked but is excluded
//! from `paid_total`.

use std::collections::BTreeMap;

use crate::audit::Timestamp;
use crate::error::PosError;
use crate::ids::{validate_identifier, CheckId, LineItemId, PaymentId, RefundId};
use crate::line_item::{LineItem, LineTotals, TaxLine};
use crate::money::{Currency, Money};
use crate::rounding::RoundingMode;

/// The lifecycle state of a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckStatus {
    /// Accepting items and payments.
    Open,
    /// Parked; still editable and payable, but not active on the terminal.
    Held,
    /// Settled and sealed. Content is immutable; only refunds may follow.
    Closed,
    /// Cancelled before settlement. Content is immutable.
    Voided,
    /// Fully refunded after closing. Content is immutable.
    Refunded,
    /// Consolidated into another check (POS-02). Content is immutable and the
    /// check carries no active lines or payments.
    Merged,
}

impl CheckStatus {
    /// `true` for the states in which content may change.
    pub fn is_mutable(self) -> bool {
        matches!(self, CheckStatus::Open | CheckStatus::Held)
    }

    /// `true` when the state machine has no outgoing transitions.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            CheckStatus::Voided | CheckStatus::Refunded | CheckStatus::Merged
        )
    }

    /// Whether one edge of the state machine connects `self` to `to`.
    ///
    /// `Closed → Refunded` is an edge, but it is taken only by a refund that
    /// settles the whole captured amount; there is no direct transition command
    /// for it.
    pub fn can_transition_to(self, to: CheckStatus) -> bool {
        matches!(
            (self, to),
            (CheckStatus::Open, CheckStatus::Held)
                | (CheckStatus::Open, CheckStatus::Closed)
                | (CheckStatus::Open, CheckStatus::Voided)
                | (CheckStatus::Held, CheckStatus::Open)
                | (CheckStatus::Held, CheckStatus::Closed)
                | (CheckStatus::Held, CheckStatus::Voided)
                | (CheckStatus::Open, CheckStatus::Merged)
                | (CheckStatus::Held, CheckStatus::Merged)
                | (CheckStatus::Closed, CheckStatus::Refunded)
        )
    }
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            CheckStatus::Open => "open",
            CheckStatus::Held => "held",
            CheckStatus::Closed => "closed",
            CheckStatus::Voided => "voided",
            CheckStatus::Refunded => "refunded",
            CheckStatus::Merged => "merged",
        };
        f.write_str(label)
    }
}

/// How a payment was tendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaymentMethod {
    /// Cash.
    Cash,
    /// A card payment handled by an external terminal. No card data is stored.
    Card,
    /// A voucher or gift credential reference.
    Voucher,
    /// Any other method.
    Other,
}

/// Settlement state of a payment link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaymentStatus {
    /// Authorised but not captured; not counted as paid.
    Authorized,
    /// Captured; counted as paid.
    Captured,
    /// Voided before capture; not counted as paid.
    Voided,
}

/// A link from the check to an external or cash payment.
///
/// The struct deliberately has no field for a PAN, CVV, track data or card
/// token. A processor reference is an opaque caller-supplied string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentLink {
    id: PaymentId,
    method: PaymentMethod,
    status: PaymentStatus,
    amount: Money,
    provider_reference: Option<String>,
}

impl PaymentLink {
    /// A captured payment.
    pub fn captured(id: PaymentId, method: PaymentMethod, amount: Money) -> Result<Self, PosError> {
        Self::new(id, method, PaymentStatus::Captured, amount)
    }

    /// An authorised but not yet captured payment.
    pub fn authorized(
        id: PaymentId,
        method: PaymentMethod,
        amount: Money,
    ) -> Result<Self, PosError> {
        Self::new(id, method, PaymentStatus::Authorized, amount)
    }

    fn new(
        id: PaymentId,
        method: PaymentMethod,
        status: PaymentStatus,
        amount: Money,
    ) -> Result<Self, PosError> {
        if !amount.is_positive() {
            return Err(PosError::NonPositiveAmount);
        }
        Ok(Self {
            id,
            method,
            status,
            amount,
            provider_reference: None,
        })
    }

    /// Attach an opaque processor reference (never card data).
    pub fn with_provider_reference(
        mut self,
        reference: impl Into<String>,
    ) -> Result<Self, PosError> {
        let reference = reference.into();
        validate_identifier(&reference, "payment provider reference")?;
        self.provider_reference = Some(reference);
        Ok(self)
    }

    /// The payment identifier.
    pub fn id(&self) -> &PaymentId {
        &self.id
    }

    /// The tender method.
    pub fn method(&self) -> PaymentMethod {
        self.method
    }

    /// The settlement state.
    pub fn status(&self) -> PaymentStatus {
        self.status
    }

    /// The amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The optional opaque processor reference.
    pub fn provider_reference(&self) -> Option<&str> {
        self.provider_reference.as_deref()
    }
}

/// Why and when a line item or payment was voided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoidRecord {
    reason: String,
    at: Timestamp,
}

impl VoidRecord {
    /// Construct a void record. A non-blank reason is required.
    pub fn new(reason: impl Into<String>, at: Timestamp) -> Result<Self, PosError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(PosError::MissingReason);
        }
        validate_identifier(&reason, "void reason")?;
        Ok(Self { reason, at })
    }

    /// The recorded reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The caller-supplied void time.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}

/// A refund recorded against a closed check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refund {
    id: RefundId,
    amount: Money,
    reason: String,
}

impl Refund {
    /// Construct a refund. The amount must be positive and a reason required.
    pub fn new(id: RefundId, amount: Money, reason: impl Into<String>) -> Result<Self, PosError> {
        if !amount.is_positive() {
            return Err(PosError::NonPositiveAmount);
        }
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(PosError::MissingReason);
        }
        validate_identifier(&reason, "refund reason")?;
        Ok(Self { id, amount, reason })
    }

    /// The refund identifier.
    pub fn id(&self) -> &RefundId {
        &self.id
    }

    /// The refunded amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The reason recorded with the refund.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Exact totals for a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckTotals {
    /// The check currency.
    pub currency: Currency,
    /// The rounding mode fixed at check creation.
    pub rounding: RoundingMode,
    /// Sum of line base amounts.
    pub subtotal: Money,
    /// Sum of line discounts.
    pub discount_total: Money,
    /// Sum of line tax amounts.
    pub tax_total: Money,
    /// The check tip.
    pub tip: Money,
    /// `subtotal − discount_total + tax_total + tip`.
    pub grand_total: Money,
    /// Sum of captured payment amounts.
    pub paid_total: Money,
    /// Sum of recorded refunds.
    pub refunded_total: Money,
    /// `paid_total − refunded_total`.
    pub net_paid: Money,
    /// `grand_total − net_paid` (negative when the customer is owed money).
    pub amount_due: Money,
    /// Per-line calculations, in line-item identifier order.
    pub line_totals: Vec<LineTotals>,
    /// Tax grouped by rate, in ascending rate order.
    pub tax_lines: Vec<TaxLine>,
    /// `true` once the line-derived totals were frozen by close or void.
    pub sealed: bool,
}

/// Line-derived subtotal, tax and tip snapshot. Frozen at close/void.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CheckSummary {
    subtotal: Money,
    discount_total: Money,
    tax_total: Money,
    tip: Money,
    grand_total: Money,
    line_totals: Vec<LineTotals>,
    tax_lines: Vec<TaxLine>,
}

/// A payable check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    id: CheckId,
    currency: Currency,
    rounding: RoundingMode,
    status: CheckStatus,
    opened_at: Timestamp,
    lines: BTreeMap<LineItemId, LineItem>,
    tip: Money,
    payments: BTreeMap<PaymentId, PaymentLink>,
    refunds: BTreeMap<RefundId, Refund>,
    voided_lines: BTreeMap<LineItemId, VoidRecord>,
    voided_payments: BTreeMap<PaymentId, VoidRecord>,
    merged_into: Option<CheckId>,
    sealed: Option<CheckSummary>,
}

impl Check {
    pub(crate) fn new(
        id: CheckId,
        currency: Currency,
        rounding: RoundingMode,
        opened_at: Timestamp,
    ) -> Self {
        Self {
            id,
            currency,
            rounding,
            status: CheckStatus::Open,
            opened_at,
            lines: BTreeMap::new(),
            tip: Money::zero(currency),
            payments: BTreeMap::new(),
            refunds: BTreeMap::new(),
            voided_lines: BTreeMap::new(),
            voided_payments: BTreeMap::new(),
            merged_into: None,
            sealed: None,
        }
    }

    /// The check identifier.
    pub fn id(&self) -> &CheckId {
        &self.id
    }

    /// The check currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The rounding mode fixed at creation.
    pub fn rounding(&self) -> RoundingMode {
        self.rounding
    }

    /// The current state.
    pub fn status(&self) -> CheckStatus {
        self.status
    }

    /// The time the check was created.
    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }

    /// The current tip.
    pub fn tip(&self) -> Money {
        self.tip
    }

    /// Line items in identifier order, including voided lines.
    pub fn line_items(&self) -> impl Iterator<Item = &LineItem> {
        self.lines.values()
    }

    /// Active (not voided) line items in identifier order.
    pub fn active_line_items(&self) -> impl Iterator<Item = &LineItem> {
        self.lines
            .iter()
            .filter(|(id, _)| !self.voided_lines.contains_key(*id))
            .map(|(_, line)| line)
    }

    /// Look up one line item, voided or active.
    pub fn line_item(&self, id: &LineItemId) -> Option<&LineItem> {
        self.lines.get(id)
    }

    /// Payment links in identifier order, including voided payments.
    pub fn payments(&self) -> impl Iterator<Item = &PaymentLink> {
        self.payments.values()
    }

    /// Refund records in identifier order.
    pub fn refunds(&self) -> impl Iterator<Item = &Refund> {
        self.refunds.values()
    }

    /// Void records for line items.
    pub fn voided_lines(&self) -> impl Iterator<Item = (&LineItemId, &VoidRecord)> {
        self.voided_lines.iter()
    }

    /// Void records for payments.
    pub fn voided_payments(&self) -> impl Iterator<Item = (&PaymentId, &VoidRecord)> {
        self.voided_payments.iter()
    }

    /// `true` when the line has a void record.
    pub fn line_is_voided(&self, id: &LineItemId) -> bool {
        self.voided_lines.contains_key(id)
    }

    /// `true` when the payment has a void record.
    pub fn payment_is_voided(&self, id: &PaymentId) -> bool {
        self.voided_payments.contains_key(id)
    }

    /// The check a merged source was consolidated into, when it is merged.
    pub fn merged_into(&self) -> Option<&CheckId> {
        self.merged_into.as_ref()
    }

    /// `true` once line-derived totals have been frozen.
    pub fn is_sealed(&self) -> bool {
        self.sealed.is_some()
    }

    fn ensure_mutable(&self) -> Result<(), PosError> {
        if self.status.is_mutable() {
            Ok(())
        } else {
            Err(PosError::CheckNotMutable {
                status: self.status,
            })
        }
    }

    fn ensure_transition(&self, to: CheckStatus) -> Result<(), PosError> {
        if self.status.can_transition_to(to) {
            Ok(())
        } else {
            Err(PosError::InvalidTransition {
                from: self.status,
                to,
            })
        }
    }

    fn require_currency(&self, amount: Money) -> Result<(), PosError> {
        if amount.currency() != self.currency {
            return Err(PosError::CurrencyMismatch);
        }
        Ok(())
    }

    fn captured_total(&self) -> Result<Money, PosError> {
        Money::checked_sum(
            self.currency,
            self.payments
                .iter()
                .filter(|(id, payment)| {
                    !self.voided_payments.contains_key(*id)
                        && payment.status() == PaymentStatus::Captured
                })
                .map(|(_, payment)| payment.amount()),
        )
    }

    fn refunded_total(&self) -> Result<Money, PosError> {
        Money::checked_sum(self.currency, self.refunds.values().map(Refund::amount))
    }

    fn compute_summary(&self) -> Result<CheckSummary, PosError> {
        let mut subtotal = Money::zero(self.currency);
        let mut discount_total = Money::zero(self.currency);
        let mut tax_total = Money::zero(self.currency);
        let mut line_totals = Vec::with_capacity(self.lines.len());
        let mut tax_lines: BTreeMap<i32, TaxLine> = BTreeMap::new();

        for (line_id, line) in &self.lines {
            if self.voided_lines.contains_key(line_id) {
                continue;
            }
            let totals = line.compute(self.rounding)?;
            subtotal = subtotal.checked_add(totals.base)?;
            discount_total = discount_total.checked_add(totals.discount)?;
            tax_total = tax_total.checked_add(totals.tax)?;
            if let Some(rate) = totals.tax_rate {
                let entry = tax_lines.entry(rate.ppm()).or_insert(TaxLine {
                    rate,
                    taxable_base: Money::zero(self.currency),
                    tax: Money::zero(self.currency),
                });
                entry.taxable_base = entry.taxable_base.checked_add(totals.taxable_base)?;
                entry.tax = entry.tax.checked_add(totals.tax)?;
            }
            line_totals.push(totals);
        }

        // subtotal − discount_total + tax_total + tip, left to right.
        let grand_total = subtotal
            .checked_sub(discount_total)?
            .checked_add(tax_total)?
            .checked_add(self.tip)?;

        Ok(CheckSummary {
            subtotal,
            discount_total,
            tax_total,
            tip: self.tip,
            grand_total,
            line_totals,
            tax_lines: tax_lines.into_values().collect(),
        })
    }

    /// Compute the check's exact totals.
    ///
    /// Once sealed, the line-derived part is served from the frozen snapshot;
    /// only the payment and refund aggregates are live.
    pub fn totals(&self) -> Result<CheckTotals, PosError> {
        let summary = match &self.sealed {
            Some(sealed) => sealed.clone(),
            None => self.compute_summary()?,
        };
        let paid_total = self.captured_total()?;
        let refunded_total = self.refunded_total()?;
        let net_paid = paid_total.checked_sub(refunded_total)?;
        let amount_due = summary.grand_total.checked_sub(net_paid)?;

        Ok(CheckTotals {
            currency: self.currency,
            rounding: self.rounding,
            subtotal: summary.subtotal,
            discount_total: summary.discount_total,
            tax_total: summary.tax_total,
            tip: summary.tip,
            grand_total: summary.grand_total,
            paid_total,
            refunded_total,
            net_paid,
            amount_due,
            line_totals: summary.line_totals,
            tax_lines: summary.tax_lines,
            sealed: self.sealed.is_some(),
        })
    }

    /// Recompute the line-derived totals and compare them with the sealed
    /// snapshot. Returns `Ok(true)` for an unsealed check (nothing to verify).
    ///
    /// This is an audit aid: a closed check must never disagree with itself.
    pub fn sealed_totals_are_consistent(&self) -> Result<bool, PosError> {
        match &self.sealed {
            None => Ok(true),
            Some(sealed) => Ok(*sealed == self.compute_summary()?),
        }
    }

    fn seal(&mut self) -> Result<Money, PosError> {
        let summary = self.compute_summary()?;
        let grand_total = summary.grand_total;
        self.sealed = Some(summary);
        Ok(grand_total)
    }

    pub(crate) fn add_line(&mut self, line: LineItem) -> Result<LineTotals, PosError> {
        self.ensure_mutable()?;
        if self.lines.contains_key(line.id()) {
            return Err(PosError::LineItemAlreadyExists(line.id().clone()));
        }
        self.require_currency(line.unit_price())?;
        // Compute before inserting so an invalid discount cannot half-apply.
        let totals = line.compute(self.rounding)?;
        self.lines.insert(line.id().clone(), line);
        Ok(totals)
    }

    pub(crate) fn update_line(
        &mut self,
        line: LineItem,
    ) -> Result<(LineTotals, LineTotals), PosError> {
        self.ensure_mutable()?;
        let previous = self
            .lines
            .get(line.id())
            .ok_or_else(|| PosError::LineItemNotFound(line.id().clone()))?;
        self.require_currency(line.unit_price())?;
        let previous_totals = previous.compute(self.rounding)?;
        let new_totals = line.compute(self.rounding)?;
        self.lines.insert(line.id().clone(), line);
        Ok((previous_totals, new_totals))
    }

    pub(crate) fn remove_line(&mut self, id: &LineItemId) -> Result<LineTotals, PosError> {
        self.ensure_mutable()?;
        let line = self
            .lines
            .get(id)
            .ok_or_else(|| PosError::LineItemNotFound(id.clone()))?;
        let totals = line.compute(self.rounding)?;
        self.lines.remove(id);
        Ok(totals)
    }

    /// Remove an active line item and hand it to the caller (POS-02 moves).
    pub(crate) fn take_line(&mut self, id: &LineItemId) -> Result<LineItem, PosError> {
        self.ensure_mutable()?;
        if self.voided_lines.contains_key(id) {
            return Err(PosError::LineItemVoided(id.clone()));
        }
        self.lines
            .remove(id)
            .ok_or_else(|| PosError::LineItemNotFound(id.clone()))
    }

    /// Void a line item without removing it. The line stays for audit and is
    /// excluded from totals.
    pub(crate) fn void_line(
        &mut self,
        id: &LineItemId,
        record: VoidRecord,
    ) -> Result<(), PosError> {
        self.ensure_mutable()?;
        if !self.lines.contains_key(id) {
            return Err(PosError::LineItemNotFound(id.clone()));
        }
        if self.voided_lines.contains_key(id) {
            return Err(PosError::LineItemAlreadyVoided(id.clone()));
        }
        self.voided_lines.insert(id.clone(), record);
        Ok(())
    }

    /// Void a linked payment without removing it. The payment stays for audit
    /// and is excluded from `paid_total`.
    pub(crate) fn void_payment(
        &mut self,
        id: &PaymentId,
        record: VoidRecord,
    ) -> Result<(), PosError> {
        self.ensure_mutable()?;
        if !self.payments.contains_key(id) {
            return Err(PosError::PaymentLinkNotFound(id.clone()));
        }
        if self.voided_payments.contains_key(id) {
            return Err(PosError::PaymentAlreadyVoided(id.clone()));
        }
        if let Some(payment) = self.payments.get_mut(id) {
            payment.status = PaymentStatus::Voided;
        }
        self.voided_payments.insert(id.clone(), record);
        Ok(())
    }

    /// Remove an active (not voided) payment and hand it to the caller.
    pub(crate) fn take_payment(&mut self, id: &PaymentId) -> Result<PaymentLink, PosError> {
        self.ensure_mutable()?;
        if self.voided_payments.contains_key(id) {
            return Err(PosError::PaymentVoided(id.clone()));
        }
        self.payments
            .remove(id)
            .ok_or_else(|| PosError::PaymentLinkNotFound(id.clone()))
    }

    /// Split `amount` off one payment into a new payment link with
    /// `target_id`, preserving method, status and processor reference.
    ///
    /// The source amount is reduced by exactly `amount`; a full-amount split
    /// removes the source link. The two amounts always sum to the original.
    pub(crate) fn split_payment_off(
        &mut self,
        id: &PaymentId,
        target_id: PaymentId,
        amount: Money,
    ) -> Result<PaymentLink, PosError> {
        self.ensure_mutable()?;
        self.require_currency(amount)?;
        if !amount.is_positive() {
            return Err(PosError::NonPositiveAmount);
        }
        let source = self
            .payments
            .get(id)
            .cloned()
            .ok_or_else(|| PosError::PaymentLinkNotFound(id.clone()))?;
        if self.voided_payments.contains_key(id) || source.status == PaymentStatus::Voided {
            return Err(PosError::PaymentVoided(id.clone()));
        }
        if amount.minor() > source.amount.minor() {
            return Err(PosError::PaymentAllocationExceeds {
                requested: amount,
                available: source.amount,
            });
        }
        if amount == source.amount {
            self.payments.remove(id);
        } else {
            let remaining = source.amount.checked_sub(amount)?;
            if let Some(payment) = self.payments.get_mut(id) {
                payment.amount = remaining;
            }
        }
        let mut part = source;
        part.id = target_id;
        part.amount = amount;
        Ok(part)
    }

    /// Split `amount` of the tip off into the returned value, leaving the rest
    /// on this check. The two parts always sum to the original tip.
    pub(crate) fn split_tip(&mut self, amount: Money) -> Result<Money, PosError> {
        self.ensure_mutable()?;
        self.require_currency(amount)?;
        if amount.is_negative() {
            return Err(PosError::NegativeAmount);
        }
        if amount.minor() > self.tip.minor() {
            return Err(PosError::TipAllocationExceeds {
                requested: amount,
                available: self.tip,
            });
        }
        self.tip = self.tip.checked_sub(amount)?;
        Ok(amount)
    }

    /// Mark a source check as merged after its active content has been moved.
    /// The check must carry no active lines, active payments or tip.
    pub(crate) fn mark_merged(&mut self, target: CheckId) -> Result<(), PosError> {
        self.ensure_transition(CheckStatus::Merged)?;
        let active_lines = self
            .lines
            .keys()
            .filter(|id| !self.voided_lines.contains_key(*id))
            .count();
        let active_payments = self
            .payments
            .keys()
            .filter(|id| !self.voided_payments.contains_key(*id))
            .count();
        if active_lines != 0 || active_payments != 0 || !self.tip.is_zero() {
            return Err(PosError::AmbiguousMerge(
                "source still carries active lines, payments or tip",
            ));
        }
        self.status = CheckStatus::Merged;
        self.merged_into = Some(target);
        self.seal()?;
        Ok(())
    }

    pub(crate) fn set_tip(&mut self, tip: Money) -> Result<Money, PosError> {
        self.ensure_mutable()?;
        self.require_currency(tip)?;
        if tip.is_negative() {
            return Err(PosError::NegativeAmount);
        }
        let previous = self.tip;
        self.tip = tip;
        Ok(previous)
    }

    pub(crate) fn link_payment(&mut self, payment: PaymentLink) -> Result<(), PosError> {
        self.ensure_mutable()?;
        self.require_currency(payment.amount())?;
        if self.payments.contains_key(payment.id()) {
            return Err(PosError::PaymentAlreadyLinked(payment.id().clone()));
        }
        self.payments.insert(payment.id().clone(), payment);
        Ok(())
    }

    pub(crate) fn hold(&mut self) -> Result<(), PosError> {
        self.ensure_transition(CheckStatus::Held)?;
        self.status = CheckStatus::Held;
        Ok(())
    }

    pub(crate) fn resume(&mut self) -> Result<(), PosError> {
        self.ensure_transition(CheckStatus::Open)?;
        self.status = CheckStatus::Open;
        Ok(())
    }

    /// Close a fully settled check and return its frozen grand total.
    pub(crate) fn close(&mut self) -> Result<Money, PosError> {
        self.ensure_transition(CheckStatus::Closed)?;
        if self.lines.is_empty() {
            return Err(PosError::EmptyCheck);
        }
        let totals = self.totals()?;
        if !totals.amount_due.is_zero() {
            return Err(PosError::CheckNotFullyPaid {
                amount_due: totals.amount_due,
            });
        }
        self.status = CheckStatus::Closed;
        self.seal()
    }

    /// Void a check and return its frozen grand total.
    pub(crate) fn void(&mut self) -> Result<Money, PosError> {
        self.ensure_transition(CheckStatus::Voided)?;
        self.status = CheckStatus::Voided;
        self.seal()
    }

    /// Record a refund on a closed check. Returns `true` when this refund
    /// settled the whole captured amount and moved the check to `Refunded`.
    pub(crate) fn record_refund(&mut self, refund: Refund) -> Result<bool, PosError> {
        if self.status != CheckStatus::Closed && self.status != CheckStatus::Refunded {
            return Err(PosError::CheckNotClosed {
                status: self.status,
            });
        }
        self.require_currency(refund.amount())?;
        if self.refunds.contains_key(refund.id()) {
            return Err(PosError::RefundAlreadyRecorded(refund.id().clone()));
        }
        let paid = self.captured_total()?;
        let refunded = self.refunded_total()?;
        let remaining = paid.checked_sub(refunded)?;
        if !remaining.is_positive() {
            return Err(PosError::NothingToRefund);
        }
        if refund.amount().minor() > remaining.minor() {
            return Err(PosError::RefundExceedsPaid {
                requested: refund.amount(),
                remaining,
            });
        }

        let new_refunded = refunded.checked_add(refund.amount())?;
        self.refunds.insert(refund.id().clone(), refund);
        if new_refunded == paid {
            self.status = CheckStatus::Refunded;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
