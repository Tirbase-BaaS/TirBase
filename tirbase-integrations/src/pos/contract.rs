// SPDX-License-Identifier: Apache-2.0

//! The POS connector surface: typed requests per family and one trait.
//!
//! A connector implements [`PosConnector`] and overrides the methods for the
//! families it supports; every other method answers
//! [`OperationResult::unsupported`]. [`PosConnector::execute`] dispatches a
//! [`PosOperation`] to the right method, which is what the runtime and the
//! conformance suite drive, so a connector never writes its own dispatch.
//!
//! Requests are plain data. Their convenience constructors derive the
//! idempotency key and fill in the reference, but the invariant gate is
//! [`PosOperation::validate`]: the runtime calls it before every attempt, and a
//! connector must call it before touching the vendor, because the conformance
//! suite feeds malformed operations straight to the connector and requires a
//! [`PosOutcome::Permanent`] refusal.

use crate::connector::ConnectorHealth;

use super::pci::{assert_no_card_data, PaymentMethodToken};
use super::{
    pos_idempotency_key, Amount, PosError, PosFamily, PosOperationKind, MAX_REFERENCE_LEN,
    MAX_TENANT_LEN, POS_KEY_PREFIX,
};

fn require_text(field: &str, value: &str, max_len: usize) -> Result<(), PosError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PosError::Invariant {
            field: field.to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if trimmed.len() > max_len {
        return Err(PosError::Invariant {
            field: field.to_string(),
            detail: format!("must be at most {max_len} bytes"),
        });
    }
    assert_no_card_data(field, trimmed)
}

fn check_amount(field: &str, amount: &Amount) -> Result<(), PosError> {
    if !amount.is_valid() {
        return Err(PosError::Invariant {
            field: field.to_string(),
            detail: "must be a non-negative amount in a three-letter currency".to_string(),
        });
    }
    Ok(())
}

fn check_key(key: &str) -> Result<(), PosError> {
    if !key.starts_with(POS_KEY_PREFIX) || key.len() != POS_KEY_PREFIX.len() + 32 {
        return Err(PosError::Invariant {
            field: "idempotency_key".to_string(),
            detail: "must be derived by pos_idempotency_key".to_string(),
        });
    }
    if !key[POS_KEY_PREFIX.len()..]
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PosError::Invariant {
            field: "idempotency_key".to_string(),
            detail: "must be lower-case hexadecimal after the prefix".to_string(),
        });
    }
    Ok(())
}

/// What a connector promises across its families.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosCapabilities {
    /// Families the connector implements.
    pub families: Vec<PosFamily>,
    /// Whether delivering the same idempotency key twice is a duplicate, not a
    /// second vendor record.
    pub idempotent: bool,
    /// Whether the connector only ever receives opaque payment tokens.
    pub tokenizes_card_data: bool,
    /// Largest single operation it accepts, in minor units.
    pub max_amount_minor: i64,
    /// Currencies it accepts, as ISO-4217 codes.
    pub currencies: Vec<String>,
}

impl PosCapabilities {
    /// Capabilities for a connector serving `families`.
    pub fn for_families(families: &[PosFamily]) -> Self {
        Self {
            families: families.to_vec(),
            idempotent: true,
            tokenizes_card_data: true,
            max_amount_minor: 10_000_000,
            currencies: vec!["EUR".to_string(), "USD".to_string(), "GBP".to_string()],
        }
    }

    /// Whether the connector serves `family`.
    pub fn serves(&self, family: PosFamily) -> bool {
        self.families.contains(&family)
    }
}

/// One attempt's conclusion, uniform across every family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationResult {
    /// What happened.
    pub outcome: super::PosOutcome,
    /// Vendor reference (charge id, entry id, invoice id, job id).
    pub reference: String,
    /// Amount the vendor says it recorded, when the operation carries one.
    pub amount: Option<Amount>,
    /// Vendor `Retry-After`, when it supplied one.
    pub retry_after_secs: Option<u64>,
    /// Short evidence, safe to log.
    pub detail: String,
}

impl OperationResult {
    /// The vendor recorded it.
    pub fn accepted(reference: impl Into<String>, amount: Option<Amount>) -> Self {
        Self {
            outcome: super::PosOutcome::Accepted,
            reference: reference.into(),
            amount,
            retry_after_secs: None,
            detail: "accepted".to_string(),
        }
    }

    /// The vendor already had this idempotency key.
    pub fn replayed(reference: impl Into<String>, amount: Option<Amount>) -> Self {
        Self {
            outcome: super::PosOutcome::Replayed,
            reference: reference.into(),
            amount,
            retry_after_secs: None,
            detail: "replayed".to_string(),
        }
    }

    /// The vendor is temporarily unavailable.
    pub fn retryable(detail: impl Into<String>) -> Self {
        Self {
            outcome: super::PosOutcome::Retryable,
            reference: String::new(),
            amount: None,
            retry_after_secs: None,
            detail: detail.into(),
        }
    }

    /// The vendor refused permanently.
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            outcome: super::PosOutcome::Permanent,
            reference: String::new(),
            amount: None,
            retry_after_secs: None,
            detail: detail.into(),
        }
    }

    /// The connector does not implement this family.
    pub fn unsupported(family: PosFamily) -> Self {
        Self::permanent(format!("{} family is not supported", family.as_str()))
    }

    /// Whether the vendor recorded the operation.
    pub fn is_settled(&self) -> bool {
        self.outcome.is_settled()
    }

    /// Attach a `Retry-After` hint.
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_secs = Some(seconds);
        self
    }
}

/// Authorise a payment intent, optionally capturing in the same call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    /// Tenant.
    pub tenant: String,
    /// POS-03 payment intent id.
    pub payment_intent: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Opaque token from the terminal SDK.
    pub token: PaymentMethodToken,
    /// Amount to authorise.
    pub amount: Amount,
    /// Capture immediately (sale) rather than authorise only.
    pub capture: bool,
    /// When the request was made.
    pub requested_est: i64,
}

impl AuthorizeRequest {
    /// Build an authorisation request, deriving its idempotency key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connector: &str,
        tenant: &str,
        payment_intent: &str,
        token: PaymentMethodToken,
        amount: Amount,
        capture: bool,
        requested_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            payment_intent: payment_intent.to_string(),
            idempotency_key: pos_idempotency_key(connector, "authorize", payment_intent),
            token,
            amount,
            capture,
            requested_est,
        }
    }
}

/// Capture a previously authorised amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    /// Tenant.
    pub tenant: String,
    /// Payment intent id.
    pub payment_intent: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Amount to capture.
    pub amount: Amount,
    /// When the request was made.
    pub requested_est: i64,
}

impl CaptureRequest {
    /// Build a capture request, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        payment_intent: &str,
        amount: Amount,
        requested_est: i64,
        suffix: &str,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            payment_intent: payment_intent.to_string(),
            idempotency_key: pos_idempotency_key(
                connector,
                "capture",
                &format!("{payment_intent}:{suffix}"),
            ),
            amount,
            requested_est,
        }
    }
}

/// Void an authorisation before capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoidRequest {
    /// Tenant.
    pub tenant: String,
    /// Payment intent id.
    pub payment_intent: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// When the request was made.
    pub requested_est: i64,
}

impl VoidRequest {
    /// Build a void request, deriving its idempotency key.
    pub fn new(connector: &str, tenant: &str, payment_intent: &str, requested_est: i64) -> Self {
        Self {
            tenant: tenant.to_string(),
            payment_intent: payment_intent.to_string(),
            idempotency_key: pos_idempotency_key(connector, "void", payment_intent),
            requested_est,
        }
    }
}

/// Refund a captured amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundRequest {
    /// Tenant.
    pub tenant: String,
    /// Payment intent id.
    pub payment_intent: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Amount to refund.
    pub amount: Amount,
    /// Why the refund is being made (POS-05 parity).
    pub reason: String,
    /// When the request was made.
    pub requested_est: i64,
}

impl RefundRequest {
    /// Build a refund request, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        payment_intent: &str,
        amount: Amount,
        reason: &str,
        requested_est: i64,
        suffix: &str,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            payment_intent: payment_intent.to_string(),
            idempotency_key: pos_idempotency_key(
                connector,
                "refund",
                &format!("{payment_intent}:{suffix}"),
            ),
            amount,
            reason: reason.to_string(),
            requested_est,
        }
    }
}

/// Journal line direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Debit.
    Debit,
    /// Credit.
    Credit,
}

impl Direction {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Debit => "debit",
            Direction::Credit => "credit",
        }
    }
}

/// One journal line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalLine {
    /// Ledger account.
    pub account: String,
    /// Debit or credit.
    pub direction: Direction,
    /// Line amount.
    pub amount: Amount,
}

/// A balanced double-entry journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Tenant.
    pub tenant: String,
    /// Sale, refund or shift reference.
    pub reference: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Lines; debits must equal credits and share one currency.
    pub lines: Vec<JournalLine>,
    /// When the entry was posted.
    pub posted_est: i64,
}

impl JournalEntry {
    /// Build a journal entry, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        reference: &str,
        lines: Vec<JournalLine>,
        posted_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            reference: reference.to_string(),
            idempotency_key: pos_idempotency_key(connector, "journal-entry", reference),
            lines,
            posted_est,
        }
    }

    /// Sum of the debit lines.
    pub fn debit_total(&self) -> Result<Amount, PosError> {
        let currency = self
            .lines
            .first()
            .map(|line| line.amount.currency.clone())
            .ok_or_else(|| PosError::Invariant {
                field: "lines".to_string(),
                detail: "a journal entry needs at least one line".to_string(),
            })?;
        let mut total = Amount::zero(&currency)?;
        for line in &self.lines {
            if line.direction == Direction::Debit {
                total = total.checked_add(&line.amount)?;
            }
        }
        Ok(total)
    }

    /// Sum of the credit lines.
    pub fn credit_total(&self) -> Result<Amount, PosError> {
        let currency = self
            .lines
            .first()
            .map(|line| line.amount.currency.clone())
            .ok_or_else(|| PosError::Invariant {
                field: "lines".to_string(),
                detail: "a journal entry needs at least one line".to_string(),
            })?;
        let mut total = Amount::zero(&currency)?;
        for line in &self.lines {
            if line.direction == Direction::Credit {
                total = total.checked_add(&line.amount)?;
            }
        }
        Ok(total)
    }
}

/// One invoice line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceLine {
    /// Human-readable description.
    pub description: String,
    /// Whole quantity.
    pub quantity: u32,
    /// Unit price, tax-exclusive.
    pub unit: Amount,
}

impl InvoiceLine {
    /// Quantity times unit price.
    pub fn total(&self) -> Result<Amount, PosError> {
        self.unit.checked_mul(self.quantity)
    }
}

/// An invoice to issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// Tenant.
    pub tenant: String,
    /// Invoice number in the tenant's numbering series.
    pub number: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Customer reference (an id, not a name or card detail).
    pub customer: String,
    /// Lines.
    pub lines: Vec<InvoiceLine>,
    /// When the invoice was issued.
    pub issued_est: i64,
}

impl Invoice {
    /// Build an invoice, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        number: &str,
        customer: &str,
        lines: Vec<InvoiceLine>,
        issued_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            number: number.to_string(),
            idempotency_key: pos_idempotency_key(connector, "invoice", number),
            customer: customer.to_string(),
            lines,
            issued_est,
        }
    }

    /// Sum of the line totals.
    pub fn total(&self) -> Result<Amount, PosError> {
        let currency = self
            .lines
            .first()
            .map(|line| line.unit.currency.clone())
            .ok_or_else(|| PosError::Invariant {
                field: "lines".to_string(),
                detail: "an invoice needs at least one line".to_string(),
            })?;
        let mut total = Amount::zero(&currency)?;
        for line in &self.lines {
            let line_total = line.total()?;
            total = total.checked_add(&line_total)?;
        }
        Ok(total)
    }
}

/// A credit note against an issued invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditNote {
    /// Tenant.
    pub tenant: String,
    /// Invoice being credited.
    pub invoice_number: String,
    /// Credit-note number in the tenant's series.
    pub number: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Amount credited.
    pub amount: Amount,
    /// Why it was issued.
    pub reason: String,
    /// When it was issued.
    pub issued_est: i64,
}

impl CreditNote {
    /// Build a credit note, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        invoice_number: &str,
        number: &str,
        amount: Amount,
        reason: &str,
        issued_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            invoice_number: invoice_number.to_string(),
            number: number.to_string(),
            idempotency_key: pos_idempotency_key(connector, "credit-note", number),
            amount,
            reason: reason.to_string(),
            issued_est,
        }
    }
}

/// A delivery job to book with a courier platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryOrder {
    /// Tenant.
    pub tenant: String,
    /// Sale or order reference.
    pub reference: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Drop-off address as free text (customer PII, never card data).
    pub dropoff: String,
    /// Courier instructions.
    pub notes: String,
    /// Declared value, when the courier requires one.
    pub amount: Option<Amount>,
    /// When the job was booked.
    pub requested_est: i64,
}

impl DeliveryOrder {
    /// Build a delivery order, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        reference: &str,
        dropoff: &str,
        notes: &str,
        amount: Option<Amount>,
        requested_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            reference: reference.to_string(),
            idempotency_key: pos_idempotency_key(connector, "delivery", reference),
            dropoff: dropoff.to_string(),
            notes: notes.to_string(),
            amount,
            requested_est,
        }
    }
}

/// Cancel a delivery job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryCancel {
    /// Tenant.
    pub tenant: String,
    /// Delivery reference.
    pub reference: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// When the cancel was requested.
    pub requested_est: i64,
}

impl DeliveryCancel {
    /// Build a cancel request, deriving its idempotency key.
    pub fn new(connector: &str, tenant: &str, reference: &str, requested_est: i64) -> Self {
        Self {
            tenant: tenant.to_string(),
            reference: reference.to_string(),
            idempotency_key: pos_idempotency_key(connector, "delivery-cancel", reference),
            requested_est,
        }
    }
}

/// Ask a courier platform for a job's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryStatus {
    /// Tenant.
    pub tenant: String,
    /// Delivery reference.
    pub reference: String,
}

impl DeliveryStatus {
    /// Build a status query.
    pub fn new(tenant: &str, reference: &str) -> Self {
        Self {
            tenant: tenant.to_string(),
            reference: reference.to_string(),
        }
    }
}

/// One taxed basket line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxQueryLine {
    /// Tax code the tenant assigns to the item.
    pub tax_code: String,
    /// Net amount the line is taxed on.
    pub amount: Amount,
}

/// A request for the tax due on a basket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxQuery {
    /// Tenant.
    pub tenant: String,
    /// Sale reference.
    pub reference: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Jurisdiction code (for example `ES-MAD`).
    pub jurisdiction: String,
    /// Basket lines.
    pub lines: Vec<TaxQueryLine>,
    /// When the quote was requested.
    pub requested_est: i64,
}

impl TaxQuery {
    /// Build a quote request, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        reference: &str,
        jurisdiction: &str,
        lines: Vec<TaxQueryLine>,
        requested_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            reference: reference.to_string(),
            idempotency_key: pos_idempotency_key(connector, "tax-quote", reference),
            jurisdiction: jurisdiction.to_string(),
            lines,
            requested_est,
        }
    }
}

/// Verify a previously quoted tax total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxVerify {
    /// Tenant.
    pub tenant: String,
    /// Quote reference.
    pub reference: String,
    /// Derived idempotency key.
    pub idempotency_key: String,
    /// Total the register expects the authority to confirm.
    pub expected: Amount,
    /// When the verification was requested.
    pub requested_est: i64,
}

impl TaxVerify {
    /// Build a verification request, deriving its idempotency key.
    pub fn new(
        connector: &str,
        tenant: &str,
        reference: &str,
        expected: Amount,
        requested_est: i64,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            reference: reference.to_string(),
            idempotency_key: pos_idempotency_key(connector, "tax-verify", reference),
            expected,
            requested_est,
        }
    }
}

/// One POS operation, grouped by family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PosOperation {
    /// Authorise (and optionally capture) a payment intent.
    Authorize(AuthorizeRequest),
    /// Capture an authorisation.
    Capture(CaptureRequest),
    /// Void an authorisation.
    Void(VoidRequest),
    /// Refund a captured amount.
    Refund(RefundRequest),
    /// Post a balanced journal entry.
    PostEntry(JournalEntry),
    /// Issue an invoice.
    IssueInvoice(Invoice),
    /// Issue a credit note.
    CreditNote(CreditNote),
    /// Book a delivery job.
    CreateDelivery(DeliveryOrder),
    /// Cancel a delivery job.
    CancelDelivery(DeliveryCancel),
    /// Query a delivery job.
    DeliveryStatus(DeliveryStatus),
    /// Quote the tax due on a basket.
    QuoteTax(TaxQuery),
    /// Verify a quoted tax total.
    VerifyTax(TaxVerify),
}

impl PosOperation {
    /// Family the operation belongs to.
    pub fn family(&self) -> PosFamily {
        match self {
            PosOperation::Authorize(_)
            | PosOperation::Capture(_)
            | PosOperation::Void(_)
            | PosOperation::Refund(_) => PosFamily::Payment,
            PosOperation::PostEntry(_) => PosFamily::Accounting,
            PosOperation::IssueInvoice(_) | PosOperation::CreditNote(_) => PosFamily::Einvoicing,
            PosOperation::CreateDelivery(_)
            | PosOperation::CancelDelivery(_)
            | PosOperation::DeliveryStatus(_) => PosFamily::Delivery,
            PosOperation::QuoteTax(_) | PosOperation::VerifyTax(_) => PosFamily::Tax,
        }
    }

    /// Stable operation kind, used in idempotency keys and logs.
    pub fn kind(&self) -> PosOperationKind {
        match self {
            PosOperation::Authorize(_) => PosOperationKind::Authorize,
            PosOperation::Capture(_) => PosOperationKind::Capture,
            PosOperation::Void(_) => PosOperationKind::Void,
            PosOperation::Refund(_) => PosOperationKind::Refund,
            PosOperation::PostEntry(_) => PosOperationKind::PostEntry,
            PosOperation::IssueInvoice(_) => PosOperationKind::IssueInvoice,
            PosOperation::CreditNote(_) => PosOperationKind::CreditNote,
            PosOperation::CreateDelivery(_) => PosOperationKind::CreateDelivery,
            PosOperation::CancelDelivery(_) => PosOperationKind::CancelDelivery,
            PosOperation::DeliveryStatus(_) => PosOperationKind::DeliveryStatus,
            PosOperation::QuoteTax(_) => PosOperationKind::QuoteTax,
            PosOperation::VerifyTax(_) => PosOperationKind::VerifyTax,
        }
    }

    /// Derived idempotency key of the operation.
    pub fn idempotency_key(&self) -> &str {
        match self {
            PosOperation::Authorize(request) => &request.idempotency_key,
            PosOperation::Capture(request) => &request.idempotency_key,
            PosOperation::Void(request) => &request.idempotency_key,
            PosOperation::Refund(request) => &request.idempotency_key,
            PosOperation::PostEntry(request) => &request.idempotency_key,
            PosOperation::IssueInvoice(request) => &request.idempotency_key,
            PosOperation::CreditNote(request) => &request.idempotency_key,
            PosOperation::CreateDelivery(request) => &request.idempotency_key,
            PosOperation::CancelDelivery(request) => &request.idempotency_key,
            PosOperation::DeliveryStatus(_) => "",
            PosOperation::QuoteTax(request) => &request.idempotency_key,
            PosOperation::VerifyTax(request) => &request.idempotency_key,
        }
    }

    /// The business reference the operation acts on.
    pub fn reference(&self) -> &str {
        match self {
            PosOperation::Authorize(request) => &request.payment_intent,
            PosOperation::Capture(request) => &request.payment_intent,
            PosOperation::Void(request) => &request.payment_intent,
            PosOperation::Refund(request) => &request.payment_intent,
            PosOperation::PostEntry(request) => &request.reference,
            PosOperation::IssueInvoice(request) => &request.number,
            PosOperation::CreditNote(request) => &request.number,
            PosOperation::CreateDelivery(request) => &request.reference,
            PosOperation::CancelDelivery(request) => &request.reference,
            PosOperation::DeliveryStatus(request) => &request.reference,
            PosOperation::QuoteTax(request) => &request.reference,
            PosOperation::VerifyTax(request) => &request.reference,
        }
    }

    /// The amount the vendor is expected to record, when the operation has one.
    ///
    /// The runtime compares it with the amount the connector reports, so a
    /// vendor that sweeps a different figure is caught instead of reconciled
    /// later.
    pub fn amount(&self) -> Option<Amount> {
        match self {
            PosOperation::Authorize(request) => Some(request.amount.clone()),
            PosOperation::Capture(request) => Some(request.amount.clone()),
            PosOperation::Void(_) => None,
            PosOperation::Refund(request) => Some(request.amount.clone()),
            PosOperation::PostEntry(request) => request.debit_total().ok(),
            PosOperation::IssueInvoice(request) => request.total().ok(),
            PosOperation::CreditNote(request) => Some(request.amount.clone()),
            PosOperation::CreateDelivery(request) => request.amount.clone(),
            PosOperation::CancelDelivery(_) | PosOperation::DeliveryStatus(_) => None,
            PosOperation::QuoteTax(_) => None,
            PosOperation::VerifyTax(request) => Some(request.expected.clone()),
        }
    }

    /// The tenant the operation belongs to.
    pub fn tenant(&self) -> &str {
        match self {
            PosOperation::Authorize(request) => &request.tenant,
            PosOperation::Capture(request) => &request.tenant,
            PosOperation::Void(request) => &request.tenant,
            PosOperation::Refund(request) => &request.tenant,
            PosOperation::PostEntry(request) => &request.tenant,
            PosOperation::IssueInvoice(request) => &request.tenant,
            PosOperation::CreditNote(request) => &request.tenant,
            PosOperation::CreateDelivery(request) => &request.tenant,
            PosOperation::CancelDelivery(request) => &request.tenant,
            PosOperation::DeliveryStatus(request) => &request.tenant,
            PosOperation::QuoteTax(request) => &request.tenant,
            PosOperation::VerifyTax(request) => &request.tenant,
        }
    }

    /// Validate every invariant before an attempt.
    ///
    /// A connector must call this first: the conformance suite hands malformed
    /// operations straight to the connector and requires a permanent refusal.
    pub fn validate(&self) -> Result<(), PosError> {
        require_text("tenant", self.tenant(), MAX_TENANT_LEN)?;
        require_text("reference", self.reference(), MAX_REFERENCE_LEN)?;
        match self {
            PosOperation::Authorize(request) => {
                check_key(&request.idempotency_key)?;
                check_amount("amount", &request.amount)?;
                if request.amount.minor == 0 {
                    return Err(PosError::InvalidAmount {
                        detail: "an authorisation must be greater than zero".to_string(),
                    });
                }
                if !request.token.is_valid() {
                    return Err(PosError::CardDataDetected {
                        field: "payment_method_token".to_string(),
                    });
                }
                Ok(())
            }
            PosOperation::Capture(request) => {
                check_key(&request.idempotency_key)?;
                check_amount("amount", &request.amount)?;
                if request.amount.minor == 0 {
                    return Err(PosError::InvalidAmount {
                        detail: "a capture must be greater than zero".to_string(),
                    });
                }
                Ok(())
            }
            PosOperation::Void(request) => check_key(&request.idempotency_key),
            PosOperation::Refund(request) => {
                check_key(&request.idempotency_key)?;
                check_amount("amount", &request.amount)?;
                require_text("reason", &request.reason, 240)
            }
            PosOperation::PostEntry(request) => {
                check_key(&request.idempotency_key)?;
                if request.lines.len() < 2 {
                    return Err(PosError::Invariant {
                        field: "lines".to_string(),
                        detail: "double entry needs at least two lines".to_string(),
                    });
                }
                for line in &request.lines {
                    require_text("account", &line.account, 64)?;
                    check_amount("line.amount", &line.amount)?;
                    if line.amount.minor == 0 {
                        return Err(PosError::InvalidAmount {
                            detail: "a journal line must be greater than zero".to_string(),
                        });
                    }
                }
                let debits = request.debit_total()?;
                let credits = request.credit_total()?;
                if !debits.matches(&credits) {
                    return Err(PosError::AmountMismatch {
                        reference: request.reference.clone(),
                        expected_minor: debits.minor,
                        got_minor: credits.minor,
                    });
                }
                Ok(())
            }
            PosOperation::IssueInvoice(request) => {
                check_key(&request.idempotency_key)?;
                require_text("customer", &request.customer, MAX_REFERENCE_LEN)?;
                if request.lines.is_empty() {
                    return Err(PosError::Invariant {
                        field: "lines".to_string(),
                        detail: "an invoice needs at least one line".to_string(),
                    });
                }
                for line in &request.lines {
                    require_text("line.description", &line.description, 240)?;
                    check_amount("line.unit", &line.unit)?;
                    if line.quantity == 0 || line.unit.minor == 0 {
                        return Err(PosError::Invariant {
                            field: "line".to_string(),
                            detail: "quantity and unit price must be greater than zero".to_string(),
                        });
                    }
                }
                let total = request.total()?;
                if total.minor == 0 {
                    return Err(PosError::InvalidAmount {
                        detail: "an invoice total must be greater than zero".to_string(),
                    });
                }
                Ok(())
            }
            PosOperation::CreditNote(request) => {
                check_key(&request.idempotency_key)?;
                require_text("invoice_number", &request.invoice_number, MAX_REFERENCE_LEN)?;
                check_amount("amount", &request.amount)?;
                require_text("reason", &request.reason, 240)
            }
            PosOperation::CreateDelivery(request) => {
                check_key(&request.idempotency_key)?;
                require_text("dropoff", &request.dropoff, 240)?;
                if let Some(amount) = &request.amount {
                    check_amount("amount", amount)?;
                }
                Ok(())
            }
            PosOperation::CancelDelivery(request) => check_key(&request.idempotency_key),
            PosOperation::DeliveryStatus(_) => Ok(()),
            PosOperation::QuoteTax(request) => {
                check_key(&request.idempotency_key)?;
                require_text("jurisdiction", &request.jurisdiction, 32)?;
                if request.lines.is_empty() {
                    return Err(PosError::Invariant {
                        field: "lines".to_string(),
                        detail: "a quote needs at least one line".to_string(),
                    });
                }
                for line in &request.lines {
                    require_text("line.tax_code", &line.tax_code, 32)?;
                    check_amount("line.amount", &line.amount)?;
                }
                Ok(())
            }
            PosOperation::VerifyTax(request) => {
                check_key(&request.idempotency_key)?;
                check_amount("expected", &request.expected)
            }
        }
    }
}

/// The connector contract.
///
/// Each method group is one family's interface. Default implementations answer
/// [`OperationResult::unsupported`], so a payments-only connector implements
/// [`Self::authorize`], [`Self::capture`], [`Self::void`] and [`Self::refund`]
/// and leaves the rest alone.
pub trait PosConnector: Send + Sync {
    /// Stable connector name, used in idempotency keys and logs.
    fn name(&self) -> &str;

    /// What the connector promises.
    fn capabilities(&self) -> PosCapabilities;

    /// Current readiness.
    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("ready")
    }

    /// Authorise (and optionally capture) a payment intent.
    fn authorize(&self, _request: &AuthorizeRequest) -> OperationResult {
        OperationResult::unsupported(PosFamily::Payment)
    }

    /// Capture an authorisation.
    fn capture(&self, _request: &CaptureRequest) -> OperationResult {
        OperationResult::unsupported(PosFamily::Payment)
    }

    /// Void an authorisation.
    fn void(&self, _request: &VoidRequest) -> OperationResult {
        OperationResult::unsupported(PosFamily::Payment)
    }

    /// Refund a captured amount.
    fn refund(&self, _request: &RefundRequest) -> OperationResult {
        OperationResult::unsupported(PosFamily::Payment)
    }

    /// Post a balanced journal entry.
    fn post_entry(&self, _request: &JournalEntry) -> OperationResult {
        OperationResult::unsupported(PosFamily::Accounting)
    }

    /// Issue an invoice.
    fn issue_invoice(&self, _request: &Invoice) -> OperationResult {
        OperationResult::unsupported(PosFamily::Einvoicing)
    }

    /// Issue a credit note.
    fn credit_note(&self, _request: &CreditNote) -> OperationResult {
        OperationResult::unsupported(PosFamily::Einvoicing)
    }

    /// Book a delivery job.
    fn create_delivery(&self, _request: &DeliveryOrder) -> OperationResult {
        OperationResult::unsupported(PosFamily::Delivery)
    }

    /// Cancel a delivery job.
    fn cancel_delivery(&self, _request: &DeliveryCancel) -> OperationResult {
        OperationResult::unsupported(PosFamily::Delivery)
    }

    /// Query a delivery job.
    fn delivery_status(&self, _request: &DeliveryStatus) -> OperationResult {
        OperationResult::unsupported(PosFamily::Delivery)
    }

    /// Quote the tax due on a basket.
    fn quote_tax(&self, _request: &TaxQuery) -> OperationResult {
        OperationResult::unsupported(PosFamily::Tax)
    }

    /// Verify a quoted tax total.
    fn verify_tax(&self, _request: &TaxVerify) -> OperationResult {
        OperationResult::unsupported(PosFamily::Tax)
    }

    /// Dispatch one operation to its family method.
    fn execute(&self, operation: &PosOperation) -> OperationResult {
        match operation {
            PosOperation::Authorize(request) => self.authorize(request),
            PosOperation::Capture(request) => self.capture(request),
            PosOperation::Void(request) => self.void(request),
            PosOperation::Refund(request) => self.refund(request),
            PosOperation::PostEntry(request) => self.post_entry(request),
            PosOperation::IssueInvoice(request) => self.issue_invoice(request),
            PosOperation::CreditNote(request) => self.credit_note(request),
            PosOperation::CreateDelivery(request) => self.create_delivery(request),
            PosOperation::CancelDelivery(request) => self.cancel_delivery(request),
            PosOperation::DeliveryStatus(request) => self.delivery_status(request),
            PosOperation::QuoteTax(request) => self.quote_tax(request),
            PosOperation::VerifyTax(request) => self.verify_tax(request),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pos::mock::MockPaymentTerminal;

    fn token() -> PaymentMethodToken {
        PaymentMethodToken::new("tok_test_5f2c1a").expect("valid token")
    }

    #[test]
    fn captured_amounts_must_be_positive_and_reasons_present() {
        let request = RefundRequest::new(
            "terminal",
            "acme",
            "intent-1",
            Amount::new("EUR", 100).expect("valid"),
            "",
            10,
            "r1",
        );
        assert!(PosOperation::Refund(request).validate().is_err());
    }

    #[test]
    fn unbalanced_journal_entries_are_refused() {
        let entry = JournalEntry::new(
            "ledger",
            "acme",
            "sale-1",
            vec![
                JournalLine {
                    account: "cash".to_string(),
                    direction: Direction::Debit,
                    amount: Amount::new("EUR", 1_000).expect("valid"),
                },
                JournalLine {
                    account: "sales".to_string(),
                    direction: Direction::Credit,
                    amount: Amount::new("EUR", 900).expect("valid"),
                },
            ],
            10,
        );
        assert!(matches!(
            PosOperation::PostEntry(entry).validate(),
            Err(PosError::AmountMismatch { .. })
        ));
    }

    #[test]
    fn dispatch_reaches_the_family_method() {
        let terminal = MockPaymentTerminal::new("terminal");
        let request = AuthorizeRequest::new(
            terminal.name(),
            "acme",
            "intent-1",
            token(),
            Amount::new("EUR", 500).expect("valid"),
            true,
            10,
        );
        let result = terminal.execute(&PosOperation::Authorize(request));
        assert!(result.is_settled());
        let unsupported = terminal.execute(&PosOperation::DeliveryStatus(DeliveryStatus::new(
            "acme", "order-1",
        )));
        assert_eq!(unsupported.outcome, super::super::PosOutcome::Permanent);
    }
}
