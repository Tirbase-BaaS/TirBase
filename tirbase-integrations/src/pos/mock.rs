// SPDX-License-Identifier: Apache-2.0

//! Mock POS vendors: a payment terminal, an accounting API, a delivery platform
//! and a tax authority.
//!
//! The mocks enforce the rules a real vendor is supposed to enforce — they
//! validate the operation, deduplicate on the idempotency key, refuse an
//! over-capture and an over-refund, keep a settlement report and can inject
//! transient failures — so a connector can be developed and certified without a
//! sandbox account. They hold only opaque payment tokens: a charge record never
//! contains card data.
//!
//! [`MockPosVendor`] composes all four into one connector for the conformance
//! suite.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use crate::connector::ConnectorHealth;

use super::contract::{
    AuthorizeRequest, CaptureRequest, CreditNote, DeliveryCancel, DeliveryOrder, DeliveryStatus,
    Invoice, JournalEntry, OperationResult, PosCapabilities, PosConnector, PosOperation,
    RefundRequest, TaxQuery, TaxVerify, VoidRequest,
};
use super::reconcile::{ReconciliationSource, RemoteSettlement};
use super::{Amount, PosFamily};

fn lock<T>(inner: &Mutex<T>) -> MutexGuard<'_, T> {
    inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn validate(operation: PosOperation) -> Option<OperationResult> {
    operation
        .validate()
        .err()
        .map(|error| OperationResult::permanent(error.to_string()))
}

/// How the mock terminal misbehaves, if at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MockTerminalConfig {
    /// Data requests to reject as retryable before behaving.
    pub fail_first: usize,
    /// Report an amount one minor unit above the requested one.
    pub report_wrong_amount: bool,
    /// Decline every authorisation permanently.
    pub decline: bool,
    /// Seconds between capture and the vendor confirming settlement.
    pub settle_delay_secs: i64,
}

/// One charge the mock terminal recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeRecord {
    /// Vendor charge id.
    pub reference: String,
    /// Idempotency key presented.
    pub key: String,
    /// `authorize`, `capture` or `refund`.
    pub kind: String,
    /// Amount recorded.
    pub amount: Amount,
    /// Refund reason, empty for a sale.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthState {
    amount: Amount,
    captured_minor: i64,
    refunded_minor: i64,
    voided: bool,
}

#[derive(Debug, Default)]
struct TerminalState {
    charges: Vec<ChargeRecord>,
    by_key: BTreeMap<String, usize>,
    authorizations: BTreeMap<String, AuthState>,
    net: BTreeMap<String, (Amount, i64)>,
    failures: usize,
}

/// A mock payment terminal with card-data-free charge records.
pub struct MockPaymentTerminal {
    name: String,
    config: MockTerminalConfig,
    inner: Mutex<TerminalState>,
}

impl MockPaymentTerminal {
    /// A terminal that behaves.
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_config(name, MockTerminalConfig::default())
    }

    /// A terminal with explicit misbehaviour.
    pub fn with_config(name: impl Into<String>, config: MockTerminalConfig) -> Self {
        Self {
            name: name.into(),
            config,
            inner: Mutex::new(TerminalState {
                failures: config.fail_first,
                ..TerminalState::default()
            }),
        }
    }

    /// Every charge recorded, oldest first.
    pub fn charges(&self) -> Vec<ChargeRecord> {
        lock(&self.inner).charges.clone()
    }

    /// How many charges were recorded.
    pub fn charge_count(&self) -> usize {
        lock(&self.inner).charges.len()
    }

    /// Replace the failure budget.
    pub fn set_failures(&self, count: usize) {
        lock(&self.inner).failures = count;
    }

    fn next_charge(
        state: &mut TerminalState,
        request: &mut ChargeBuilder<'_>,
        amount: &Amount,
    ) -> String {
        let reference = format!("chg-{:06}", state.charges.len() + 1);
        state.charges.push(ChargeRecord {
            reference: reference.clone(),
            key: request.key.to_string(),
            kind: request.kind.to_string(),
            amount: amount.clone(),
            reason: request.reason.to_string(),
        });
        let index = state.charges.len() - 1;
        state.by_key.insert(request.key.to_string(), index);
        reference
    }

    fn replay(state: &TerminalState, key: &str) -> Option<OperationResult> {
        state.by_key.get(key).map(|index| {
            let charge = &state.charges[*index];
            OperationResult::replayed(charge.reference.clone(), Some(charge.amount.clone()))
        })
    }

    fn inject_failure(state: &mut TerminalState) -> Option<OperationResult> {
        if state.failures == 0 {
            return None;
        }
        state.failures -= 1;
        Some(OperationResult::retryable(
            "terminal temporarily unavailable",
        ))
    }
}

struct ChargeBuilder<'a> {
    key: &'a str,
    kind: &'a str,
    reason: &'a str,
}

impl PosConnector for MockPaymentTerminal {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&[PosFamily::Payment])
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("mock terminal ready")
    }

    fn authorize(&self, request: &AuthorizeRequest) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::Authorize(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(failure) = Self::inject_failure(&mut state) {
            return failure;
        }
        if self.config.decline {
            return OperationResult::permanent("declined: do not honour");
        }
        if let Some(replay) = Self::replay(&state, &request.idempotency_key) {
            return replay;
        }
        let mut builder = ChargeBuilder {
            key: request.idempotency_key.as_str(),
            kind: "authorize",
            reason: "",
        };
        let reference = Self::next_charge(&mut state, &mut builder, &request.amount);
        state.authorizations.insert(
            request.payment_intent.clone(),
            AuthState {
                amount: request.amount.clone(),
                captured_minor: if request.capture {
                    request.amount.minor
                } else {
                    0
                },
                refunded_minor: 0,
                voided: false,
            },
        );
        if request.capture {
            state.net.insert(
                request.payment_intent.clone(),
                (
                    request.amount.clone(),
                    request
                        .requested_est
                        .saturating_add(self.config.settle_delay_secs),
                ),
            );
        }
        let recorded = if self.config.report_wrong_amount {
            Amount {
                currency: request.amount.currency.clone(),
                minor: request.amount.minor.saturating_add(1),
            }
        } else {
            request.amount.clone()
        };
        OperationResult::accepted(reference, Some(recorded))
    }

    fn capture(&self, request: &CaptureRequest) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::Capture(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(failure) = Self::inject_failure(&mut state) {
            return failure;
        }
        if let Some(replay) = Self::replay(&state, &request.idempotency_key) {
            return replay;
        }
        {
            let Some(authorization) = state.authorizations.get_mut(&request.payment_intent) else {
                return OperationResult::permanent("unknown authorisation");
            };
            if authorization.voided {
                return OperationResult::permanent("the authorisation was voided");
            }
            if authorization.amount.currency != request.amount.currency {
                return OperationResult::permanent(
                    "capture currency differs from the authorisation",
                );
            }
            let remaining = authorization.amount.minor - authorization.captured_minor;
            if request.amount.minor > remaining {
                return OperationResult::permanent(format!(
                    "capture of {} exceeds the remaining {} minor units",
                    request.amount.minor, remaining
                ));
            }
            authorization.captured_minor += request.amount.minor;
        }
        let mut builder = ChargeBuilder {
            key: request.idempotency_key.as_str(),
            kind: "capture",
            reason: "",
        };
        let reference = Self::next_charge(&mut state, &mut builder, &request.amount);
        let entry = state
            .net
            .entry(request.payment_intent.clone())
            .or_insert_with(|| (request.amount.clone(), request.requested_est));
        entry.0.minor = entry.0.minor.saturating_add(request.amount.minor);
        entry.1 = request.requested_est;
        OperationResult::accepted(reference, Some(request.amount.clone()))
    }

    fn void(&self, request: &VoidRequest) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::Void(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(failure) = Self::inject_failure(&mut state) {
            return failure;
        }
        if let Some(replay) = Self::replay(&state, &request.idempotency_key) {
            return replay;
        }
        let currency = {
            let Some(authorization) = state.authorizations.get_mut(&request.payment_intent) else {
                return OperationResult::permanent("unknown authorisation");
            };
            if authorization.captured_minor > 0 {
                return OperationResult::permanent("a captured authorisation cannot be voided");
            }
            authorization.voided = true;
            authorization.amount.currency.clone()
        };
        let mut builder = ChargeBuilder {
            key: request.idempotency_key.as_str(),
            kind: "void",
            reason: "",
        };
        let reference = Self::next_charge(&mut state, &mut builder, &Amount { currency, minor: 0 });
        OperationResult::accepted(reference, None)
    }

    fn refund(&self, request: &RefundRequest) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::Refund(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(failure) = Self::inject_failure(&mut state) {
            return failure;
        }
        if let Some(replay) = Self::replay(&state, &request.idempotency_key) {
            return replay;
        }
        {
            let Some(authorization) = state.authorizations.get_mut(&request.payment_intent) else {
                return OperationResult::permanent("unknown authorisation");
            };
            if authorization.amount.currency != request.amount.currency {
                return OperationResult::permanent("refund currency differs from the capture");
            }
            let refundable = authorization.captured_minor - authorization.refunded_minor;
            if request.amount.minor > refundable {
                return OperationResult::permanent(format!(
                    "refund of {} exceeds the refundable {} minor units",
                    request.amount.minor, refundable
                ));
            }
            authorization.refunded_minor += request.amount.minor;
        }
        let mut builder = ChargeBuilder {
            key: request.idempotency_key.as_str(),
            kind: "refund",
            reason: request.reason.as_str(),
        };
        let reference = Self::next_charge(&mut state, &mut builder, &request.amount);
        let entry = state
            .net
            .entry(request.payment_intent.clone())
            .or_insert_with(|| (request.amount.clone(), request.requested_est));
        entry.0.minor = entry.0.minor.saturating_sub(request.amount.minor);
        entry.1 = request.requested_est;
        OperationResult::accepted(reference, Some(request.amount.clone()))
    }
}

impl ReconciliationSource for MockPaymentTerminal {
    fn settlements(&self, _tenant: &str) -> Vec<RemoteSettlement> {
        lock(&self.inner)
            .net
            .iter()
            .map(|(reference, (amount, settled_est))| RemoteSettlement {
                reference: reference.clone(),
                amount: amount.clone(),
                settled_est: Some(*settled_est),
            })
            .collect()
    }
}

/// One journal entry the mock accounting API accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRecord {
    /// Business reference.
    pub reference: String,
    /// Vendor entry id.
    pub entry_id: String,
    /// Currency of the entry.
    pub currency: String,
    /// Total debits in minor units.
    pub debit_minor: i64,
    /// Total credits in minor units.
    pub credit_minor: i64,
}

#[derive(Debug, Default)]
struct AccountingState {
    entries: Vec<EntryRecord>,
    by_reference: BTreeMap<String, usize>,
    by_key: BTreeMap<String, usize>,
}

/// A mock double-entry accounting API.
pub struct MockAccountingApi {
    name: String,
    inner: Mutex<AccountingState>,
}

impl MockAccountingApi {
    /// An accounting API that accepts balanced entries.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: Mutex::new(AccountingState::default()),
        }
    }

    /// Entries posted, oldest first.
    pub fn entries(&self) -> Vec<EntryRecord> {
        lock(&self.inner).entries.clone()
    }
}

impl PosConnector for MockAccountingApi {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&[PosFamily::Accounting])
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("mock ledger ready")
    }

    fn post_entry(&self, request: &JournalEntry) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::PostEntry(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(index) = state.by_key.get(&request.idempotency_key) {
            let entry = &state.entries[*index];
            return OperationResult::replayed(
                entry.entry_id.clone(),
                Some(Amount {
                    currency: entry.currency.clone(),
                    minor: entry.debit_minor,
                }),
            );
        }
        if state.by_reference.contains_key(&request.reference) {
            return OperationResult::permanent("this reference is already posted");
        }
        let debit = request.debit_total();
        let Ok(debit) = debit else {
            return OperationResult::permanent("journal entry has no debits");
        };
        let entry_id = format!("jrn-{:06}", state.entries.len() + 1);
        state.entries.push(EntryRecord {
            reference: request.reference.clone(),
            entry_id: entry_id.clone(),
            currency: debit.currency.clone(),
            debit_minor: debit.minor,
            credit_minor: debit.minor,
        });
        let index = state.entries.len() - 1;
        state.by_reference.insert(request.reference.clone(), index);
        state.by_key.insert(request.idempotency_key.clone(), index);
        OperationResult::accepted(entry_id, Some(debit))
    }
}

/// One delivery job the mock platform booked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    /// Sale or order reference.
    pub reference: String,
    /// Vendor job id.
    pub job_id: String,
    /// `booked` or `cancelled`.
    pub status: String,
    /// Drop-off address.
    pub dropoff: String,
}

#[derive(Debug, Default)]
struct DeliveryState {
    jobs: Vec<JobRecord>,
    by_reference: BTreeMap<String, usize>,
    by_key: BTreeMap<String, usize>,
}

/// A mock courier platform.
pub struct MockDeliveryPlatform {
    name: String,
    inner: Mutex<DeliveryState>,
}

impl MockDeliveryPlatform {
    /// A courier platform that books jobs.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: Mutex::new(DeliveryState::default()),
        }
    }

    /// Jobs booked, oldest first.
    pub fn jobs(&self) -> Vec<JobRecord> {
        lock(&self.inner).jobs.clone()
    }
}

impl PosConnector for MockDeliveryPlatform {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&[PosFamily::Delivery])
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("mock courier ready")
    }

    fn create_delivery(&self, request: &DeliveryOrder) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::CreateDelivery(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(index) = state.by_key.get(&request.idempotency_key) {
            let job = &state.jobs[*index];
            return OperationResult::replayed(job.job_id.clone(), request.amount.clone());
        }
        if state.by_reference.contains_key(&request.reference) {
            return OperationResult::permanent("this order already has a delivery");
        }
        let job_id = format!("job-{:06}", state.jobs.len() + 1);
        state.jobs.push(JobRecord {
            reference: request.reference.clone(),
            job_id: job_id.clone(),
            status: "booked".to_string(),
            dropoff: request.dropoff.clone(),
        });
        let index = state.jobs.len() - 1;
        state.by_reference.insert(request.reference.clone(), index);
        state.by_key.insert(request.idempotency_key.clone(), index);
        OperationResult::accepted(job_id, request.amount.clone())
    }

    fn cancel_delivery(&self, request: &DeliveryCancel) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::CancelDelivery(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(index) = state.by_key.get(&request.idempotency_key) {
            let job = &state.jobs[*index];
            return OperationResult::replayed(job.job_id.clone(), None);
        }
        let Some(index) = state.by_reference.get(&request.reference).copied() else {
            return OperationResult::permanent("unknown delivery");
        };
        state.jobs[index].status = "cancelled".to_string();
        state.by_key.insert(request.idempotency_key.clone(), index);
        let job_id = state.jobs[index].job_id.clone();
        OperationResult::accepted(job_id, None)
    }

    fn delivery_status(&self, request: &DeliveryStatus) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::DeliveryStatus(request.clone())) {
            return refusal;
        }
        let state = lock(&self.inner);
        let Some(index) = state.by_reference.get(&request.reference).copied() else {
            return OperationResult::permanent("unknown delivery");
        };
        let job = &state.jobs[index];
        let mut result = OperationResult::accepted(job.job_id.clone(), None);
        result.detail = format!("status {}", job.status);
        result
    }
}

#[derive(Debug, Default)]
struct TaxState {
    quotes: BTreeMap<String, Amount>,
    by_key: BTreeMap<String, String>,
}

/// A mock tax authority with three rate codes.
pub struct MockTaxAuthority {
    name: String,
    rates: BTreeMap<String, u32>,
    inner: Mutex<TaxState>,
}

impl MockTaxAuthority {
    /// An authority that knows `standard` (21%), `reduced` (10%) and `zero`.
    pub fn new(name: impl Into<String>) -> Self {
        let mut rates = BTreeMap::new();
        rates.insert("standard".to_string(), 2_100);
        rates.insert("reduced".to_string(), 1_000);
        rates.insert("zero".to_string(), 0);
        Self {
            name: name.into(),
            rates,
            inner: Mutex::new(TaxState::default()),
        }
    }

    fn tax_for(&self, tax_code: &str, amount: &Amount) -> Option<Amount> {
        let basis_points = *self.rates.get(tax_code)?;
        let numerator = i128::from(amount.minor) * i128::from(basis_points) + 5_000;
        let minor = i64::try_from(numerator / 10_000).unwrap_or(i64::MAX);
        Amount::new(&amount.currency, minor).ok()
    }
}

impl PosConnector for MockTaxAuthority {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&[PosFamily::Tax])
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("mock tax authority ready")
    }

    fn quote_tax(&self, request: &TaxQuery) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::QuoteTax(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.inner);
        if let Some(reference) = state.by_key.get(&request.idempotency_key) {
            let amount = state.quotes.get(reference).cloned();
            return OperationResult::replayed(reference.clone(), amount);
        }
        let Some(first) = request.lines.first() else {
            return OperationResult::permanent("a quote needs at least one line");
        };
        let mut total = Amount {
            currency: first.amount.currency.clone(),
            minor: 0,
        };
        for line in &request.lines {
            let Some(tax) = self.tax_for(&line.tax_code, &line.amount) else {
                return OperationResult::permanent(format!("unknown tax code {:?}", line.tax_code));
            };
            if tax.currency != total.currency {
                return OperationResult::permanent("mixed currencies in one quote");
            }
            total.minor = total.minor.saturating_add(tax.minor);
        }
        state
            .quotes
            .insert(request.reference.clone(), total.clone());
        state
            .by_key
            .insert(request.idempotency_key.clone(), request.reference.clone());
        OperationResult::accepted(request.reference.clone(), Some(total))
    }

    fn verify_tax(&self, request: &TaxVerify) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::VerifyTax(request.clone())) {
            return refusal;
        }
        let state = lock(&self.inner);
        let Some(quoted) = state.quotes.get(&request.reference) else {
            return OperationResult::permanent("no quote for this reference");
        };
        if !quoted.matches(&request.expected) {
            return OperationResult::permanent(format!(
                "quoted {} does not match the expected {}",
                quoted.minor, request.expected.minor
            ));
        }
        let mut result = OperationResult::accepted(request.reference.clone(), Some(quoted.clone()));
        result.detail = "tax verified".to_string();
        result
    }
}

#[derive(Debug, Default)]
struct InvoiceState {
    invoices: BTreeMap<String, Amount>,
    credited: BTreeMap<String, i64>,
    by_key: BTreeMap<String, String>,
}

/// All four mocks behind one connector, for the conformance suite.
pub struct MockPosVendor {
    name: String,
    payments: MockPaymentTerminal,
    accounting: MockAccountingApi,
    delivery: MockDeliveryPlatform,
    tax: MockTaxAuthority,
    invoices: Mutex<InvoiceState>,
}

impl MockPosVendor {
    /// A vendor serving all five families.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            payments: MockPaymentTerminal::new(format!("{name}-payments")),
            accounting: MockAccountingApi::new(format!("{name}-accounting")),
            delivery: MockDeliveryPlatform::new(format!("{name}-delivery")),
            tax: MockTaxAuthority::new(format!("{name}-tax")),
            invoices: Mutex::new(InvoiceState::default()),
            name,
        }
    }

    /// The payment terminal behind this vendor.
    pub fn payments(&self) -> &MockPaymentTerminal {
        &self.payments
    }

    /// The accounting API behind this vendor.
    pub fn accounting(&self) -> &MockAccountingApi {
        &self.accounting
    }

    /// The delivery platform behind this vendor.
    pub fn delivery(&self) -> &MockDeliveryPlatform {
        &self.delivery
    }

    /// The tax authority behind this vendor.
    pub fn tax(&self) -> &MockTaxAuthority {
        &self.tax
    }
}

impl PosConnector for MockPosVendor {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&PosFamily::all())
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("mock POS vendor ready")
    }

    fn authorize(&self, request: &AuthorizeRequest) -> OperationResult {
        self.payments.authorize(request)
    }

    fn capture(&self, request: &CaptureRequest) -> OperationResult {
        self.payments.capture(request)
    }

    fn void(&self, request: &VoidRequest) -> OperationResult {
        self.payments.void(request)
    }

    fn refund(&self, request: &RefundRequest) -> OperationResult {
        self.payments.refund(request)
    }

    fn post_entry(&self, request: &JournalEntry) -> OperationResult {
        self.accounting.post_entry(request)
    }

    fn issue_invoice(&self, request: &Invoice) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::IssueInvoice(request.clone())) {
            return refusal;
        }
        let Ok(total) = request.total() else {
            return OperationResult::permanent("an invoice needs a total");
        };
        let mut state = lock(&self.invoices);
        if let Some(number) = state.by_key.get(&request.idempotency_key) {
            let amount = state.invoices.get(number).cloned();
            return OperationResult::replayed(number.clone(), amount);
        }
        if state.invoices.contains_key(&request.number) {
            return OperationResult::permanent("this invoice number is already issued");
        }
        state.invoices.insert(request.number.clone(), total.clone());
        state
            .by_key
            .insert(request.idempotency_key.clone(), request.number.clone());
        let mut result = OperationResult::accepted(request.number.clone(), Some(total));
        result.detail = "invoice issued".to_string();
        result
    }

    fn credit_note(&self, request: &CreditNote) -> OperationResult {
        if let Some(refusal) = validate(PosOperation::CreditNote(request.clone())) {
            return refusal;
        }
        let mut state = lock(&self.invoices);
        if let Some(number) = state.by_key.get(&request.idempotency_key) {
            return OperationResult::replayed(number.clone(), Some(request.amount.clone()));
        }
        let Some(invoice_total) = state.invoices.get(&request.invoice_number).cloned() else {
            return OperationResult::permanent("unknown invoice");
        };
        let already = state
            .credited
            .get(&request.invoice_number)
            .copied()
            .unwrap_or(0);
        if request.amount.minor > invoice_total.minor.saturating_sub(already) {
            return OperationResult::permanent("the credit exceeds the invoice");
        }
        state.credited.insert(
            request.invoice_number.clone(),
            already + request.amount.minor,
        );
        state
            .by_key
            .insert(request.idempotency_key.clone(), request.number.clone());
        OperationResult::accepted(request.number.clone(), Some(request.amount.clone()))
    }

    fn create_delivery(&self, request: &DeliveryOrder) -> OperationResult {
        self.delivery.create_delivery(request)
    }

    fn cancel_delivery(&self, request: &DeliveryCancel) -> OperationResult {
        self.delivery.cancel_delivery(request)
    }

    fn delivery_status(&self, request: &DeliveryStatus) -> OperationResult {
        self.delivery.delivery_status(request)
    }

    fn quote_tax(&self, request: &TaxQuery) -> OperationResult {
        self.tax.quote_tax(request)
    }

    fn verify_tax(&self, request: &TaxVerify) -> OperationResult {
        self.tax.verify_tax(request)
    }
}

impl ReconciliationSource for MockPosVendor {
    fn settlements(&self, tenant: &str) -> Vec<RemoteSettlement> {
        self.payments.settlements(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pos::contract::AuthorizeRequest;
    use crate::pos::{PaymentMethodToken, PosOutcome};

    fn authorize(connector: &str, intent: &str, minor: i64) -> AuthorizeRequest {
        AuthorizeRequest::new(
            connector,
            "acme",
            intent,
            PaymentMethodToken::new("tok_terminal_1").expect("valid token"),
            Amount::new("EUR", minor).expect("valid amount"),
            true,
            10,
        )
    }

    #[test]
    fn the_terminal_deduplicates_and_refuses_a_second_capture() {
        let terminal = MockPaymentTerminal::new("terminal");
        let request = authorize("terminal", "intent-1", 2_500);
        let first = terminal.authorize(&request);
        assert_eq!(first.outcome, PosOutcome::Accepted);
        assert_eq!(terminal.authorize(&request).outcome, PosOutcome::Replayed);
        assert_eq!(terminal.charge_count(), 1);

        let over = CaptureRequest::new(
            "terminal",
            "acme",
            "intent-1",
            Amount::new("EUR", 1).expect("valid"),
            11,
            "over",
        );
        assert_eq!(terminal.capture(&over).outcome, PosOutcome::Permanent);
    }

    #[test]
    fn the_terminal_reports_a_wrong_amount_only_when_asked() {
        let terminal = MockPaymentTerminal::with_config(
            "terminal",
            MockTerminalConfig {
                report_wrong_amount: true,
                ..MockTerminalConfig::default()
            },
        );
        let result = terminal.authorize(&authorize("terminal", "intent-2", 2_500));
        assert_eq!(result.amount.map(|amount| amount.minor), Some(2_501));
    }
}
