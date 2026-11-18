// SPDX-License-Identifier: Apache-2.0

//! Conformance suite a closed POS connector must pass.
//!
//! Point the suite at a connector wired to the mocks (or a vendor sandbox) and it
//! either certifies it or names every check it failed. It drives each family the
//! connector declares through a coherent sequence and requires:
//!
//! - honest classification (a transient failure is not permanent, and a refusal
//!   is not success);
//! - **replay safety** — the same idempotency key twice must be a duplicate, not
//!   a second charge, entry, invoice or job;
//! - **amount integrity** — the amount the vendor reports must be the amount the
//!   operation asked for, an over-capture and an over-refund must be refused, a
//!   journal must balance and a credit note may not exceed its invoice;
//! - **no card data** — no result detail may contain a card-number-shaped run.
//!
//! The suite is deterministic: every instant is `checked_est`.

use super::contract::{
    AuthorizeRequest, CaptureRequest, CreditNote, DeliveryCancel, DeliveryOrder, DeliveryStatus,
    Direction, Invoice, InvoiceLine, JournalEntry, JournalLine, OperationResult, PosConnector,
    RefundRequest, TaxQuery, TaxQueryLine, TaxVerify, VoidRequest,
};
use super::pci::{contains_card_data, PaymentMethodToken};
use super::{Amount, PosFamily, PosOutcome};

/// One check in a certification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosCheck {
    /// Check name.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// What was observed.
    pub detail: String,
}

/// Result of certifying one POS connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosCertificationReport {
    /// Connector name.
    pub connector: String,
    /// Families the connector declared.
    pub families: Vec<PosFamily>,
    /// Individual checks, in order.
    pub checks: Vec<PosCheck>,
    /// Whether every check passed.
    pub certified: bool,
    /// When certification ran.
    pub checked_est: i64,
}

impl PosCertificationReport {
    /// Failed checks.
    pub fn failures(&self) -> Vec<&PosCheck> {
        self.checks.iter().filter(|check| !check.passed).collect()
    }

    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "connector": self.connector,
            "families": self.families.iter().map(|family| family.as_str()).collect::<Vec<_>>(),
            "certified": self.certified,
            "checked_est": self.checked_est,
            "checks": self.checks.iter().map(|check| serde_json::json!({
                "name": check.name,
                "passed": check.passed,
                "detail": check.detail,
            })).collect::<Vec<_>>(),
        })
    }

    /// Compact human summary.
    pub fn summary(&self) -> String {
        let passed = self.checks.iter().filter(|check| check.passed).count();
        if self.certified {
            format!("{} certified ({} checks)", self.connector, passed)
        } else {
            let failures: Vec<&str> = self
                .failures()
                .iter()
                .map(|check| check.name.as_str())
                .collect();
            format!(
                "{} not certified: {}/{} checks passed, failed: {}",
                self.connector,
                passed,
                self.checks.len(),
                failures.join(", ")
            )
        }
    }
}

struct Suite<'connector> {
    connector: &'connector dyn PosConnector,
    name: String,
    tenant: String,
    checks: Vec<PosCheck>,
    details: Vec<String>,
}

impl Suite<'_> {
    fn check(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.checks.push(PosCheck {
            name: name.to_string(),
            passed,
            detail: detail.into(),
        });
    }

    fn settle(
        &mut self,
        name: &str,
        result: OperationResult,
        expected: PosOutcome,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        let passed = result.outcome == expected;
        let observed = format!(
            "{detail}: expected {}, got {} ({})",
            expected.as_str(),
            result.outcome.as_str(),
            result.detail
        );
        self.details.push(result.detail.clone());
        self.check(name, passed, observed);
    }

    fn amount(currency: &str, minor: i64) -> Amount {
        Amount {
            currency: currency.to_string(),
            minor,
        }
    }
}

/// Certify a POS connector against the standard suite.
pub fn certify_pos(connector: &dyn PosConnector, checked_est: i64) -> PosCertificationReport {
    let name = connector.name().to_string();
    let capabilities = connector.capabilities();
    let mut suite = Suite {
        connector,
        name: name.clone(),
        tenant: "conformance".to_string(),
        checks: Vec::new(),
        details: Vec::new(),
    };

    suite.check(
        "identity",
        !name.trim().is_empty()
            && name.len() <= 64
            && name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            }),
        format!("name {name:?}"),
    );

    let mut families = capabilities.families.clone();
    families.sort_unstable();
    families.dedup();
    suite.check(
        "families",
        !capabilities.families.is_empty() && families.len() == capabilities.families.len(),
        format!(
            "declares {:?}",
            capabilities
                .families
                .iter()
                .map(|family| family.as_str())
                .collect::<Vec<_>>()
        ),
    );
    suite.check(
        "idempotent-capability",
        capabilities.idempotent,
        format!("declares idempotent={}", capabilities.idempotent),
    );
    suite.check(
        "amount-ceiling",
        capabilities.max_amount_minor > 0,
        format!(
            "maximum single amount {} minor units",
            capabilities.max_amount_minor
        ),
    );
    let health = connector.health();
    suite.check("health", !health.detail.trim().is_empty(), health.detail);

    if capabilities.serves(PosFamily::Payment) {
        payment_checks(&mut suite, 2_500, checked_est);
    }
    if capabilities.serves(PosFamily::Accounting) {
        accounting_checks(&mut suite, checked_est);
    }
    if capabilities.serves(PosFamily::Einvoicing) {
        invoice_checks(&mut suite, checked_est);
    }
    if capabilities.serves(PosFamily::Delivery) {
        delivery_checks(&mut suite, checked_est);
    }
    if capabilities.serves(PosFamily::Tax) {
        tax_checks(&mut suite, checked_est);
    }

    let leaks: Vec<&String> = suite
        .details
        .iter()
        .filter(|detail| contains_card_data(detail))
        .collect();
    suite.check(
        "no-card-data",
        leaks.is_empty(),
        format!("scanned {} result details", suite.details.len()),
    );

    let certified = suite.checks.iter().all(|check| check.passed);
    PosCertificationReport {
        connector: name,
        families: capabilities.families,
        checks: suite.checks,
        certified,
        checked_est,
    }
}

fn payment_checks(suite: &mut Suite<'_>, minor: i64, checked_est: i64) {
    let name = suite.name.clone();
    let tenant = suite.tenant.clone();
    let reference = "conf-intent-1".to_string();
    let amount = Suite::amount("EUR", minor);
    let token = PaymentMethodToken::unchecked_for_tests("tok_conformance_1");
    if !token.is_valid() {
        suite.check("token-shape", false, "the suite token is malformed");
        return;
    }
    suite.check(
        "tokenizes-card-data",
        suite.connector.capabilities().tokenizes_card_data,
        "the connector only accepts opaque tokens",
    );

    let authorize = AuthorizeRequest::new(
        &name,
        &tenant,
        &reference,
        token,
        amount.clone(),
        true,
        checked_est,
    );

    let first = suite.connector.authorize(&authorize);
    suite.settle(
        "authorize",
        first.clone(),
        PosOutcome::Accepted,
        "authorize",
    );
    let echoed = first
        .amount
        .as_ref()
        .map(|reported| reported.matches(&amount))
        .unwrap_or(false);
    suite.check(
        "amount-echo",
        echoed,
        format!(
            "the vendor reported {:?} for an authorisation of {}",
            first.amount.as_ref().map(|reported| reported.minor),
            minor
        ),
    );

    let replay = suite.connector.authorize(&authorize);
    suite.settle(
        "replay",
        replay.clone(),
        PosOutcome::Replayed,
        "the same authorisation key presented twice",
    );

    // Nothing is left to capture, so an extra capture must be refused rather
    // than quietly sweeping the till.
    let over_capture = CaptureRequest::new(
        &name,
        &tenant,
        &reference,
        Suite::amount("EUR", 1),
        checked_est,
        "over",
    );
    let refusal = suite.connector.capture(&over_capture);
    suite.settle(
        "amount-mismatch-capture",
        refusal,
        PosOutcome::Permanent,
        "a capture above the authorised amount",
    );

    let over_refund = RefundRequest::new(
        &name,
        &tenant,
        &reference,
        Suite::amount("EUR", minor + 1),
        "conformance refund",
        checked_est,
        "over",
    );
    let refusal = suite.connector.refund(&over_refund);
    suite.settle(
        "amount-mismatch-refund",
        refusal,
        PosOutcome::Permanent,
        "a refund above the captured amount",
    );

    let refund = RefundRequest::new(
        &name,
        &tenant,
        &reference,
        Suite::amount("EUR", minor),
        "conformance refund",
        checked_est,
        "full",
    );
    let refunded = suite.connector.refund(&refund);
    suite.settle("refund", refunded.clone(), PosOutcome::Accepted, "refund");
    suite.check(
        "refund-amount-echo",
        refunded
            .amount
            .as_ref()
            .map(|reported| reported.minor == minor)
            .unwrap_or(false),
        "the vendor echoes the refunded amount",
    );

    let void = VoidRequest::new(&name, &tenant, &reference, checked_est);
    let void_result = suite.connector.void(&void);
    suite.settle(
        "void-after-capture-refused",
        void_result,
        PosOutcome::Permanent,
        "a void after capture",
    );
}

fn accounting_checks(suite: &mut Suite<'_>, checked_est: i64) {
    let name = suite.name.clone();
    let tenant = suite.tenant.clone();
    let entry = JournalEntry::new(
        &name,
        &tenant,
        "conf-entry-1",
        vec![
            JournalLine {
                account: "cash".to_string(),
                direction: Direction::Debit,
                amount: Suite::amount("EUR", 1_000),
            },
            JournalLine {
                account: "sales".to_string(),
                direction: Direction::Credit,
                amount: Suite::amount("EUR", 1_000),
            },
        ],
        checked_est,
    );
    let posted = suite.connector.post_entry(&entry);
    suite.settle(
        "journal-entry",
        posted.clone(),
        PosOutcome::Accepted,
        "posting a balanced entry",
    );

    let replay = suite.connector.post_entry(&entry);
    suite.settle(
        "journal-replay",
        replay,
        PosOutcome::Replayed,
        "posting the same entry twice",
    );

    let unbalanced = JournalEntry::new(
        &name,
        &tenant,
        "conf-entry-2",
        vec![
            JournalLine {
                account: "cash".to_string(),
                direction: Direction::Debit,
                amount: Suite::amount("EUR", 1_000),
            },
            JournalLine {
                account: "sales".to_string(),
                direction: Direction::Credit,
                amount: Suite::amount("EUR", 900),
            },
        ],
        checked_est,
    );
    let refusal = suite.connector.post_entry(&unbalanced);
    suite.settle(
        "journal-balance",
        refusal,
        PosOutcome::Permanent,
        "an unbalanced entry",
    );
}

fn invoice_checks(suite: &mut Suite<'_>, checked_est: i64) {
    let name = suite.name.clone();
    let tenant = suite.tenant.clone();
    let invoice = Invoice::new(
        &name,
        &tenant,
        "conf-invoice-1",
        "customer-1",
        vec![InvoiceLine {
            description: "Espresso".to_string(),
            quantity: 2,
            unit: Suite::amount("EUR", 250),
        }],
        checked_est,
    );
    let issued = suite.connector.issue_invoice(&invoice);
    suite.settle(
        "invoice",
        issued.clone(),
        PosOutcome::Accepted,
        "issuing an invoice",
    );
    suite.check(
        "invoice-total-echo",
        issued
            .amount
            .as_ref()
            .map(|reported| reported.minor == 500)
            .unwrap_or(false),
        "the vendor reports the invoice total",
    );

    let replay = suite.connector.issue_invoice(&invoice);
    suite.settle(
        "invoice-replay",
        replay,
        PosOutcome::Replayed,
        "issuing the same invoice twice",
    );

    let over = CreditNote::new(
        &name,
        &tenant,
        "conf-invoice-1",
        "conf-credit-1",
        Suite::amount("EUR", 600),
        "conformance credit",
        checked_est,
    );
    let refusal = suite.connector.credit_note(&over);
    suite.settle(
        "credit-cap",
        refusal,
        PosOutcome::Permanent,
        "a credit note above the invoice",
    );

    let credit = CreditNote::new(
        &name,
        &tenant,
        "conf-invoice-1",
        "conf-credit-2",
        Suite::amount("EUR", 200),
        "conformance credit",
        checked_est,
    );
    let credited = suite.connector.credit_note(&credit);
    suite.settle(
        "credit-note",
        credited,
        PosOutcome::Accepted,
        "a credit note within the invoice",
    );
}

fn delivery_checks(suite: &mut Suite<'_>, checked_est: i64) {
    let name = suite.name.clone();
    let tenant = suite.tenant.clone();
    let order = DeliveryOrder::new(
        &name,
        &tenant,
        "conf-order-1",
        "Calle Mayor 1, Madrid",
        "leave at the door",
        Some(Suite::amount("EUR", 1_500)),
        checked_est,
    );
    let booked = suite.connector.create_delivery(&order);
    suite.settle(
        "delivery",
        booked,
        PosOutcome::Accepted,
        "booking a delivery",
    );

    let replay = suite.connector.create_delivery(&order);
    suite.settle(
        "delivery-replay",
        replay,
        PosOutcome::Replayed,
        "booking the same delivery twice",
    );

    let cancel = DeliveryCancel::new(&name, &tenant, "conf-order-1", checked_est);
    let cancelled = suite.connector.cancel_delivery(&cancel);
    suite.settle(
        "delivery-cancel",
        cancelled,
        PosOutcome::Accepted,
        "cancelling a delivery",
    );

    let status = DeliveryStatus::new(&tenant, "conf-order-1");
    let queried = suite.connector.delivery_status(&status);
    suite.settle(
        "delivery-status",
        queried,
        PosOutcome::Accepted,
        "querying a delivery",
    );
}

fn tax_checks(suite: &mut Suite<'_>, checked_est: i64) {
    let name = suite.name.clone();
    let tenant = suite.tenant.clone();
    let quote = TaxQuery::new(
        &name,
        &tenant,
        "conf-tax-1",
        "ES-MAD",
        vec![TaxQueryLine {
            tax_code: "standard".to_string(),
            amount: Suite::amount("EUR", 1_000),
        }],
        checked_est,
    );
    let quoted = suite.connector.quote_tax(&quote);
    suite.settle(
        "tax-quote",
        quoted.clone(),
        PosOutcome::Accepted,
        "quoting tax",
    );
    let Some(quoted_total) = quoted.amount.clone() else {
        suite.check(
            "tax-quote-amount",
            false,
            "the vendor reported no tax total",
        );
        return;
    };
    suite.check(
        "tax-quote-amount",
        quoted_total.minor > 0,
        format!("quoted {} minor units", quoted_total.minor),
    );

    let verify = TaxVerify::new(
        &name,
        &tenant,
        "conf-tax-1",
        quoted_total.clone(),
        checked_est,
    );
    let verified = suite.connector.verify_tax(&verify);
    suite.settle(
        "tax-verify",
        verified,
        PosOutcome::Accepted,
        "verifying the quoted total",
    );

    let wrong = TaxVerify::new(
        &name,
        &tenant,
        "conf-tax-1",
        Suite::amount("EUR", 1),
        checked_est,
    );
    let refusal = suite.connector.verify_tax(&wrong);
    suite.settle(
        "tax-verify-mismatch",
        refusal,
        PosOutcome::Permanent,
        "verifying a total the authority did not quote",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::ConnectorHealth;
    use crate::pos::mock::MockPosVendor;
    use crate::pos::{PosCapabilities, PosConnector, PosOutcome};

    fn report_for(connector: &dyn PosConnector) -> PosCertificationReport {
        certify_pos(connector, 1_700_000_000)
    }

    #[test]
    fn the_mock_vendor_is_certified_across_all_families() {
        let vendor = MockPosVendor::new("acme");
        let report = report_for(&vendor);
        assert!(
            report.certified,
            "expected certification, failures: {:?}",
            report.failures()
        );
        assert_eq!(report.families.len(), 5);
        assert!(report.summary().contains("certified"));
        assert_eq!(report.to_json()["certified"], true);
        assert!(vendor.payments().charge_count() >= 2);
    }

    struct AlwaysAccepted;

    impl PosConnector for AlwaysAccepted {
        fn name(&self) -> &str {
            "always-accepted"
        }
        fn capabilities(&self) -> PosCapabilities {
            PosCapabilities::for_families(&[PosFamily::Payment])
        }
        fn health(&self) -> ConnectorHealth {
            ConnectorHealth::healthy("always")
        }
        fn authorize(&self, request: &AuthorizeRequest) -> OperationResult {
            OperationResult::accepted("chg-1", Some(request.amount.clone()))
        }
        fn capture(&self, request: &CaptureRequest) -> OperationResult {
            OperationResult::accepted("chg-2", Some(request.amount.clone()))
        }
        fn refund(&self, request: &RefundRequest) -> OperationResult {
            OperationResult::accepted("chg-3", Some(request.amount.clone()))
        }
        fn void(&self, _request: &VoidRequest) -> OperationResult {
            OperationResult::accepted("chg-4", None)
        }
    }

    #[test]
    fn a_connector_that_ignores_replay_is_rejected() {
        let report = report_for(&AlwaysAccepted);
        assert!(!report.certified);
        let failures: Vec<&str> = report
            .failures()
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        assert!(failures.contains(&"replay"), "failures: {failures:?}");
        assert!(failures.contains(&"amount-mismatch-capture"));
    }

    struct WrongAmount;

    impl PosConnector for WrongAmount {
        fn name(&self) -> &str {
            "wrong-amount"
        }
        fn capabilities(&self) -> PosCapabilities {
            PosCapabilities::for_families(&[PosFamily::Payment])
        }
        fn health(&self) -> ConnectorHealth {
            ConnectorHealth::healthy("wrong amount")
        }
        fn authorize(&self, request: &AuthorizeRequest) -> OperationResult {
            let mut amount = request.amount.clone();
            amount.minor += 1;
            OperationResult::accepted("chg-1", Some(amount))
        }
    }

    #[test]
    fn a_connector_that_reports_a_different_amount_is_rejected() {
        let report = report_for(&WrongAmount);
        let failures: Vec<&str> = report
            .failures()
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        assert!(failures.contains(&"amount-echo"), "failures: {failures:?}");
        assert_eq!(PosOutcome::Accepted.as_str(), "accepted");
    }
}
