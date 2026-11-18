// SPDX-License-Identifier: Apache-2.0

//! POS-14: the generic POS integration framework.
//!
//! Proves the four things POS-14 has to prove: a connector builds against the
//! Apache-2.0 surface alone, the conformance suite rejects replay and amount
//! mismatch, reconciliation finds every kind of difference, and no card data
//! appears in results, logs or fixtures.

use std::path::{Path, PathBuf};

use tirbase_integrations::connector::ConnectorHealth;
use tirbase_integrations::pos::contract::{
    AuthorizeRequest, CaptureRequest, DeliveryCancel, DeliveryOrder, DeliveryStatus, Direction,
    Invoice, InvoiceLine, JournalEntry, JournalLine, OperationResult, PosCapabilities,
    PosConnector, PosOperation, RefundRequest, TaxQuery, TaxQueryLine, TaxVerify, VoidRequest,
};
use tirbase_integrations::pos::mock::{
    MockAccountingApi, MockDeliveryPlatform, MockPaymentTerminal, MockPosVendor, MockTaxAuthority,
    MockTerminalConfig,
};
use tirbase_integrations::pos::{
    certify_pos, contains_card_data, pos_idempotency_key, reconcile, scrub_card_data, Amount,
    ConnectorConfig, DiscrepancyKind, LocalSettlement, PaymentMethodToken, PosError, PosFamily,
    PosOutcome, PosRuntime, PosSubmit, ReconciliationPolicy, ReconciliationSource,
    RemoteSettlement, SecretRef, CONFIG_SCHEMA_VERSION,
};
use tirbase_integrations::retry::RetryPolicy;

const FIXTURE: &str = include_str!("fixtures/pos-connector.toml");

fn token() -> PaymentMethodToken {
    PaymentMethodToken::new("tok_terminal_9a3f").expect("valid token")
}

fn euro(minor: i64) -> Amount {
    Amount::new("EUR", minor).expect("valid amount")
}

fn authorize(connector: &str, intent: &str, minor: i64, capture: bool) -> PosOperation {
    PosOperation::Authorize(AuthorizeRequest::new(
        connector,
        "acme",
        intent,
        token(),
        euro(minor),
        capture,
        1_700_000_000,
    ))
}

fn balanced_entry(connector: &str, reference: &str) -> JournalEntry {
    JournalEntry::new(
        connector,
        "acme",
        reference,
        vec![
            JournalLine {
                account: "1000-cash".to_string(),
                direction: Direction::Debit,
                amount: euro(1_000),
            },
            JournalLine {
                account: "4000-sales".to_string(),
                direction: Direction::Credit,
                amount: euro(1_000),
            },
        ],
        1_700_000_000,
    )
}

// ---------------------------------------------------------------------------
// Licence surface
// ---------------------------------------------------------------------------

#[test]
fn a_closed_connector_needs_only_the_apache_framework_manifest() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read manifest");
    assert!(manifest.contains("license = \"Apache-2.0\""));
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if !in_dependencies || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split('=').next().unwrap_or_default().trim();
        assert!(
            !name.starts_with("tirbase-"),
            "the framework must not depend on a first-party crate, found {name}"
        );
    }
    assert_eq!(PosFamily::all().len(), 5);
}

// ---------------------------------------------------------------------------
// Configuration schema and mapping DSL
// ---------------------------------------------------------------------------

#[test]
fn the_documented_configuration_fixture_parses_and_maps() {
    let config = ConnectorConfig::from_toml(FIXTURE).expect("valid fixture");
    assert_eq!(config.schema_version, CONFIG_SCHEMA_VERSION);
    assert_eq!(config.families.len(), 5);
    assert!(config.serves(PosFamily::Einvoicing));
    assert_eq!(config.timeout_ms, 4_000);
    assert_eq!(config.retry_policy().max_attempts, 4);
    assert_eq!(config.reconciliation.interval_secs, 900);
    assert_eq!(config.secret.len(), 2);
    assert_eq!(
        config.secret[0],
        SecretRef {
            name: "api_key".to_string(),
            from: "env:ACME_POS_API_KEY".to_string(),
        }
    );
    assert_eq!(config.secret_env("api_key"), Some("ACME_POS_API_KEY"));
    assert_eq!(
        config.secret[1].file_path(),
        Some("/run/secrets/acme-pos-hmac")
    );

    let mapped = config
        .apply_mapping(&serde_json::json!({
            "event": { "event_id": "sale-1" },
            "payload": { "amount_minor": 2_500, "payment_intent": " intent-1 " }
        }))
        .expect("mapping runs")
        .expect("mapping document");
    assert_eq!(mapped["payment"]["amount_minor"], 2_500);
    assert_eq!(mapped["payment"]["currency"], "EUR");
    assert_eq!(mapped["payment"]["reference"], "intent-1");
}

#[test]
fn unusable_configuration_is_refused_with_the_field_named() {
    let http = FIXTURE.replace("https://pos.acme.example/v1", "http://pos.acme.example/v1");
    assert!(
        ConnectorConfig::from_toml(&http).is_err(),
        "https is required"
    );

    let inline_secret = FIXTURE.replace("env:ACME_POS_API_KEY", "s3cr3t-value");
    let error = ConnectorConfig::from_toml(&inline_secret).expect_err("inline secret");
    assert_eq!(error.field, "secret.from");

    let card_name = FIXTURE.replace("name = \"api_key\"", "name = \"card_number\"");
    assert!(ConnectorConfig::from_toml(&card_name).is_err());

    let duplicate_family = FIXTURE.replace(
        "[\"payment\", \"accounting\", \"einvoicing\", \"delivery\", \"tax\"]",
        "[\"payment\", \"payment\"]",
    );
    assert!(ConnectorConfig::from_toml(&duplicate_family).is_err());

    let bad_mapping = FIXTURE.replace(
        "source = \"payload.amount_minor\"",
        "source = \"body.amount\"",
    );
    assert!(ConnectorConfig::from_toml(&bad_mapping).is_err());

    let bad_version = FIXTURE.replace("schema_version = 1", "schema_version = 2");
    assert!(ConnectorConfig::from_toml(&bad_version).is_err());
}

#[test]
fn loopback_http_needs_an_explicit_opt_in() {
    let loopback = FIXTURE
        .replace("https://pos.acme.example/v1", "http://127.0.0.1:8787")
        .replace(
            "timeout_ms = 4000",
            "timeout_ms = 4000\nallow_insecure_loopback = true",
        );
    let config = ConnectorConfig::from_toml(&loopback).expect("loopback config");
    assert!(config.allow_insecure_loopback);
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

#[test]
fn idempotency_keys_are_derived_per_operation_and_reference() {
    let authorize_key = pos_idempotency_key("acme", "authorize", "intent-1");
    assert_eq!(
        authorize_key,
        pos_idempotency_key("acme", "authorize", "intent-1")
    );
    assert_ne!(
        authorize_key,
        pos_idempotency_key("acme", "refund", "intent-1")
    );
    assert_ne!(
        authorize_key,
        pos_idempotency_key("other", "authorize", "intent-1")
    );
    assert!(authorize_key.starts_with("pos-"));
}

#[test]
fn amounts_refuse_mixed_currencies_and_negative_arithmetic() {
    assert!(Amount::new("eur", 100).is_err());
    assert!(Amount::new("EUR", -1).is_err());
    assert_eq!(
        euro(1_000).checked_add(&euro(500)).expect("sum").minor,
        1_500
    );
    assert!(matches!(
        euro(500).checked_add(&Amount::new("USD", 1).expect("valid")),
        Err(PosError::CurrencyMismatch { .. })
    ));
    assert!(euro(500).checked_sub(&euro(1_000)).is_err());
    assert_eq!(euro(250).checked_mul(4).expect("product").minor, 1_000);
}

#[test]
fn malformed_operations_never_reach_a_vendor() {
    let pan_shaped = AuthorizeRequest::new(
        "terminal",
        "acme",
        "intent-1",
        PaymentMethodToken::unchecked_for_tests("1234567890123456"),
        euro(100),
        true,
        10,
    );
    assert!(matches!(
        PosOperation::Authorize(pan_shaped).validate(),
        Err(PosError::CardDataDetected { .. })
    ));

    let no_reason = RefundRequest::new("terminal", "acme", "intent-1", euro(100), "  ", 10, "r");
    assert!(PosOperation::Refund(no_reason).validate().is_err());

    let unbalanced = JournalEntry::new(
        "ledger",
        "acme",
        "sale-1",
        vec![
            JournalLine {
                account: "cash".to_string(),
                direction: Direction::Debit,
                amount: euro(1_000),
            },
            JournalLine {
                account: "sales".to_string(),
                direction: Direction::Credit,
                amount: euro(999),
            },
        ],
        10,
    );
    assert!(matches!(
        PosOperation::PostEntry(unbalanced).validate(),
        Err(PosError::AmountMismatch { .. })
    ));

    let zero_quantity = Invoice::new(
        "einvoice",
        "acme",
        "INV-1",
        "customer-1",
        vec![InvoiceLine {
            description: "Espresso".to_string(),
            quantity: 0,
            unit: euro(250),
        }],
        10,
    );
    assert!(PosOperation::IssueInvoice(zero_quantity)
        .validate()
        .is_err());
}

// ---------------------------------------------------------------------------
// Runtime: idempotency, retries, dead letters, integrity
// ---------------------------------------------------------------------------

#[test]
fn a_sale_settles_once_and_a_repeat_submission_does_not_reach_the_terminal() {
    let terminal = MockPaymentTerminal::new("terminal");
    let mut runtime = PosRuntime::new(terminal);
    assert_eq!(
        runtime.submit(authorize("terminal", "intent-1", 2_500, true), 10),
        Ok(PosSubmit::Queued(1))
    );
    assert_eq!(
        runtime.submit(authorize("terminal", "intent-1", 2_500, true), 11),
        Ok(PosSubmit::AlreadyQueued(1))
    );
    let report = runtime.flush(12);
    assert_eq!(report.accepted, 1);
    assert_eq!(
        runtime.submit(authorize("terminal", "intent-1", 2_500, true), 13),
        Ok(PosSubmit::AlreadySettled(1))
    );
    assert_eq!(runtime.connector().charge_count(), 1);
    assert_eq!(runtime.metrics().accepted, 1);
    assert_eq!(
        runtime.settled_for(&pos_idempotency_key("terminal", "authorize", "intent-1")),
        Some(PosOutcome::Accepted)
    );
    assert_eq!(runtime.logs().len(), 1);
    for record in runtime.logs() {
        assert!(!contains_card_data(&record.to_json().to_string()));
    }
}

#[test]
fn a_transient_failure_retries_with_backoff_then_delivers() {
    let terminal = MockPaymentTerminal::with_config(
        "terminal",
        MockTerminalConfig {
            fail_first: 1,
            ..MockTerminalConfig::default()
        },
    );
    let mut runtime = PosRuntime::new(terminal).with_retry_policy(RetryPolicy::new(3, 5, 2, 30));
    runtime
        .submit(authorize("terminal", "intent-2", 1_000, true), 10)
        .expect("queued");
    let first = runtime.flush(11);
    assert_eq!(first.retried, 1);
    let record = runtime.records()[0].clone();
    assert_eq!(record.attempts, 1);
    assert_eq!(record.next_attempt_est, 16);
    // Before the backoff elapses nothing is attempted.
    assert_eq!(runtime.flush(15).attempted, 0);
    assert_eq!(runtime.flush(16).accepted, 1);
    assert_eq!(runtime.records()[0].attempts, 2);
}

#[test]
fn an_exhausted_retry_budget_dead_letters_and_replay_keeps_the_key() {
    let terminal = MockPaymentTerminal::new("terminal");
    terminal.set_failures(10);
    let mut runtime = PosRuntime::new(terminal).with_retry_policy(RetryPolicy::new(2, 1, 2, 5));
    runtime
        .submit(authorize("terminal", "intent-3", 500, true), 10)
        .expect("queued");
    assert_eq!(runtime.flush(11).retried, 1);
    assert_eq!(runtime.flush(100).dead_lettered, 1);
    assert_eq!(runtime.dead_letters().len(), 1);
    let letter = runtime.dead_letters()[0].clone();
    assert!(letter.reason.contains("retry budget"));

    runtime.connector().set_failures(0);
    let seq = runtime.replay(&letter.dlq_id, 200).expect("replayed");
    assert_eq!(runtime.dead_letters()[0].replay_count, 1);
    assert_eq!(runtime.flush(201).accepted, 1);
    let replayed = runtime
        .records()
        .iter()
        .find(|record| record.seq == seq)
        .expect("replayed record");
    assert_eq!(replayed.key, letter.key);
    assert!(runtime.replay(&letter.dlq_id, 300).is_err());
    assert_eq!(runtime.metrics().replays, 1);
}

#[test]
fn a_vendor_that_reports_the_wrong_amount_is_never_settled() {
    let terminal = MockPaymentTerminal::with_config(
        "terminal",
        MockTerminalConfig {
            report_wrong_amount: true,
            ..MockTerminalConfig::default()
        },
    );
    let mut runtime = PosRuntime::new(terminal);
    runtime
        .submit(authorize("terminal", "intent-4", 2_500, true), 10)
        .expect("queued");
    let report = runtime.flush(11);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(runtime.integrity_violations().len(), 1);
    let violation = &runtime.integrity_violations()[0];
    assert_eq!(violation.expected.minor, 2_500);
    assert_eq!(violation.got.minor, 2_501);
    assert_eq!(runtime.metrics().rejected, 1);
    assert!(runtime
        .settled_for(&pos_idempotency_key("terminal", "authorize", "intent-4"))
        .is_none());
}

// ---------------------------------------------------------------------------
// Conformance
// ---------------------------------------------------------------------------

#[test]
fn the_reference_vendor_is_certified_for_all_five_families() {
    let vendor = MockPosVendor::new("acme");
    let report = certify_pos(&vendor, 1_700_000_000);
    assert!(report.certified, "failures: {:?}", report.failures());
    assert_eq!(report.families, PosFamily::all().to_vec());
    let names: Vec<&str> = report
        .checks
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    for expected in [
        "identity",
        "families",
        "authorize",
        "amount-echo",
        "replay",
        "amount-mismatch-capture",
        "amount-mismatch-refund",
        "journal-entry",
        "journal-balance",
        "invoice",
        "credit-cap",
        "delivery-replay",
        "tax-quote",
        "no-card-data",
    ] {
        assert!(names.contains(&expected), "missing check {expected}");
    }
    assert!(report.to_json()["families"]
        .as_array()
        .expect("families array")
        .contains(&serde_json::json!("einvoicing")));
}

struct AcceptsEverything;

impl PosConnector for AcceptsEverything {
    fn name(&self) -> &str {
        "accepts-everything"
    }
    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&[PosFamily::Payment])
    }
    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("accepts everything")
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
fn the_suite_rejects_a_connector_that_ignores_replay() {
    let report = certify_pos(&AcceptsEverything, 1_700_000_000);
    assert!(!report.certified);
    let failures: Vec<&str> = report
        .failures()
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    assert!(failures.contains(&"replay"), "failures: {failures:?}");
    assert!(report.summary().contains("not certified"));
}

struct OverCapture;

impl PosConnector for OverCapture {
    fn name(&self) -> &str {
        "over-capture"
    }
    fn capabilities(&self) -> PosCapabilities {
        PosCapabilities::for_families(&[PosFamily::Payment])
    }
    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("over capture")
    }
    fn authorize(&self, request: &AuthorizeRequest) -> OperationResult {
        OperationResult::accepted("chg-1", Some(request.amount.clone()))
    }
    fn capture(&self, request: &CaptureRequest) -> OperationResult {
        // A vendor that settles more than it was authorised to sweep.
        OperationResult::accepted("chg-2", Some(request.amount.clone()))
    }
    fn refund(&self, request: &RefundRequest) -> OperationResult {
        OperationResult::accepted("chg-3", Some(request.amount.clone()))
    }
}

#[test]
fn the_suite_rejects_a_connector_that_accepts_an_amount_mismatch() {
    let report = certify_pos(&OverCapture, 1_700_000_000);
    assert!(!report.certified);
    let failures: Vec<&str> = report
        .failures()
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    assert!(
        failures.contains(&"amount-mismatch-capture"),
        "failures: {failures:?}"
    );
}

// ---------------------------------------------------------------------------
// Mocks and reconciliation
// ---------------------------------------------------------------------------

#[test]
fn the_accounting_mock_balances_deduplicates_and_refuses_a_reused_reference() {
    let ledger = MockAccountingApi::new("ledger");
    let entry = balanced_entry("ledger", "sale-1");
    let posted = ledger.post_entry(&entry);
    assert_eq!(posted.outcome, PosOutcome::Accepted);
    assert_eq!(
        posted.amount.as_ref().map(|amount| amount.minor),
        Some(1_000)
    );
    assert_eq!(ledger.post_entry(&entry).outcome, PosOutcome::Replayed);
    assert_eq!(ledger.entries().len(), 1);

    let mut second = balanced_entry("ledger", "sale-1");
    second.idempotency_key = pos_idempotency_key("ledger", "journal-entry", "sale-1-b");
    assert_eq!(ledger.post_entry(&second).outcome, PosOutcome::Permanent);
}

#[test]
fn the_delivery_mock_books_cancels_and_reports_status() {
    let courier = MockDeliveryPlatform::new("courier");
    let order = DeliveryOrder::new(
        "courier",
        "acme",
        "order-1",
        "Calle Mayor 1, Madrid",
        "ring twice",
        Some(euro(1_500)),
        10,
    );
    let booked = courier.create_delivery(&order);
    assert_eq!(booked.outcome, PosOutcome::Accepted);
    assert_eq!(
        courier.create_delivery(&order).outcome,
        PosOutcome::Replayed
    );
    assert_eq!(courier.jobs().len(), 1);

    let cancel = DeliveryCancel::new("courier", "acme", "order-1", 11);
    assert_eq!(
        courier.cancel_delivery(&cancel).outcome,
        PosOutcome::Accepted
    );
    let status = courier.delivery_status(&DeliveryStatus::new("acme", "order-1"));
    assert_eq!(status.outcome, PosOutcome::Accepted);
    assert!(status.detail.contains("cancelled"));
    assert_eq!(
        courier
            .delivery_status(&DeliveryStatus::new("acme", "order-404"))
            .outcome,
        PosOutcome::Permanent
    );
}

#[test]
fn the_tax_mock_quotes_half_up_and_refuses_a_different_total() {
    let authority = MockTaxAuthority::new("authority");
    let quote = TaxQuery::new(
        "authority",
        "acme",
        "sale-1",
        "ES-MAD",
        vec![TaxQueryLine {
            tax_code: "standard".to_string(),
            amount: euro(1_000),
        }],
        10,
    );
    let quoted = authority.quote_tax(&quote);
    assert_eq!(quoted.outcome, PosOutcome::Accepted);
    // 21% of 10.00 is 2.10.
    assert_eq!(quoted.amount.as_ref().map(|amount| amount.minor), Some(210));
    assert_eq!(authority.quote_tax(&quote).outcome, PosOutcome::Replayed);

    let verified = authority.verify_tax(&TaxVerify::new(
        "authority",
        "acme",
        "sale-1",
        euro(210),
        11,
    ));
    assert_eq!(verified.outcome, PosOutcome::Accepted);
    let wrong = authority.verify_tax(&TaxVerify::new(
        "authority",
        "acme",
        "sale-1",
        euro(200),
        12,
    ));
    assert_eq!(wrong.outcome, PosOutcome::Permanent);
}

struct DoctoredSource {
    lines: Vec<RemoteSettlement>,
}

impl ReconciliationSource for DoctoredSource {
    fn settlements(&self, _tenant: &str) -> Vec<RemoteSettlement> {
        self.lines.clone()
    }
}

#[test]
fn the_runtime_reconciles_a_settled_sale_against_the_vendor_report() {
    let mut runtime = PosRuntime::new(MockPosVendor::new("acme"));
    runtime
        .submit(authorize("acme", "intent-5", 2_500, true), 10)
        .expect("queued");
    assert_eq!(runtime.flush(11).accepted, 1);
    let policy = ReconciliationPolicy::default();
    let report = runtime.reconcile("acme", runtime.connector(), &policy, 12);
    assert!(
        report.balanced(),
        "discrepancies: {:?}",
        report.discrepancies
    );
    assert_eq!(report.matched, 1);

    let refund = RefundRequest::new(
        "acme",
        "acme",
        "intent-5",
        euro(1_000),
        "damaged",
        13,
        "part",
    );
    runtime
        .submit(PosOperation::Refund(refund), 14)
        .expect("queued");
    assert_eq!(runtime.flush(15).accepted, 1);
    let report = runtime.reconcile("acme", runtime.connector(), &policy, 16);
    assert!(
        report.balanced(),
        "discrepancies: {:?}",
        report.discrepancies
    );

    let doctored = DoctoredSource {
        lines: vec![RemoteSettlement {
            reference: "intent-5".to_string(),
            amount: euro(1_400),
            settled_est: Some(15),
        }],
    };
    let report = runtime.reconcile("acme", &doctored, &policy, 17);
    assert!(!report.balanced());
    assert_eq!(
        report.discrepancies[0].kind,
        DiscrepancyKind::AmountMismatch
    );
}

#[test]
fn reconciliation_reports_missing_lines_duplicates_and_tolerance() {
    let local = vec![
        LocalSettlement {
            reference: "a".to_string(),
            amount: euro(1_000),
            settled_est: 10,
        },
        LocalSettlement {
            reference: "b".to_string(),
            amount: euro(1_000),
            settled_est: 10,
        },
    ];
    let remote = vec![
        RemoteSettlement {
            reference: "a".to_string(),
            amount: euro(1_000),
            settled_est: Some(10),
        },
        RemoteSettlement {
            reference: "a".to_string(),
            amount: euro(1_000),
            settled_est: Some(11),
        },
        RemoteSettlement {
            reference: "c".to_string(),
            amount: euro(500),
            settled_est: Some(11),
        },
    ];
    let report = reconcile(
        "acme",
        &local,
        &remote,
        &ReconciliationPolicy::default(),
        12,
    );
    let kinds: Vec<DiscrepancyKind> = report
        .discrepancies
        .iter()
        .map(|entry| entry.kind)
        .collect();
    assert!(kinds.contains(&DiscrepancyKind::DuplicateRemote));
    assert!(kinds.contains(&DiscrepancyKind::MissingRemote));
    assert!(kinds.contains(&DiscrepancyKind::MissingLocal));
    assert_eq!(report.to_json()["balanced"], false);

    let tolerant = ReconciliationPolicy {
        tolerance_minor: 50,
        ..ReconciliationPolicy::default()
    };
    let report = reconcile("acme", &local, &remote, &tolerant, 12);
    assert!(report
        .discrepancies
        .iter()
        .any(|entry| entry.kind == DiscrepancyKind::DuplicateRemote));
}

// ---------------------------------------------------------------------------
// PCI: no card data in results, logs or fixtures
// ---------------------------------------------------------------------------

#[test]
fn tokens_errors_and_logs_never_carry_card_data() {
    assert!(PaymentMethodToken::new("1234567890123456").is_err());
    assert!(PaymentMethodToken::new("1234 5678 9012 3456").is_err());
    assert!(PaymentMethodToken::new("tok_terminal_9a3f").is_ok());
    assert_eq!(
        format!(
            "{:?}",
            PaymentMethodToken::new("tok_terminal_9a3f").expect("valid")
        ),
        "PaymentMethodToken(***)"
    );

    let scrubbed = scrub_card_data("declined 1234 5678 9012 3456 cvv=123");
    assert!(!scrubbed.contains("1234"));
    assert!(!contains_card_data(&scrubbed));

    let error = PosError::Transport {
        detail: "gateway returned 1234 5678 9012 3456".to_string(),
    };
    assert!(!contains_card_data(&error.to_string()));

    let mut runtime = PosRuntime::new(MockPaymentTerminal::new("terminal"));
    runtime
        .submit(authorize("terminal", "intent-6", 900, true), 10)
        .expect("queued");
    runtime.flush(11);
    for record in runtime.logs() {
        assert!(!contains_card_data(&record.detail));
        assert!(!contains_card_data(&record.to_json().to_string()));
    }
    assert!(contains_card_data("1234567890123456"));
    assert!(!contains_card_data("2026-11-18 2500 EUR"));
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for character in digits.chars().rev() {
        let Some(digit) = character.to_digit(10) else {
            return false;
        };
        let value = if double {
            let doubled = digit * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            digit
        };
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

/// Every 13–19 digit run in a text, ignoring grouping spaces and dashes.
fn digit_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if current.is_empty() {
            continue;
        } else if matches!(character, ' ' | '-') {
            // A grouping separator only continues a run; the next character
            // decides.
            continue;
        } else if (13..=19).contains(&current.len()) {
            runs.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if (13..=19).contains(&current.len()) {
        runs.push(current);
    }
    runs
}

#[test]
fn no_fixture_or_pos_source_contains_a_luhn_valid_card_number() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().expect("workspace root").to_path_buf();
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(manifest_dir.join("src/pos")).expect("pos sources") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    for entry in std::fs::read_dir(manifest_dir.join("tests/fixtures")).expect("fixtures") {
        files.push(entry.expect("dir entry").path());
    }
    files.push(manifest_dir.join("tests/pos14.rs"));
    files.push(workspace.join("docs/compliance/pos-14-generic-pos-integration-framework.md"));
    files.push(workspace.join("docs/connectors/pos-connector-guide.md"));

    let mut offenders: Vec<String> = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for run in digit_runs(&text) {
            if luhn_valid(&run) {
                offenders.push(format!("{}: {run}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "card-number-shaped fixtures found: {offenders:?}"
    );
}
