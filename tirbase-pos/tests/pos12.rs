// SPDX-License-Identifier: AGPL-3.0-only

//! POS-12 behavioural tests: settlement batches built from mock processor files,
//! reconciliation with partial settlements, the exception queue, the chargeback
//! lifecycle and tip pooling.

use tirbase_pos::{
    ChargebackBook, ChargebackChange, ChargebackId, ChargebackSpec, ChargebackState, CheckId,
    CreateIntent, Currency, Employee, EmployeeAccess, EmployeeDirectory, EmployeeId, EmployeeRole,
    Evidence, EvidenceKind, EvidenceRef, ExceptionCategory, IdempotencyKey, IngestOutcome,
    IntentBinding, Money, Organization, PaymentIntentId, PaymentIntentStore, PaymentMethod,
    Permission, PinRef, Processor, ProcessorBatchFile, ProcessorRecordId, ProcessorToken,
    SettlementBatchId, SettlementBook, SettlementDay, SettlementError, SettlementKey, StaffSession,
    Store, StoreId, Terminal, TerminalId, Timestamp, TipChange, TipError, TipLedger, TipMember,
    TipPoolId, TipPoolPolicy,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn ts(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn store_id() -> StoreId {
    StoreId::new("store-1").unwrap()
}

fn till(id: &str) -> TerminalId {
    TerminalId::new(id).unwrap()
}

fn employee(id: &str) -> EmployeeId {
    EmployeeId::new(id).unwrap()
}

fn check(id: &str) -> CheckId {
    CheckId::new(id).unwrap()
}

fn intent(id: &str) -> PaymentIntentId {
    PaymentIntentId::new(id).unwrap()
}

fn record(id: &str) -> ProcessorRecordId {
    ProcessorRecordId::new(id).unwrap()
}

fn chargeback(id: &str) -> ChargebackId {
    ChargebackId::new(id).unwrap()
}

fn pool(id: &str) -> TipPoolId {
    TipPoolId::new(id).unwrap()
}

fn organization() -> Organization {
    let mut org = Organization::new();
    let store = store_id();
    org.add_store(Store::new(store.clone(), "Store One").unwrap())
        .unwrap();
    for id in ["till-1", "till-2"] {
        org.add_terminal(Terminal::new(till(id), store.clone(), id).unwrap())
            .unwrap();
    }
    for (id, role) in [
        ("emp-1", EmployeeRole::Cashier),
        ("emp-2", EmployeeRole::Supervisor),
        ("emp-3", EmployeeRole::Manager),
    ] {
        org.add_employee(Employee::new(employee(id), store.clone(), id, vec![role]).unwrap())
            .unwrap();
    }
    org
}

fn directory() -> EmployeeDirectory {
    let org = organization();
    let mut directory = EmployeeDirectory::new();
    for (id, pin) in [("emp-1", "pin-1"), ("emp-2", "pin-2"), ("emp-3", "pin-3")] {
        let record = org.employee(&employee(id)).unwrap().clone();
        directory
            .add(EmployeeAccess::new(record, Some(PinRef::new(pin).unwrap()), None).unwrap())
            .unwrap();
    }
    directory
}

fn session(id: &str, terminal: &str) -> StaffSession {
    directory().session(&employee(id), till(terminal)).unwrap()
}

/// The supervisor holds every settlement and tip permission.
fn supervisor() -> StaffSession {
    session("emp-2", "till-1")
}

fn manager() -> StaffSession {
    session("emp-3", "till-2")
}

fn cashier() -> StaffSession {
    session("emp-1", "till-1")
}

fn day(text: &str) -> SettlementDay {
    SettlementDay::parse(text).unwrap()
}

fn batch_key(day_text: &str) -> SettlementKey {
    SettlementKey::new(
        Processor::new("acquirer-1").unwrap(),
        till("till-1"),
        day(day_text),
    )
}

const HEADER: &str = "batch,batch-1,acquirer-1,till-1,2026-11-18,USD";

fn file(body: &str) -> ProcessorBatchFile {
    let text = format!("{HEADER}\n{body}");
    match ProcessorBatchFile::parse(&text) {
        Ok(file) => file,
        Err(error) => panic!("fixture did not parse: {error}\n{text}"),
    }
}

fn ingest(book: &mut SettlementBook, body: &str) -> IngestOutcome {
    book.ingest(&supervisor(), file(body), ts(9_000)).unwrap()
}

/// Create, authorize and capture one intent.
fn capture(store: &mut PaymentIntentStore, intent_id: &str, check_id: &str, minor: i64) {
    let id = intent(intent_id);
    let binding = IntentBinding::new(
        check(check_id),
        money(minor),
        till("till-1"),
        employee("emp-2"),
        PaymentMethod::Card,
    )
    .unwrap();
    store
        .create(CreateIntent::new(
            id.clone(),
            IdempotencyKey::new(format!("key-{intent_id}")).unwrap(),
            binding,
            ts(1_000),
        ))
        .unwrap();
    let token = ProcessorToken::new(format!("tok-{intent_id}")).unwrap();
    store.authorize(&id, token.clone(), ts(1_001)).unwrap();
    store.capture(&id, money(minor), token, ts(1_002)).unwrap();
}

// ---------------------------------------------------------------------------
// Requirement 1 — settlement batches per terminal, processor and day
// ---------------------------------------------------------------------------

#[test]
fn processor_file_builds_a_batch_from_a_mock_file() {
    let mut book = SettlementBook::new();
    let outcome = ingest(
        &mut book,
        "capture,rec-1,intent-1,1090,100,1700000000000\n\
         refund,rec-2,intent-2,500,0,1700000000001\n\
         adjustment,rec-3,-,25,0,1700000000002\n",
    );
    assert_eq!(outcome.added, 3);
    assert!(outcome.is_clean());

    let key = batch_key("2026-11-18");
    let batch = book.batch(&key).expect("batch exists");
    assert_eq!(batch.id().as_str(), "batch-1");
    assert_eq!(batch.day().to_string(), "2026-11-18");
    assert_eq!(batch.day().index(), day("2026-11-18").index());
    assert_eq!(batch.terminal_id(), &till("till-1"));
    assert_eq!(batch.processor().as_str(), "acquirer-1");
    assert_eq!(batch.currency(), usd());
    assert!(batch.is_open());

    let totals = batch.totals().unwrap();
    assert_eq!(totals.captured, money(1_090));
    assert_eq!(totals.tips, money(100));
    assert_eq!(totals.refunded, money(500));
    assert_eq!(totals.adjustments, money(25));
    assert_eq!(totals.capture_count, 1);
    assert_eq!(totals.net().unwrap(), money(590));
}

#[test]
fn batches_are_scoped_by_processor_terminal_and_day() {
    let mut book = SettlementBook::new();
    ingest(&mut book, "capture,rec-1,intent-1,1000,0,1\n");
    assert_eq!(book.len(), 1);

    // Same file body but the next day: a second batch.
    let next_day = ProcessorBatchFile::parse(
        "batch,batch-2,acquirer-1,till-1,2026-11-19,USD\ncapture,rec-2,intent-2,700,0,2\n",
    )
    .unwrap();
    book.ingest(&manager(), next_day, ts(9_100)).unwrap();
    assert_eq!(book.len(), 2);

    // A different terminal is a separate batch even on the same day.
    let other_till = ProcessorBatchFile::parse(
        "batch,batch-3,acquirer-1,till-2,2026-11-18,USD\ncapture,rec-3,intent-3,300,0,3\n",
    )
    .unwrap();
    book.ingest(&manager(), other_till, ts(9_200)).unwrap();
    assert_eq!(book.len(), 3);

    // So is a different processor.
    let other_processor = ProcessorBatchFile::parse(
        "batch,batch-4,acquirer-2,till-1,2026-11-18,USD\ncapture,rec-4,intent-4,200,0,4\n",
    )
    .unwrap();
    book.ingest(&manager(), other_processor, ts(9_300)).unwrap();
    assert_eq!(book.len(), 4);

    assert_eq!(book.batch(&batch_key("2026-11-18")).unwrap().len(), 1);
    assert_eq!(
        book.batch(&batch_key("2026-11-19"))
            .unwrap()
            .day()
            .to_string(),
        "2026-11-19"
    );
}

#[test]
fn continuation_files_merge_into_the_same_batch() {
    let mut book = SettlementBook::new();
    ingest(&mut book, "capture,rec-1,intent-1,1000,0,1\n");
    let second = ingest(&mut book, "capture,rec-2,intent-2,500,0,2\n");
    assert_eq!(second.added, 1);
    assert_eq!(book.len(), 1);
    let batch = book.batch(&batch_key("2026-11-18")).unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch.totals().unwrap().captured, money(1_500));
}

#[test]
fn malformed_processor_files_are_rejected() {
    assert_eq!(
        ProcessorBatchFile::parse("capture,rec-1,intent-1,10,0,1").unwrap_err(),
        SettlementError::MalformedFile {
            line: 1,
            reason: "record before the batch header"
        }
    );
    assert_eq!(
        ProcessorBatchFile::parse("").unwrap_err(),
        SettlementError::MalformedFile {
            line: 1,
            reason: "missing batch header"
        }
    );
    assert_eq!(
        ProcessorBatchFile::parse(&format!("{HEADER}\nteleport,rec-1,intent-1,10,0,1"))
            .unwrap_err(),
        SettlementError::MalformedFile {
            line: 2,
            reason: "unknown record kind"
        }
    );
    assert_eq!(
        ProcessorBatchFile::parse(&format!("{HEADER}\ncapture,rec-1,intent-1,-10,0,1"))
            .unwrap_err(),
        SettlementError::MalformedFile {
            line: 2,
            reason: "invalid amount"
        }
    );
    // A tip larger than the amount it belongs to is not a settlement line.
    assert_eq!(
        ProcessorBatchFile::parse(&format!("{HEADER}\ncapture,rec-1,intent-1,10,20,1"))
            .unwrap_err(),
        SettlementError::MalformedFile {
            line: 2,
            reason: "inconsistent record amounts"
        }
    );
    assert_eq!(
        ProcessorBatchFile::parse(&format!("{HEADER}\n{HEADER}")).unwrap_err(),
        SettlementError::MalformedFile {
            line: 2,
            reason: "duplicate batch header"
        }
    );
    assert_eq!(
        SettlementDay::parse("2026-02-30").unwrap_err(),
        SettlementError::InvalidSettlementDay
    );
    // Comments and blank lines carry no records but are not errors.
    let commented = ProcessorBatchFile::parse(&format!(
        "# settlement file\n{HEADER}\n\n# one capture\ncapture,rec-1,intent-1,10,0,1\n"
    ))
    .unwrap();
    assert_eq!(commented.records().len(), 1);
}

#[test]
fn settlement_days_round_trip_through_the_epoch() {
    assert_eq!(day("1970-01-01").index(), 0);
    assert_eq!(day("1970-01-02").index(), 1);
    assert_eq!(day("2000-02-29").to_string(), "2000-02-29");
    assert_eq!(day("2026-11-18").to_string(), "2026-11-18");
    for text in ["1970-01-01", "2000-02-29", "2024-12-31", "2026-11-18"] {
        let parsed = day(text);
        assert_eq!(SettlementDay::from_index(parsed.index()), parsed);
    }
    assert_eq!(
        SettlementDay::from_timestamp(ts(0)).to_string(),
        "1970-01-01"
    );
    assert!(SettlementDay::from_timestamp(ts(0)) < day("2026-11-18"));
}

#[test]
fn a_closed_batch_accepts_nothing_more() {
    let mut book = SettlementBook::new();
    ingest(&mut book, "capture,rec-1,intent-1,1000,0,1\n");
    let key = batch_key("2026-11-18");
    book.close_batch(&supervisor(), &key, ts(10_000)).unwrap();
    assert!(book.batch(&key).unwrap().is_closed());
    assert_eq!(book.batch(&key).unwrap().closed_at(), Some(ts(10_000)));
    assert_eq!(
        book.close_batch(&supervisor(), &key, ts(10_001)),
        Err(SettlementError::BatchClosed(key.clone()))
    );
    let error = book
        .ingest(
            &supervisor(),
            file("capture,rec-2,intent-2,500,0,2\n"),
            ts(10_002),
        )
        .unwrap_err();
    assert_eq!(error, SettlementError::BatchClosed(key));
    // The refused record never reached the batch.
    assert_eq!(book.batch(&batch_key("2026-11-18")).unwrap().len(), 1);
}

#[test]
fn a_batch_id_or_currency_change_is_refused() {
    let mut book = SettlementBook::new();
    ingest(&mut book, "capture,rec-1,intent-1,1000,0,1\n");

    let renamed = ProcessorBatchFile::parse(
        "batch,batch-9,acquirer-1,till-1,2026-11-18,USD\ncapture,rec-2,intent-2,500,0,2\n",
    )
    .unwrap();
    assert_eq!(
        book.ingest(&supervisor(), renamed, ts(9_500)).unwrap_err(),
        SettlementError::BatchIdConflict {
            expected: SettlementBatchId::new("batch-1").unwrap(),
            actual: SettlementBatchId::new("batch-9").unwrap(),
        }
    );

    let euros = ProcessorBatchFile::parse(
        "batch,batch-1,acquirer-1,till-1,2026-11-18,EUR\ncapture,rec-2,intent-2,500,0,2\n",
    )
    .unwrap();
    assert_eq!(
        book.ingest(&supervisor(), euros, ts(9_600)).unwrap_err(),
        SettlementError::CurrencyMismatch
    );
}

// ---------------------------------------------------------------------------
// Requirement 5 — duplicate records never double-count
// ---------------------------------------------------------------------------

#[test]
fn duplicated_records_land_in_the_exception_queue() {
    let mut book = SettlementBook::new();
    let outcome = ingest(
        &mut book,
        "capture,rec-1,intent-1,1000,0,1\ncapture,rec-1,intent-1,1000,0,1\n",
    );
    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.duplicates, vec![record("rec-1")]);
    assert!(!outcome.is_clean());
    assert_eq!(book.batch(&batch_key("2026-11-18")).unwrap().len(), 1);
    assert_eq!(
        book.batch(&batch_key("2026-11-18"))
            .unwrap()
            .totals()
            .unwrap()
            .captured,
        money(1_000)
    );

    let queue = book.exceptions();
    assert_eq!(queue.len(), 1);
    let entry = queue.entries().next().unwrap();
    assert_eq!(entry.category, ExceptionCategory::DuplicateRecord);
    assert_eq!(entry.records, vec![record("rec-1")]);
    assert!(entry.is_open());
}

#[test]
fn a_repeated_record_is_a_replay_but_a_changed_one_is_a_conflict() {
    let mut book = SettlementBook::new();
    ingest(&mut book, "capture,rec-1,intent-1,1000,0,1\n");

    let replay = ingest(&mut book, "capture,rec-1,intent-1,1000,0,1\n");
    assert_eq!(replay.replayed, 1);
    assert_eq!(replay.added, 0);
    assert!(replay.is_clean());

    let conflict = ingest(&mut book, "capture,rec-1,intent-1,900,0,1\n");
    assert_eq!(conflict.conflicts, vec![record("rec-1")]);
    assert_eq!(book.batch(&batch_key("2026-11-18")).unwrap().len(), 1);

    let entry = book.exceptions().entries().next().unwrap();
    assert_eq!(entry.category, ExceptionCategory::RecordConflict);
    assert_eq!(entry.expected, Some(money(1_000)));
    assert_eq!(entry.actual, Some(money(900)));
    // The original amount is never overwritten.
    assert_eq!(
        book.batch(&batch_key("2026-11-18"))
            .unwrap()
            .record(&record("rec-1"))
            .unwrap()
            .amount(),
        money(1_000)
    );
}

// ---------------------------------------------------------------------------
// Requirement 2 — reconciliation between intents and processor records
// ---------------------------------------------------------------------------

#[test]
fn captured_intents_reconcile_against_the_processor_file() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_090);
    capture(&mut intents, "intent-2", "check-2", 500);

    let mut book = SettlementBook::new();
    ingest(
        &mut book,
        "capture,rec-1,intent-1,1090,100,1\ncapture,rec-2,intent-2,500,0,2\n",
    );
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    assert!(report.is_clean());
    assert_eq!(report.reconciled.len(), 2);

    let matched = report.match_for(&intent("intent-1")).unwrap();
    assert_eq!(matched.captured, money(1_090));
    assert_eq!(matched.settled, money(1_090));
    assert_eq!(matched.tip, money(100));
    assert_eq!(matched.check_id, check("check-1"));
    assert_eq!(matched.records, vec![record("rec-1")]);
    assert!(report.accounts_for(&intent("intent-2")));
}

#[test]
fn a_partially_settled_day_leaves_the_rest_in_the_queue() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_090);
    capture(&mut intents, "intent-2", "check-2", 500);
    capture(&mut intents, "intent-3", "check-3", 750);

    let mut book = SettlementBook::new();
    // The processor file only covers two of the three captures.
    ingest(
        &mut book,
        "capture,rec-1,intent-1,1090,100,1\ncapture,rec-2,intent-2,500,0,2\n",
    );
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    assert_eq!(report.reconciled.len(), 2);
    assert_eq!(report.exceptions.len(), 1);

    let missing = report.exception_for(&intent("intent-3")).unwrap();
    assert_eq!(missing.category, ExceptionCategory::MissingRecord);
    assert_eq!(missing.expected, Some(money(750)));
    assert_eq!(missing.actual, Some(money(0)));

    // The done-when criterion: no captured intent is silently dropped.
    for id in ["intent-1", "intent-2", "intent-3"] {
        assert!(
            report.accounts_for(&intent(id)),
            "{id} was not accounted for"
        );
    }
}

#[test]
fn short_and_over_settlements_are_distinguished() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_000);
    capture(&mut intents, "intent-2", "check-2", 1_000);

    let mut book = SettlementBook::new();
    ingest(
        &mut book,
        "capture,rec-1,intent-1,900,0,1\ncapture,rec-2,intent-2,1200,0,2\n",
    );
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    assert!(report.reconciled.is_empty());
    assert_eq!(report.exceptions.len(), 2);

    let short = report.exception_for(&intent("intent-1")).unwrap();
    assert_eq!(short.category, ExceptionCategory::PartialSettlement);
    assert_eq!(short.expected, Some(money(1_000)));
    assert_eq!(short.actual, Some(money(900)));

    let over = report.exception_for(&intent("intent-2")).unwrap();
    assert_eq!(over.category, ExceptionCategory::OverSettlement);
    assert_eq!(over.actual, Some(money(1_200)));
}

#[test]
fn two_captures_for_one_intent_are_a_duplicate_not_a_settlement() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_000);

    let mut book = SettlementBook::new();
    ingest(
        &mut book,
        "capture,rec-1,intent-1,1000,0,1\ncapture,rec-2,intent-1,1000,0,2\n",
    );
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    assert!(report.reconciled.is_empty());
    let exception = report.exception_for(&intent("intent-1")).unwrap();
    assert_eq!(exception.category, ExceptionCategory::DuplicateRecord);
    assert_eq!(exception.records, vec![record("rec-1"), record("rec-2")]);
}

#[test]
fn records_for_unknown_or_uncaptured_intents_are_unmatched() {
    let mut intents = PaymentIntentStore::new();
    // Created but never authorized or captured.
    let created = intent("intent-1");
    let binding = IntentBinding::new(
        check("check-1"),
        money(1_000),
        till("till-1"),
        employee("emp-2"),
        PaymentMethod::Card,
    )
    .unwrap();
    intents
        .create(CreateIntent::new(
            created.clone(),
            IdempotencyKey::new("key-1").unwrap(),
            binding,
            ts(1_000),
        ))
        .unwrap();

    let mut book = SettlementBook::new();
    ingest(
        &mut book,
        "capture,rec-1,intent-1,1000,0,1\n\
         capture,rec-2,intent-9,500,0,2\n\
         chargeback,rec-3,-,300,0,3\n",
    );
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    assert!(!report.is_clean());
    assert!(report.reconciled.is_empty());
    // intent-1 is not captured, intent-9 does not exist and rec-3 names nobody.
    assert_eq!(report.exceptions.len(), 3);
    assert!(report
        .exceptions
        .iter()
        .all(|entry| entry.category == ExceptionCategory::UnmatchedRecord));
    assert!(report.accounts_for(&created));
}

#[test]
fn refund_records_must_agree_with_the_intent_refund() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_000);

    let mut book = SettlementBook::new();
    ingest(
        &mut book,
        "capture,rec-1,intent-1,1000,0,1\nrefund,rec-2,intent-1,250,0,2\n",
    );
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    let exception = report.exception_for(&intent("intent-1")).unwrap();
    assert_eq!(exception.category, ExceptionCategory::RefundMismatch);
    assert_eq!(exception.expected, Some(money(0)));
    assert_eq!(exception.actual, Some(money(250)));

    // A refund the POS actually recorded reconciles against a matching record.
    let mut refunded = PaymentIntentStore::new();
    capture(&mut refunded, "intent-1", "check-1", 1_000);
    refunded
        .refund(&intent("intent-1"), money(1_000), ts(1_100))
        .unwrap();
    let mut agreeing = SettlementBook::new();
    ingest(
        &mut agreeing,
        "capture,rec-1,intent-1,1000,0,1\nrefund,rec-2,intent-1,1000,0,2\n",
    );
    let report = agreeing
        .reconcile(&supervisor(), &refunded, ts(9_401))
        .unwrap();
    assert!(report.is_clean());
    assert_eq!(
        report.match_for(&intent("intent-1")).unwrap().refunded,
        money(1_000)
    );
}

#[test]
fn reconciliation_is_idempotent_and_leaves_a_queue_entry() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_000);

    let mut book = SettlementBook::new();
    let first = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    assert_eq!(first.exceptions.len(), 1);
    assert_eq!(book.exceptions().len(), 1);

    // A second pass finds the same problem and adds no second entry.
    let second = book.reconcile(&supervisor(), &intents, ts(9_401)).unwrap();
    assert_eq!(second.exceptions.len(), 1);
    assert_eq!(book.exceptions().len(), 1);

    // Resolving is explicit: a later pass never clears or reopens an entry.
    let key = second.exceptions[0].key.clone();
    let mut queue = book.exceptions().clone();
    queue
        .resolve(&key, ts(9_500), Some("processor confirmed the void"))
        .unwrap();
    assert!(!queue.get(&key).unwrap().state.is_open());
    assert_eq!(queue.open_len(), 0);
    assert_eq!(
        queue.resolve(&key, ts(9_501), None).unwrap_err(),
        SettlementError::AlreadyResolved(key)
    );
}

#[test]
fn resolving_an_unknown_exception_is_rejected() {
    let mut intents = PaymentIntentStore::new();
    capture(&mut intents, "intent-1", "check-1", 1_000);
    let mut book = SettlementBook::new();
    let report = book.reconcile(&supervisor(), &intents, ts(9_400)).unwrap();
    let key = report.exceptions[0].key.clone();

    let mut empty = tirbase_pos::ExceptionQueue::new();
    assert_eq!(
        empty.resolve(&key, ts(9_500), None).unwrap_err(),
        SettlementError::UnknownException(key)
    );
}

#[test]
fn settlement_requires_the_settlement_permission() {
    let mut book = SettlementBook::new();
    let file = file("capture,rec-1,intent-1,1000,0,1\n");
    assert_eq!(
        book.ingest(&cashier(), file, ts(9_000)).unwrap_err(),
        SettlementError::NotPermitted(Permission::SettleBatch)
    );
    assert!(book.is_empty());

    let intents = PaymentIntentStore::new();
    assert_eq!(
        book.reconcile(&cashier(), &intents, ts(9_001)).unwrap_err(),
        SettlementError::NotPermitted(Permission::SettleBatch)
    );
}

// ---------------------------------------------------------------------------
// Requirement 3 — chargeback/refund lifecycle with evidence links
// ---------------------------------------------------------------------------

fn evidence(reference: &str, kind: EvidenceKind) -> Evidence {
    Evidence::new(
        EvidenceRef::new(reference).unwrap(),
        kind,
        Some("attached for the issuer"),
        ts(20_000),
    )
    .unwrap()
}

#[test]
fn a_chargeback_runs_a_full_lifecycle_with_evidence() {
    let mut book = ChargebackBook::new();
    let id = chargeback("cb-1");
    assert_eq!(
        book.open(
            &supervisor(),
            ChargebackSpec::new(
                id.clone(),
                intent("intent-1"),
                Some(check("check-1")),
                money(1_090),
                "goods not received",
                ts(19_000),
            ),
        )
        .unwrap(),
        ChargebackChange::Created
    );

    // The same case opening twice is a replay, not a second case.
    assert_eq!(
        book.open(
            &supervisor(),
            ChargebackSpec::new(
                id.clone(),
                intent("intent-1"),
                Some(check("check-1")),
                money(1_090),
                "goods not received",
                ts(19_001),
            ),
        )
        .unwrap(),
        ChargebackChange::Replayed
    );
    assert_eq!(book.len(), 1);

    let case = book.chargeback(&id).unwrap();
    assert_eq!(case.state(), ChargebackState::Opened);
    assert_eq!(case.opened_by(), &employee("emp-2"));
    assert!(case.debit().is_none());

    // Without evidence the case cannot be won.
    assert_eq!(
        book.win(&supervisor(), &id, ts(19_100)).unwrap_err(),
        SettlementError::EvidenceRequired(id.clone())
    );

    book.review(&supervisor(), &id, ts(19_200)).unwrap();
    assert_eq!(
        book.chargeback(&id).unwrap().state(),
        ChargebackState::UnderReview
    );
    book.attach_evidence(
        &supervisor(),
        &id,
        evidence("doc://receipts/1090", EvidenceKind::Receipt),
    )
    .unwrap();
    book.attach_evidence(
        &supervisor(),
        &id,
        evidence("doc://signatures/1090", EvidenceKind::Signature),
    )
    .unwrap();
    assert_eq!(book.chargeback(&id).unwrap().evidence().len(), 2);

    // The same document cannot be attached twice.
    assert_eq!(
        book.attach_evidence(
            &supervisor(),
            &id,
            evidence("doc://receipts/1090", EvidenceKind::Receipt),
        )
        .unwrap_err(),
        SettlementError::DuplicateEvidence(id.clone())
    );

    book.win(&supervisor(), &id, ts(19_300)).unwrap();
    let case = book.chargeback(&id).unwrap();
    assert_eq!(case.state(), ChargebackState::Won);
    assert!(case.is_closed());
    assert!(case.debit().is_none());
    // A won case is not a debit and cannot be paid.
    assert_eq!(
        book.pay(&supervisor(), &id, ts(19_400)).unwrap_err(),
        SettlementError::ChargebackAlreadyWon(id.clone())
    );
    assert_eq!(book.paid_total(usd()).unwrap(), money(0));
    // Evidence cannot be attached to a closed case.
    assert_eq!(
        book.attach_evidence(
            &supervisor(),
            &id,
            evidence("doc://correspondence/1", EvidenceKind::Correspondence),
        )
        .unwrap_err(),
        SettlementError::ChargebackClosed(id)
    );
}

#[test]
fn a_chargeback_lost_is_a_debit_and_is_paid_once() {
    let mut book = ChargebackBook::new();
    let id = chargeback("cb-2");
    book.open(
        &supervisor(),
        ChargebackSpec::new(
            id.clone(),
            intent("intent-2"),
            None,
            money(1_500),
            "unauthorised",
            ts(19_000),
        ),
    )
    .unwrap();

    // Nothing is owed until the case is lost.
    assert_eq!(
        book.pay(&supervisor(), &id, ts(19_100)).unwrap_err(),
        SettlementError::ChargebackNotLost(id.clone())
    );
    assert_eq!(book.paid_total(usd()).unwrap(), money(0));

    book.lose(&supervisor(), &id, ts(19_200)).unwrap();
    assert_eq!(book.outstanding_total(usd()).unwrap(), money(1_500));
    assert_eq!(book.chargeback(&id).unwrap().debit(), Some(money(1_500)));

    book.pay(&supervisor(), &id, ts(19_300)).unwrap();
    let case = book.chargeback(&id).unwrap();
    assert_eq!(case.state(), ChargebackState::Paid);
    assert_eq!(case.paid_by(), Some(&employee("emp-2")));
    assert_eq!(case.paid_at(), Some(ts(19_300)));
    assert_eq!(book.paid_total(usd()).unwrap(), money(1_500));
    assert_eq!(book.outstanding_total(usd()).unwrap(), money(0));
}

#[test]
fn a_chargeback_cannot_be_paid_twice() {
    let mut book = ChargebackBook::new();
    let id = chargeback("cb-3");
    book.open(
        &supervisor(),
        ChargebackSpec::new(
            id.clone(),
            intent("intent-3"),
            None,
            money(2_000),
            "duplicate transaction",
            ts(19_000),
        ),
    )
    .unwrap();
    book.lose(&supervisor(), &id, ts(19_100)).unwrap();
    book.pay(&supervisor(), &id, ts(19_200)).unwrap();
    assert_eq!(book.paid_total(usd()).unwrap(), money(2_000));

    // The second payment is refused, not replayed.
    assert_eq!(
        book.pay(&manager(), &id, ts(19_300)).unwrap_err(),
        SettlementError::ChargebackAlreadyPaid(id.clone())
    );
    // A third attempt from another operator changes nothing either.
    assert_eq!(
        book.pay(&supervisor(), &id, ts(19_400)).unwrap_err(),
        SettlementError::ChargebackAlreadyPaid(id.clone())
    );
    assert_eq!(book.paid_total(usd()).unwrap(), money(2_000));
    assert_eq!(book.chargeback(&id).unwrap().paid_at(), Some(ts(19_200)));
}

#[test]
fn chargeback_cases_are_worked_by_permitted_operators_only() {
    let mut book = ChargebackBook::new();
    let id = chargeback("cb-4");
    assert_eq!(
        book.open(
            &cashier(),
            ChargebackSpec::new(
                id.clone(),
                intent("intent-4"),
                None,
                money(500),
                "fraud",
                ts(19_000),
            ),
        )
        .unwrap_err(),
        SettlementError::NotPermitted(Permission::ManageChargebacks)
    );
    assert!(book.is_empty());

    book.open(
        &supervisor(),
        ChargebackSpec::new(
            id.clone(),
            intent("intent-4"),
            None,
            money(500),
            "fraud",
            ts(19_000),
        ),
    )
    .unwrap();
    assert_eq!(
        book.review(&cashier(), &id, ts(19_100)).unwrap_err(),
        SettlementError::NotPermitted(Permission::ManageChargebacks)
    );
    assert!(book.chargeback(&chargeback("cb-missing")).is_none());
    assert_eq!(
        book.review(&supervisor(), &chargeback("cb-missing"), ts(19_100))
            .unwrap_err(),
        SettlementError::UnknownChargeback(chargeback("cb-missing"))
    );
}

#[test]
fn a_chargeback_opened_twice_with_different_terms_is_refused() {
    let mut book = ChargebackBook::new();
    let id = chargeback("cb-5");
    book.open(
        &supervisor(),
        ChargebackSpec::new(
            id.clone(),
            intent("intent-5"),
            None,
            money(700),
            "fraud",
            ts(19_000),
        ),
    )
    .unwrap();
    assert_eq!(
        book.open(
            &supervisor(),
            ChargebackSpec::new(
                id.clone(),
                intent("intent-5"),
                None,
                money(800),
                "fraud",
                ts(19_001),
            ),
        )
        .unwrap_err(),
        SettlementError::DuplicateChargeback(id.clone())
    );
    assert_eq!(book.chargeback(&id).unwrap().amount(), money(700));
}

// ---------------------------------------------------------------------------
// Requirement 4 — tip adjustment, pooling and payout
// ---------------------------------------------------------------------------

fn tip_ledger(tips: &[(&str, &str, i64)]) -> TipLedger {
    let mut ledger = TipLedger::new();
    let sessions = directory();
    for (check_id, employee_id, minor) in tips {
        let session = sessions
            .session(&employee(employee_id), till("till-1"))
            .unwrap();
        ledger
            .record_tip(&session, check(check_id), money(*minor), ts(30_000))
            .unwrap();
    }
    ledger
}

#[test]
fn tips_are_attributed_and_adjustments_keep_the_delta() {
    let mut ledger = TipLedger::new();
    assert_eq!(
        ledger
            .record_tip(&cashier(), check("check-1"), money(100), ts(30_000))
            .unwrap(),
        TipChange::Applied
    );
    // The same tip again is a replay; a different one needs an adjustment.
    assert_eq!(
        ledger
            .record_tip(&cashier(), check("check-1"), money(100), ts(30_001))
            .unwrap(),
        TipChange::Replayed
    );
    assert_eq!(
        ledger
            .record_tip(&cashier(), check("check-1"), money(150), ts(30_002))
            .unwrap_err(),
        TipError::TipConflict(check("check-1"))
    );
    assert_eq!(
        ledger
            .record_tip(&cashier(), check("check-2"), money(0), ts(30_003))
            .unwrap_err(),
        TipError::NonPositiveAmount
    );

    // Adjusting needs the tip-payout permission, which a cashier does not have.
    assert_eq!(
        ledger
            .adjust_tip(&cashier(), &check("check-1"), money(120), ts(30_100), None)
            .unwrap_err(),
        TipError::NotPermitted(Permission::PayTips)
    );

    assert_eq!(
        ledger
            .adjust_tip(
                &supervisor(),
                &check("check-1"),
                money(130),
                ts(30_100),
                Some("guest added")
            )
            .unwrap(),
        TipChange::Applied
    );
    assert_eq!(ledger.tip(&check("check-1")).unwrap().amount(), money(130));
    assert_eq!(ledger.total(usd()).unwrap(), money(130));
    let adjustment = &ledger.adjustments()[0];
    assert_eq!(adjustment.previous(), money(100));
    assert_eq!(adjustment.adjusted(), money(130));
    assert_eq!(adjustment.delta(), money(30));
    assert_eq!(adjustment.by(), &employee("emp-2"));
    assert_eq!(adjustment.note(), Some("guest added"));

    // Adjusting to the same value changes nothing.
    assert_eq!(
        ledger
            .adjust_tip(
                &supervisor(),
                &check("check-1"),
                money(130),
                ts(30_200),
                None
            )
            .unwrap(),
        TipChange::Replayed
    );
    assert_eq!(ledger.adjustments().len(), 1);
    assert_eq!(
        ledger
            .adjust_tip(&supervisor(), &check("nope"), money(10), ts(30_300), None)
            .unwrap_err(),
        TipError::UnknownTip(check("nope"))
    );
}

#[test]
fn a_tip_payout_matches_the_allocated_tips() {
    let mut ledger = tip_ledger(&[
        ("check-1", "emp-1", 400),
        ("check-2", "emp-2", 300),
        ("check-3", "emp-3", 300),
    ]);
    assert_eq!(ledger.open_total(usd()).unwrap(), money(1_000));

    let members = [
        TipMember::even(employee("emp-1")),
        TipMember::even(employee("emp-2")),
        TipMember::even(employee("emp-3")),
    ];
    let payout = ledger
        .payout(
            &supervisor(),
            pool("pool-1"),
            TipPoolPolicy::Even,
            &members,
            ts(31_000),
        )
        .unwrap();

    assert_eq!(payout.total(), money(1_000));
    assert_eq!(payout.allocated_total().unwrap(), money(1_000));
    payout.validate().unwrap();
    // 1000/3 cannot be exact, so two members get 334 and one gets 333.
    assert_eq!(
        payout.allocation(&employee("emp-1")).unwrap().payout,
        money(334)
    );
    assert_eq!(
        payout.allocation(&employee("emp-2")).unwrap().payout,
        money(333)
    );
    assert_eq!(
        payout.allocation(&employee("emp-3")).unwrap().payout,
        money(333)
    );

    // Every tip is settled and nothing is left owed.
    assert_eq!(ledger.open_total(usd()).unwrap(), money(0));
    assert_eq!(ledger.payouts().count(), 1);
    assert_eq!(payout.paid_by(), &employee("emp-2"));
}

#[test]
fn a_weighted_pool_splits_by_weight_without_losing_a_cent() {
    let mut ledger = tip_ledger(&[("check-1", "emp-2", 1_001)]);
    let members = [
        TipMember::new(employee("emp-2"), 2),
        TipMember::new(employee("emp-3"), 1),
    ];
    let payout = ledger
        .payout(
            &supervisor(),
            pool("pool-2"),
            TipPoolPolicy::Weighted,
            &members,
            ts(31_000),
        )
        .unwrap();
    assert_eq!(payout.total(), money(1_001));
    assert_eq!(payout.allocated_total().unwrap(), money(1_001));
    // 2:1 of 1001 is 667.33 and 333.67; the leftover unit goes to the larger
    // remainder, so the sum stays exactly 1001.
    assert_eq!(
        payout.allocation(&employee("emp-2")).unwrap().payout,
        money(667)
    );
    assert_eq!(
        payout.allocation(&employee("emp-3")).unwrap().payout,
        money(334)
    );
    assert_eq!(
        payout.allocation(&employee("emp-3")).unwrap().contributed,
        money(0)
    );
    assert_eq!(
        payout.allocation(&employee("emp-2")).unwrap().contributed,
        money(1_001)
    );
}

#[test]
fn a_pool_cannot_absorb_a_tip_from_a_non_member() {
    let mut ledger = tip_ledger(&[("check-1", "emp-1", 500), ("check-2", "emp-3", 500)]);
    let members = [TipMember::even(employee("emp-1"))];
    assert_eq!(
        ledger
            .payout(
                &supervisor(),
                pool("pool-3"),
                TipPoolPolicy::Even,
                &members,
                ts(31_000),
            )
            .unwrap_err(),
        TipError::UnpooledTip(check("check-2"))
    );
    // The refused payout settled nothing.
    assert_eq!(ledger.open_total(usd()).unwrap(), money(1_000));
    assert_eq!(ledger.payouts().count(), 0);
}

#[test]
fn a_pool_validates_members_and_weights() {
    let mut ledger = tip_ledger(&[("check-1", "emp-2", 100)]);
    assert_eq!(
        ledger
            .payout(
                &supervisor(),
                pool("pool-4"),
                TipPoolPolicy::Even,
                &[],
                ts(31_000)
            )
            .unwrap_err(),
        TipError::EmptyPool
    );
    let twice = [
        TipMember::even(employee("emp-2")),
        TipMember::even(employee("emp-2")),
    ];
    assert_eq!(
        ledger
            .payout(
                &supervisor(),
                pool("pool-4"),
                TipPoolPolicy::Even,
                &twice,
                ts(31_000)
            )
            .unwrap_err(),
        TipError::DuplicateMember(employee("emp-2"))
    );
    let zero = [TipMember::new(employee("emp-2"), 0)];
    assert_eq!(
        ledger
            .payout(
                &supervisor(),
                pool("pool-4"),
                TipPoolPolicy::Weighted,
                &zero,
                ts(31_000)
            )
            .unwrap_err(),
        TipError::ZeroWeight(employee("emp-2"))
    );
    // A cashier cannot run a payout.
    let members = [TipMember::even(employee("emp-2"))];
    assert_eq!(
        ledger
            .payout(
                &cashier(),
                pool("pool-4"),
                TipPoolPolicy::Even,
                &members,
                ts(31_000)
            )
            .unwrap_err(),
        TipError::NotPermitted(Permission::PayTips)
    );
}

#[test]
fn a_pool_cannot_be_paid_twice_and_pays_only_new_tips() {
    let mut ledger = tip_ledger(&[("check-1", "emp-2", 600)]);
    let members = [
        TipMember::even(employee("emp-2")),
        TipMember::even(employee("emp-3")),
    ];
    let first = ledger
        .payout(
            &supervisor(),
            pool("pool-5"),
            TipPoolPolicy::Even,
            &members,
            ts(31_000),
        )
        .unwrap();
    assert_eq!(first.total(), money(600));

    // Repeating the same pool returns the stored payout and moves no money.
    let replay = ledger
        .payout(
            &supervisor(),
            pool("pool-5"),
            TipPoolPolicy::Even,
            &members,
            ts(31_001),
        )
        .unwrap();
    assert_eq!(replay.paid_at(), ts(31_000));
    assert_eq!(ledger.total(usd()).unwrap(), money(600));

    // New tips are paid by the next pool, never by the settled one.
    ledger
        .record_tip(&supervisor(), check("check-2"), money(200), ts(31_100))
        .unwrap();
    assert_eq!(ledger.open_total(usd()).unwrap(), money(200));
    let second = ledger
        .payout(
            &supervisor(),
            pool("pool-6"),
            TipPoolPolicy::Even,
            &members,
            ts(31_200),
        )
        .unwrap();
    assert_eq!(second.total(), money(200));
    assert_eq!(ledger.open_total(usd()).unwrap(), money(0));

    // With nothing open there is nothing to pay.
    assert_eq!(
        ledger
            .payout(
                &supervisor(),
                pool("pool-7"),
                TipPoolPolicy::Even,
                &members,
                ts(31_300),
            )
            .unwrap_err(),
        TipError::NoTips
    );

    // A settled tip can no longer be adjusted.
    assert_eq!(
        ledger
            .adjust_tip(
                &supervisor(),
                &check("check-1"),
                money(10),
                ts(31_400),
                None
            )
            .unwrap_err(),
        TipError::PoolConflict(pool("pool-5"))
    );
}

#[test]
fn a_closed_chargeback_is_not_reopened_by_a_later_loss() {
    let mut book = ChargebackBook::new();
    let id = chargeback("cb-6");
    book.open(
        &supervisor(),
        ChargebackSpec::new(
            id.clone(),
            intent("intent-6"),
            None,
            money(900),
            "fraud",
            ts(19_000),
        ),
    )
    .unwrap();
    book.attach_evidence(
        &supervisor(),
        &id,
        evidence("doc://receipts/900", EvidenceKind::Receipt),
    )
    .unwrap();
    book.win(&supervisor(), &id, ts(19_100)).unwrap();
    assert_eq!(
        book.lose(&supervisor(), &id, ts(19_200)).unwrap_err(),
        SettlementError::ChargebackAlreadyWon(id.clone())
    );
    assert_eq!(book.chargeback(&id).unwrap().state(), ChargebackState::Won);
    assert_eq!(book.paid_total(usd()).unwrap(), money(0));
}
