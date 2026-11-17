// SPDX-License-Identifier: AGPL-3.0-only

//! POS-03 behavioural tests: intent state machine, bound idempotency keys,
//! duplicate safety, amount/currency checks, token-only storage, journal
//! recovery and processor reconciliation.

use tirbase_pos::{
    CheckId, CreateIntent, CreateOutcome, Currency, EmployeeId, IdempotencyKey, IntentBinding,
    IntentEvent, IntentStatus, Money, PaymentIntentId, PaymentIntentStore, PaymentMethod, PosError,
    ProcessorReport, ProcessorToken, ReconciliationOutcome, TerminalId, Timestamp,
    TransitionOutcome,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn eur() -> Currency {
    Currency::from_code("EUR").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn money_in(currency: Currency, minor: i64) -> Money {
    Money::new(currency, minor)
}

fn ts(value: i64) -> Timestamp {
    Timestamp::from_millis(value)
}

fn check(value: &str) -> CheckId {
    CheckId::new(value).unwrap()
}

fn terminal(value: &str) -> TerminalId {
    TerminalId::new(value).unwrap()
}

fn employee(value: &str) -> EmployeeId {
    EmployeeId::new(value).unwrap()
}

fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).unwrap()
}

fn intent(value: &str) -> PaymentIntentId {
    PaymentIntentId::new(value).unwrap()
}

fn token(value: &str) -> ProcessorToken {
    ProcessorToken::new(value).unwrap()
}

fn binding(minor: i64) -> IntentBinding {
    IntentBinding::new(
        check("check-1"),
        money(minor),
        terminal("till-1"),
        employee("emp-1"),
        PaymentMethod::Card,
    )
    .unwrap()
}

fn request(id: &str, key_value: &str, binding: IntentBinding, at: i64) -> CreateIntent {
    CreateIntent::new(intent(id), key(key_value), binding, ts(at))
}

fn create(store: &mut PaymentIntentStore, id: &str, key_value: &str) -> PaymentIntentId {
    let outcome = store
        .create(request(id, key_value, binding(1_000), 1))
        .unwrap();
    assert!(matches!(outcome, CreateOutcome::Created(_)));
    intent(id)
}

fn authorize(store: &mut PaymentIntentStore, id: &PaymentIntentId) {
    let outcome = store.authorize(id, token("tok_authorized"), ts(2)).unwrap();
    assert!(matches!(outcome, TransitionOutcome::Applied(_)));
}

fn capture(store: &mut PaymentIntentStore, id: &PaymentIntentId) {
    let outcome = store
        .capture(id, money(1_000), token("tok_authorized"), ts(3))
        .unwrap();
    assert!(matches!(outcome, TransitionOutcome::Applied(_)));
}

fn captured_events(store: &PaymentIntentStore) -> usize {
    store
        .journal()
        .iter()
        .filter(|event| matches!(event, IntentEvent::Captured { .. }))
        .count()
}

#[test]
fn intent_reaches_each_state_and_terminal_states_reject_further_change() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    assert_eq!(store.intent(&id).unwrap().status(), IntentStatus::Created);
    assert_eq!(store.pending_intents().count(), 1);

    authorize(&mut store, &id);
    assert_eq!(
        store.intent(&id).unwrap().status(),
        IntentStatus::Authorized
    );
    assert_eq!(
        store.intent(&id).unwrap().processor_token(),
        Some(&token("tok_authorized"))
    );
    assert_eq!(store.pending_intents().count(), 1);

    capture(&mut store, &id);
    let captured = store.intent(&id).unwrap();
    assert_eq!(captured.status(), IntentStatus::Captured);
    assert_eq!(captured.captured_amount(), Some(money(1_000)));
    assert_eq!(store.pending_intents().count(), 0);

    let refunded = store.refund(&id, money(1_000), ts(4)).unwrap();
    assert!(matches!(refunded, TransitionOutcome::Applied(_)));
    let intent = store.intent(&id).unwrap().clone();
    assert_eq!(intent.status(), IntentStatus::Refunded);
    assert_eq!(intent.refunded_amount(), Some(money(1_000)));
    assert!(intent.is_terminal());
    assert_eq!(
        store.refund(&id, money(1_000), ts(5)).unwrap(),
        TransitionOutcome::Replayed(intent.clone())
    );
    assert_eq!(
        store.void(&id, "too late", ts(6)).unwrap_err(),
        PosError::InvalidIntentTransition {
            from: IntentStatus::Refunded,
            to: IntentStatus::Voided,
        }
    );
    assert_eq!(store.journal().len(), 4);
}

#[test]
fn idempotency_key_is_bound_to_check_amount_currency_terminal_operator_and_method() {
    let mut store = PaymentIntentStore::new();
    let original = binding(1_000);
    let first = store
        .create(request("intent-1", "bound-key", original.clone(), 1))
        .unwrap();
    assert!(matches!(first, CreateOutcome::Created(_)));

    // The proposed intent id cannot be reused under a different key.
    assert_eq!(
        store
            .create(request("intent-1", "other-key", original.clone(), 2))
            .unwrap_err(),
        PosError::IntentAlreadyExists(intent("intent-1"))
    );
    assert_eq!(store.len(), 1);

    let changed = [
        IntentBinding::new(
            check("check-2"),
            money(1_000),
            terminal("till-1"),
            employee("emp-1"),
            PaymentMethod::Card,
        )
        .unwrap(),
        IntentBinding::new(
            check("check-1"),
            money(1_001),
            terminal("till-1"),
            employee("emp-1"),
            PaymentMethod::Card,
        )
        .unwrap(),
        IntentBinding::new(
            check("check-1"),
            money_in(eur(), 1_000),
            terminal("till-1"),
            employee("emp-1"),
            PaymentMethod::Card,
        )
        .unwrap(),
        IntentBinding::new(
            check("check-1"),
            money(1_000),
            terminal("till-2"),
            employee("emp-1"),
            PaymentMethod::Card,
        )
        .unwrap(),
        IntentBinding::new(
            check("check-1"),
            money(1_000),
            terminal("till-1"),
            employee("emp-2"),
            PaymentMethod::Card,
        )
        .unwrap(),
        IntentBinding::new(
            check("check-1"),
            money(1_000),
            terminal("till-1"),
            employee("emp-1"),
            PaymentMethod::Cash,
        )
        .unwrap(),
    ];

    for (index, binding) in changed.into_iter().enumerate() {
        let err = store
            .create(request(
                &format!("intent-{index}-other"),
                "bound-key",
                binding,
                (index + 2) as i64,
            ))
            .unwrap_err();
        assert_eq!(err, PosError::IdempotencyKeyConflict(key("bound-key")));
        assert_eq!(store.len(), 1, "a conflict must not allocate an intent");
    }
    assert_eq!(store.journal().len(), 1);
}

#[test]
fn duplicate_request_returns_the_original_result_and_never_charges_twice() {
    let mut store = PaymentIntentStore::new();
    let first = store
        .create(request("intent-1", "retry-key", binding(1_000), 1))
        .unwrap();
    let CreateOutcome::Created(original) = first else {
        panic!("first create must create");
    };

    // A retry may propose a new local id; the key still returns the original.
    let duplicate = store
        .create(request("intent-retry", "retry-key", binding(1_000), 9))
        .unwrap();
    let CreateOutcome::Duplicate(duplicate) = duplicate else {
        panic!("second create must be a duplicate");
    };
    assert_eq!(duplicate, original);
    assert_eq!(duplicate.id(), &intent("intent-1"));
    assert_eq!(store.len(), 1);

    authorize(&mut store, &intent("intent-1"));
    let first_capture = store
        .capture(
            &intent("intent-1"),
            money(1_000),
            token("tok_authorized"),
            ts(3),
        )
        .unwrap();
    assert!(matches!(first_capture, TransitionOutcome::Applied(_)));

    for at in 4..20 {
        let replay = store
            .capture(
                &intent("intent-1"),
                money(1_000),
                token("tok_authorized"),
                ts(at),
            )
            .unwrap();
        assert!(replay.is_replayed());
        assert_eq!(replay.intent().status(), IntentStatus::Captured);
    }
    assert_eq!(store.len(), 1);
    assert_eq!(captured_events(&store), 1, "exactly one charge");

    // The cached create result remains the original `Created` snapshot even
    // after later transitions.
    let late_duplicate = store
        .create(request("intent-again", "retry-key", binding(1_000), 30))
        .unwrap();
    assert_eq!(late_duplicate.intent().status(), IntentStatus::Created);
    assert_eq!(late_duplicate.intent(), &original);
}

#[test]
fn amount_and_currency_mismatches_are_rejected_without_mutation() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    authorize(&mut store, &id);
    let before = store.clone();

    assert_eq!(
        store
            .capture(&id, money(1_001), token("tok_authorized"), ts(3))
            .unwrap_err(),
        PosError::IntentAmountMismatch {
            expected: money(1_000),
            actual: money(1_001),
        }
    );
    assert_eq!(store, before);

    assert_eq!(
        store
            .capture(&id, money_in(eur(), 1_000), token("tok_authorized"), ts(3))
            .unwrap_err(),
        PosError::CurrencyMismatch
    );
    assert_eq!(store, before);

    // A mismatched retry remains rejected even after a successful capture.
    capture(&mut store, &id);
    let captured = store.clone();
    assert_eq!(
        store
            .capture(&id, money(999), token("tok_authorized"), ts(4))
            .unwrap_err(),
        PosError::IntentAmountMismatch {
            expected: money(1_000),
            actual: money(999),
        }
    );
    assert_eq!(store, captured);

    assert_eq!(
        store.refund(&id, money(999), ts(5)).unwrap_err(),
        PosError::IntentAmountMismatch {
            expected: money(1_000),
            actual: money(999),
        }
    );
    assert_eq!(store, captured);
    assert_eq!(
        store
            .refund(&id, money_in(eur(), 1_000), ts(5))
            .unwrap_err(),
        PosError::CurrencyMismatch
    );
    assert_eq!(store, captured);
}

#[test]
fn out_of_order_and_conflicting_transitions_are_rejected() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    let created = store.clone();

    assert_eq!(
        store
            .capture(&id, money(1_000), token("tok_authorized"), ts(2))
            .unwrap_err(),
        PosError::InvalidIntentTransition {
            from: IntentStatus::Created,
            to: IntentStatus::Captured,
        }
    );
    assert_eq!(store, created);
    assert_eq!(
        store.refund(&id, money(1_000), ts(2)).unwrap_err(),
        PosError::InvalidIntentTransition {
            from: IntentStatus::Created,
            to: IntentStatus::Refunded,
        }
    );
    assert_eq!(store, created);

    authorize(&mut store, &id);
    let authorized = store.clone();
    assert_eq!(
        store.refund(&id, money(1_000), ts(3)).unwrap_err(),
        PosError::InvalidIntentTransition {
            from: IntentStatus::Authorized,
            to: IntentStatus::Refunded,
        }
    );
    assert_eq!(store, authorized);

    assert_eq!(
        store.authorize(&id, token("tok_other"), ts(4)).unwrap_err(),
        PosError::IntentTokenMismatch(id.clone())
    );
    assert_eq!(
        store
            .capture(&id, money(1_000), token("tok_other"), ts(4))
            .unwrap_err(),
        PosError::IntentTokenMismatch(id.clone())
    );
    assert_eq!(store, authorized);

    // Authorization after capture is a replay of the original request.
    capture(&mut store, &id);
    assert!(store
        .authorize(&id, token("tok_authorized"), ts(5))
        .unwrap()
        .is_replayed());

    // A captured intent may be voided (a processor reversal), and that is
    // terminal; a refund afterwards is rejected.
    let voided = store.void(&id, "processor reversal", ts(6)).unwrap();
    assert!(matches!(voided, TransitionOutcome::Applied(_)));
    assert_eq!(store.intent(&id).unwrap().status(), IntentStatus::Voided);
    assert!(store.void(&id, "again", ts(7)).unwrap().is_replayed());
    assert_eq!(
        store.refund(&id, money(1_000), ts(7)).unwrap_err(),
        PosError::InvalidIntentTransition {
            from: IntentStatus::Voided,
            to: IntentStatus::Refunded,
        }
    );
}

#[test]
fn processor_tokens_are_opaque_validated_and_redacted() {
    assert_eq!(token("tok_abc123").as_str(), "tok_abc123");
    assert_eq!(
        ProcessorToken::new("4111 1111 1111 1111").unwrap_err(),
        PosError::PanLikeProcessorToken
    );
    assert_eq!(
        ProcessorToken::new("4111111111111111").unwrap_err(),
        PosError::PanLikeProcessorToken
    );
    assert_eq!(
        ProcessorToken::new("").unwrap_err(),
        PosError::InvalidProcessorToken
    );
    assert_eq!(
        ProcessorToken::new("tok with space").unwrap_err(),
        PosError::InvalidProcessorToken
    );
    assert_eq!(
        ProcessorToken::new("x".repeat(257)).unwrap_err(),
        PosError::InvalidProcessorToken
    );

    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    store
        .authorize(&id, token("tok_secret_value"), ts(2))
        .unwrap();
    let debug = format!("{:?}", store.intent(&id).unwrap());
    assert!(!debug.contains("tok_secret_value"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn crash_after_authorization_recovers_the_intent_from_the_journal() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    authorize(&mut store, &id);
    let journal = store.journal().to_vec();

    let recovered = PaymentIntentStore::recover(&journal).unwrap();
    assert_eq!(recovered, store);
    assert_eq!(
        recovered.intent(&id).unwrap().status(),
        IntentStatus::Authorized
    );
    assert_eq!(
        recovered.intent(&id).unwrap().processor_token(),
        Some(&token("tok_authorized"))
    );
    assert_eq!(recovered.journal(), journal);

    // Startup duplicate traffic still returns the original create result.
    let duplicate = recovered
        .clone()
        .create(request("intent-1", "key-1", binding(1_000), 10));
    let duplicate = duplicate.unwrap();
    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.intent().id(), &id);
    assert_eq!(recovered.len(), 1);
}

#[test]
fn journal_recovery_rebuilds_every_applied_state() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    authorize(&mut store, &id);
    capture(&mut store, &id);
    store.refund(&id, money(1_000), ts(4)).unwrap();

    let recovered = PaymentIntentStore::recover(store.journal()).unwrap();
    assert_eq!(recovered, store);
    assert_eq!(
        recovered.intent(&id).unwrap().status(),
        IntentStatus::Refunded
    );
    assert_eq!(recovered.journal().len(), 4);
}

#[test]
fn reconciliation_recovers_processor_state_after_a_lost_response() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");

    let outcome = store
        .reconcile(
            &id,
            ProcessorReport::Authorized {
                token: token("tok_authorized"),
            },
            ts(2),
        )
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Recovered(_)));
    assert_eq!(
        store.intent(&id).unwrap().status(),
        IntentStatus::Authorized
    );

    let outcome = store
        .reconcile(
            &id,
            ProcessorReport::Captured {
                token: token("tok_authorized"),
                amount: money(1_000),
            },
            ts(3),
        )
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Recovered(_)));
    assert_eq!(store.intent(&id).unwrap().status(), IntentStatus::Captured);

    let outcome = store
        .reconcile(
            &id,
            ProcessorReport::Refunded {
                amount: money(1_000),
            },
            ts(4),
        )
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Recovered(_)));
    assert_eq!(store.intent(&id).unwrap().status(), IntentStatus::Refunded);

    // A later agreement is not another transition.
    let matched = store
        .reconcile(
            &id,
            ProcessorReport::Refunded {
                amount: money(1_000),
            },
            ts(5),
        )
        .unwrap();
    assert!(matches!(matched, ReconciliationOutcome::Matched(_)));
    assert_eq!(captured_events(&store), 1);
}

#[test]
fn reconciliation_can_jump_directly_to_captured_and_leaves_unknown_reports_unresolved() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    let outcome = store
        .reconcile(
            &id,
            ProcessorReport::Captured {
                token: token("tok_authorized"),
                amount: money(1_000),
            },
            ts(2),
        )
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Recovered(_)));
    assert_eq!(store.intent(&id).unwrap().status(), IntentStatus::Captured);
    assert_eq!(store.journal().len(), 3);

    let before = store.clone();
    let outcome = store
        .reconcile(&id, ProcessorReport::NotFound, ts(3))
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Unresolved(_)));
    assert_eq!(store, before);

    let mismatch = store
        .reconcile(&id, ProcessorReport::Refunded { amount: money(999) }, ts(4))
        .unwrap_err();
    assert_eq!(
        mismatch,
        PosError::IntentAmountMismatch {
            expected: money(1_000),
            actual: money(999),
        }
    );
    assert_eq!(store, before);
}

#[test]
fn reconciliation_voids_an_authorized_intent_and_refuses_to_regress_a_refund() {
    let mut store = PaymentIntentStore::new();
    let id = create(&mut store, "intent-1", "key-1");
    authorize(&mut store, &id);
    let outcome = store
        .reconcile(&id, ProcessorReport::Voided, ts(3))
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Recovered(_)));
    assert_eq!(store.intent(&id).unwrap().status(), IntentStatus::Voided);
    assert_eq!(
        store.intent(&id).unwrap().void_reason(),
        Some("processor reconciliation")
    );

    let mut refunded = PaymentIntentStore::new();
    let id = create(&mut refunded, "intent-1", "key-1");
    authorize(&mut refunded, &id);
    capture(&mut refunded, &id);
    refunded.refund(&id, money(1_000), ts(4)).unwrap();
    let before = refunded.clone();
    let outcome = refunded
        .reconcile(&id, ProcessorReport::Voided, ts(5))
        .unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::Unresolved(_)));
    assert_eq!(refunded, before);
}
