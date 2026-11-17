// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for the POS-03 acceptance criteria:
//!
//! - duplicate and concurrent retries produce one intent and one capture;
//! - out-of-order requests never double-charge or move the state backwards;
//! - journal recovery reconstructs exactly the applied state;
//! - amount, currency and idempotency-binding mismatches are rejected without
//!   mutation.

use proptest::prelude::*;
use tirbase_pos::{
    CheckId, CreateIntent, Currency, EmployeeId, IdempotencyKey, IntentBinding, IntentEvent,
    IntentStatus, Money, PaymentIntentId, PaymentIntentStore, PaymentMethod, PosError,
    ProcessorToken, TerminalId, Timestamp,
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

fn binding() -> IntentBinding {
    IntentBinding::new(
        check("check-1"),
        money(1_000),
        terminal("till-1"),
        employee("emp-1"),
        PaymentMethod::Card,
    )
    .unwrap()
}

fn request(id: &str, at: i64) -> CreateIntent {
    CreateIntent::new(intent(id), key("property-key"), binding(), ts(at))
}

fn seed(store: &mut PaymentIntentStore) -> PaymentIntentId {
    let id = intent("intent-1");
    store.create(request("intent-1", 1)).unwrap();
    id
}

fn captured_events(store: &PaymentIntentStore) -> usize {
    store
        .journal()
        .iter()
        .filter(|event| matches!(event, IntentEvent::Captured { .. }))
        .count()
}

fn created_events(store: &PaymentIntentStore) -> usize {
    store
        .journal()
        .iter()
        .filter(|event| matches!(event, IntentEvent::Created { .. }))
        .count()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn duplicate_creates_allocate_one_intent(attempts in 1_usize..40) {
        let mut store = PaymentIntentStore::new();
        let original = store.create(request("intent-1", 1)).unwrap();
        let original = original.intent().clone();

        for attempt in 0..attempts {
            let outcome = store
                .create(request(&format!("retry-{attempt}"), (attempt + 2) as i64))
                .unwrap();
            prop_assert!(outcome.is_duplicate());
            prop_assert_eq!(outcome.intent(), &original);
        }
        prop_assert_eq!(store.len(), 1);
        prop_assert_eq!(created_events(&store), 1);
        prop_assert_eq!(store.journal().len(), 1);
    }

    #[test]
    fn duplicate_captures_charge_once(attempts in 1_usize..40) {
        let mut store = PaymentIntentStore::new();
        let id = seed(&mut store);
        store.authorize(&id, token("tok_1"), ts(2)).unwrap();
        store
            .capture(&id, money(1_000), token("tok_1"), ts(3))
            .unwrap();

        for attempt in 0..attempts {
            let outcome = store
                .capture(
                    &id,
                    money(1_000),
                    token("tok_1"),
                    ts((attempt + 4) as i64),
                )
                .unwrap();
            prop_assert!(outcome.is_replayed());
            prop_assert_eq!(outcome.intent().status(), IntentStatus::Captured);
        }
        prop_assert_eq!(captured_events(&store), 1);
        prop_assert_eq!(store.len(), 1);
    }

    #[test]
    fn interleaved_concurrent_retries_converge(
        actions in proptest::collection::vec(0_u8..3, 0..60)
    ) {
        let mut store = PaymentIntentStore::new();
        let id = seed(&mut store);
        store.authorize(&id, token("tok_1"), ts(2)).unwrap();
        store
            .capture(&id, money(1_000), token("tok_1"), ts(3))
            .unwrap();

        for (index, action) in actions.into_iter().enumerate() {
            let at = ts((index + 4) as i64);
            match action {
                0 => {
                    let outcome = store
                        .create(request(&format!("concurrent-{index}"), at.millis()))
                        .unwrap();
                    prop_assert!(outcome.is_duplicate());
                }
                1 => {
                    let outcome = store.authorize(&id, token("tok_1"), at).unwrap();
                    prop_assert!(outcome.is_replayed());
                }
                _ => {
                    let outcome = store
                        .capture(&id, money(1_000), token("tok_1"), at)
                        .unwrap();
                    prop_assert!(outcome.is_replayed());
                }
            }
            prop_assert_eq!(store.len(), 1);
            prop_assert_eq!(created_events(&store), 1);
            prop_assert_eq!(captured_events(&store), 1);
        }
        prop_assert_eq!(
            store.intent(&id).unwrap().status(),
            IntentStatus::Captured
        );
    }

    #[test]
    fn arbitrary_out_of_order_requests_never_double_capture(
        actions in proptest::collection::vec(0_u8..5, 0..80)
    ) {
        let mut store = PaymentIntentStore::new();
        let id = seed(&mut store);

        for (index, action) in actions.into_iter().enumerate() {
            let at = ts((index + 2) as i64);
            match action {
                0 => {
                    let _ = store.authorize(&id, token("tok_1"), at);
                }
                1 => {
                    let _ = store.capture(&id, money(1_000), token("tok_1"), at);
                }
                2 => {
                    let _ = store.refund(&id, money(1_000), at);
                }
                3 => {
                    let _ = store.void(&id, "property void", at);
                }
                _ => {
                    let _ = store.create(request("intent-1", at.millis()));
                }
            }

            let intent = store.intent(&id).unwrap();
            prop_assert!(captured_events(&store) <= 1);
            prop_assert_eq!(store.len(), 1);
            prop_assert_eq!(created_events(&store), 1);

            match intent.status() {
                IntentStatus::Created => {
                    prop_assert_eq!(captured_events(&store), 0);
                    prop_assert!(intent.processor_token().is_none());
                }
                IntentStatus::Authorized => {
                    prop_assert_eq!(captured_events(&store), 0);
                    prop_assert!(intent.processor_token().is_some());
                }
                IntentStatus::Captured => {
                    prop_assert_eq!(captured_events(&store), 1);
                    prop_assert_eq!(intent.captured_amount(), Some(money(1_000)));
                }
                IntentStatus::Refunded => {
                    prop_assert_eq!(captured_events(&store), 1);
                    prop_assert_eq!(intent.refunded_amount(), Some(money(1_000)));
                }
                IntentStatus::Voided => {
                    prop_assert!(intent.void_reason().is_some());
                }
            }

            // A replay of the *capture* request after any terminal state must
            // not add another capture event.
            let _ = store.capture(&id, money(1_000), token("tok_1"), at);
            prop_assert!(captured_events(&store) <= 1);
        }
    }

    #[test]
    fn recovery_is_exact_for_arbitrary_applied_state(
        actions in proptest::collection::vec(0_u8..4, 0..40)
    ) {
        let mut store = PaymentIntentStore::new();
        let id = seed(&mut store);

        for (index, action) in actions.into_iter().enumerate() {
            let at = ts((index + 2) as i64);
            match action {
                0 => {
                    let _ = store.authorize(&id, token("tok_1"), at);
                }
                1 => {
                    let _ = store.capture(&id, money(1_000), token("tok_1"), at);
                }
                2 => {
                    let _ = store.refund(&id, money(1_000), at);
                }
                _ => {
                    let _ = store.void(&id, "property void", at);
                }
            }

            let recovered = PaymentIntentStore::recover(store.journal()).unwrap();
            prop_assert_eq!(&recovered, &store);
            prop_assert_eq!(recovered.journal(), store.journal());
        }
    }

    #[test]
    fn wrong_amount_or_currency_is_rejected_without_mutation(
        delta in 1_i64..10_000,
        foreign_currency: bool,
    ) {
        let mut store = PaymentIntentStore::new();
        let id = seed(&mut store);
        store.authorize(&id, token("tok_1"), ts(2)).unwrap();
        let before = store.clone();

        let wrong = if foreign_currency {
            Money::new(eur(), 1_000)
        } else {
            Money::new(usd(), 1_000 + delta)
        };
        let capture_error = store
            .capture(&id, wrong, token("tok_1"), ts(3))
            .unwrap_err();
        if foreign_currency {
            prop_assert_eq!(capture_error, PosError::CurrencyMismatch);
        } else {
            let is_mismatch = matches!(
                capture_error,
                PosError::IntentAmountMismatch { expected, actual }
                    if expected == money(1_000) && actual == wrong
            );
            prop_assert!(is_mismatch);
        }
        prop_assert_eq!(&store, &before);

        store
            .capture(&id, money(1_000), token("tok_1"), ts(4))
            .unwrap();
        let captured = store.clone();
        let refund_error = if foreign_currency {
            store.refund(&id, Money::new(eur(), 1_000), ts(5)).unwrap_err()
        } else {
            store.refund(&id, money(1_000 + delta), ts(5)).unwrap_err()
        };
        if foreign_currency {
            prop_assert_eq!(refund_error, PosError::CurrencyMismatch);
        } else {
            let is_mismatch = matches!(refund_error, PosError::IntentAmountMismatch { .. });
            prop_assert!(is_mismatch);
        }
        prop_assert_eq!(&store, &captured);
    }

    #[test]
    fn a_reused_key_with_any_changed_binding_is_a_conflict(field in 0_u8..6) {
        let mut store = PaymentIntentStore::new();
        store.create(request("intent-1", 1)).unwrap();
        let before = store.clone();

        let changed = match field {
            0 => IntentBinding::new(
                check("check-2"),
                money(1_000),
                terminal("till-1"),
                employee("emp-1"),
                PaymentMethod::Card,
            )
            .unwrap(),
            1 => IntentBinding::new(
                check("check-1"),
                money(1_001),
                terminal("till-1"),
                employee("emp-1"),
                PaymentMethod::Card,
            )
            .unwrap(),
            2 => IntentBinding::new(
                check("check-1"),
                Money::new(eur(), 1_000),
                terminal("till-1"),
                employee("emp-1"),
                PaymentMethod::Card,
            )
            .unwrap(),
            3 => IntentBinding::new(
                check("check-1"),
                money(1_000),
                terminal("till-2"),
                employee("emp-1"),
                PaymentMethod::Card,
            )
            .unwrap(),
            4 => IntentBinding::new(
                check("check-1"),
                money(1_000),
                terminal("till-1"),
                employee("emp-2"),
                PaymentMethod::Card,
            )
            .unwrap(),
            _ => IntentBinding::new(
                check("check-1"),
                money(1_000),
                terminal("till-1"),
                employee("emp-1"),
                PaymentMethod::Cash,
            )
            .unwrap(),
        };

        let outcome = store.create(CreateIntent::new(
            intent("intent-other"),
            key("property-key"),
            changed,
            ts(9),
        ));
        prop_assert_eq!(
            outcome.unwrap_err(),
            PosError::IdempotencyKeyConflict(key("property-key"))
        );
        prop_assert_eq!(&store, &before);
    }

    #[test]
    fn card_number_like_tokens_are_rejected(prefix in "[0-9]{13,19}") {
        prop_assert!(matches!(
            ProcessorToken::new(prefix),
            Err(PosError::PanLikeProcessorToken)
        ));
    }
}
