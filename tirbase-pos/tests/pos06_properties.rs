// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for POS-06: replay cannot execute a refund twice, an amount
//! mismatch is always rejected, and interleaved terminals never share a nonce.

use std::collections::BTreeMap;

use proptest::prelude::*;
use tirbase_pos::{
    ApprovalAction, ApprovalGuard, ApprovalId, CheckId, CreateIntent, Currency, DiscountCap,
    DiscountCaps, Employee, EmployeeId, EmployeeRole, EnvelopeAction, EnvelopeCode, EnvelopePolicy,
    IdempotencyKey, IntentBinding, Money, OperatorRole, Organization, PaymentDesk, PaymentEnvelope,
    PaymentId, PaymentIntentId, PaymentMethod, PaymentNonce, ProcessorToken, Rate, RefundCaps,
    StackingPolicy, Store, StoreId, Terminal, TerminalEpoch, TerminalId, Timestamp,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn ts(value: i64) -> Timestamp {
    Timestamp::from_millis(value)
}

fn check() -> CheckId {
    CheckId::new("check-1").unwrap()
}

fn terminal(index: usize) -> TerminalId {
    TerminalId::new(format!("till-{index}")).unwrap()
}

fn employee(index: usize) -> EmployeeId {
    EmployeeId::new(format!("emp-{index}")).unwrap()
}

fn approver() -> EmployeeId {
    EmployeeId::new("supervisor").unwrap()
}

fn organization(terminals: usize) -> Organization {
    let mut org = Organization::new();
    let store = Store::new(StoreId::new("store-1").unwrap(), "Store One").unwrap();
    let store_id = store.id().clone();
    org.add_store(store).unwrap();
    for index in 0..terminals {
        org.add_terminal(Terminal::new(terminal(index), store_id.clone(), "till").unwrap())
            .unwrap();
        org.add_employee(
            Employee::new(
                employee(index),
                store_id.clone(),
                format!("emp-{index}"),
                vec![EmployeeRole::Cashier],
            )
            .unwrap(),
        )
        .unwrap();
    }
    org.add_employee(
        Employee::new(
            approver(),
            store_id,
            "Supervisor",
            vec![EmployeeRole::Supervisor],
        )
        .unwrap(),
    )
    .unwrap();
    org
}

fn desk(terminals: usize, per_operator_cap: i64, max_nonce_entries: usize) -> PaymentDesk {
    let caps = RefundCaps::new(
        money(per_operator_cap),
        money(1_000_000),
        money(1_000_000),
        money(1_000_000),
    )
    .unwrap();
    let discounts = DiscountCaps::new(
        DiscountCap::new(Rate::from_ppm(100_000).unwrap(), money(100)).unwrap(),
        DiscountCap::new(Rate::from_ppm(100_000).unwrap(), money(100)).unwrap(),
        StackingPolicy::Deny,
    )
    .unwrap();
    let mut guard = ApprovalGuard::new(usd(), caps, discounts, 1).unwrap();
    guard.register_approver(approver(), OperatorRole::Supervisor);
    let policy =
        EnvelopePolicy::new(usd(), money(10_000), money(10_000), 16, max_nonce_entries).unwrap();
    let mut desk = PaymentDesk::new(organization(terminals), policy, guard).unwrap();
    for index in 0..terminals {
        desk.begin_epoch(&terminal(index), TerminalEpoch::new(1))
            .unwrap();
    }
    desk
}

fn create_authorized(
    desk: &mut PaymentDesk,
    payment_id: &str,
    terminal_index: usize,
    amount: i64,
    at: i64,
) {
    let intent_id = PaymentIntentId::new(format!("intent-{payment_id}")).unwrap();
    let binding = IntentBinding::new(
        check(),
        money(amount),
        terminal(terminal_index),
        employee(terminal_index),
        PaymentMethod::Card,
    )
    .unwrap();
    desk.create_intent(CreateIntent::new(
        intent_id.clone(),
        IdempotencyKey::new(format!("key-{payment_id}")).unwrap(),
        binding,
        ts(at),
    ))
    .unwrap();
    desk.authorize_intent(
        &intent_id,
        ProcessorToken::new(format!("tok-{payment_id}")).unwrap(),
        ts(at + 1),
    )
    .unwrap();
}

fn envelope(
    payment_id: &str,
    terminal_index: usize,
    nonce_id: &str,
    counter: u64,
    amount: i64,
) -> PaymentEnvelope {
    PaymentEnvelope::new(
        PaymentId::new(payment_id).unwrap(),
        PaymentIntentId::new(format!("intent-{payment_id}")).unwrap(),
        check(),
        terminal(terminal_index),
        TerminalEpoch::new(1),
        employee(terminal_index),
        PaymentNonce::new(nonce_id).unwrap(),
        counter,
        money(amount),
        money(0),
        money(amount),
        PaymentMethod::Card,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn a_replayed_refund_executes_at_most_once(
        amount in 1_i64..5_000,
        attempts in 1_usize..8,
    ) {
        // A zero operator cap forces the POS-05 approval path for every refund.
        let mut desk = desk(1, 0, 64);
        create_authorized(&mut desk, "pay-1", 0, amount, 1);
        let capture = envelope("pay-1", 0, "capture-nonce", 1, amount);
        prop_assert!(!desk.capture(&capture, ProcessorToken::new("tok-pay-1").unwrap(), ts(2))
            .unwrap()
            .is_replayed());

        let approval = ApprovalId::new("refund-approval").unwrap();
        desk.approvals_mut()
            .request_approval(
                approval.clone(),
                ApprovalAction::Refund,
                check(),
                money(amount),
                "customer return",
                employee(0),
                terminal(0),
                ts(3),
                ts(1_000),
            )
            .unwrap();
        desk.approvals_mut()
            .approve(&approval, &approver(), ts(4))
            .unwrap();

        let refund = envelope("pay-1", 0, "refund-nonce", 2, amount)
            .with_action(EnvelopeAction::Refund, "customer return")
            .with_approval(approval.clone());

        let mut journal_after_first = 0;
        for attempt in 0..attempts {
            let outcome = desk.refund(&refund, ts(5 + attempt as i64)).unwrap();
            if attempt == 0 {
                prop_assert!(!outcome.is_replayed());
                journal_after_first = desk.intents().journal().len();
            } else {
                prop_assert!(outcome.is_replayed());
            }
            prop_assert_eq!(desk.approvals().refunded_by_operator(&employee(0)), money(amount));
            prop_assert_eq!(desk.intents().journal().len(), journal_after_first);
        }
    }

    #[test]
    fn an_amount_mismatch_is_always_rejected(
        intent_amount in 1_i64..5_000,
        envelope_amount in -10_i64..5_000,
    ) {
        let mut desk = desk(1, 1_000_000, 64);
        create_authorized(&mut desk, "pay-1", 0, intent_amount, 1);
        let request = envelope("pay-1", 0, "nonce-1", 1, envelope_amount);

        let outcome = desk.capture(
            &request,
            ProcessorToken::new("tok-pay-1").unwrap(),
            ts(2),
        );
        if envelope_amount <= 0 {
            prop_assert_eq!(
                outcome.unwrap_err().envelope_code(),
                Some(EnvelopeCode::InvalidAmount)
            );
        } else if envelope_amount != intent_amount {
            prop_assert_eq!(
                outcome.unwrap_err().envelope_code(),
                Some(EnvelopeCode::IntentMismatch)
            );
        } else {
            prop_assert!(!outcome.unwrap().is_replayed());
        }
        if envelope_amount != intent_amount {
            prop_assert_eq!(desk.nonce_count(), 0);
        }
    }

    #[test]
    fn concurrent_terminals_never_share_a_nonce(
        claims in proptest::collection::vec((0_usize..3, 0_usize..4), 1..24)
    ) {
        let mut desk = desk(3, 1_000_000, 256);
        let mut counters = [0_u64; 3];
        let mut accepted_counters = [0_u64; 3];
        let mut seen: BTreeMap<usize, usize> = BTreeMap::new();

        for (index, (terminal_index, nonce_index)) in claims.into_iter().enumerate() {
            let payment_id = format!("pay-{index}");
            create_authorized(&mut desk, &payment_id, terminal_index, 1_000, index as i64 * 10);

            let counter = counters[terminal_index] + 1;
            counters[terminal_index] = counter;
            let request = envelope(
                &payment_id,
                terminal_index,
                &format!("nonce-{nonce_index}"),
                counter,
                1_000,
            );
            let outcome = desk.capture(
                &request,
                ProcessorToken::new(format!("tok-{payment_id}")).unwrap(),
                ts(index as i64 * 10 + 2),
            );

            match seen.get(&nonce_index) {
                Some(_first_terminal) => {
                    // Any reuse — whether from the same terminal or another one —
                    // is a nonce conflict, never a replay.
                    prop_assert_eq!(
                        outcome.unwrap_err().envelope_code(),
                        Some(EnvelopeCode::NonceReuse)
                    );
                }
                None => {
                    prop_assert!(!outcome.unwrap().is_replayed());
                    seen.insert(nonce_index, terminal_index);
                    accepted_counters[terminal_index] = counter;
                }
            }

            // Each terminal's accepted counter remains strictly monotonic.
            prop_assert_eq!(
                desk.last_counter(&terminal(terminal_index), TerminalEpoch::new(1)),
                if accepted_counters[terminal_index] == 0 {
                    None
                } else {
                    Some(accepted_counters[terminal_index])
                }
            );
        }
    }
}
