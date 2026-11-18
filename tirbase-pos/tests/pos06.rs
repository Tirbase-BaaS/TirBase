// SPDX-License-Identifier: AGPL-3.0-only

//! POS-06 behavioural tests: payment amount envelope, actor and epoch checks,
//! nonce/counter anti-replay, bounded replay window, and intent/approval
//! binding through the production `PaymentDesk` caller.

use tirbase_pos::{
    ApprovalAction, ApprovalGuard, ApprovalId, ApprovalStatus, CheckId, CheckStatus, CreateIntent,
    Currency, DenialCode, DiscountCap, DiscountCaps, Employee, EmployeeId, EmployeeRole,
    EnvelopeAction, EnvelopeCode, EnvelopePolicy, IdempotencyKey, IntentBinding, IntentStatus,
    Money, OperatorRole, Organization, PaymentDesk, PaymentEnvelope, PaymentError, PaymentId,
    PaymentIntentId, PaymentMethod, PaymentNonce, PaymentOutcome, ProcessorToken, Rate, RefundCaps,
    StackingPolicy, Store, StoreId, Terminal, TerminalEpoch, TerminalId, Timestamp,
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

fn check() -> CheckId {
    CheckId::new("check-1").unwrap()
}

fn terminal(value: &str) -> TerminalId {
    TerminalId::new(value).unwrap()
}

fn employee(value: &str) -> EmployeeId {
    EmployeeId::new(value).unwrap()
}

fn payment(value: &str) -> PaymentId {
    PaymentId::new(value).unwrap()
}

fn intent(value: &str) -> PaymentIntentId {
    PaymentIntentId::new(format!("intent-{value}")).unwrap()
}

fn nonce(value: &str) -> PaymentNonce {
    PaymentNonce::new(value).unwrap()
}

fn approval(value: &str) -> ApprovalId {
    ApprovalId::new(value).unwrap()
}

fn token(value: &str) -> ProcessorToken {
    ProcessorToken::new(format!("tok-{value}")).unwrap()
}

fn organization() -> Organization {
    let mut org = Organization::new();
    let store = Store::new(StoreId::new("store-1").unwrap(), "Store One").unwrap();
    let other = Store::new(StoreId::new("store-2").unwrap(), "Store Two").unwrap();
    let store_id = store.id().clone();
    let other_id = other.id().clone();
    org.add_store(store).unwrap();
    org.add_store(other).unwrap();
    for id in ["till-1", "till-2"] {
        org.add_terminal(Terminal::new(terminal(id), store_id.clone(), id).unwrap())
            .unwrap();
    }
    org.add_terminal(Terminal::new(terminal("till-3"), other_id.clone(), "Till 3").unwrap())
        .unwrap();
    for id in ["emp-1", "emp-2"] {
        org.add_employee(
            Employee::new(
                employee(id),
                store_id.clone(),
                id,
                vec![EmployeeRole::Cashier],
            )
            .unwrap(),
        )
        .unwrap();
    }
    org.add_employee(
        Employee::new(
            employee("emp-3"),
            other_id,
            "emp-3",
            vec![EmployeeRole::Cashier],
        )
        .unwrap(),
    )
    .unwrap();
    org
}

fn approvals(required: u8, per_operator: i64) -> ApprovalGuard {
    let caps = RefundCaps::new(
        money(per_operator),
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
    let mut guard = ApprovalGuard::new(usd(), caps, discounts, required).unwrap();
    guard.register_approver(employee("supervisor"), OperatorRole::Supervisor);
    guard.register_approver(employee("admin"), OperatorRole::Admin);
    guard
}

fn desk() -> PaymentDesk {
    let policy = EnvelopePolicy::new(usd(), money(10_000), money(10_000), 4, 64).unwrap();
    let mut desk = PaymentDesk::new(organization(), policy, approvals(1, 1_000)).unwrap();
    desk.begin_epoch(&terminal("till-1"), TerminalEpoch::new(1))
        .unwrap();
    desk.begin_epoch(&terminal("till-2"), TerminalEpoch::new(1))
        .unwrap();
    desk
}

fn envelope(
    payment_id: &str,
    terminal_id: &str,
    operator_id: &str,
    nonce_id: &str,
) -> PaymentEnvelope {
    PaymentEnvelope::new(
        payment(payment_id),
        intent(payment_id),
        check(),
        terminal(terminal_id),
        TerminalEpoch::new(1),
        employee(operator_id),
        nonce(nonce_id),
        1,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    )
}

fn create_authorized(
    desk: &mut PaymentDesk,
    payment_id: &str,
    terminal_id: &str,
    operator_id: &str,
    at: i64,
) {
    let intent_id = intent(payment_id);
    let binding = IntentBinding::new(
        check(),
        money(2_000),
        terminal(terminal_id),
        employee(operator_id),
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
    desk.authorize_intent(&intent_id, token(payment_id), ts(at + 1))
        .unwrap();
}

fn capture(desk: &mut PaymentDesk, envelope: &PaymentEnvelope) -> PaymentOutcome {
    let payment_id = envelope.payment_id().as_str().to_owned();
    desk.capture(envelope, token(&payment_id), ts(20)).unwrap()
}

fn refund_approval(
    desk: &mut PaymentDesk,
    id: &str,
    terminal_id: &str,
    requester_id: &str,
    amount: i64,
    reason: &str,
) -> ApprovalId {
    let approval_id = approval(id);
    desk.approvals_mut()
        .request_approval(
            approval_id.clone(),
            ApprovalAction::Refund,
            check(),
            money(amount),
            reason,
            employee(requester_id),
            terminal(terminal_id),
            ts(30),
            ts(1_000),
        )
        .unwrap();
    desk.approvals_mut()
        .approve(&approval_id, &employee("supervisor"), ts(31))
        .unwrap();
    approval_id
}

#[test]
fn capture_executes_once_and_an_identical_replay_does_not_touch_the_journal() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    let envelope = envelope("pay-1", "till-1", "emp-1", "nonce-1");

    let first = capture(&mut desk, &envelope);
    assert!(!first.is_replayed());
    assert_eq!(first.intent().status(), IntentStatus::Captured);
    let journal_after_first = desk.intents().journal().len();
    assert_eq!(
        desk.last_counter(&terminal("till-1"), TerminalEpoch::new(1)),
        Some(1)
    );
    assert_eq!(desk.nonce_count(), 1);

    let second = capture(&mut desk, &envelope);
    assert!(second.is_replayed());
    assert_eq!(second.intent().status(), IntentStatus::Captured);
    assert_eq!(desk.intents().journal().len(), journal_after_first);
    assert_eq!(desk.nonce_count(), 1);
}

#[test]
fn amount_envelope_rejects_negative_zero_and_out_of_range_values() {
    let mut desk = desk();
    let base = envelope("pay-1", "till-1", "emp-1", "nonce-1");

    let cases = [
        (
            base.clone()
                .with_amounts(Money::new(usd(), 0), money(0), money(100)),
            EnvelopeCode::InvalidTotal,
        ),
        (
            base.clone().with_amounts(money(-1), money(0), money(100)),
            EnvelopeCode::InvalidTotal,
        ),
        (
            base.clone()
                .with_amounts(money(1_000), money(-1), money(100)),
            EnvelopeCode::InvalidTip,
        ),
        (
            base.clone()
                .with_amounts(money(1_000), money(1_001), money(100)),
            EnvelopeCode::TipExceedsTotal,
        ),
        (
            base.clone().with_amounts(money(1_000), money(0), money(0)),
            EnvelopeCode::InvalidAmount,
        ),
        (
            base.clone()
                .with_amounts(money(1_000), money(0), money(-100)),
            EnvelopeCode::InvalidAmount,
        ),
        (
            base.clone()
                .with_amounts(money(1_000), money(0), money(1_001)),
            EnvelopeCode::AmountExceedsTotal,
        ),
        (
            base.clone()
                .with_amounts(money(20_000), money(0), money(10_001)),
            EnvelopeCode::AmountOutOfRange,
        ),
        (
            base.clone()
                .with_amounts(money(20_000), money(0), money(100)),
            EnvelopeCode::TotalOutOfRange,
        ),
        (
            base.clone()
                .with_amounts(Money::new(eur(), 1_000), money(0), money(100)),
            EnvelopeCode::CurrencyMismatch,
        ),
    ];

    for (envelope, expected) in cases {
        let error = desk.capture(&envelope, token("pay-1"), ts(10)).unwrap_err();
        assert_eq!(error.envelope_code(), Some(expected), "case: {envelope:?}");
    }
    assert_eq!(desk.nonce_count(), 0, "rejected envelopes record no nonce");
}

#[test]
fn terminal_operator_and_epoch_bindings_are_enforced() {
    let mut desk = desk();

    let unknown_terminal = envelope("pay-1", "till-x", "emp-1", "nonce-1");
    assert_eq!(
        desk.capture(&unknown_terminal, token("pay-1"), ts(10))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::UnknownTerminal)
    );

    let unknown_operator = envelope("pay-1", "till-1", "emp-x", "nonce-2");
    assert_eq!(
        desk.capture(&unknown_operator, token("pay-1"), ts(10))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::UnknownOperator)
    );

    let cross_store_operator = envelope("pay-1", "till-1", "emp-3", "nonce-3");
    assert_eq!(
        desk.capture(&cross_store_operator, token("pay-1"), ts(10))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::ActorMismatch)
    );

    // till-2 is registered but its epoch has been started; till-3 has none.
    let no_epoch = envelope("pay-1", "till-3", "emp-3", "nonce-4");
    assert_eq!(
        desk.capture(&no_epoch, token("pay-1"), ts(10))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::EpochNotRegistered)
    );

    let wrong_epoch = PaymentEnvelope::new(
        payment("pay-1"),
        intent("pay-1"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(2),
        employee("emp-1"),
        nonce("nonce-5"),
        1,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    );
    assert_eq!(
        desk.capture(&wrong_epoch, token("pay-1"), ts(10))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::EpochMismatch)
    );
    assert_eq!(desk.nonce_count(), 0);
}

#[test]
fn nonce_reuse_across_terminals_epochs_and_amounts_is_a_conflict() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    let first = envelope("pay-1", "till-1", "emp-1", "shared-nonce");
    assert!(!capture(&mut desk, &first).is_replayed());

    // Same nonce on another terminal, with a fresh counter.
    create_authorized(&mut desk, "pay-2", "till-2", "emp-2", 2);
    let other_terminal = envelope("pay-2", "till-2", "emp-2", "shared-nonce").with_amounts(
        money(2_000),
        money(200),
        money(2_000),
    );
    assert_eq!(
        desk.capture(&other_terminal, token("pay-2"), ts(21))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::NonceReuse)
    );

    // Same nonce, terminal and epoch but a changed amount is also a conflict.
    create_authorized(&mut desk, "pay-3", "till-1", "emp-1", 3);
    let changed = PaymentEnvelope::new(
        payment("pay-3"),
        intent("pay-3"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("shared-nonce"),
        2,
        money(2_000),
        money(200),
        money(1_500),
        PaymentMethod::Card,
    );
    assert_eq!(
        desk.capture(&changed, token("pay-3"), ts(22))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::NonceReuse)
    );

    // Same nonce after the terminal advances epoch.
    desk.begin_epoch(&terminal("till-1"), TerminalEpoch::new(2))
        .unwrap();
    create_authorized(&mut desk, "pay-4", "till-1", "emp-1", 4);
    let next_epoch = PaymentEnvelope::new(
        payment("pay-4"),
        intent("pay-4"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(2),
        employee("emp-1"),
        nonce("shared-nonce"),
        1,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    );
    assert_eq!(
        desk.capture(&next_epoch, token("pay-4"), ts(23))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::NonceReuse)
    );
}

#[test]
fn counters_must_advance_and_the_replay_window_is_bounded() {
    let mut desk = desk();
    for index in 1..=6_u64 {
        let payment_id = format!("pay-{index}");
        create_authorized(&mut desk, &payment_id, "till-1", "emp-1", index as i64);
        let request = PaymentEnvelope::new(
            payment(&payment_id),
            intent(&payment_id),
            check(),
            terminal("till-1"),
            TerminalEpoch::new(1),
            employee("emp-1"),
            nonce(&format!("nonce-{index}")),
            index,
            money(2_000),
            money(200),
            money(2_000),
            PaymentMethod::Card,
        );
        assert!(!capture(&mut desk, &request).is_replayed());
        assert_eq!(
            desk.last_counter(&terminal("till-1"), TerminalEpoch::new(1)),
            Some(index)
        );
    }

    // Last counter is 6, replay window is 4: counter 2 (gap 4) is too old.
    let stale = PaymentEnvelope::new(
        payment("pay-2"),
        intent("pay-2"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("nonce-2"),
        2,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    );
    assert_eq!(
        desk.capture(&stale, token("pay-2"), ts(40))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::ReplayWindowExpired)
    );

    // Counter 4 is inside the window and replays without executing.
    let inside = PaymentEnvelope::new(
        payment("pay-4"),
        intent("pay-4"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("nonce-4"),
        4,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    );
    assert!(desk
        .capture(&inside, token("pay-4"), ts(41))
        .unwrap()
        .is_replayed());

    // A new nonce may not go backwards.
    create_authorized(&mut desk, "pay-7", "till-1", "emp-1", 50);
    let backwards = PaymentEnvelope::new(
        payment("pay-7"),
        intent("pay-7"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("nonce-7"),
        5,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    );
    assert_eq!(
        desk.capture(&backwards, token("pay-7"), ts(42))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::CounterNotMonotonic)
    );
}

#[test]
fn refund_approval_is_bound_to_the_payment_and_a_replay_cannot_refund_twice() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    capture(
        &mut desk,
        &envelope("pay-1", "till-1", "emp-1", "capture-1"),
    );

    let approval_id = refund_approval(
        &mut desk,
        "refund-approval",
        "till-1",
        "emp-1",
        2_000,
        "customer return",
    );
    let mut request = PaymentEnvelope::new(
        payment("pay-1"),
        intent("pay-1"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("refund-1"),
        2,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    )
    .with_action(EnvelopeAction::Refund, "customer return")
    .with_approval(approval_id.clone());

    let first = desk.refund(&request, ts(50)).unwrap();
    assert!(!first.is_replayed());
    assert_eq!(first.intent().status(), IntentStatus::Refunded);
    assert_eq!(
        desk.approvals().approval(&approval_id).unwrap().status(),
        ApprovalStatus::Consumed
    );
    assert_eq!(
        desk.approvals().refunded_by_operator(&employee("emp-1")),
        money(2_000)
    );
    let journal = desk.intents().journal().len();

    // The identical replay returns the recorded intent and consumes nothing.
    let replay = desk.refund(&request, ts(51)).unwrap();
    assert!(replay.is_replayed());
    assert_eq!(
        desk.approvals().refunded_by_operator(&employee("emp-1")),
        money(2_000)
    );
    assert_eq!(desk.intents().journal().len(), journal);

    // A fresh envelope cannot drive a second refund of the same intent.
    request = PaymentEnvelope::new(
        payment("pay-1"),
        intent("pay-1"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("refund-2"),
        3,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    )
    .with_action(EnvelopeAction::Refund, "customer return");
    assert_eq!(
        desk.refund(&request, ts(52)).unwrap_err().envelope_code(),
        Some(EnvelopeCode::IntentState)
    );
}

#[test]
fn mismatched_approvals_are_rejected_before_guard_consumption() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    capture(
        &mut desk,
        &envelope("pay-1", "till-1", "emp-1", "capture-1"),
    );

    // Approval for another amount.
    let wrong_amount = refund_approval(
        &mut desk,
        "wrong-amount",
        "till-1",
        "emp-1",
        1_500,
        "customer return",
    );
    let mut request = PaymentEnvelope::new(
        payment("pay-1"),
        intent("pay-1"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("refund-1"),
        2,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    )
    .with_action(EnvelopeAction::Refund, "customer return")
    .with_approval(wrong_amount.clone());
    assert_eq!(
        desk.refund(&request, ts(50)).unwrap_err().envelope_code(),
        Some(EnvelopeCode::ApprovalMismatch)
    );
    assert_eq!(
        desk.approvals().approval(&wrong_amount).unwrap().status(),
        ApprovalStatus::Ready,
        "the mismatch does not consume the approval"
    );

    // Approval for a different reason.
    let wrong_reason = refund_approval(
        &mut desk,
        "wrong-reason",
        "till-1",
        "emp-1",
        2_000,
        "different reason",
    );
    request = request.with_approval(wrong_reason);
    assert_eq!(
        desk.refund(&request, ts(51)).unwrap_err().envelope_code(),
        Some(EnvelopeCode::ApprovalMismatch)
    );

    // Approval requested by another operator (different exact payment request).
    let wrong_requester = refund_approval(
        &mut desk,
        "wrong-requester",
        "till-1",
        "emp-2",
        2_000,
        "customer return",
    );
    request = request.with_approval(wrong_requester);
    assert_eq!(
        desk.refund(&request, ts(52)).unwrap_err().envelope_code(),
        Some(EnvelopeCode::ApprovalMismatch)
    );

    // Capture cannot carry an approval at all.
    create_authorized(&mut desk, "pay-2", "till-1", "emp-1", 2);
    let capture_with_approval = PaymentEnvelope::new(
        payment("pay-2"),
        intent("pay-2"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("capture-2"),
        2,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    )
    .with_approval(approval("any"));
    assert_eq!(
        desk.capture(&capture_with_approval, token("pay-2"), ts(53))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::ApprovalMismatch)
    );
}

#[test]
fn captured_void_needs_an_approval_and_a_replay_cannot_void_twice() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    capture(
        &mut desk,
        &envelope("pay-1", "till-1", "emp-1", "capture-1"),
    );

    let build = |with_approval: bool, nonce_id: &str, counter: u64| {
        let mut request = PaymentEnvelope::new(
            payment("pay-1"),
            intent("pay-1"),
            check(),
            terminal("till-1"),
            TerminalEpoch::new(1),
            employee("emp-1"),
            nonce(nonce_id),
            counter,
            money(2_000),
            money(200),
            money(2_000),
            PaymentMethod::Card,
        )
        .with_action(EnvelopeAction::Void, "duplicate tender");
        if with_approval {
            request = request.with_approval(approval("void-approval"));
        }
        request
    };

    // A captured payment void requires POS-05 approval.
    let error = desk
        .void(&build(false, "void-no-approval", 2), ts(50))
        .unwrap_err();
    assert!(matches!(
        error,
        PaymentError::Guard(ref guard) if guard.code() == DenialCode::VoidApprovalRequired
    ));

    desk.approvals_mut()
        .request_approval(
            approval("void-approval"),
            ApprovalAction::VoidPayment(payment("pay-1")),
            check(),
            money(2_000),
            "duplicate tender",
            employee("emp-1"),
            terminal("till-1"),
            ts(50),
            ts(1_000),
        )
        .unwrap();
    desk.approvals_mut()
        .approve(&approval("void-approval"), &employee("supervisor"), ts(51))
        .unwrap();

    let first = desk
        .void(&build(true, "void-approval-nonce", 2), ts(52))
        .unwrap();
    assert!(!first.is_replayed());
    assert_eq!(first.intent().status(), IntentStatus::Voided);

    let replay = desk
        .void(&build(true, "void-approval-nonce", 2), ts(53))
        .unwrap();
    assert!(replay.is_replayed());
    assert_eq!(replay.intent().status(), IntentStatus::Voided);
    assert_eq!(
        desk.approvals()
            .approval(&approval("void-approval"))
            .unwrap()
            .status(),
        ApprovalStatus::Consumed
    );

    // A new envelope for the same already-voided intent is not executable.
    assert_eq!(
        desk.void(&build(true, "void-second-nonce", 3), ts(54))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::IntentState)
    );
}

#[test]
fn intent_binding_mismatch_is_rejected_without_consuming_the_nonce() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    let mut request = envelope("pay-1", "till-1", "emp-1", "nonce-1");
    request = request.with_amounts(money(2_000), money(200), money(1_900));

    assert_eq!(
        desk.capture(&request, token("pay-1"), ts(20))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::IntentMismatch)
    );
    assert_eq!(desk.nonce_count(), 0);

    // The correct envelope still works afterwards.
    let correct = envelope("pay-1", "till-1", "emp-1", "nonce-1");
    assert!(!capture(&mut desk, &correct).is_replayed());
}

#[test]
fn replay_capacity_fails_closed_instead_of_evicting_nonces() {
    let policy = EnvelopePolicy::new(usd(), money(10_000), money(10_000), 4, 1).unwrap();
    let mut desk = PaymentDesk::new(organization(), policy, approvals(1, 1_000)).unwrap();
    desk.begin_epoch(&terminal("till-1"), TerminalEpoch::new(1))
        .unwrap();

    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    assert!(!capture(&mut desk, &envelope("pay-1", "till-1", "emp-1", "nonce-1")).is_replayed());
    assert_eq!(desk.nonce_count(), 1);

    create_authorized(&mut desk, "pay-2", "till-1", "emp-1", 2);
    let second = PaymentEnvelope::new(
        payment("pay-2"),
        intent("pay-2"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("nonce-2"),
        2,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    );
    assert_eq!(
        desk.capture(&second, token("pay-2"), ts(21))
            .unwrap_err()
            .envelope_code(),
        Some(EnvelopeCode::ReplayCapacityExceeded)
    );
    assert_eq!(desk.nonce_count(), 1);
}

#[test]
fn epoch_can_only_move_forward_and_rejects_old_epoch_envelopes() {
    let mut desk = desk();
    desk.begin_epoch(&terminal("till-1"), TerminalEpoch::new(1))
        .unwrap();
    desk.begin_epoch(&terminal("till-1"), TerminalEpoch::new(3))
        .unwrap();
    assert_eq!(
        desk.begin_epoch(&terminal("till-1"), TerminalEpoch::new(2))
            .unwrap_err()
            .code(),
        EnvelopeCode::EpochMismatch
    );
    assert_eq!(
        desk.epoch_of(&terminal("till-1")),
        Some(TerminalEpoch::new(3))
    );

    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    assert_eq!(
        desk.capture(
            &envelope("pay-1", "till-1", "emp-1", "nonce-1"),
            token("pay-1"),
            ts(20)
        )
        .unwrap_err()
        .envelope_code(),
        Some(EnvelopeCode::EpochMismatch)
    );
}

#[test]
fn check_status_is_carried_to_the_void_guard() {
    let mut desk = desk();
    create_authorized(&mut desk, "pay-1", "till-1", "emp-1", 1);
    capture(
        &mut desk,
        &envelope("pay-1", "till-1", "emp-1", "capture-1"),
    );

    let request = PaymentEnvelope::new(
        payment("pay-1"),
        intent("pay-1"),
        check(),
        terminal("till-1"),
        TerminalEpoch::new(1),
        employee("emp-1"),
        nonce("void-1"),
        2,
        money(2_000),
        money(200),
        money(2_000),
        PaymentMethod::Card,
    )
    .with_action(EnvelopeAction::Void, "closed check reversal")
    .with_check_status(CheckStatus::Closed);

    let error = desk.void(&request, ts(50)).unwrap_err();
    assert!(matches!(
        error,
        PaymentError::Guard(ref guard) if guard.code() == DenialCode::VoidApprovalRequired
    ));
}
