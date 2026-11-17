// SPDX-License-Identifier: AGPL-3.0-only

//! POS-05 behavioural tests: refund caps, discount caps and stacking, void
//! approval, M-of-N approvals, expiry, self-approval, reuse and security events.

use tirbase_pos::{
    ApprovalAction, ApprovalGuard, ApprovalId, ApprovalStatus, CheckId, CheckStatus, Currency,
    DenialCode, DiscountCap, DiscountCaps, DiscountKind, DiscountRequest, DiscountScope,
    EmployeeId, LineItemId, Money, OperatorRole, PaymentId, PaymentStatus, Rate, RefundCaps,
    RefundRequest, RoundingMode, SecurityAction, StackingPolicy, TerminalId, Timestamp,
    VoidRequest, VoidTarget,
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

fn employee(value: &str) -> EmployeeId {
    EmployeeId::new(value).unwrap()
}

fn terminal(value: &str) -> TerminalId {
    TerminalId::new(value).unwrap()
}

fn check(value: &str) -> CheckId {
    CheckId::new(value).unwrap()
}

fn approval(value: &str) -> ApprovalId {
    ApprovalId::new(value).unwrap()
}

fn rate(ppm: i32) -> Rate {
    Rate::from_ppm(ppm).unwrap()
}

fn refund_caps(operator: i64, terminal: i64, day: i64, check: i64) -> RefundCaps {
    RefundCaps::new(money(operator), money(terminal), money(day), money(check)).unwrap()
}

fn discount_caps(stacking: StackingPolicy) -> DiscountCaps {
    DiscountCaps::new(
        DiscountCap::new(rate(200_000), money(200)).unwrap(),
        DiscountCap::new(rate(100_000), money(500)).unwrap(),
        stacking,
    )
    .unwrap()
}

fn guard(required: u8, refund_caps: RefundCaps) -> ApprovalGuard {
    ApprovalGuard::new(
        usd(),
        refund_caps,
        discount_caps(StackingPolicy::Deny),
        required,
    )
    .unwrap()
}

fn register_approvers(guard: &mut ApprovalGuard) {
    guard.register_approver(employee("supervisor"), OperatorRole::Supervisor);
    guard.register_approver(employee("admin"), OperatorRole::Admin);
    guard.register_approver(employee("cashier"), OperatorRole::Operator);
}

fn refund_request(
    operator: &str,
    terminal_id: &str,
    check_id: &str,
    minor: i64,
    reason: &str,
    at: i64,
) -> RefundRequest {
    RefundRequest::new(
        employee(operator),
        terminal(terminal_id),
        check(check_id),
        money(minor),
        reason,
        ts(at),
    )
}

fn discount_request(
    scope: DiscountScope,
    base: i64,
    discount: DiscountKind,
    existing: Vec<DiscountKind>,
    reason: &str,
    at: i64,
) -> DiscountRequest {
    DiscountRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-1"),
        scope,
        money(base),
        discount,
        existing,
        RoundingMode::HalfAwayFromZero,
        reason,
        ts(at),
    )
}

fn approved_refund(guard: &mut ApprovalGuard, amount: i64, at: i64) -> ApprovalId {
    let id = approval("refund-approval");
    guard
        .request_approval(
            id.clone(),
            ApprovalAction::Refund,
            check("check-1"),
            money(amount),
            "manager override",
            employee("cashier"),
            terminal("till-1"),
            ts(at),
            ts(at + 100),
        )
        .unwrap();
    guard
        .approve(&id, &employee("supervisor"), ts(at + 1))
        .unwrap();
    guard.approve(&id, &employee("admin"), ts(at + 2)).unwrap();
    id
}

fn last_event(guard: &ApprovalGuard) -> &tirbase_pos::SecurityEvent {
    guard.security_events().last().unwrap()
}

#[test]
fn refund_caps_are_enforced_independently_for_each_dimension() {
    let mut operator_guard = guard(2, refund_caps(1_000, 10_000, 10_000, 10_000));
    operator_guard
        .authorize_refund(&refund_request(
            "cashier", "till-1", "check-1", 600, "return", 1,
        ))
        .unwrap();
    let err = operator_guard
        .authorize_refund(&refund_request(
            "cashier", "till-1", "check-1", 500, "return", 2,
        ))
        .unwrap_err();
    assert_eq!(err.code(), DenialCode::RefundOperatorCap);
    assert_eq!(
        operator_guard.refunded_by_operator(&employee("cashier")),
        money(600)
    );
    assert_eq!(operator_guard.security_events().len(), 1);

    let mut terminal_guard = guard(2, refund_caps(10_000, 1_000, 10_000, 10_000));
    terminal_guard
        .authorize_refund(&refund_request(
            "one", "till-1", "check-1", 600, "return", 1,
        ))
        .unwrap();
    assert_eq!(
        terminal_guard
            .authorize_refund(&refund_request(
                "two", "till-1", "check-2", 500, "return", 2
            ))
            .unwrap_err()
            .code(),
        DenialCode::RefundTerminalCap
    );

    let mut day_guard = guard(2, refund_caps(10_000, 10_000, 1_000, 10_000));
    day_guard
        .authorize_refund(&refund_request(
            "one", "till-1", "check-1", 600, "return", 1,
        ))
        .unwrap();
    assert_eq!(
        day_guard
            .authorize_refund(&refund_request(
                "two", "till-2", "check-2", 500, "return", 2
            ))
            .unwrap_err()
            .code(),
        DenialCode::RefundDayCap
    );

    let mut check_guard = guard(2, refund_caps(10_000, 10_000, 10_000, 1_000));
    check_guard
        .authorize_refund(&refund_request(
            "one", "till-1", "check-1", 600, "return", 1,
        ))
        .unwrap();
    assert_eq!(
        check_guard
            .authorize_refund(&refund_request(
                "two", "till-2", "check-1", 500, "return", 2
            ))
            .unwrap_err()
            .code(),
        DenialCode::RefundCheckCap
    );
    assert_eq!(check_guard.refunded_on_check(&check("check-1")), money(600));
}

#[test]
fn above_cap_refund_needs_m_of_n_and_consumes_the_approval() {
    let mut guard = guard(2, refund_caps(1_000, 10_000, 10_000, 10_000));
    register_approvers(&mut guard);

    assert_eq!(
        guard
            .authorize_refund(&refund_request(
                "cashier",
                "till-1",
                "check-1",
                1_500,
                "manager override",
                1
            ))
            .unwrap_err()
            .code(),
        DenialCode::RefundOperatorCap
    );

    let id = approval("override-1");
    guard
        .request_approval(
            id.clone(),
            ApprovalAction::Refund,
            check("check-1"),
            money(1_500),
            "manager override",
            employee("cashier"),
            terminal("till-1"),
            ts(1),
            ts(100),
        )
        .unwrap();
    assert_eq!(
        guard
            .approve(&id, &employee("cashier"), ts(2))
            .unwrap_err()
            .code(),
        DenialCode::ApprovalSelfNotAllowed
    );
    assert_eq!(
        guard
            .approve(&id, &employee("cashier"), ts(2))
            .unwrap_err()
            .code(),
        DenialCode::ApprovalSelfNotAllowed
    );
    assert_eq!(
        guard.approve(&id, &employee("supervisor"), ts(2)).unwrap(),
        ApprovalStatus::Pending
    );
    assert_eq!(
        guard
            .approve(&id, &employee("supervisor"), ts(3))
            .unwrap_err()
            .code(),
        DenialCode::ApprovalDuplicate
    );
    assert_eq!(
        guard.approve(&id, &employee("admin"), ts(4)).unwrap(),
        ApprovalStatus::Ready
    );

    let request = refund_request("cashier", "till-1", "check-1", 1_500, "manager override", 5)
        .with_approval(id.clone());
    guard.authorize_refund(&request).unwrap();
    assert_eq!(
        guard.refunded_by_operator(&employee("cashier")),
        money(1_500)
    );
    assert_eq!(
        guard.approval(&id).unwrap().status(),
        ApprovalStatus::Consumed
    );
    assert_eq!(
        guard.authorize_refund(&request).unwrap_err().code(),
        DenialCode::ApprovalAlreadyUsed
    );
    assert_eq!(
        guard.refunded_by_operator(&employee("cashier")),
        money(1_500)
    );
}

#[test]
fn approval_binding_and_void_rules_are_exact() {
    let mut guard = guard(2, refund_caps(1_000, 10_000, 10_000, 10_000));
    register_approvers(&mut guard);
    let id = approved_refund(&mut guard, 1_500, 1);

    let wrong_amount = refund_request("cashier", "till-1", "check-1", 1_400, "manager override", 5)
        .with_approval(id.clone());
    assert_eq!(
        guard.authorize_refund(&wrong_amount).unwrap_err().code(),
        DenialCode::ApprovalBindingMismatch
    );
    let wrong_check = RefundRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-2"),
        money(1_500),
        "manager override",
        ts(5),
    )
    .with_approval(id.clone());
    assert_eq!(
        guard.authorize_refund(&wrong_check).unwrap_err().code(),
        DenialCode::ApprovalBindingMismatch
    );
    let wrong_reason = refund_request("cashier", "till-1", "check-1", 1_500, "different reason", 5)
        .with_approval(id.clone());
    assert_eq!(
        guard.authorize_refund(&wrong_reason).unwrap_err().code(),
        DenialCode::ApprovalBindingMismatch
    );
    // The approval was not consumed by the mismatches.
    assert!(guard.approval(&id).unwrap().is_ready());

    // Voiding an authorized payment needs no approval.
    let authorized_void = VoidRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-1"),
        VoidTarget::Payment(PaymentId::new("payment-1").unwrap()),
        money(500),
        "duplicate tender",
        ts(6),
        CheckStatus::Open,
        Some(PaymentStatus::Authorized),
    );
    guard.authorize_void(&authorized_void).unwrap();

    // A captured payment does.
    let captured_void = VoidRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-1"),
        VoidTarget::Payment(PaymentId::new("payment-1").unwrap()),
        money(500),
        "duplicate tender",
        ts(7),
        CheckStatus::Open,
        Some(PaymentStatus::Captured),
    );
    assert_eq!(
        guard.authorize_void(&captured_void).unwrap_err().code(),
        DenialCode::VoidApprovalRequired
    );

    // A closed check does too, and requires the matching action.
    let closed_void = VoidRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-2"),
        VoidTarget::Check,
        money(2_000),
        "closed check reversal",
        ts(8),
        CheckStatus::Closed,
        None,
    );
    assert_eq!(
        guard.authorize_void(&closed_void).unwrap_err().code(),
        DenialCode::VoidApprovalRequired
    );
    let void_id = approval("void-approval");
    guard
        .request_approval(
            void_id.clone(),
            ApprovalAction::VoidCheck,
            check("check-2"),
            money(2_000),
            "closed check reversal",
            employee("cashier"),
            terminal("till-1"),
            ts(8),
            ts(100),
        )
        .unwrap();
    guard
        .approve(&void_id, &employee("supervisor"), ts(9))
        .unwrap();
    guard.approve(&void_id, &employee("admin"), ts(10)).unwrap();
    let approved_closed_void = closed_void.clone().with_approval(void_id.clone());
    guard.authorize_void(&approved_closed_void).unwrap();
    assert_eq!(
        guard.approval(&void_id).unwrap().status(),
        ApprovalStatus::Consumed
    );
    assert_eq!(
        guard
            .authorize_void(&closed_void.with_approval(void_id))
            .unwrap_err()
            .code(),
        DenialCode::ApprovalAlreadyUsed
    );
}

#[test]
fn discount_caps_stack_and_allow_approved_overrides() {
    let mut deny_guard = guard(2, refund_caps(10_000, 10_000, 10_000, 10_000));
    let line = DiscountScope::Line(LineItemId::new("line-1").unwrap());
    assert_eq!(
        deny_guard
            .authorize_discount(&discount_request(
                line.clone(),
                1_000,
                DiscountKind::Percent(rate(250_000)),
                vec![],
                "promo",
                1
            ))
            .unwrap_err()
            .code(),
        DenialCode::DiscountLinePercentCap
    );
    assert_eq!(
        deny_guard
            .authorize_discount(&discount_request(
                line.clone(),
                1_000,
                DiscountKind::Amount(money(250)),
                vec![],
                "promo",
                2
            ))
            .unwrap_err()
            .code(),
        DenialCode::DiscountLineAmountCap
    );
    assert_eq!(
        deny_guard
            .authorize_discount(&discount_request(
                DiscountScope::Check,
                1_000,
                DiscountKind::Percent(rate(150_000)),
                vec![],
                "promo",
                3
            ))
            .unwrap_err()
            .code(),
        DenialCode::DiscountCheckPercentCap
    );
    assert_eq!(
        deny_guard
            .authorize_discount(&discount_request(
                DiscountScope::Check,
                1_000,
                DiscountKind::Amount(money(600)),
                vec![],
                "promo",
                4
            ))
            .unwrap_err()
            .code(),
        DenialCode::DiscountCheckAmountCap
    );
    assert_eq!(
        deny_guard
            .authorize_discount(&discount_request(
                line.clone(),
                1_000,
                DiscountKind::Percent(rate(100_000)),
                vec![DiscountKind::Percent(rate(50_000))],
                "promo",
                5
            ))
            .unwrap_err()
            .code(),
        DenialCode::DiscountStackingDenied
    );

    let mut additive = ApprovalGuard::new(
        usd(),
        refund_caps(10_000, 10_000, 10_000, 10_000),
        discount_caps(StackingPolicy::Additive),
        2,
    )
    .unwrap();
    additive
        .authorize_discount(&discount_request(
            line.clone(),
            1_000,
            DiscountKind::Percent(rate(100_000)),
            vec![DiscountKind::Percent(rate(50_000))],
            "promo",
            6,
        ))
        .unwrap();

    let mut best_of = ApprovalGuard::new(
        usd(),
        refund_caps(10_000, 10_000, 10_000, 10_000),
        discount_caps(StackingPolicy::BestOf),
        2,
    )
    .unwrap();
    best_of
        .authorize_discount(&discount_request(
            line.clone(),
            1_000,
            DiscountKind::Amount(money(150)),
            vec![DiscountKind::Amount(money(100))],
            "promo",
            7,
        ))
        .unwrap();
    assert_eq!(
        best_of
            .authorize_discount(&discount_request(
                line.clone(),
                1_000,
                DiscountKind::Amount(money(50)),
                vec![DiscountKind::Amount(money(100))],
                "promo",
                8
            ))
            .unwrap_err()
            .code(),
        DenialCode::DiscountStackingDenied
    );

    // An approved over-cap line discount is allowed once.
    register_approvers(&mut deny_guard);
    let id = approval("discount-approval");
    deny_guard
        .request_approval(
            id.clone(),
            ApprovalAction::Discount {
                line: Some(LineItemId::new("line-1").unwrap()),
            },
            check("check-1"),
            money(250),
            "promo",
            employee("cashier"),
            terminal("till-1"),
            ts(9),
            ts(100),
        )
        .unwrap();
    deny_guard
        .approve(&id, &employee("supervisor"), ts(10))
        .unwrap();
    deny_guard.approve(&id, &employee("admin"), ts(11)).unwrap();
    deny_guard
        .authorize_discount(
            &discount_request(
                line.clone(),
                1_000,
                DiscountKind::Amount(money(250)),
                vec![],
                "promo",
                12,
            )
            .with_approval(id.clone()),
        )
        .unwrap();
    assert_eq!(
        deny_guard.approval(&id).unwrap().status(),
        ApprovalStatus::Consumed
    );
}

#[test]
fn expired_and_unready_approvals_are_denied() {
    let mut guard = guard(2, refund_caps(1_000, 10_000, 10_000, 10_000));
    register_approvers(&mut guard);
    let id = approval("expiring");
    guard
        .request_approval(
            id.clone(),
            ApprovalAction::Refund,
            check("check-1"),
            money(1_500),
            "override",
            employee("cashier"),
            terminal("till-1"),
            ts(0),
            ts(10),
        )
        .unwrap();
    guard.approve(&id, &employee("supervisor"), ts(1)).unwrap();
    let early = refund_request("cashier", "till-1", "check-1", 1_500, "override", 9)
        .with_approval(id.clone());
    assert_eq!(
        guard.authorize_refund(&early).unwrap_err().code(),
        DenialCode::ApprovalNotReady
    );
    guard.approve(&id, &employee("admin"), ts(2)).unwrap();
    let expired = refund_request("cashier", "till-1", "check-1", 1_500, "override", 10)
        .with_approval(id.clone());
    assert_eq!(
        guard.authorize_refund(&expired).unwrap_err().code(),
        DenialCode::ApprovalExpired
    );

    // A fresh approval can still be used before expiry.
    let good_id = approval("not-expired");
    guard
        .request_approval(
            good_id.clone(),
            ApprovalAction::Refund,
            check("check-1"),
            money(1_500),
            "override",
            employee("cashier"),
            terminal("till-1"),
            ts(10),
            ts(20),
        )
        .unwrap();
    guard
        .approve(&good_id, &employee("supervisor"), ts(11))
        .unwrap();
    guard.approve(&good_id, &employee("admin"), ts(12)).unwrap();
    guard
        .authorize_refund(
            &refund_request("cashier", "till-1", "check-1", 1_500, "override", 19)
                .with_approval(good_id),
        )
        .unwrap();
}

#[test]
fn role_matrix_and_denial_events_are_stable() {
    let allowed = [
        ("supervisor", OperatorRole::Supervisor),
        ("qa", OperatorRole::Qa),
        ("admin", OperatorRole::Admin),
    ];
    for (name, role) in allowed {
        let mut guard = guard(1, refund_caps(100, 10_000, 10_000, 10_000));
        guard.register_approver(employee(name), role);
        let id = approval("role-approval");
        guard
            .request_approval(
                id.clone(),
                ApprovalAction::Refund,
                check("check-1"),
                money(500),
                "override",
                employee("cashier"),
                terminal("till-1"),
                ts(0),
                ts(10),
            )
            .unwrap();
        assert_eq!(
            guard.approve(&id, &employee(name), ts(1)).unwrap(),
            ApprovalStatus::Ready
        );
    }

    for role in [
        OperatorRole::Operator,
        OperatorRole::Auditor,
        OperatorRole::Integrator,
        OperatorRole::BreakGlass,
    ] {
        let mut guard = guard(1, refund_caps(100, 10_000, 10_000, 10_000));
        guard.register_approver(employee("valid-approver"), OperatorRole::Supervisor);
        guard.register_approver(employee("wrong-role"), role);
        let id = approval("role-denied");
        guard
            .request_approval(
                id.clone(),
                ApprovalAction::Refund,
                check("check-1"),
                money(500),
                "override",
                employee("cashier"),
                terminal("till-1"),
                ts(0),
                ts(10),
            )
            .unwrap();
        let err = guard
            .approve(&id, &employee("wrong-role"), ts(1))
            .unwrap_err();
        assert_eq!(err.code(), DenialCode::ApprovalRoleDenied);
        let event = last_event(&guard);
        assert_eq!(event.code, DenialCode::ApprovalRoleDenied);
        assert_eq!(event.code.as_str(), "approval.role_denied");
        assert_eq!(event.action, SecurityAction::Approval);
    }

    // Event sequences are dense even across mixed operation families.
    let mut guard = guard(2, refund_caps(1_000, 10_000, 10_000, 10_000));
    register_approvers(&mut guard);
    let _ = guard.authorize_refund(&refund_request(
        "cashier", "till-1", "check-1", 1_500, "override", 1,
    ));
    let _ = guard.authorize_discount(&discount_request(
        DiscountScope::Check,
        1_000,
        DiscountKind::Percent(rate(150_000)),
        vec![],
        "promo",
        2,
    ));
    let _ = guard.authorize_void(&VoidRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-1"),
        VoidTarget::Check,
        money(1_000),
        "void",
        ts(3),
        CheckStatus::Closed,
        None,
    ));
    for (index, event) in guard.security_events().iter().enumerate() {
        assert_eq!(event.sequence, (index + 1) as u64);
    }
    assert_eq!(
        guard.security_events()[0].code,
        DenialCode::RefundOperatorCap
    );
    assert_eq!(
        guard.security_events()[1].code,
        DenialCode::DiscountCheckPercentCap
    );
    assert_eq!(
        guard.security_events()[2].code,
        DenialCode::VoidApprovalRequired
    );
}

#[test]
fn invalid_request_contexts_are_denied_with_events() {
    let mut guard = guard(2, refund_caps(1_000, 1_000, 1_000, 1_000));
    let wrong_currency = RefundRequest::new(
        employee("cashier"),
        terminal("till-1"),
        check("check-1"),
        Money::new(Currency::from_code("EUR").unwrap(), 10),
        "return",
        ts(1),
    );
    assert_eq!(
        guard.authorize_refund(&wrong_currency).unwrap_err().code(),
        DenialCode::CurrencyMismatch
    );
    assert_eq!(
        guard
            .authorize_refund(&refund_request(
                "cashier", "till-1", "check-1", 0, "return", 2
            ))
            .unwrap_err()
            .code(),
        DenialCode::InvalidAmount
    );
    assert_eq!(
        guard
            .authorize_discount(&DiscountRequest::new(
                employee("cashier"),
                terminal("till-1"),
                check("check-1"),
                DiscountScope::Check,
                money(100),
                DiscountKind::Amount(money(10)),
                vec![],
                RoundingMode::HalfAwayFromZero,
                " ",
                ts(3),
            ))
            .unwrap_err()
            .code(),
        DenialCode::InvalidReason
    );
    assert_eq!(
        guard.security_events().len(),
        3,
        "each denial emits one event"
    );

    let err = guard
        .request_approval(
            approval("bad-expiry"),
            ApprovalAction::Refund,
            check("check-1"),
            money(500),
            "override",
            employee("cashier"),
            terminal("till-1"),
            ts(10),
            ts(10),
        )
        .unwrap_err();
    assert_eq!(err.code(), DenialCode::ApprovalInvalidExpiry);
    assert_eq!(guard.security_events().len(), 4);
}

#[test]
fn requester_only_pool_is_too_small_and_denied_with_an_event() {
    let mut guard = guard(1, refund_caps(10_000, 10_000, 10_000, 10_000));
    // The only eligible approver is the requester, who cannot self-approve.
    guard.register_approver(employee("cashier"), OperatorRole::Supervisor);
    let error = guard
        .request_approval(
            approval("self-only"),
            ApprovalAction::Refund,
            check("check-1"),
            money(500),
            "override",
            employee("cashier"),
            terminal("till-1"),
            ts(0),
            ts(10),
        )
        .unwrap_err();
    assert_eq!(error.code(), DenialCode::ApprovalPoolTooSmall);
    let event = guard.security_events().last().unwrap();
    assert_eq!(event.code, DenialCode::ApprovalPoolTooSmall);
    assert_eq!(event.action, SecurityAction::Approval);
}
