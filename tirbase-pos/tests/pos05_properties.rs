// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for POS-05 caps, approval expiry, the F-03 role matrix and
//! single-use approval behavior under repeated concurrent attempts.

use proptest::prelude::*;
use tirbase_pos::{
    role_may_approve, ApprovalAction, ApprovalGuard, ApprovalId, ApprovalStatus, BusinessDay,
    CheckId, Currency, DenialCode, DiscountCap, DiscountCaps, EmployeeId, Money, OperatorRole,
    Rate, RefundCaps, RefundRequest, StackingPolicy, TerminalId, Timestamp,
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

fn employee(value: impl Into<String>) -> EmployeeId {
    EmployeeId::new(value.into()).unwrap()
}

fn terminal(value: &str) -> TerminalId {
    TerminalId::new(value).unwrap()
}

fn check(value: &str) -> CheckId {
    CheckId::new(value).unwrap()
}

fn caps(operator: i64, terminal_cap: i64, day: i64, check_cap: i64) -> RefundCaps {
    RefundCaps::new(
        money(operator),
        money(terminal_cap),
        money(day),
        money(check_cap),
    )
    .unwrap()
}

fn guard(required: u8, refund_caps: RefundCaps) -> ApprovalGuard {
    let discounts = DiscountCaps::new(
        DiscountCap::new(Rate::from_ppm(200_000).unwrap(), money(200)).unwrap(),
        DiscountCap::new(Rate::from_ppm(100_000).unwrap(), money(500)).unwrap(),
        StackingPolicy::Deny,
    )
    .unwrap();
    ApprovalGuard::new(usd(), refund_caps, discounts, required).unwrap()
}

fn request(
    operator: &str,
    terminal_id: &str,
    check_id: &str,
    amount: i64,
    at: i64,
) -> RefundRequest {
    RefundRequest::new(
        employee(operator),
        terminal(terminal_id),
        check(check_id),
        money(amount),
        "return",
        ts(at),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn refund_caps_hold_for_arbitrary_request_sequences(
        requests in proptest::collection::vec((0_u8..3, 0_u8..3, 0_u8..3, 1_i64..800), 0..40)
    ) {
        let caps = caps(2_000, 3_000, 4_000, 2_500);
        let mut guard = guard(2, caps.clone());
        for (index, (operator, terminal_index, check_index, amount)) in requests.into_iter().enumerate() {
            let operator_id = employee(format!("operator-{operator}"));
            let terminal_id = terminal(&format!("till-{terminal_index}"));
            let check_id = check(&format!("check-{check_index}"));
            let before_operator = guard.refunded_by_operator(&operator_id);
            let before_terminal = guard.refunded_by_terminal(&terminal_id);
            let day = BusinessDay::from_timestamp(ts(index as i64));
            let before_day = guard.refunded_on_day(day);
            let before_check = guard.refunded_on_check(&check_id);

            let outcome = guard.authorize_refund(&request(
                &format!("operator-{operator}"),
                &format!("till-{terminal_index}"),
                &format!("check-{check_index}"),
                amount,
                index as i64,
            ));
            match outcome {
                Ok(()) => {
                    prop_assert!(guard.refunded_by_operator(&operator_id) <= caps.per_operator());
                    prop_assert!(guard.refunded_by_terminal(&terminal_id) <= caps.per_terminal());
                    prop_assert!(guard.refunded_on_day(day) <= caps.per_day());
                    prop_assert!(guard.refunded_on_check(&check_id) <= caps.per_check());
                }
                Err(error) => {
                    prop_assert!(matches!(
                        error.code(),
                        DenialCode::RefundOperatorCap
                            | DenialCode::RefundTerminalCap
                            | DenialCode::RefundDayCap
                            | DenialCode::RefundCheckCap
                    ));
                    prop_assert_eq!(guard.refunded_by_operator(&operator_id), before_operator);
                    prop_assert_eq!(guard.refunded_by_terminal(&terminal_id), before_terminal);
                    prop_assert_eq!(guard.refunded_on_day(day), before_day);
                    prop_assert_eq!(guard.refunded_on_check(&check_id), before_check);
                }
            }
        }
    }

    #[test]
    fn approvals_are_usable_only_before_expiry(
        start in 0_i64..50,
        life in 1_i64..50,
        offset in 0_i64..60,
    ) {
        let expiry = start + life;
        let use_at = start + offset;
        let mut guard = guard(1, caps(100, 10_000, 10_000, 10_000));
        guard.register_approver(employee("supervisor"), OperatorRole::Supervisor);
        let id = ApprovalId::new("expiry-approval").unwrap();
        guard
            .request_approval(
                id.clone(),
                ApprovalAction::Refund,
                check("check-1"),
                money(500),
                "override",
                employee("cashier"),
                terminal("till-1"),
                ts(start),
                ts(expiry),
            )
            .unwrap();
        prop_assert_eq!(
            guard.approve(&id, &employee("supervisor"), ts(start)).unwrap(),
            ApprovalStatus::Ready
        );

        let outcome = guard.authorize_refund(
            &RefundRequest::new(
                employee("cashier"),
                terminal("till-1"),
                check("check-1"),
                money(500),
                "override",
                ts(use_at),
            )
            .with_approval(id),
        );
        if use_at >= expiry {
            prop_assert_eq!(
                outcome.unwrap_err().code(),
                DenialCode::ApprovalExpired
            );
        } else {
            prop_assert!(outcome.is_ok());
        }
    }

    #[test]
    fn role_matrix_matches_f03_permissions(index in 0_usize..OperatorRole::ALL.len()) {
        let role = OperatorRole::ALL[index];
        let approver = employee("approver");
        let mut guard = guard(1, caps(100, 10_000, 10_000, 10_000));
        guard.register_approver(approver.clone(), role);
        if !role_may_approve(role) {
            // Keep the eligible pool non-empty so the request is accepted and
            // the approval attempt exercises the role check.
            guard.register_approver(employee("valid-approver"), OperatorRole::Supervisor);
        }
        let id = ApprovalId::new("role-approval").unwrap();
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
        let outcome = guard.approve(&id, &approver, ts(1));
        if role_may_approve(role) {
            prop_assert_eq!(outcome.unwrap(), ApprovalStatus::Ready);
        } else {
            prop_assert_eq!(
                outcome.unwrap_err().code(),
                DenialCode::ApprovalRoleDenied
            );
            prop_assert_eq!(
                guard.security_events().last().unwrap().code,
                DenialCode::ApprovalRoleDenied
            );
        }
    }

    #[test]
    fn a_single_approval_authorizes_at_most_one_refund(attempts in 1_usize..12) {
        let mut guard = guard(2, caps(100, 10_000, 10_000, 10_000));
        guard.register_approver(employee("supervisor"), OperatorRole::Supervisor);
        guard.register_approver(employee("admin"), OperatorRole::Admin);
        let id = ApprovalId::new("single-use").unwrap();
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
                ts(100),
            )
            .unwrap();
        guard
            .approve(&id, &employee("supervisor"), ts(1))
            .unwrap();
        guard
            .approve(&id, &employee("admin"), ts(2))
            .unwrap();
        let refund = RefundRequest::new(
            employee("cashier"),
            terminal("till-1"),
            check("check-1"),
            money(500),
            "override",
            ts(3),
        )
        .with_approval(id);

        for attempt in 0..attempts {
            let outcome = guard.authorize_refund(&refund);
            if attempt == 0 {
                prop_assert!(outcome.is_ok());
            } else {
                prop_assert_eq!(
                    outcome.unwrap_err().code(),
                    DenialCode::ApprovalAlreadyUsed
                );
            }
        }
        prop_assert_eq!(guard.refunded_by_operator(&employee("cashier")), money(500));
        prop_assert_eq!(guard.security_events().len(), attempts - 1);
    }
}
