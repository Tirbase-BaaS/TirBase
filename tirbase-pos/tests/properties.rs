// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for the POS-01 acceptance criteria:
//!
//! - totals are exact under every supported rounding mode;
//! - a replayed create/update is idempotent;
//! - a closed check cannot be silently mutated;
//! - rounding never leaves the integer interval around the exact quotient.

use proptest::prelude::*;
use tirbase_pos::{
    div_round, CheckId, CheckStatus, CheckTotals, Currency, Discount, Employee, EmployeeId,
    EmployeeRole, LineItem, LineItemId, Modifier, Money, OperationId, Order, OrderCommand,
    Organization, Ownership, PaymentId, PaymentLink, PaymentMethod, Quantity, Rate, Refund,
    RefundId, RoundingMode, Store, StoreId, Terminal, TerminalId, Timestamp,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn op(n: usize) -> OperationId {
    OperationId::new(format!("op-{n}")).unwrap()
}

fn fixture() -> (Organization, Ownership) {
    let store_id = StoreId::new("store-1").unwrap();
    let mut org = Organization::new();
    org.add_store(Store::new(store_id.clone(), "Store One").unwrap())
        .unwrap();
    org.add_terminal(
        Terminal::new(
            TerminalId::new("till-1").unwrap(),
            store_id.clone(),
            "Till 1",
        )
        .unwrap(),
    )
    .unwrap();
    org.add_employee(
        Employee::new(
            EmployeeId::new("emp-1").unwrap(),
            store_id.clone(),
            "Ada",
            vec![EmployeeRole::Cashier, EmployeeRole::Supervisor],
        )
        .unwrap(),
    )
    .unwrap();
    let ownership = Ownership::new(
        store_id,
        TerminalId::new("till-1").unwrap(),
        EmployeeId::new("emp-1").unwrap(),
        None,
    );
    (org, ownership)
}

fn new_order(rounding: RoundingMode) -> (Order, CheckId) {
    let (org, ownership) = fixture();
    let mut order = Order::open(
        tirbase_pos::OrderId::new("order-1").unwrap(),
        ownership,
        &org,
        Timestamp::from_millis(1_000),
    )
    .unwrap();
    let check_id = CheckId::new("check-1").unwrap();
    order
        .apply(OrderCommand::CreateCheck {
            operation_id: op(0),
            check_id: check_id.clone(),
            currency: usd(),
            rounding,
            at: Timestamp::from_millis(1_001),
        })
        .unwrap();
    (order, check_id)
}

#[derive(Clone, Debug)]
struct LineSpec {
    qty_thousandths: i64,
    unit_minor: i64,
    modifier_deltas: Vec<i64>,
    discount_percent_ppm: Option<i32>,
    discount_amount_minor: Option<i64>,
    tax_ppm: Option<i32>,
}

fn line_strategy() -> impl Strategy<Value = LineSpec> {
    (
        1_000_i64..=5_000,
        500_i64..=50_000,
        prop::collection::vec(-100_i64..=300, 0..3),
        0_u8..=2,
        0_i32..=1_000_000,
        0_i64..=100,
        0_u8..=1,
    )
        .prop_map(
            |(qty, unit, modifiers, discount_kind, percent, amount, has_tax)| LineSpec {
                qty_thousandths: qty,
                unit_minor: unit,
                modifier_deltas: modifiers,
                discount_percent_ppm: (discount_kind == 0).then_some(percent),
                discount_amount_minor: (discount_kind == 1).then_some(amount),
                tax_ppm: (has_tax == 1).then_some(percent),
            },
        )
}

fn rounding_strategy() -> impl Strategy<Value = RoundingMode> {
    (0_usize..RoundingMode::ALL.len()).prop_map(|index| RoundingMode::ALL[index])
}

fn build_line(spec: &LineSpec, index: usize) -> LineItem {
    let mut line = LineItem::new(
        LineItemId::new(format!("line-{index}")).unwrap(),
        format!("Item {index}"),
        Quantity::from_thousandths(spec.qty_thousandths).unwrap(),
        Money::new(usd(), spec.unit_minor),
    )
    .unwrap();
    for (modifier_index, delta) in spec.modifier_deltas.iter().enumerate() {
        line = line
            .with_modifier(
                Modifier::new(
                    format!("modifier-{modifier_index}"),
                    Money::new(usd(), *delta),
                )
                .unwrap(),
            )
            .unwrap();
    }
    if let Some(ppm) = spec.discount_percent_ppm {
        line = line
            .with_discount(Discount::percent("Member", Rate::from_ppm(ppm).unwrap()).unwrap())
            .unwrap();
    } else if let Some(amount) = spec.discount_amount_minor {
        line = line
            .with_discount(Discount::amount("Coupon", Money::new(usd(), amount)).unwrap())
            .unwrap();
    }
    if let Some(ppm) = spec.tax_ppm {
        line = line.with_tax_rate(Rate::from_ppm(ppm).unwrap());
    }
    line
}

fn add_line_command(operation: usize, check_id: &CheckId, line: LineItem) -> OrderCommand {
    OrderCommand::AddLineItem {
        operation_id: op(operation),
        check_id: check_id.clone(),
        line,
        at: Timestamp::from_millis(2_000 + operation as i64),
    }
}

/// Assert every exactness identity the model promises.
fn assert_totals_exact(totals: &CheckTotals, expected_tip: Money) {
    let currency = usd();

    let subtotal =
        Money::checked_sum(currency, totals.line_totals.iter().map(|line| line.base)).unwrap();
    let discount_total = Money::checked_sum(
        currency,
        totals.line_totals.iter().map(|line| line.discount),
    )
    .unwrap();
    let tax_total =
        Money::checked_sum(currency, totals.line_totals.iter().map(|line| line.tax)).unwrap();
    let grouped_tax =
        Money::checked_sum(currency, totals.tax_lines.iter().map(|line| line.tax)).unwrap();
    let grouped_base = Money::checked_sum(
        currency,
        totals.tax_lines.iter().map(|line| line.taxable_base),
    )
    .unwrap();
    let taxed_base = Money::checked_sum(
        currency,
        totals
            .line_totals
            .iter()
            .filter(|line| line.tax_rate.is_some())
            .map(|line| line.taxable_base),
    )
    .unwrap();

    assert_eq!(
        totals.subtotal, subtotal,
        "subtotal is not the sum of lines"
    );
    assert_eq!(
        totals.discount_total, discount_total,
        "discount total is not the sum of line discounts"
    );
    assert_eq!(
        totals.tax_total, tax_total,
        "tax total is not the sum of line taxes"
    );
    assert_eq!(
        totals.tax_total, grouped_tax,
        "grouped tax lines disagree with per-line tax"
    );
    assert_eq!(
        grouped_base, taxed_base,
        "grouped taxable bases disagree with the per-line taxable bases"
    );
    assert_eq!(totals.tip, expected_tip);
    assert_eq!(
        totals.grand_total,
        subtotal
            .checked_sub(discount_total)
            .unwrap()
            .checked_add(tax_total)
            .unwrap()
            .checked_add(expected_tip)
            .unwrap(),
        "grand total identity failed"
    );

    for line in &totals.line_totals {
        assert_eq!(
            line.taxable_base,
            line.base.checked_sub(line.discount).unwrap(),
            "taxable base identity failed"
        );
        assert_eq!(
            line.total,
            line.taxable_base.checked_add(line.tax).unwrap(),
            "line total identity failed"
        );
        assert!(
            !line.discount.is_negative() && line.discount.minor() <= line.base.minor(),
            "discount escaped the line base"
        );
    }

    assert_eq!(
        totals.amount_due,
        totals.grand_total.checked_sub(totals.net_paid).unwrap(),
        "amount due identity failed"
    );
    assert_eq!(
        totals.net_paid,
        totals
            .paid_total
            .checked_sub(totals.refunded_total)
            .unwrap(),
        "net paid identity failed"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// For every rounding mode, the same line set produces totals that satisfy
    /// every exact integer identity, survive a close, and are frozen.
    #[test]
    fn prop_totals_are_exact_under_every_rounding_mode(
        specs in prop::collection::vec(line_strategy(), 1..6),
        tip_minor in 0_i64..=500,
    ) {
        for mode in RoundingMode::ALL {
            let (mut order, check_id) = new_order(mode);
            for (index, spec) in specs.iter().enumerate() {
                order
                    .apply(add_line_command(
                        10 + index,
                        &check_id,
                        build_line(spec, index),
                    ))
                    .unwrap();
            }
            let tip = Money::new(usd(), tip_minor);
            order
                .apply(OrderCommand::SetTip {
                    operation_id: op(50),
                    check_id: check_id.clone(),
                    tip,
                    at: Timestamp::from_millis(3_000),
                })
                .unwrap();

            let preview = order.check(&check_id).unwrap().totals().unwrap();
            assert_totals_exact(&preview, tip);
            prop_assert!(!preview.sealed);
            prop_assert!(preview.grand_total.is_positive());

            order
                .apply(OrderCommand::LinkPayment {
                    operation_id: op(51),
                    check_id: check_id.clone(),
                    payment: PaymentLink::captured(
                        PaymentId::new("payment-1").unwrap(),
                        PaymentMethod::Cash,
                        preview.grand_total,
                    )
                    .unwrap(),
                    at: Timestamp::from_millis(3_001),
                })
                .unwrap();
            order
                .apply(OrderCommand::CloseCheck {
                    operation_id: op(52),
                    check_id: check_id.clone(),
                    at: Timestamp::from_millis(3_002),
                })
                .unwrap();

            let closed = order.check(&check_id).unwrap();
            prop_assert_eq!(closed.status(), CheckStatus::Closed);
            prop_assert!(closed.sealed_totals_are_consistent().unwrap());
            let sealed = closed.totals().unwrap();
            prop_assert!(sealed.sealed);
            prop_assert_eq!(sealed.subtotal, preview.subtotal);
            prop_assert_eq!(sealed.discount_total, preview.discount_total);
            prop_assert_eq!(sealed.tax_total, preview.tax_total);
            prop_assert_eq!(sealed.grand_total, preview.grand_total);
            prop_assert_eq!(sealed.amount_due, Money::zero(usd()));
            assert_totals_exact(&sealed, tip);

            // A full refund is the only post-close mutation the model allows.
            order
                .apply(OrderCommand::RefundCheck {
                    operation_id: op(53),
                    check_id: check_id.clone(),
                    refund: Refund::new(
                        RefundId::new("refund-1").unwrap(),
                        sealed.paid_total,
                        "Customer request",
                    )
                    .unwrap(),
                    at: Timestamp::from_millis(3_003),
                })
                .unwrap();
            let refunded = order.check(&check_id).unwrap();
            prop_assert_eq!(refunded.status(), CheckStatus::Refunded);
            let after = refunded.totals().unwrap();
            prop_assert_eq!(after.net_paid, Money::zero(usd()));
            prop_assert_eq!(after.amount_due, after.grand_total);
            prop_assert!(refunded.sealed_totals_are_consistent().unwrap());

            // Even after the refund, content is frozen.
            let rejected = order.apply(add_line_command(
                60,
                &check_id,
                build_line(&specs[0], 99),
            ));
            prop_assert!(
                matches!(rejected, Err(tirbase_pos::PosError::CheckNotMutable { .. })),
                "a refunded (closed) check accepted a content mutation"
            );
        }
    }

    /// Applying the same command batch twice changes nothing: the second pass
    /// reports every command as replayed and the aggregate is byte-for-byte
    /// equal (state, audit log and applied-operation index).
    #[test]
    fn prop_replay_of_create_and_updates_is_idempotent(
        specs in prop::collection::vec(line_strategy(), 1..5),
        tip_minor in 0_i64..=500,
        mode in rounding_strategy(),
        duplicate_one in any::<bool>(),
    ) {
        let (mut order, check_id) = new_order(mode);
        let create = OrderCommand::CreateCheck {
            operation_id: op(0),
            check_id: check_id.clone(),
            currency: usd(),
            rounding: mode,
            at: Timestamp::from_millis(1_001),
        };
        let mut commands = vec![create.clone()];
        for (index, spec) in specs.iter().enumerate() {
            commands.push(add_line_command(
                10 + index,
                &check_id,
                build_line(spec, index),
            ));
        }

        // Include an update so both create and update replay are covered.
        let mut updated_spec = specs[0].clone();
        updated_spec.qty_thousandths += 1;
        commands.push(OrderCommand::UpdateLineItem {
            operation_id: op(40),
            check_id: check_id.clone(),
            line: build_line(&updated_spec, 0),
            at: Timestamp::from_millis(2_500),
        });
        commands.push(OrderCommand::SetTip {
            operation_id: op(41),
            check_id: check_id.clone(),
            tip: Money::new(usd(), tip_minor),
            at: Timestamp::from_millis(2_501),
        });

        if duplicate_one {
            commands.push(commands[1].clone());
        }

        let first = order.replay(&commands).unwrap();
        prop_assert_eq!(
            first.len(),
            commands.len(),
            "one receipt per command, including replays"
        );
        prop_assert!(first
            .iter()
            .any(|receipt| receipt.outcome == tirbase_pos::ApplyOutcome::Replayed));

        let snapshot = order.clone();
        let audit_len = order.audit_events().len();

        let second = order.replay(&commands).unwrap();
        prop_assert!(second
            .iter()
            .all(|receipt| receipt.outcome == tirbase_pos::ApplyOutcome::Replayed));
        prop_assert_eq!(order.audit_events().len(), audit_len);
        prop_assert_eq!(&order, &snapshot);
        prop_assert!(order.applied_operation_count() <= commands.len());

        // A closed check replays identically too.
        let totals = order.check(&check_id).unwrap().totals().unwrap();
        let pay = OrderCommand::LinkPayment {
            operation_id: op(70),
            check_id: check_id.clone(),
            payment: PaymentLink::captured(
                PaymentId::new("payment-1").unwrap(),
                PaymentMethod::Card,
                totals.grand_total,
            )
            .unwrap(),
            at: Timestamp::from_millis(4_000),
        };
        let close = OrderCommand::CloseCheck {
            operation_id: op(71),
            check_id: check_id.clone(),
            at: Timestamp::from_millis(4_001),
        };
        order.apply(pay.clone()).unwrap();
        order.apply(close.clone()).unwrap();
        let closed = order.clone();
        prop_assert_eq!(
            order.apply(pay).unwrap().outcome,
            tirbase_pos::ApplyOutcome::Replayed
        );
        prop_assert_eq!(
            order.apply(close).unwrap().outcome,
            tirbase_pos::ApplyOutcome::Replayed
        );
        prop_assert_eq!(&order, &closed);
    }

    /// A closed check rejects every content and transition command, leaves the
    /// audit log and applied-operation index untouched, and keeps its sealed
    /// totals.
    #[test]
    fn prop_closed_check_rejects_every_mutation(
        spec in line_strategy(),
        mode in rounding_strategy(),
    ) {
        let (mut order, check_id) = new_order(mode);
        order
            .apply(add_line_command(10, &check_id, build_line(&spec, 0)))
            .unwrap();
        let preview = order.check(&check_id).unwrap().totals().unwrap();
        order
            .apply(OrderCommand::LinkPayment {
                operation_id: op(11),
                check_id: check_id.clone(),
                payment: PaymentLink::captured(
                    PaymentId::new("payment-1").unwrap(),
                    PaymentMethod::Cash,
                    preview.grand_total,
                )
                .unwrap(),
                at: Timestamp::from_millis(2_000),
            })
            .unwrap();
        order
            .apply(OrderCommand::CloseCheck {
                operation_id: op(12),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(2_001),
            })
            .unwrap();

        let check = order.check(&check_id).unwrap();
        let status = check.status();
        let sealed_totals = check.totals().unwrap();
        let original_line = check.line_items().next().unwrap().clone();
        let audit_len = order.audit_events().len();
        let applied_len = order.applied_operation_count();

        let mut replacement_spec = spec.clone();
        replacement_spec.unit_minor += 1;

        let attempts = vec![
            add_line_command(20, &check_id, build_line(&spec, 1)),
            OrderCommand::UpdateLineItem {
                operation_id: op(21),
                check_id: check_id.clone(),
                line: build_line(&replacement_spec, 0),
                at: Timestamp::from_millis(2_100),
            },
            OrderCommand::RemoveLineItem {
                operation_id: op(22),
                check_id: check_id.clone(),
                line_item_id: original_line.id().clone(),
                at: Timestamp::from_millis(2_101),
            },
            OrderCommand::SetTip {
                operation_id: op(23),
                check_id: check_id.clone(),
                tip: Money::new(usd(), 1),
                at: Timestamp::from_millis(2_102),
            },
            OrderCommand::LinkPayment {
                operation_id: op(24),
                check_id: check_id.clone(),
                payment: PaymentLink::captured(
                    PaymentId::new("payment-2").unwrap(),
                    PaymentMethod::Cash,
                    Money::new(usd(), 1),
                )
                .unwrap(),
                at: Timestamp::from_millis(2_103),
            },
            OrderCommand::HoldCheck {
                operation_id: op(25),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(2_104),
            },
            OrderCommand::VoidCheck {
                operation_id: op(26),
                check_id: check_id.clone(),
                reason: "late void".into(),
                at: Timestamp::from_millis(2_105),
            },
        ];

        for attempt in attempts {
            prop_assert!(order.apply(attempt).is_err());
            let check = order.check(&check_id).unwrap();
            prop_assert_eq!(check.status(), status);
            prop_assert_eq!(check.totals().unwrap(), sealed_totals.clone());
            prop_assert_eq!(order.audit_events().len(), audit_len);
            prop_assert_eq!(order.applied_operation_count(), applied_len);
        }
    }

    /// Rounding always stays between the exact floor and ceiling, and within
    /// one minor unit of the exact quotient.
    #[test]
    fn prop_rounding_is_bounded_by_floor_and_ceiling(
        numerator in -1_000_000_i64..=1_000_000,
        denominator in 1_i64..=10_000,
        mode in rounding_strategy(),
    ) {
        let n = i128::from(numerator);
        let d = i128::from(denominator);
        let rounded = i128::from(div_round(n, d, mode).unwrap());
        let floor = n.div_euclid(d);
        let ceil = -((-n).div_euclid(d));
        prop_assert!(rounded >= floor, "rounding fell below floor");
        prop_assert!(rounded <= ceil, "rounding rose above ceiling");
        prop_assert!(
            (rounded * d - n).abs() < d,
            "rounding error exceeded one minor unit"
        );
    }

    /// Rounding is monotone in the numerator for every mode.
    #[test]
    fn prop_rounding_is_monotone(
        numerator in -100_000_i64..=100_000,
        denominator in 1_i64..=1_000,
        mode in rounding_strategy(),
    ) {
        let low = div_round(i128::from(numerator), i128::from(denominator), mode).unwrap();
        let high = div_round(
            i128::from(numerator + 1),
            i128::from(denominator),
            mode,
        )
        .unwrap();
        prop_assert!(low <= high, "rounding is not monotone: {low} > {high}");
    }
}
