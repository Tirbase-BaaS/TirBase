// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for the POS-02 acceptance criteria:
//!
//! - merging replicas is commutative and associative;
//! - replaying an operation log is idempotent (including voids);
//! - splitting a check conserves subtotal, discount, tax, tip and payments;
//! - splitting a line is exact or explicitly rejected, never silently lossy;
//! - merging checks conserves every money component.

use proptest::prelude::*;
use tirbase_pos::{
    ApplyOutcome, BookOp, BookOpKind, CheckId, CheckStatus, CheckTotals, Currency, Discount,
    Employee, EmployeeId, EmployeeRole, LineItem, LineItemId, Money, OperationId, OrderCommand,
    OrderId, Organization, Ownership, PaymentAllocation, PaymentId, PaymentLink, PaymentMethod,
    PosBook, PosError, Quantity, Rate, RoundingMode, Store, StoreId, Terminal, TerminalId,
    Timestamp,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn op_id(value: impl Into<String>) -> OperationId {
    OperationId::new(value.into()).unwrap()
}

fn check_id(value: impl Into<String>) -> CheckId {
    CheckId::new(value.into()).unwrap()
}

fn line_id(value: impl Into<String>) -> LineItemId {
    LineItemId::new(value.into()).unwrap()
}

fn ts(value: i64) -> Timestamp {
    Timestamp::from_millis(value)
}

fn organization() -> Organization {
    let store_id = StoreId::new("store-1").unwrap();
    let mut org = Organization::new();
    org.add_store(Store::new(store_id.clone(), "One").unwrap())
        .unwrap();
    for till in ["till-1", "till-2"] {
        org.add_terminal(
            Terminal::new(TerminalId::new(till).unwrap(), store_id.clone(), till).unwrap(),
        )
        .unwrap();
    }
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
    org
}

fn ownership(till: &str) -> Ownership {
    Ownership::new(
        StoreId::new("store-1").unwrap(),
        TerminalId::new(till).unwrap(),
        EmployeeId::new("emp-1").unwrap(),
        None,
    )
}

fn new_book() -> PosBook {
    let mut book = PosBook::new(organization());
    book.add_order(OrderId::new("order-1").unwrap(), ownership("till-1"), ts(0))
        .unwrap();
    book.add_order(OrderId::new("order-2").unwrap(), ownership("till-2"), ts(0))
        .unwrap();
    book
}

fn wrap(command: OrderCommand, actor: &str, lamport: u64) -> BookOp {
    BookOp::new(
        command.operation_id().clone(),
        OrderId::new("order-1").unwrap(),
        TerminalId::new(actor).unwrap(),
        lamport,
        command.at(),
        BookOpKind::Order(command),
    )
}

fn apply(book: &mut PosBook, op: BookOp) {
    book.apply(op).unwrap();
}

fn make_check(book: &mut PosBook, check: &CheckId, operation: usize, actor: &str, lamport: u64) {
    apply(
        book,
        wrap(
            OrderCommand::CreateCheck {
                operation_id: op_id(format!("create-{operation}")),
                check_id: check.clone(),
                currency: usd(),
                rounding: RoundingMode::HalfAwayFromZero,
                at: ts(lamport as i64),
            },
            actor,
            lamport,
        ),
    );
}

fn add_line(
    book: &mut PosBook,
    check: &CheckId,
    line: LineItem,
    operation: usize,
    actor: &str,
    lamport: u64,
) {
    apply(
        book,
        wrap(
            OrderCommand::AddLineItem {
                operation_id: op_id(format!("line-{}-{operation}", check.as_str())),
                check_id: check.clone(),
                line,
                at: ts(lamport as i64),
            },
            actor,
            lamport,
        ),
    );
}

fn set_tip(
    book: &mut PosBook,
    check: &CheckId,
    tip: Money,
    operation: usize,
    actor: &str,
    lamport: u64,
) {
    apply(
        book,
        wrap(
            OrderCommand::SetTip {
                operation_id: op_id(format!("tip-{operation}")),
                check_id: check.clone(),
                tip,
                at: ts(lamport as i64),
            },
            actor,
            lamport,
        ),
    );
}

fn link_payment(
    book: &mut PosBook,
    check: &CheckId,
    payment: PaymentLink,
    operation: usize,
    actor: &str,
    lamport: u64,
) {
    apply(
        book,
        wrap(
            OrderCommand::LinkPayment {
                operation_id: op_id(format!("pay-{}-{operation}", check.as_str())),
                check_id: check.clone(),
                payment,
                at: ts(lamport as i64),
            },
            actor,
            lamport,
        ),
    );
}

fn totals(book: &PosBook, check: &CheckId) -> CheckTotals {
    book.check(check).unwrap().totals().unwrap()
}

fn assert_conserved(before: &CheckTotals, parts: &[&CheckTotals]) {
    let currency = before.currency;
    assert_eq!(
        Money::checked_sum(currency, parts.iter().map(|p| p.subtotal)).unwrap(),
        before.subtotal
    );
    assert_eq!(
        Money::checked_sum(currency, parts.iter().map(|p| p.discount_total)).unwrap(),
        before.discount_total
    );
    assert_eq!(
        Money::checked_sum(currency, parts.iter().map(|p| p.tax_total)).unwrap(),
        before.tax_total
    );
    assert_eq!(
        Money::checked_sum(currency, parts.iter().map(|p| p.tip)).unwrap(),
        before.tip
    );
    assert_eq!(
        Money::checked_sum(currency, parts.iter().map(|p| p.grand_total)).unwrap(),
        before.grand_total
    );
    assert_eq!(
        Money::checked_sum(currency, parts.iter().map(|p| p.paid_total)).unwrap(),
        before.paid_total
    );
}

fn assert_summed(before_a: &CheckTotals, before_b: &CheckTotals, after: &CheckTotals) {
    assert_eq!(
        after.subtotal,
        before_a.subtotal.checked_add(before_b.subtotal).unwrap()
    );
    assert_eq!(
        after.discount_total,
        before_a
            .discount_total
            .checked_add(before_b.discount_total)
            .unwrap()
    );
    assert_eq!(
        after.tax_total,
        before_a.tax_total.checked_add(before_b.tax_total).unwrap()
    );
    assert_eq!(after.tip, before_a.tip.checked_add(before_b.tip).unwrap());
    assert_eq!(
        after.grand_total,
        before_a
            .grand_total
            .checked_add(before_b.grand_total)
            .unwrap()
    );
    assert_eq!(
        after.paid_total,
        before_a
            .paid_total
            .checked_add(before_b.paid_total)
            .unwrap()
    );
}

/// Seven checks, each with one line and one payment, plus a fixed catalogue of
/// independent operations. Every subset of the catalogue is valid on its own,
/// so any divergence after merging is a real convergence bug.
struct Convergence {
    book: PosBook,
    catalog: Vec<BookOp>,
}

fn convergence_book() -> Convergence {
    let mut book = new_book();
    let mut lamport = 1_u64;
    let checks: Vec<CheckId> = (1..=7).map(|n| check_id(format!("c-{n}"))).collect();
    for (index, check) in checks.iter().enumerate() {
        make_check(&mut book, check, index, "till-1", lamport);
        lamport += 1;
        add_line(
            &mut book,
            check,
            LineItem::new(
                line_id(format!("l-{}", index + 1)),
                format!("Item {}", index + 1),
                Quantity::from_units(1).unwrap(),
                Money::new(usd(), 1_000),
            )
            .unwrap()
            .with_tax_rate(Rate::from_percent(10).unwrap()),
            index,
            "till-1",
            lamport,
        );
        lamport += 1;
        link_payment(
            &mut book,
            check,
            PaymentLink::captured(
                PaymentId::new(format!("p-{}", index + 1)).unwrap(),
                PaymentMethod::Cash,
                Money::new(usd(), 1_000),
            )
            .unwrap(),
            index,
            "till-1",
            lamport,
        );
        lamport += 1;
    }

    let catalog = vec![
        BookOp::new(
            op_id("cat-void-line"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            101,
            ts(101),
            BookOpKind::VoidLineItem {
                check_id: checks[0].clone(),
                line_item_id: line_id("l-1"),
                reason: "catalog void line".into(),
            },
        ),
        BookOp::new(
            op_id("cat-void-payment"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            102,
            ts(102),
            BookOpKind::VoidPayment {
                check_id: checks[1].clone(),
                payment_id: PaymentId::new("p-2").unwrap(),
                reason: "catalog void payment".into(),
            },
        ),
        BookOp::new(
            op_id("cat-split-check"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            103,
            ts(103),
            BookOpKind::SplitCheck {
                source_check_id: checks[2].clone(),
                target_check_id: check_id("c-3a"),
                line_item_ids: vec![line_id("l-3")],
                tip_to_target: Money::zero(usd()),
                payment_allocations: vec![],
            },
        ),
        BookOp::new(
            op_id("cat-transfer-line"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            104,
            ts(104),
            BookOpKind::TransferLineItem {
                from_check_id: checks[3].clone(),
                to_check_id: checks[4].clone(),
                line_item_id: line_id("l-4"),
            },
        ),
        BookOp::new(
            op_id("cat-merge"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            105,
            ts(105),
            BookOpKind::MergeChecks {
                source_check_id: checks[5].clone(),
                target_check_id: checks[0].clone(),
            },
        ),
        BookOp::new(
            op_id("cat-split-line"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            106,
            ts(106),
            BookOpKind::SplitLineItem {
                check_id: checks[1].clone(),
                line_item_id: line_id("l-2"),
                new_line_item_id: line_id("l-2b"),
                first_quantity: Quantity::from_thousandths(500).unwrap(),
                preserve_totals: true,
            },
        ),
        BookOp::new(
            op_id("cat-transfer-check"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            107,
            ts(107),
            BookOpKind::TransferCheck {
                to_order_id: OrderId::new("order-2").unwrap(),
                check_id: checks[4].clone(),
            },
        ),
        BookOp::new(
            op_id("cat-void-payment-2"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            108,
            ts(108),
            BookOpKind::VoidPayment {
                check_id: checks[6].clone(),
                payment_id: PaymentId::new("p-7").unwrap(),
                reason: "catalog void payment two".into(),
            },
        ),
    ];
    Convergence { book, catalog }
}

fn replica(selection: &[bool]) -> PosBook {
    let convergence = convergence_book();
    let mut book = convergence.book;
    for (selected, op) in selection.iter().zip(convergence.catalog) {
        if *selected {
            apply(&mut book, op);
        }
    }
    book
}

fn selection() -> impl Strategy<Value = Vec<bool>> {
    prop::collection::vec(any::<bool>(), 8)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn merge_is_commutative(selection_a in selection(), selection_b in selection()) {
        let a = replica(&selection_a);
        let b = replica(&selection_b);
        prop_assert!(a.rejected_operations().is_empty());
        prop_assert!(b.rejected_operations().is_empty());

        let mut ab = a.clone();
        ab.merge(&b).unwrap();
        let mut ba = b.clone();
        ba.merge(&a).unwrap();
        prop_assert_eq!(&ab, &ba);
        prop_assert!(ab.rejected_operations().is_empty());
    }

    #[test]
    fn merge_is_associative(
        selection_a in selection(),
        selection_b in selection(),
        selection_c in selection(),
    ) {
        let a = replica(&selection_a);
        let b = replica(&selection_b);
        let c = replica(&selection_c);

        let mut left = a.clone();
        left.merge(&b).unwrap();
        left.merge(&c).unwrap();

        let mut bc = b.clone();
        bc.merge(&c).unwrap();
        let mut right = a.clone();
        right.merge(&bc).unwrap();

        prop_assert_eq!(&left, &right);
        prop_assert!(left.rejected_operations().is_empty());
    }

    #[test]
    fn replaying_a_log_is_idempotent(selection in selection()) {
        let book = replica(&selection);
        let ops: Vec<BookOp> = book.operations().map(|(_, op)| op.clone()).collect();
        let mut replayed = book.clone();
        for outcome in replayed.replay(&ops).unwrap() {
            prop_assert_eq!(outcome, ApplyOutcome::Replayed);
        }
        prop_assert_eq!(&replayed, &book);
        prop_assert_eq!(replayed.replay(&ops).unwrap().len(), ops.len());
    }
}

// ---------------------------------------------------------------------------
// Check split conservation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct LineSpec {
    minor: i64,
    quantity: i64,
    discount_percent: Option<i32>,
    tax_percent: Option<i32>,
}

fn line_spec() -> impl Strategy<Value = LineSpec> {
    (
        1_i64..=5_000,
        1_i64..=3,
        prop::option::of(0_i32..=30),
        prop::option::of(0_i32..=25),
    )
        .prop_map(
            |(minor, quantity, discount_percent, tax_percent)| LineSpec {
                minor,
                quantity,
                discount_percent,
                tax_percent,
            },
        )
}

fn build_line(id: LineItemId, spec: &LineSpec) -> LineItem {
    let mut line = LineItem::new(
        id,
        "Generated",
        Quantity::from_units(spec.quantity).unwrap(),
        Money::new(usd(), spec.minor),
    )
    .unwrap();
    if let Some(percent) = spec.discount_percent {
        line = line
            .with_discount(
                Discount::percent("Generated", Rate::from_percent(percent).unwrap()).unwrap(),
            )
            .unwrap();
    }
    if let Some(percent) = spec.tax_percent {
        line = line.with_tax_rate(Rate::from_percent(percent).unwrap());
    }
    line
}

fn check_with(
    lines: &[LineSpec],
    tip_minor: i64,
    payment_minors: &[i64],
    check: &CheckId,
) -> PosBook {
    let mut book = new_book();
    make_check(&mut book, check, 0, "till-1", 1);
    let mut lamport = 2_u64;
    for (index, spec) in lines.iter().enumerate() {
        add_line(
            &mut book,
            check,
            build_line(line_id(format!("line-{index}")), spec),
            index,
            "till-1",
            lamport,
        );
        lamport += 1;
    }
    if tip_minor > 0 {
        set_tip(
            &mut book,
            check,
            Money::new(usd(), tip_minor),
            10,
            "till-1",
            lamport,
        );
        lamport += 1;
    }
    for (index, minor) in payment_minors.iter().enumerate() {
        link_payment(
            &mut book,
            check,
            PaymentLink::captured(
                PaymentId::new(format!("payment-{index}")).unwrap(),
                PaymentMethod::Cash,
                Money::new(usd(), *minor),
            )
            .unwrap(),
            index,
            "till-1",
            lamport,
        );
        lamport += 1;
    }
    book
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn split_check_conserves_every_component(
        lines in prop::collection::vec(line_spec(), 2..=4),
        tip_minor in 0_i64..=1_000,
        payment_minors in prop::collection::vec(1_i64..=2_000, 0..=3),
        move_flags in prop::collection::vec(any::<bool>(), 4),
        allocation_flags in prop::collection::vec(any::<bool>(), 3),
        tip_part in 0_i64..=1_000,
    ) {
        let move_flags = &move_flags[..lines.len()];
        let moved: Vec<usize> = move_flags
            .iter()
            .enumerate()
            .filter_map(|(index, flag)| flag.then_some(index))
            .collect();
        prop_assume!(!moved.is_empty() && moved.len() < lines.len());

        let flags = &allocation_flags[..payment_minors.len()];
        let allocations: Vec<(usize, i64)> = flags
            .iter()
            .enumerate()
            .filter_map(|(index, flag)| flag.then_some(index))
            .map(|index| (index, 1 + (tip_part % payment_minors[index])))
            .collect();

        let source = check_id("source");
        let target = check_id("target");
        let mut book = check_with(&lines, tip_minor, &payment_minors, &source);
        let before = totals(&book, &source);
        let tip_to_target = Money::new(usd(), tip_part.min(tip_minor));
        let payment_allocations: Vec<PaymentAllocation> = allocations
            .iter()
            .map(|(index, amount)| PaymentAllocation {
                source_payment_id: PaymentId::new(format!("payment-{index}")).unwrap(),
                target_payment_id: PaymentId::new(format!("payment-part-{index}")).unwrap(),
                amount: Money::new(usd(), *amount),
            })
            .collect();

        book.apply(BookOp::new(
            op_id("split-check"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            100,
            ts(100),
            BookOpKind::SplitCheck {
                source_check_id: source.clone(),
                target_check_id: target.clone(),
                line_item_ids: moved
                    .iter()
                    .map(|index| line_id(format!("line-{index}")))
                    .collect(),
                tip_to_target,
                payment_allocations,
            },
        ))
        .unwrap();

        let after_source = totals(&book, &source);
        let after_target = totals(&book, &target);
        assert_conserved(&before, &[&after_source, &after_target]);
    }

    #[test]
    fn split_line_is_exact_or_rejected(
        minor in 1_i64..=2_000,
        (total_thousandths, first) in
            (2_i64..=5_000).prop_flat_map(|total| (Just(total), 1_i64..total)),
        discount_percent in prop::option::of(0_i32..=30),
        tax_percent in prop::option::of(0_i32..=25),
    ) {
        let check = check_id("line-check");
        let mut book = new_book();
        make_check(&mut book, &check, 0, "till-1", 1);
        let mut line = LineItem::new(
            line_id("whole"),
            "Generated",
            Quantity::from_thousandths(total_thousandths).unwrap(),
            Money::new(usd(), minor),
        )
        .unwrap();
        if let Some(percent) = discount_percent {
            line = line
                .with_discount(
                    Discount::percent("Generated", Rate::from_percent(percent).unwrap()).unwrap(),
                )
                .unwrap();
        }
        if let Some(percent) = tax_percent {
            line = line.with_tax_rate(Rate::from_percent(percent).unwrap());
        }
        add_line(&mut book, &check, line, 1, "till-1", 2);
        let before = totals(&book, &check);
        let snapshot = book.clone();

        let result = book.apply(BookOp::new(
            op_id("split-line"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            100,
            ts(100),
            BookOpKind::SplitLineItem {
                check_id: check.clone(),
                line_item_id: line_id("whole"),
                new_line_item_id: line_id("part"),
                first_quantity: Quantity::from_thousandths(first).unwrap(),
                preserve_totals: true,
            },
        ));

        match result {
            Ok(_) => {
                let after = totals(&book, &check);
                prop_assert_eq!(after.subtotal, before.subtotal);
                prop_assert_eq!(after.discount_total, before.discount_total);
                prop_assert_eq!(after.tax_total, before.tax_total);
                prop_assert_eq!(after.grand_total, before.grand_total);
                let quantity: i64 = book
                    .check(&check)
                    .unwrap()
                    .active_line_items()
                    .map(|line| line.quantity().thousandths())
                    .sum();
                prop_assert_eq!(quantity, total_thousandths);
            }
            Err(PosError::LossySplit) => {
                prop_assert_eq!(&book, &snapshot);
            }
            Err(other) => prop_assert!(false, "unexpected split error: {other:?}"),
        }
    }

    #[test]
    fn merge_checks_conserves_every_component(
        lines_a in prop::collection::vec(line_spec(), 1..=3),
        lines_b in prop::collection::vec(line_spec(), 1..=3),
        tip_a in 0_i64..=500,
        tip_b in 0_i64..=500,
        payment_a in 0_i64..=1_000,
        payment_b in 0_i64..=1_000,
    ) {
        let source = check_id("merge-source");
        let target = check_id("merge-target");
        let mut book = new_book();
        make_check(&mut book, &target, 0, "till-1", 1);
        let mut lamport = 2_u64;
        for (index, spec) in lines_a.iter().enumerate() {
            add_line(
                &mut book,
                &target,
                build_line(line_id(format!("a-{index}")), spec),
                index,
                "till-1",
                lamport,
            );
            lamport += 1;
        }
        if tip_a > 0 {
            set_tip(&mut book, &target, Money::new(usd(), tip_a), 20, "till-1", lamport);
            lamport += 1;
        }
        if payment_a > 0 {
            link_payment(
                &mut book,
                &target,
                PaymentLink::captured(
                    PaymentId::new("a-payment").unwrap(),
                    PaymentMethod::Cash,
                    Money::new(usd(), payment_a),
                )
                .unwrap(),
                30,
                "till-1",
                lamport,
            );
            lamport += 1;
        }

        make_check(&mut book, &source, 1, "till-1", lamport);
        lamport += 1;
        for (index, spec) in lines_b.iter().enumerate() {
            add_line(
                &mut book,
                &source,
                build_line(line_id(format!("b-{index}")), spec),
                index,
                "till-1",
                lamport,
            );
            lamport += 1;
        }
        if tip_b > 0 {
            set_tip(&mut book, &source, Money::new(usd(), tip_b), 21, "till-1", lamport);
            lamport += 1;
        }
        if payment_b > 0 {
            link_payment(
                &mut book,
                &source,
                PaymentLink::captured(
                    PaymentId::new("b-payment").unwrap(),
                    PaymentMethod::Cash,
                    Money::new(usd(), payment_b),
                )
                .unwrap(),
                31,
                "till-1",
                lamport,
            );
        }

        let before_target = totals(&book, &target);
        let before_source = totals(&book, &source);
        book.apply(BookOp::new(
            op_id("merge"),
            OrderId::new("order-1").unwrap(),
            TerminalId::new("till-1").unwrap(),
            100,
            ts(100),
            BookOpKind::MergeChecks {
                source_check_id: source.clone(),
                target_check_id: target.clone(),
            },
        ))
        .unwrap();

        let after_target = totals(&book, &target);
        let after_source = totals(&book, &source);
        assert_summed(&before_target, &before_source, &after_target);
        prop_assert_eq!(book.check(&source).unwrap().status(), CheckStatus::Merged);
        prop_assert_eq!(
            book.check(&source).unwrap().merged_into(),
            Some(&target)
        );
        prop_assert_eq!(after_source.grand_total, Money::zero(usd()));
    }
}
