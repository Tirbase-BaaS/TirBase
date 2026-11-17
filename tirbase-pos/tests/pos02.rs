// SPDX-License-Identifier: AGPL-3.0-only

//! POS-02 behavioural tests: offline splits, deterministic conflicts, void
//! replay, transfers and explicit rejection of lossy or ambiguous merges.

use tirbase_pos::{
    BookOp, BookOpKind, CheckId, CheckStatus, Currency, Discount, Employee, EmployeeId,
    EmployeeRole, LineItem, LineItemId, Money, OperationId, OrderCommand, OrderId, Organization,
    Ownership, PaymentAllocation, PaymentId, PaymentLink, PaymentMethod, PosBook, Quantity, Rate,
    RoundingMode, Store, StoreId, Terminal, TerminalId, Timestamp,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn eur() -> Currency {
    Currency::from_code("EUR").unwrap()
}

fn op_id(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
}

fn terminal(value: &str) -> TerminalId {
    TerminalId::new(value).unwrap()
}

fn order_id(value: &str) -> OrderId {
    OrderId::new(value).unwrap()
}

fn check_id(value: &str) -> CheckId {
    CheckId::new(value).unwrap()
}

fn line_id(value: &str) -> LineItemId {
    LineItemId::new(value).unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn ts(value: i64) -> Timestamp {
    Timestamp::from_millis(value)
}

fn ownership(till: &str, employee: &str) -> Ownership {
    Ownership::new(
        StoreId::new("store-1").unwrap(),
        terminal(till),
        EmployeeId::new(employee).unwrap(),
        None,
    )
}

fn organization() -> Organization {
    let mut org = Organization::new();
    let store_one = StoreId::new("store-1").unwrap();
    let store_two = StoreId::new("store-2").unwrap();
    org.add_store(Store::new(store_one.clone(), "One").unwrap())
        .unwrap();
    org.add_store(Store::new(store_two.clone(), "Two").unwrap())
        .unwrap();
    for (till, store) in [
        ("till-1", &store_one),
        ("till-2", &store_one),
        ("till-3", &store_two),
    ] {
        org.add_terminal(Terminal::new(terminal(till), store.clone(), till).unwrap())
            .unwrap();
    }
    for (employee, store) in [("emp-1", &store_one), ("emp-2", &store_two)] {
        org.add_employee(
            Employee::new(
                EmployeeId::new(employee).unwrap(),
                store.clone(),
                employee,
                vec![EmployeeRole::Cashier, EmployeeRole::Supervisor],
            )
            .unwrap(),
        )
        .unwrap();
    }
    org
}

fn create_cmd(
    id: &str,
    check: &CheckId,
    currency: Currency,
    rounding: RoundingMode,
    at: i64,
) -> OrderCommand {
    OrderCommand::CreateCheck {
        operation_id: op_id(id),
        check_id: check.clone(),
        currency,
        rounding,
        at: ts(at),
    }
}

fn line(id: &str, name: &str, minor: i64) -> LineItem {
    LineItem::new(
        line_id(id),
        name,
        Quantity::from_units(1).unwrap(),
        money(minor),
    )
    .unwrap()
}

fn add_cmd(id: &str, check: &CheckId, line: LineItem, at: i64) -> OrderCommand {
    OrderCommand::AddLineItem {
        operation_id: op_id(id),
        check_id: check.clone(),
        line,
        at: ts(at),
    }
}

fn tip_cmd(id: &str, check: &CheckId, amount: Money, at: i64) -> OrderCommand {
    OrderCommand::SetTip {
        operation_id: op_id(id),
        check_id: check.clone(),
        tip: amount,
        at: ts(at),
    }
}

fn payment(id: &str, minor: i64) -> PaymentLink {
    PaymentLink::captured(
        PaymentId::new(id).unwrap(),
        PaymentMethod::Cash,
        money(minor),
    )
    .unwrap()
}

fn pay_cmd(id: &str, check: &CheckId, payment: PaymentLink, at: i64) -> OrderCommand {
    OrderCommand::LinkPayment {
        operation_id: op_id(id),
        check_id: check.clone(),
        payment,
        at: ts(at),
    }
}

fn wrap(command: OrderCommand, order: &OrderId, actor: &str, lamport: u64) -> BookOp {
    BookOp::new(
        command.operation_id().clone(),
        order.clone(),
        terminal(actor),
        lamport,
        command.at(),
        BookOpKind::Order(command),
    )
}

fn apply_both(a: &mut PosBook, b: &mut PosBook, op: BookOp) {
    a.apply(op.clone()).unwrap();
    b.apply(op).unwrap();
}

/// Seed two identical replicas: three orders/terminals, check-1 with three
/// lines plus tip and two payments, check-2 and check-3 for merge tests.
fn seed() -> (PosBook, PosBook) {
    let org = organization();
    let mut a = PosBook::new(org.clone());
    let mut b = PosBook::new(org);
    let order_one = order_id("order-1");
    let order_two = order_id("order-2");
    let order_three = order_id("order-3");
    for book in [&mut a, &mut b] {
        book.add_order(order_one.clone(), ownership("till-1", "emp-1"), ts(0))
            .unwrap();
        book.add_order(order_two.clone(), ownership("till-2", "emp-1"), ts(0))
            .unwrap();
        book.add_order(
            order_three.clone(),
            Ownership::new(
                StoreId::new("store-2").unwrap(),
                terminal("till-3"),
                EmployeeId::new("emp-2").unwrap(),
                None,
            ),
            ts(0),
        )
        .unwrap();
    }

    let one = check_id("check-1");
    let two = check_id("check-2");
    let three = check_id("check-3");
    let seed_ops = vec![
        wrap(
            create_cmd("seed-1", &one, usd(), RoundingMode::HalfAwayFromZero, 1),
            &order_one,
            "till-1",
            1,
        ),
        wrap(
            add_cmd("seed-2", &one, line("l1", "Coffee", 1_000), 2),
            &order_one,
            "till-1",
            2,
        ),
        wrap(
            add_cmd("seed-3", &one, line("l2", "Tea", 1_000), 3),
            &order_one,
            "till-1",
            3,
        ),
        wrap(
            add_cmd("seed-4", &one, line("l3", "Cake", 1_000), 4),
            &order_one,
            "till-1",
            4,
        ),
        wrap(
            tip_cmd("seed-5", &one, money(300), 5),
            &order_one,
            "till-1",
            5,
        ),
        wrap(
            pay_cmd("seed-6", &one, payment("p1", 1_000), 6),
            &order_one,
            "till-1",
            6,
        ),
        wrap(
            pay_cmd("seed-7", &one, payment("p2", 200), 7),
            &order_one,
            "till-1",
            7,
        ),
        wrap(
            create_cmd("seed-8", &two, usd(), RoundingMode::HalfAwayFromZero, 8),
            &order_one,
            "till-1",
            8,
        ),
        wrap(
            add_cmd("seed-9", &two, line("l4", "Soup", 500), 9),
            &order_one,
            "till-1",
            9,
        ),
        wrap(
            tip_cmd("seed-10", &two, money(50), 10),
            &order_one,
            "till-1",
            10,
        ),
        wrap(
            pay_cmd("seed-11", &two, payment("p3", 500), 11),
            &order_one,
            "till-1",
            11,
        ),
        wrap(
            create_cmd("seed-12", &three, usd(), RoundingMode::HalfAwayFromZero, 12),
            &order_one,
            "till-1",
            12,
        ),
        wrap(
            add_cmd("seed-13", &three, line("l5", "Juice", 250), 13),
            &order_one,
            "till-1",
            13,
        ),
        wrap(
            pay_cmd("seed-14", &three, payment("p4", 250), 14),
            &order_one,
            "till-1",
            14,
        ),
    ];
    for op in seed_ops {
        apply_both(&mut a, &mut b, op);
    }
    (a, b)
}

struct SplitRequest<'a> {
    id: &'a str,
    source: &'a CheckId,
    target: &'a CheckId,
    lines: Vec<LineItemId>,
    tip: Money,
    allocations: Vec<PaymentAllocation>,
    actor: &'a str,
    lamport: u64,
}

fn split_check_op(request: SplitRequest<'_>) -> BookOp {
    BookOp::new(
        op_id(request.id),
        order_id("order-1"),
        terminal(request.actor),
        request.lamport,
        ts(request.lamport as i64),
        BookOpKind::SplitCheck {
            source_check_id: request.source.clone(),
            target_check_id: request.target.clone(),
            line_item_ids: request.lines,
            tip_to_target: request.tip,
            payment_allocations: request.allocations,
        },
    )
}

fn total_of(book: &PosBook, id: &CheckId) -> tirbase_pos::CheckTotals {
    book.check(id).unwrap().totals().unwrap()
}

fn assert_split_totals_conserved(
    before: &tirbase_pos::CheckTotals,
    parts: &[&tirbase_pos::CheckTotals],
) {
    let currency = before.currency;
    let subtotal = Money::checked_sum(currency, parts.iter().map(|p| p.subtotal)).unwrap();
    let discount = Money::checked_sum(currency, parts.iter().map(|p| p.discount_total)).unwrap();
    let tax = Money::checked_sum(currency, parts.iter().map(|p| p.tax_total)).unwrap();
    let tip = Money::checked_sum(currency, parts.iter().map(|p| p.tip)).unwrap();
    let grand = Money::checked_sum(currency, parts.iter().map(|p| p.grand_total)).unwrap();
    let paid = Money::checked_sum(currency, parts.iter().map(|p| p.paid_total)).unwrap();
    assert_eq!(subtotal, before.subtotal, "subtotal was not conserved");
    assert_eq!(
        discount, before.discount_total,
        "discount was not conserved"
    );
    assert_eq!(tax, before.tax_total, "tax was not conserved");
    assert_eq!(tip, before.tip, "tip was not conserved");
    assert_eq!(grand, before.grand_total, "grand total was not conserved");
    assert_eq!(paid, before.paid_total, "payments were not conserved");
}

#[test]
fn two_terminals_split_the_same_check_offline_and_converge() {
    let (mut a, mut b) = seed();
    let source = check_id("check-1");
    let before = total_of(&a, &source);

    let split_by_a = split_check_op(SplitRequest {
        id: "a-split",
        source: &source,
        target: &check_id("check-1a"),
        lines: vec![line_id("l1")],
        tip: money(100),
        allocations: vec![PaymentAllocation {
            source_payment_id: PaymentId::new("p1").unwrap(),
            target_payment_id: PaymentId::new("pa").unwrap(),
            amount: money(400),
        }],
        actor: "till-1",
        lamport: 100,
    });
    let split_by_b = split_check_op(SplitRequest {
        id: "b-split",
        source: &source,
        target: &check_id("check-1b"),
        lines: vec![line_id("l2")],
        tip: money(200),
        allocations: vec![PaymentAllocation {
            source_payment_id: PaymentId::new("p2").unwrap(),
            target_payment_id: PaymentId::new("pb").unwrap(),
            amount: money(200),
        }],
        actor: "till-2",
        lamport: 100,
    });
    a.apply(split_by_a).unwrap();
    b.apply(split_by_b).unwrap();

    a.merge(&b).unwrap();
    b.merge(&a).unwrap();
    assert_eq!(
        a, b,
        "replicas diverged after unioning their operation logs"
    );

    let one = total_of(&a, &source);
    let one_a = total_of(&a, &check_id("check-1a"));
    let one_b = total_of(&a, &check_id("check-1b"));
    assert_split_totals_conserved(&before, &[&one, &one_a, &one_b]);
    assert_eq!(
        a.check(&check_id("check-1a"))
            .unwrap()
            .line_items()
            .map(|line| line.id().as_str())
            .collect::<Vec<_>>(),
        ["l1"]
    );
    assert_eq!(
        a.check(&check_id("check-1b"))
            .unwrap()
            .line_items()
            .map(|line| line.id().as_str())
            .collect::<Vec<_>>(),
        ["l2"]
    );
    assert!(a.rejected_operations().is_empty());
}

#[test]
fn concurrent_split_of_the_same_line_has_one_deterministic_winner() {
    let (mut a, mut b) = seed();
    let source = check_id("check-1");
    let by_a = split_check_op(SplitRequest {
        id: "a-split",
        source: &source,
        target: &check_id("check-1a"),
        lines: vec![line_id("l1")],
        tip: money(0),
        allocations: vec![],
        actor: "till-1",
        lamport: 100,
    });
    let by_b = split_check_op(SplitRequest {
        id: "b-split",
        source: &source,
        target: &check_id("check-1b"),
        lines: vec![line_id("l1")],
        tip: money(0),
        allocations: vec![],
        actor: "till-2",
        lamport: 100,
    });
    a.apply(by_a).unwrap();
    b.apply(by_b).unwrap();

    a.merge(&b).unwrap();
    b.merge(&a).unwrap();
    assert_eq!(a, b);
    assert_eq!(
        a.rejected_operations().len(),
        1,
        "exactly one split must lose"
    );
    let winner = a.rejected_operations().keys().next().unwrap();
    // Actor `till-1` sorts before `till-2`, so the first operation wins.
    assert_eq!(winner.as_str(), "b-split");
    assert!(a.check(&check_id("check-1a")).is_some());
    assert!(a.check(&check_id("check-1b")).is_none());
}

#[test]
fn replayed_void_does_not_double_void() {
    let (mut a, mut b) = seed();
    let check = check_id("check-1");
    let void_line = BookOp::new(
        op_id("void-line"),
        order_id("order-1"),
        terminal("till-1"),
        100,
        ts(100),
        BookOpKind::VoidLineItem {
            check_id: check.clone(),
            line_item_id: line_id("l1"),
            reason: "dropped".into(),
        },
    );
    a.apply(void_line.clone()).unwrap();
    let after_first = a.clone();
    let audit_len = a.audit_events().len();
    let total_after = total_of(&a, &check);

    assert_eq!(
        a.apply(void_line.clone()).unwrap(),
        tirbase_pos::ApplyOutcome::Replayed
    );
    assert_eq!(a, after_first);
    assert_eq!(a.audit_events().len(), audit_len);
    assert_eq!(total_of(&a, &check), total_after);
    assert!(a.check(&check).unwrap().line_is_voided(&line_id("l1")));

    let different = BookOp::new(
        op_id("void-line-again"),
        order_id("order-1"),
        terminal("till-1"),
        101,
        ts(101),
        BookOpKind::VoidLineItem {
            check_id: check.clone(),
            line_item_id: line_id("l1"),
            reason: "again".into(),
        },
    );
    assert!(matches!(
        a.apply(different),
        Err(tirbase_pos::PosError::LineItemAlreadyVoided(_))
    ));
    assert_eq!(a, after_first);
    assert_eq!(a.audit_events().len(), audit_len);

    // The same rule applies to payments and survives replication.
    let void_payment = BookOp::new(
        op_id("void-payment"),
        order_id("order-1"),
        terminal("till-1"),
        102,
        ts(102),
        BookOpKind::VoidPayment {
            check_id: check.clone(),
            payment_id: PaymentId::new("p1").unwrap(),
            reason: "chargeback hold".into(),
        },
    );
    apply_both(&mut a, &mut b, void_payment.clone());
    assert_eq!(
        b.apply(void_payment).unwrap(),
        tirbase_pos::ApplyOutcome::Replayed
    );
    assert_eq!(total_of(&a, &check).paid_total, money(200));
    assert_eq!(
        a.apply(BookOp::new(
            op_id("void-payment-again"),
            order_id("order-1"),
            terminal("till-1"),
            103,
            ts(103),
            BookOpKind::VoidPayment {
                check_id: check.clone(),
                payment_id: PaymentId::new("p1").unwrap(),
                reason: "again".into(),
            },
        ))
        .unwrap_err(),
        tirbase_pos::PosError::PaymentAlreadyVoided(PaymentId::new("p1").unwrap())
    );
}

#[test]
fn void_line_excludes_it_from_totals_but_keeps_it_for_audit() {
    let (mut a, mut b) = seed();
    let check = check_id("check-1");
    let before = total_of(&a, &check);
    let void = BookOp::new(
        op_id("void-l1"),
        order_id("order-1"),
        terminal("till-1"),
        100,
        ts(100),
        BookOpKind::VoidLineItem {
            check_id: check.clone(),
            line_item_id: line_id("l1"),
            reason: "customer changed order".into(),
        },
    );
    apply_both(&mut a, &mut b, void);
    let after = total_of(&a, &check);
    assert_eq!(
        after.subtotal,
        before.subtotal.checked_sub(money(1_000)).unwrap()
    );
    assert!(a.check(&check).unwrap().line_item(&line_id("l1")).is_some());
    assert!(a.check(&check).unwrap().line_is_voided(&line_id("l1")));
    assert_eq!(a.check(&check).unwrap().voided_lines().count(), 1);
}

#[test]
fn split_line_item_preserves_money_or_rejects_loss() {
    let (mut a, mut b) = seed();
    let order_one = order_id("order-1");
    let exact = check_id("check-exact");
    let lossy = check_id("check-lossy");
    for book in [&mut a, &mut b] {
        book.apply(wrap(
            create_cmd("x-1", &exact, usd(), RoundingMode::HalfAwayFromZero, 50),
            &order_one,
            "till-1",
            50,
        ))
        .unwrap();
        book.apply(wrap(
            add_cmd(
                "x-2",
                &exact,
                LineItem::new(
                    line_id("x-line"),
                    "Weighted",
                    Quantity::from_units(2).unwrap(),
                    money(1_000),
                )
                .unwrap()
                .with_discount(
                    Discount::percent("Member", Rate::from_percent(10).unwrap()).unwrap(),
                )
                .unwrap()
                .with_tax_rate(Rate::from_percent(10).unwrap()),
                51,
            ),
            &order_one,
            "till-1",
            51,
        ))
        .unwrap();
        book.apply(wrap(
            create_cmd("x-3", &lossy, usd(), RoundingMode::HalfAwayFromZero, 52),
            &order_one,
            "till-1",
            52,
        ))
        .unwrap();
        book.apply(wrap(
            add_cmd(
                "x-4",
                &lossy,
                LineItem::new(
                    line_id("lossy-line"),
                    "Tiny",
                    Quantity::from_thousandths(1_001).unwrap(),
                    money(1),
                )
                .unwrap(),
                53,
            ),
            &order_one,
            "till-1",
            53,
        ))
        .unwrap();
    }

    let exact_before = total_of(&a, &exact);
    let split = BookOp::new(
        op_id("split-exact"),
        order_one.clone(),
        terminal("till-1"),
        100,
        ts(100),
        BookOpKind::SplitLineItem {
            check_id: exact.clone(),
            line_item_id: line_id("x-line"),
            new_line_item_id: line_id("x-line-b"),
            first_quantity: Quantity::from_units(1).unwrap(),
            preserve_totals: true,
        },
    );
    apply_both(&mut a, &mut b, split);
    let exact_after = total_of(&a, &exact);
    assert_eq!(exact_after.subtotal, exact_before.subtotal);
    assert_eq!(exact_after.discount_total, exact_before.discount_total);
    assert_eq!(exact_after.tax_total, exact_before.tax_total);
    assert_eq!(exact_after.grand_total, exact_before.grand_total);
    assert_eq!(a.check(&exact).unwrap().line_items().count(), 2);

    let snapshot = a.clone();
    let err = a
        .apply(BookOp::new(
            op_id("split-lossy"),
            order_one.clone(),
            terminal("till-1"),
            101,
            ts(101),
            BookOpKind::SplitLineItem {
                check_id: lossy.clone(),
                line_item_id: line_id("lossy-line"),
                new_line_item_id: line_id("lossy-line-b"),
                first_quantity: Quantity::from_thousandths(500).unwrap(),
                preserve_totals: true,
            },
        ))
        .unwrap_err();
    assert_eq!(err, tirbase_pos::PosError::LossySplit);
    assert_eq!(
        a, snapshot,
        "a rejected lossy split must not mutate the book"
    );

    // Explicit opt-in permits recalculation, never silently.
    a.apply(BookOp::new(
        op_id("split-lossy-opt-in"),
        order_one,
        terminal("till-1"),
        102,
        ts(102),
        BookOpKind::SplitLineItem {
            check_id: lossy,
            line_item_id: line_id("lossy-line"),
            new_line_item_id: line_id("lossy-line-b"),
            first_quantity: Quantity::from_thousandths(500).unwrap(),
            preserve_totals: false,
        },
    ))
    .unwrap();
}

#[test]
fn transfer_line_and_check_preserve_content_and_reject_cross_store() {
    let (mut a, mut b) = seed();
    let order_one = order_id("order-1");
    let order_two = order_id("order-2");
    let source = check_id("check-1");
    let target = check_id("check-2");
    let before = total_of(&a, &source);
    let target_before = total_of(&a, &target);

    let transfer = BookOp::new(
        op_id("transfer-line"),
        order_one.clone(),
        terminal("till-1"),
        100,
        ts(100),
        BookOpKind::TransferLineItem {
            from_check_id: source.clone(),
            to_check_id: target.clone(),
            line_item_id: line_id("l1"),
        },
    );
    apply_both(&mut a, &mut b, transfer);
    assert_eq!(
        total_of(&a, &source)
            .subtotal
            .checked_add(total_of(&a, &target).subtotal)
            .unwrap(),
        before.subtotal.checked_add(target_before.subtotal).unwrap()
    );
    assert!(a
        .check(&target)
        .unwrap()
        .line_item(&line_id("l1"))
        .is_some());

    let move_check = BookOp::new(
        op_id("transfer-check"),
        order_one.clone(),
        terminal("till-1"),
        101,
        ts(101),
        BookOpKind::TransferCheck {
            to_order_id: order_two.clone(),
            check_id: target.clone(),
        },
    );
    apply_both(&mut a, &mut b, move_check);
    assert!(a.order(&order_one).unwrap().check(&target).is_none());
    assert!(a.order(&order_two).unwrap().check(&target).is_some());

    let cross_store = BookOp::new(
        op_id("transfer-cross-store"),
        order_one,
        terminal("till-1"),
        102,
        ts(102),
        BookOpKind::TransferCheck {
            to_order_id: order_id("order-3"),
            check_id: source,
        },
    );
    assert_eq!(
        a.apply(cross_store).unwrap_err(),
        tirbase_pos::PosError::CrossStoreTransfer
    );
}

#[test]
fn merge_checks_preserves_totals_and_rejects_ambiguous_or_incompatible_merges() {
    let (mut a, mut b) = seed();
    let order_one = order_id("order-1");
    let check_one = check_id("check-1");
    let check_two = check_id("check-2");
    let before_one = total_of(&a, &check_one);
    let before_two = total_of(&a, &check_two);

    let merge = BookOp::new(
        op_id("merge-1"),
        order_one.clone(),
        terminal("till-1"),
        100,
        ts(100),
        BookOpKind::MergeChecks {
            source_check_id: check_two.clone(),
            target_check_id: check_one.clone(),
        },
    );
    apply_both(&mut a, &mut b, merge);
    let merged = total_of(&a, &check_one);
    assert_eq!(
        merged.subtotal,
        before_one
            .subtotal
            .checked_add(before_two.subtotal)
            .unwrap()
    );
    assert_eq!(
        merged.tax_total,
        before_one
            .tax_total
            .checked_add(before_two.tax_total)
            .unwrap()
    );
    assert_eq!(
        merged.tip,
        before_one.tip.checked_add(before_two.tip).unwrap()
    );
    assert_eq!(
        merged.paid_total,
        before_one
            .paid_total
            .checked_add(before_two.paid_total)
            .unwrap()
    );
    assert_eq!(
        merged.grand_total,
        before_one
            .grand_total
            .checked_add(before_two.grand_total)
            .unwrap()
    );
    let source = a.check(&check_two).unwrap();
    assert_eq!(source.status(), CheckStatus::Merged);
    assert_eq!(source.merged_into(), Some(&check_one));
    assert_eq!(total_of(&a, &check_two).grand_total, Money::zero(usd()));

    // Different currency is refused before any move.
    let eur_check = check_id("check-eur");
    a.apply(wrap(
        create_cmd(
            "eur-1",
            &eur_check,
            eur(),
            RoundingMode::HalfAwayFromZero,
            200,
        ),
        &order_one,
        "till-1",
        200,
    ))
    .unwrap();
    let err = a
        .apply(BookOp::new(
            op_id("merge-eur"),
            order_one.clone(),
            terminal("till-1"),
            201,
            ts(201),
            BookOpKind::MergeChecks {
                source_check_id: eur_check,
                target_check_id: check_one.clone(),
            },
        ))
        .unwrap_err();
    assert_eq!(
        err,
        tirbase_pos::PosError::IncompatibleChecks("currency differs")
    );

    // A line identifier present on both checks is refused as ambiguous.
    let duplicate_check = check_id("check-duplicate");
    a.apply(wrap(
        create_cmd(
            "dup-1",
            &duplicate_check,
            usd(),
            RoundingMode::HalfAwayFromZero,
            300,
        ),
        &order_one,
        "till-1",
        300,
    ))
    .unwrap();
    a.apply(wrap(
        add_cmd(
            "dup-2",
            &duplicate_check,
            line("l1", "Coffee again", 100),
            301,
        ),
        &order_one,
        "till-1",
        301,
    ))
    .unwrap();
    let err = a
        .apply(BookOp::new(
            op_id("merge-duplicate"),
            order_one,
            terminal("till-1"),
            302,
            ts(302),
            BookOpKind::MergeChecks {
                source_check_id: duplicate_check,
                target_check_id: check_one,
            },
        ))
        .unwrap_err();
    assert_eq!(
        err,
        tirbase_pos::PosError::AmbiguousMerge("line id exists on both checks")
    );
}
