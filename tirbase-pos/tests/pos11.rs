// SPDX-License-Identifier: AGPL-3.0-only

//! POS-11 behavioural tests: the employee permission matrix, shift boundaries,
//! drawer cash and variance attribution, X/Z reports, and offline
//! reconciliation without duplicate cash movements.

use tirbase_pos::{
    BadgeRef, BookOp, BookOpKind, CashMovementId, CashMovementKind, CheckId, CheckStatus, Currency,
    Discount, DrawerCountId, Employee, EmployeeAccess, EmployeeDirectory, EmployeeId, EmployeeRole,
    LineItem, LineItemId, Money, OperationId, Order, OrderCommand, OrderId, Organization,
    Ownership, PaymentId, PaymentLink, PaymentMethod, Permission, PermissionSet, PinRef, PosBook,
    Quantity, Rate, Refund, RefundId, ReportKind, RoundingMode, SaleRecord, Shift, ShiftBook,
    ShiftChange, ShiftError, ShiftEvent, ShiftEventBody, ShiftId, ShiftSpec, StaffError,
    StaffSession, Store, StoreId, Terminal, TerminalId, Timestamp,
};

fn store_id() -> StoreId {
    StoreId::new("store-1").unwrap()
}

fn till(id: &str) -> TerminalId {
    TerminalId::new(id).unwrap()
}

fn employee(id: &str) -> EmployeeId {
    EmployeeId::new(id).unwrap()
}

fn shift_id(id: &str) -> ShiftId {
    ShiftId::new(id).unwrap()
}

fn movement_id(id: &str) -> CashMovementId {
    CashMovementId::new(id).unwrap()
}

fn count_id(id: &str) -> DrawerCountId {
    DrawerCountId::new(id).unwrap()
}

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn rate(percent: i32) -> Rate {
    Rate::from_percent(percent).unwrap()
}

fn ts(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
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

fn spec(id: &str, terminal: &str, float: i64) -> ShiftSpec {
    ShiftSpec::new(
        shift_id(id),
        store_id(),
        till(terminal),
        money(float),
        ts(1_000),
    )
}

fn open_shift(operator: &StaffSession, id: &str, terminal: &str, float: i64) -> Shift {
    Shift::open(operator, spec(id, terminal, float)).unwrap()
}

fn order_for(org: &Organization, tag: &str) -> (Order, CheckId) {
    let ownership = Ownership::new(store_id(), till("till-1"), employee("emp-1"), None);
    let mut order = Order::open(
        OrderId::new(format!("order-{tag}")).unwrap(),
        ownership,
        org,
        ts(0),
    )
    .unwrap();
    let check_id = CheckId::new(format!("check-{tag}")).unwrap();
    order
        .apply(OrderCommand::CreateCheck {
            operation_id: OperationId::new(format!("op-{tag}-create")).unwrap(),
            check_id: check_id.clone(),
            currency: usd(),
            rounding: RoundingMode::HalfAwayFromZero,
            at: ts(1),
        })
        .unwrap();
    (order, check_id)
}

fn add_line(order: &mut Order, tag: &str, line: LineItem) {
    let check = CheckId::new(format!("check-{tag}")).unwrap();
    order
        .apply(OrderCommand::AddLineItem {
            operation_id: OperationId::new(format!("op-{tag}-line-{}", line.id())).unwrap(),
            check_id: check,
            line,
            at: ts(2),
        })
        .unwrap();
}

fn pay(
    order: &mut Order,
    tag: &str,
    check: &CheckId,
    id: &str,
    method: PaymentMethod,
    amount: Money,
) {
    order
        .apply(OrderCommand::LinkPayment {
            operation_id: OperationId::new(format!("op-{tag}-pay-{id}")).unwrap(),
            check_id: check.clone(),
            payment: PaymentLink::captured(PaymentId::new(id).unwrap(), method, amount).unwrap(),
            at: ts(3),
        })
        .unwrap();
}

fn settle(order: &mut Order, tag: &str, check: &CheckId) {
    order
        .apply(OrderCommand::CloseCheck {
            operation_id: OperationId::new(format!("op-{tag}-close")).unwrap(),
            check_id: check.clone(),
            at: ts(4),
        })
        .unwrap();
}

/// 2 x Coffee at 4.50, 10% tax, 1.00 tip, paid 6.00 cash and 4.90 card.
fn coffee_sale(org: &Organization, tag: &str) -> SaleRecord {
    let (mut order, check) = order_for(org, tag);
    add_line(
        &mut order,
        tag,
        LineItem::new(
            LineItemId::new("line-1").unwrap(),
            "Coffee",
            Quantity::from_units(2).unwrap(),
            money(450),
        )
        .unwrap()
        .with_tax_rate(rate(10)),
    );
    order
        .apply(OrderCommand::SetTip {
            operation_id: OperationId::new(format!("op-{tag}-tip")).unwrap(),
            check_id: check.clone(),
            tip: money(100),
            at: ts(3),
        })
        .unwrap();
    pay(
        &mut order,
        tag,
        &check,
        "pay-cash",
        PaymentMethod::Cash,
        money(600),
    );
    pay(
        &mut order,
        tag,
        &check,
        "pay-card",
        PaymentMethod::Card,
        money(490),
    );
    settle(&mut order, tag, &check);
    SaleRecord::from_check(order.check(&check).unwrap()).unwrap()
}

/// 1 x Item at 10.00 with a 10% line discount and 10% tax, paid cash.
fn discounted_sale(org: &Organization, tag: &str) -> SaleRecord {
    let (mut order, check) = order_for(org, tag);
    add_line(
        &mut order,
        tag,
        LineItem::new(
            LineItemId::new("line-1").unwrap(),
            "Item",
            Quantity::from_units(1).unwrap(),
            money(1_000),
        )
        .unwrap()
        .with_discount(Discount::percent("promo", rate(10)).unwrap())
        .unwrap()
        .with_tax_rate(rate(10)),
    );
    pay(
        &mut order,
        tag,
        &check,
        "pay-cash",
        PaymentMethod::Cash,
        money(990),
    );
    settle(&mut order, tag, &check);
    SaleRecord::from_check(order.check(&check).unwrap()).unwrap()
}

/// A coffee sale with 1.00 refunded after closing.
fn refunded_sale(org: &Organization, tag: &str) -> SaleRecord {
    let (mut order, check) = order_for(org, tag);
    add_line(
        &mut order,
        tag,
        LineItem::new(
            LineItemId::new("line-1").unwrap(),
            "Coffee",
            Quantity::from_units(2).unwrap(),
            money(450),
        )
        .unwrap()
        .with_tax_rate(rate(10)),
    );
    order
        .apply(OrderCommand::SetTip {
            operation_id: OperationId::new(format!("op-{tag}-tip")).unwrap(),
            check_id: check.clone(),
            tip: money(100),
            at: ts(3),
        })
        .unwrap();
    pay(
        &mut order,
        tag,
        &check,
        "pay-cash",
        PaymentMethod::Cash,
        money(600),
    );
    pay(
        &mut order,
        tag,
        &check,
        "pay-card",
        PaymentMethod::Card,
        money(490),
    );
    settle(&mut order, tag, &check);
    order
        .apply(OrderCommand::RefundCheck {
            operation_id: OperationId::new(format!("op-{tag}-refund")).unwrap(),
            check_id: check.clone(),
            refund: Refund::new(
                RefundId::new("refund-1").unwrap(),
                money(100),
                "customer return",
            )
            .unwrap(),
            at: ts(5),
        })
        .unwrap();
    SaleRecord::from_check(order.check(&check).unwrap()).unwrap()
}

/// One 10.00 line plus a 5.00 line voided before payment; paid 11.00 cash.
fn voided_sale(org: &Organization) -> SaleRecord {
    let order_id = OrderId::new("order-void").unwrap();
    let check = CheckId::new("check-void").unwrap();
    let actor = till("till-1");
    let mut book = PosBook::new(org.clone());
    book.add_order(
        order_id.clone(),
        Ownership::new(store_id(), actor.clone(), employee("emp-1"), None),
        ts(0),
    )
    .unwrap();
    // A wrapped order command must carry the envelope's operation id and time.
    let mut apply = |id: &str, at: i64, kind: BookOpKind| {
        book.apply(BookOp::new(
            OperationId::new(id).unwrap(),
            order_id.clone(),
            actor.clone(),
            at as u64,
            ts(at),
            kind,
        ))
        .unwrap();
    };
    apply(
        "void-cmd-1",
        1,
        BookOpKind::Order(OrderCommand::CreateCheck {
            operation_id: OperationId::new("void-cmd-1").unwrap(),
            check_id: check.clone(),
            currency: usd(),
            rounding: RoundingMode::HalfAwayFromZero,
            at: ts(1),
        }),
    );
    apply(
        "void-cmd-2",
        2,
        BookOpKind::Order(OrderCommand::AddLineItem {
            operation_id: OperationId::new("void-cmd-2").unwrap(),
            check_id: check.clone(),
            line: LineItem::new(
                LineItemId::new("void-l1").unwrap(),
                "Tea",
                Quantity::from_units(1).unwrap(),
                money(1_000),
            )
            .unwrap()
            .with_tax_rate(rate(10)),
            at: ts(2),
        }),
    );
    apply(
        "void-cmd-3",
        3,
        BookOpKind::Order(OrderCommand::AddLineItem {
            operation_id: OperationId::new("void-cmd-3").unwrap(),
            check_id: check.clone(),
            line: LineItem::new(
                LineItemId::new("void-l2").unwrap(),
                "Cake",
                Quantity::from_units(1).unwrap(),
                money(500),
            )
            .unwrap()
            .with_tax_rate(rate(10)),
            at: ts(3),
        }),
    );
    apply(
        "void-line-1",
        4,
        BookOpKind::VoidLineItem {
            check_id: check.clone(),
            line_item_id: LineItemId::new("void-l2").unwrap(),
            reason: "dropped".into(),
        },
    );
    apply(
        "void-cmd-5",
        5,
        BookOpKind::Order(OrderCommand::LinkPayment {
            operation_id: OperationId::new("void-cmd-5").unwrap(),
            check_id: check.clone(),
            payment: PaymentLink::captured(
                PaymentId::new("void-p1").unwrap(),
                PaymentMethod::Cash,
                money(1_100),
            )
            .unwrap(),
            at: ts(5),
        }),
    );
    apply(
        "void-cmd-6",
        6,
        BookOpKind::Order(OrderCommand::CloseCheck {
            operation_id: OperationId::new("void-cmd-6").unwrap(),
            check_id: check.clone(),
            at: ts(6),
        }),
    );
    SaleRecord::from_check(book.check(&check).unwrap()).unwrap()
}

#[test]
fn permission_matrix_follows_operational_roles() {
    let cashier = PermissionSet::for_roles(&[EmployeeRole::Cashier]);
    assert!(cashier.contains(Permission::Sell));
    assert!(cashier.contains(Permission::CountDrawer));
    assert!(cashier.contains(Permission::ViewXReport));
    assert!(!cashier.contains(Permission::CloseShift));
    assert!(!cashier.contains(Permission::CashOut));
    assert!(!cashier.contains(Permission::ManageEmployees));

    let supervisor = PermissionSet::for_roles(&[EmployeeRole::Supervisor]);
    assert!(supervisor.contains(Permission::OpenShift));
    assert!(supervisor.contains(Permission::CloseShift));
    assert!(supervisor.contains(Permission::ReconcileOffline));
    assert!(!supervisor.contains(Permission::ManageEmployees));

    let manager = PermissionSet::for_roles(&[EmployeeRole::Manager]);
    assert_eq!(manager, PermissionSet::all());
    assert_eq!(manager.len(), Permission::ALL.len() as u32);
}

#[test]
fn credentials_are_opaque_references_with_duplicate_protection() {
    let org = organization();
    let mut directory = EmployeeDirectory::new();
    let access = EmployeeAccess::new(
        org.employee(&employee("emp-1")).unwrap().clone(),
        Some(PinRef::new("pin-1").unwrap()),
        Some(BadgeRef::new("badge-1").unwrap()),
    )
    .unwrap();
    directory.add(access).unwrap();

    let reused_pin = EmployeeAccess::new(
        org.employee(&employee("emp-2")).unwrap().clone(),
        Some(PinRef::new("pin-1").unwrap()),
        None,
    )
    .unwrap();
    assert_eq!(
        directory.add(reused_pin),
        Err(StaffError::DuplicatePin(PinRef::new("pin-1").unwrap()))
    );
    assert_eq!(
        EmployeeAccess::new(
            org.employee(&employee("emp-2")).unwrap().clone(),
            None,
            None
        ),
        Err(StaffError::NoCredential)
    );
    assert_eq!(PinRef::new("").unwrap_err(), StaffError::InvalidPinRef);
    assert_eq!(
        BadgeRef::new("badge\u{0}").unwrap_err(),
        StaffError::InvalidBadgeRef
    );

    let session = directory
        .session(&employee("emp-1"), till("till-1"))
        .unwrap();
    assert!(session.can(Permission::Sell));
    assert_eq!(
        session.require(Permission::CloseShift),
        Err(StaffError::NotPermitted(Permission::CloseShift))
    );
}

#[test]
fn shift_open_requires_permission_and_matching_scope() {
    let cashier = session("emp-1", "till-1");
    assert_eq!(
        Shift::open(&cashier, spec("shift-1", "till-1", 10_000)).unwrap_err(),
        ShiftError::NotPermitted(Permission::OpenShift)
    );

    let supervisor = session("emp-2", "till-1");
    assert_eq!(
        Shift::open(&supervisor, spec("shift-1", "till-2", 10_000)).unwrap_err(),
        ShiftError::TerminalMismatch
    );
    let other_store = ShiftSpec::new(
        shift_id("shift-1"),
        StoreId::new("store-2").unwrap(),
        till("till-1"),
        money(10_000),
        ts(1_000),
    );
    assert_eq!(
        Shift::open(&supervisor, other_store).unwrap_err(),
        ShiftError::StoreMismatch
    );
    assert_eq!(
        Shift::open(&supervisor, spec("shift-1", "till-1", -1)).unwrap_err(),
        ShiftError::NegativeAmount
    );
}

#[test]
fn cash_movements_derive_expected_drawer_cash_and_are_idempotent() {
    let org = organization();
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);

    let movement = |id: &str, kind, amount, at| (movement_id(id), kind, money(amount), ts(at));
    let (id, kind, amount, at) = movement("move-1", CashMovementKind::CashIn, 2_000, 2_000);
    assert_eq!(
        shift
            .record_movement(
                &supervisor,
                id.clone(),
                kind,
                amount,
                at,
                Some("float top-up")
            )
            .unwrap(),
        ShiftChange::Applied
    );
    let (id, kind, amount, at) = movement("move-1", CashMovementKind::CashIn, 2_000, 2_000);
    assert_eq!(
        shift
            .record_movement(&supervisor, id, kind, amount, at, Some("float top-up"))
            .unwrap(),
        ShiftChange::Replayed
    );
    let (id, kind, amount, at) = movement("move-1", CashMovementKind::CashIn, 1, 2_000);
    assert_eq!(
        shift
            .record_movement(
                &supervisor,
                id.clone(),
                kind,
                amount,
                at,
                Some("float top-up")
            )
            .unwrap_err(),
        ShiftError::MovementConflict(id)
    );

    shift
        .record_movement(
            &supervisor,
            movement_id("move-2"),
            CashMovementKind::CashOut,
            money(500),
            ts(2_001),
            None,
        )
        .unwrap();
    shift
        .record_movement(
            &supervisor,
            movement_id("move-3"),
            CashMovementKind::SafeDrop,
            money(3_000),
            ts(2_002),
            None,
        )
        .unwrap();
    assert_eq!(shift.expected_cash().unwrap(), money(8_500));

    shift
        .record_sale(&supervisor, coffee_sale(&org, "a"))
        .unwrap();
    assert_eq!(shift.expected_cash().unwrap(), money(9_100));

    let totals = shift.totals().unwrap();
    assert_eq!(totals.opening_float, money(10_000));
    assert_eq!(totals.cash_in, money(2_000));
    assert_eq!(totals.cash_out, money(500));
    assert_eq!(totals.safe_drops, money(3_000));
    assert_eq!(totals.cash_sales, money(600));
    assert_eq!(totals.card_sales, money(490));
    assert_eq!(totals.sale_count, 1);
}

#[test]
fn movement_requires_its_own_permission() {
    let supervisor = session("emp-2", "till-1");
    let cashier = session("emp-1", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);

    assert_eq!(
        shift
            .record_movement(
                &cashier,
                movement_id("move-1"),
                CashMovementKind::CashIn,
                money(100),
                ts(2_000),
                None,
            )
            .unwrap_err(),
        ShiftError::NotPermitted(Permission::CashIn)
    );
    assert_eq!(
        shift
            .record_movement(
                &cashier,
                movement_id("move-2"),
                CashMovementKind::CashRefund,
                money(100),
                ts(2_000),
                None,
            )
            .unwrap_err(),
        ShiftError::NotPermitted(Permission::Refund)
    );
    assert!(shift
        .record_movement(
            &supervisor,
            movement_id("move-3"),
            CashMovementKind::SafeDrop,
            money(300),
            ts(2_000),
            None,
        )
        .is_ok());
}

#[test]
fn drawer_count_variance_is_attributed_to_the_operator() {
    let supervisor = session("emp-2", "till-1");
    let cashier = session("emp-1", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    shift
        .record_movement(
            &supervisor,
            movement_id("move-1"),
            CashMovementKind::CashOut,
            money(1_000),
            ts(2_000),
            None,
        )
        .unwrap();

    let variance = shift
        .record_count(
            &cashier,
            count_id("count-1"),
            money(8_700),
            ts(3_000),
            Some("blind count"),
        )
        .unwrap();
    assert_eq!(variance.expected, money(9_000));
    assert_eq!(variance.counted, money(8_700));
    assert_eq!(variance.variance, money(-300));
    assert_eq!(variance.operator, employee("emp-1"));
    assert!(variance.is_short());
    assert_eq!(shift.counts()[0].by(), &employee("emp-1"));
    assert_eq!(shift.counts()[0].note(), Some("blind count"));

    let over = shift
        .record_count(
            &supervisor,
            count_id("count-2"),
            money(9_250),
            ts(3_500),
            None,
        )
        .unwrap();
    assert_eq!(over.operator, employee("emp-2"));
    assert_eq!(over.variance, money(250));
    assert!(over.is_over());
    assert_eq!(shift.variances().len(), 2);
}

#[test]
fn x_report_reports_totals_without_closing_the_shift() {
    let org = organization();
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    shift
        .record_sale(&supervisor, coffee_sale(&org, "a"))
        .unwrap();
    shift
        .record_sale(&supervisor, discounted_sale(&org, "b"))
        .unwrap();
    shift
        .record_count(
            &supervisor,
            count_id("count-1"),
            money(11_590),
            ts(4_000),
            None,
        )
        .unwrap();

    let report = shift.x_report(&supervisor, ts(5_000)).unwrap();
    assert_eq!(report.kind(), ReportKind::X);
    assert!(!report.is_final());
    assert_eq!(report.closed_at(), None);
    assert_eq!(report.closed_by(), None);
    assert!(shift.is_open());

    let totals = report.totals();
    assert_eq!(totals.subtotal, money(1_900));
    assert_eq!(totals.discount_total, money(100));
    assert_eq!(totals.tax_total, money(180));
    assert_eq!(totals.tip, money(100));
    assert_eq!(totals.grand_total, money(2_080));
    assert_eq!(totals.cash_sales, money(1_590));
    assert_eq!(totals.card_sales, money(490));
    assert_eq!(totals.sale_count, 2);
    assert_eq!(report.expected_cash(), money(11_590));
    assert!(report.final_variance().unwrap().is_balanced());

    // Reading a report is not an event: no count or movement was added.
    assert_eq!(shift.counts().len(), 1);
    assert_eq!(shift.movements().len(), 0);
}

#[test]
fn z_report_closes_the_shift_and_cannot_be_edited() {
    let org = organization();
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    shift
        .record_movement(
            &supervisor,
            movement_id("move-1"),
            CashMovementKind::CashOut,
            money(500),
            ts(2_000),
            Some("petty cash"),
        )
        .unwrap();

    let report = shift
        .close(
            &supervisor,
            count_id("count-close"),
            money(10_000),
            ts(5_000),
            Some("end of day"),
        )
        .unwrap();
    assert!(report.is_final());
    assert_eq!(report.kind(), ReportKind::Z);
    assert_eq!(report.closed_by(), Some(&employee("emp-2")));
    assert_eq!(report.closed_at(), Some(ts(5_000)));
    assert_eq!(report.expected_cash(), money(9_500));
    assert!(report.final_variance().unwrap().is_over());
    assert_eq!(report.final_variance().unwrap().variance, money(500));
    assert_eq!(report.final_variance().unwrap().operator, employee("emp-2"));
    assert!(shift.is_closed());
    assert_eq!(shift.z_report(), Some(&report));

    let frozen = report.clone();
    assert_eq!(
        shift
            .record_movement(
                &supervisor,
                movement_id("move-2"),
                CashMovementKind::CashIn,
                money(100),
                ts(6_000),
                None,
            )
            .unwrap_err(),
        ShiftError::Closed
    );
    assert_eq!(
        shift
            .record_sale(&supervisor, coffee_sale(&org, "late"))
            .unwrap_err(),
        ShiftError::Closed
    );
    assert_eq!(
        shift
            .record_count(
                &supervisor,
                count_id("count-late"),
                money(0),
                ts(6_000),
                None
            )
            .unwrap_err(),
        ShiftError::Closed
    );
    assert_eq!(
        shift.x_report(&supervisor, ts(6_000)).unwrap_err(),
        ShiftError::Closed
    );
    assert_eq!(
        shift
            .reconcile(&supervisor, Vec::<ShiftEvent>::new())
            .unwrap_err(),
        ShiftError::Closed
    );
    assert_eq!(
        shift
            .close(
                &supervisor,
                count_id("count-again"),
                money(0),
                ts(7_000),
                None
            )
            .unwrap_err(),
        ShiftError::Closed
    );

    // Every refused edit left the stored report exactly as it was.
    assert_eq!(shift.z_report(), Some(&frozen));
    assert_eq!(shift.z_report().unwrap().totals(), frozen.totals());
    assert_eq!(ShiftError::Closed.code(), "shift.closed");
}

#[test]
fn sale_requires_a_settled_check() {
    let org = organization();
    let (order, check) = order_for(&org, "open");
    assert_eq!(
        SaleRecord::from_check(order.check(&check).unwrap()).unwrap_err(),
        ShiftError::SaleNotSettled(CheckStatus::Open)
    );
}

#[test]
fn events_before_opening_are_rejected() {
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    assert_eq!(
        shift
            .record_movement(
                &supervisor,
                movement_id("move-1"),
                CashMovementKind::CashIn,
                money(100),
                ts(999),
                None,
            )
            .unwrap_err(),
        ShiftError::TimeBeforeOpen
    );
    assert_eq!(
        shift
            .record_count(
                &supervisor,
                count_id("count-1"),
                money(10_000),
                ts(999),
                None
            )
            .unwrap_err(),
        ShiftError::TimeBeforeOpen
    );
}

#[test]
fn a_sale_cannot_be_recorded_twice_with_different_figures() {
    let org = organization();
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    let sale = coffee_sale(&org, "dup");
    assert_eq!(
        shift.record_sale(&supervisor, sale.clone()).unwrap(),
        ShiftChange::Applied
    );
    assert_eq!(
        shift.record_sale(&supervisor, sale).unwrap(),
        ShiftChange::Replayed
    );
    assert_eq!(shift.sales().count(), 1);
    assert_eq!(shift.expected_cash().unwrap(), money(10_600));

    assert_eq!(
        shift
            .record_sale(&supervisor, discounted_sale(&org, "dup"))
            .unwrap_err(),
        ShiftError::SaleConflict(CheckId::new("check-dup").unwrap())
    );
    assert_eq!(shift.expected_cash().unwrap(), money(10_600));
}

#[test]
fn drawer_is_exclusive_per_terminal_but_tills_stay_independent() {
    let mut book = ShiftBook::new();
    let one = session("emp-2", "till-1");
    let two = session("emp-2", "till-2");

    book.open(&one, spec("shift-1", "till-1", 10_000)).unwrap();
    assert_eq!(
        book.open(&one, spec("shift-2", "till-1", 10_000))
            .unwrap_err(),
        ShiftError::DrawerAlreadyOpen(till("till-1"))
    );
    assert_eq!(
        book.open(&one, spec("shift-1", "till-1", 10_000))
            .unwrap_err(),
        ShiftError::DuplicateShift(shift_id("shift-1"))
    );
    book.open(&two, spec("shift-2", "till-2", 5_000)).unwrap();
    assert_eq!(book.shifts().count(), 2);

    book.shift_mut(&shift_id("shift-1"))
        .unwrap()
        .record_movement(
            &one,
            movement_id("move-1"),
            CashMovementKind::CashIn,
            money(1_000),
            ts(2_000),
            None,
        )
        .unwrap();
    assert_eq!(
        book.shift(&shift_id("shift-1"))
            .unwrap()
            .expected_cash()
            .unwrap(),
        money(11_000)
    );
    assert_eq!(
        book.shift(&shift_id("shift-2"))
            .unwrap()
            .expected_cash()
            .unwrap(),
        money(5_000)
    );

    book.close(
        &shift_id("shift-1"),
        &one,
        count_id("count-1"),
        money(11_000),
        ts(9_000),
        None,
    )
    .unwrap();
    assert!(book.open_on(&till("till-1")).is_none());
    assert!(book.open_on(&till("till-2")).is_some());
    // The released terminal can be opened again; the other till is untouched.
    book.open(&one, spec("shift-3", "till-1", 1_000)).unwrap();
    assert_eq!(book.shifts().count(), 3);
}

#[test]
fn offline_events_reconcile_without_duplicate_cash_movements() {
    let org = organization();
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    let events = vec![
        ShiftEvent {
            actor: employee("emp-1"),
            body: ShiftEventBody::CashMovement {
                id: movement_id("move-1"),
                kind: CashMovementKind::CashIn,
                amount: money(2_000),
                at: ts(2_000),
                note: None,
            },
        },
        ShiftEvent {
            actor: employee("emp-1"),
            body: ShiftEventBody::sale(coffee_sale(&org, "offline")),
        },
        ShiftEvent {
            actor: employee("emp-1"),
            body: ShiftEventBody::DrawerCount {
                id: count_id("count-1"),
                counted: money(12_600),
                at: ts(3_000),
                note: Some("offline count".into()),
            },
        },
    ];

    let first = shift.reconcile(&supervisor, events.clone()).unwrap();
    assert_eq!(first.applied, 3);
    assert_eq!(first.replayed, 0);
    assert!(first.is_clean());
    assert_eq!(shift.expected_cash().unwrap(), money(12_600));
    let snapshot = shift.clone();
    let expected = shift.expected_cash().unwrap();

    // The terminal reconnects and replays the same log.
    let second = shift.reconcile(&supervisor, events.clone()).unwrap();
    assert_eq!(second.applied, 0);
    assert_eq!(second.replayed, 3);
    assert!(second.is_clean());
    assert_eq!(shift, snapshot);
    assert_eq!(shift.movements().len(), 1);
    assert_eq!(shift.sales().count(), 1);
    assert_eq!(shift.variances().len(), 1);
    assert_eq!(shift.expected_cash().unwrap(), expected);
}

#[test]
fn conflicting_offline_movement_is_rejected_without_moving_cash() {
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    let original = ShiftEvent {
        actor: employee("emp-1"),
        body: ShiftEventBody::CashMovement {
            id: movement_id("move-1"),
            kind: CashMovementKind::CashIn,
            amount: money(2_000),
            at: ts(2_000),
            note: None,
        },
    };
    shift.reconcile(&supervisor, [original.clone()]).unwrap();
    assert_eq!(shift.expected_cash().unwrap(), money(12_000));

    let conflicting = ShiftEvent {
        actor: employee("emp-1"),
        body: ShiftEventBody::CashMovement {
            id: movement_id("move-1"),
            kind: CashMovementKind::CashIn,
            amount: money(3_000),
            at: ts(2_000),
            note: None,
        },
    };
    let report = shift.reconcile(&supervisor, [conflicting]).unwrap();
    assert_eq!(report.applied, 0);
    assert_eq!(report.replayed, 0);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(
        report.rejected[0].error,
        ShiftError::MovementConflict(movement_id("move-1"))
    );
    assert!(!report.is_clean());
    assert_eq!(shift.movements().len(), 1);
    assert_eq!(shift.expected_cash().unwrap(), money(12_000));
}

#[test]
fn a_wire_sale_that_does_not_add_up_is_rejected() {
    let org = organization();
    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 10_000);
    let mut value = serde_json::to_value(coffee_sale(&org, "wire")).unwrap();
    value["grand_total"]["minor"] = serde_json::json!(1);
    let tampered: SaleRecord = serde_json::from_value(value).unwrap();

    let report = shift
        .reconcile(
            &supervisor,
            [ShiftEvent {
                actor: employee("emp-1"),
                body: ShiftEventBody::sale(tampered),
            }],
        )
        .unwrap();
    assert_eq!(report.applied, 0);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].error.code(), "shift.invalid_sale");
    assert_eq!(shift.sales().count(), 0);
    assert_eq!(shift.expected_cash().unwrap(), money(10_000));
}

#[test]
fn an_offline_shift_is_adopted_once_per_terminal() {
    let supervisor = session("emp-2", "till-1");
    let mut local = open_shift(&supervisor, "shift-offline", "till-1", 5_000);
    local
        .record_movement(
            &supervisor,
            movement_id("move-1"),
            CashMovementKind::CashIn,
            money(1_000),
            ts(2_000),
            None,
        )
        .unwrap();

    let mut book = ShiftBook::new();
    book.adopt_offline(local.clone()).unwrap();
    assert_eq!(book.open_on(&till("till-1")).unwrap().id(), local.id());
    assert_eq!(
        book.open_on(&till("till-1"))
            .unwrap()
            .expected_cash()
            .unwrap(),
        money(6_000)
    );
    assert_eq!(
        book.adopt_offline(local).unwrap_err(),
        ShiftError::DuplicateShift(shift_id("shift-offline"))
    );
    assert_eq!(
        book.adopt_offline(open_shift(&supervisor, "shift-offline-2", "till-1", 0))
            .unwrap_err(),
        ShiftError::DrawerAlreadyOpen(till("till-1"))
    );
}

#[test]
fn voids_and_refunds_appear_in_the_report() {
    let org = organization();
    let voided = voided_sale(&org);
    assert_eq!(voided.voided_lines(), 1);
    assert_eq!(voided.subtotal(), money(1_000));
    assert_eq!(voided.tax_total(), money(100));
    assert_eq!(voided.grand_total(), money(1_100));
    assert_eq!(voided.cash_paid(), money(1_100));

    let refunded = refunded_sale(&org, "r");
    assert_eq!(refunded.refunded_total(), money(100));
    assert_eq!(refunded.grand_total(), money(1_090));

    let supervisor = session("emp-2", "till-1");
    let mut shift = open_shift(&supervisor, "shift-1", "till-1", 0);
    shift.record_sale(&supervisor, voided).unwrap();
    shift.record_sale(&supervisor, refunded).unwrap();

    let totals = shift.totals().unwrap();
    assert_eq!(totals.voided_lines, 1);
    assert_eq!(totals.voided_payments, 0);
    assert_eq!(totals.refunded_total, money(100));
    assert_eq!(totals.tax_total, money(190));
    assert_eq!(totals.subtotal, money(1_900));
    assert_eq!(totals.grand_total, money(2_190));
    assert_eq!(totals.cash_sales, money(1_700));
    assert_eq!(totals.card_sales, money(490));

    let report = shift
        .close(
            &supervisor,
            count_id("count-1"),
            money(1_700),
            ts(9_000),
            None,
        )
        .unwrap();
    assert_eq!(report.totals().refunded_total, money(100));
    assert_eq!(report.totals().voided_lines, 1);
    assert!(report.final_variance().unwrap().is_balanced());
}
