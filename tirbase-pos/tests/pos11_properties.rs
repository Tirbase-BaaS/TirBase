// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for POS-11: expected cash always follows the ledger, variance
//! is exactly counted minus expected, offline reconciliation is idempotent, and
//! concurrent drawers never affect each other.

use proptest::prelude::*;
use tirbase_pos::{
    CashMovementId, CashMovementKind, CheckId, Currency, DrawerCountId, Employee, EmployeeAccess,
    EmployeeDirectory, EmployeeId, EmployeeRole, LineItem, LineItemId, Money, OperationId, Order,
    OrderCommand, OrderId, Organization, Ownership, PaymentId, PaymentLink, PaymentMethod, PinRef,
    Quantity, RoundingMode, SaleRecord, Shift, ShiftBook, ShiftEvent, ShiftEventBody, ShiftId,
    ShiftSpec, StaffSession, Store, StoreId, Terminal, TerminalId, Timestamp,
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
    ] {
        org.add_employee(Employee::new(employee(id), store.clone(), id, vec![role]).unwrap())
            .unwrap();
    }
    org
}

fn directory() -> EmployeeDirectory {
    let org = organization();
    let mut directory = EmployeeDirectory::new();
    for (id, pin) in [("emp-1", "pin-1"), ("emp-2", "pin-2")] {
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

fn open_shift(operator: &StaffSession, id: &str, terminal: &str, float: i64) -> Shift {
    Shift::open(
        operator,
        ShiftSpec::new(
            shift_id(id),
            store_id(),
            till(terminal),
            money(float),
            ts(0),
        ),
    )
    .unwrap()
}

/// One cash sale whose grand total is exactly `amount`.
fn cash_sale(org: &Organization, tag: &str, amount: i64) -> SaleRecord {
    let ownership = Ownership::new(store_id(), till("till-1"), employee("emp-1"), None);
    let mut order = Order::open(
        OrderId::new(format!("order-{tag}")).unwrap(),
        ownership,
        org,
        ts(0),
    )
    .unwrap();
    let check = CheckId::new(format!("check-{tag}")).unwrap();
    order
        .apply(OrderCommand::CreateCheck {
            operation_id: OperationId::new(format!("op-{tag}-create")).unwrap(),
            check_id: check.clone(),
            currency: usd(),
            rounding: RoundingMode::HalfAwayFromZero,
            at: ts(1),
        })
        .unwrap();
    order
        .apply(OrderCommand::AddLineItem {
            operation_id: OperationId::new(format!("op-{tag}-line")).unwrap(),
            check_id: check.clone(),
            line: LineItem::new(
                LineItemId::new("line-1").unwrap(),
                "Item",
                Quantity::from_units(1).unwrap(),
                money(amount),
            )
            .unwrap(),
            at: ts(2),
        })
        .unwrap();
    order
        .apply(OrderCommand::LinkPayment {
            operation_id: OperationId::new(format!("op-{tag}-pay")).unwrap(),
            check_id: check.clone(),
            payment: PaymentLink::captured(
                PaymentId::new("pay-1").unwrap(),
                PaymentMethod::Cash,
                money(amount),
            )
            .unwrap(),
            at: ts(3),
        })
        .unwrap();
    order
        .apply(OrderCommand::CloseCheck {
            operation_id: OperationId::new(format!("op-{tag}-close")).unwrap(),
            check_id: check.clone(),
            at: ts(4),
        })
        .unwrap();
    SaleRecord::from_check(order.check(&check).unwrap()).unwrap()
}

fn movement_kind(index: u8) -> CashMovementKind {
    match index % 3 {
        0 => CashMovementKind::CashIn,
        1 => CashMovementKind::CashOut,
        _ => CashMovementKind::SafeDrop,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn expected_cash_follows_the_ledger(
        float in 0_i64..50_000,
        movements in proptest::collection::vec((0_u8..3, 1_i64..10_000, 1_i64..100), 0..10),
        sale_minor in 1_i64..20_000,
        count_delta in -2_000_i64..2_000,
    ) {
        let org = organization();
        let supervisor = session("emp-2", "till-1");
        let mut shift = open_shift(&supervisor, "shift-1", "till-1", float);
        let mut expected = money(float);

        for (index, (kind_index, amount, at)) in movements.iter().enumerate() {
            let kind = movement_kind(*kind_index);
            let amount = money(*amount);
            shift
                .record_movement(
                    &supervisor,
                    movement_id(&format!("m-{index}")),
                    kind,
                    amount,
                    ts(*at),
                    None,
                )
                .unwrap();
            expected = if kind == CashMovementKind::CashIn {
                expected.checked_add(amount).unwrap()
            } else {
                expected.checked_sub(amount).unwrap()
            };
        }
        prop_assert_eq!(shift.expected_cash().unwrap(), expected);

        let sale = cash_sale(&org, "s", sale_minor);
        shift.record_sale(&supervisor, sale.clone()).unwrap();
        expected = expected.checked_add(sale.cash_paid()).unwrap();
        prop_assert_eq!(shift.expected_cash().unwrap(), expected);

        let counted = money((expected.minor() + count_delta).max(0));
        let variance = shift
            .record_count(&supervisor, count_id("c-1"), counted, ts(200), None)
            .unwrap();
        prop_assert_eq!(variance.expected, expected);
        prop_assert_eq!(variance.counted, counted);
        prop_assert_eq!(variance.variance, counted.checked_sub(expected).unwrap());
        prop_assert_eq!(&variance.operator, &employee("emp-2"));

        let report = shift
            .close(&supervisor, count_id("c-close"), counted, ts(300), None)
            .unwrap();
        prop_assert!(report.is_final());
        prop_assert_eq!(report.expected_cash(), expected);
        prop_assert_eq!(
            report.final_variance().unwrap().variance,
            counted.checked_sub(expected).unwrap()
        );
        prop_assert_eq!(report.movements().len(), movements.len());
    }

    #[test]
    fn reconciliation_is_idempotent(
        float in 0_i64..20_000,
        moves in proptest::collection::vec((0_u8..3, 1_i64..5_000, 1_i64..50), 0..8),
        counted in 0_i64..30_000,
    ) {
        let supervisor = session("emp-2", "till-1");
        let mut shift = open_shift(&supervisor, "shift-1", "till-1", float);
        let events: Vec<ShiftEvent> = moves
            .iter()
            .enumerate()
            .map(|(index, (kind_index, amount, at))| ShiftEvent {
                actor: employee("emp-1"),
                body: ShiftEventBody::CashMovement {
                    id: movement_id(&format!("m-{index}")),
                    kind: movement_kind(*kind_index),
                    amount: money(*amount),
                    at: ts(*at),
                    note: None,
                },
            })
            .collect();

        let first = shift.reconcile(&supervisor, events.clone()).unwrap();
        prop_assert_eq!(first.applied, events.len());
        prop_assert!(first.is_clean());
        let snapshot = shift.clone();
        let expected = shift.expected_cash().unwrap();

        let second = shift.reconcile(&supervisor, events.clone()).unwrap();
        prop_assert_eq!(second.applied, 0);
        prop_assert_eq!(second.replayed, events.len());
        prop_assert_eq!(&shift, &snapshot);
        prop_assert_eq!(shift.movements().len(), events.len());
        prop_assert_eq!(shift.expected_cash().unwrap(), expected);

        let variance = shift
            .record_count(&supervisor, count_id("c-1"), money(counted), ts(200), None)
            .unwrap();
        prop_assert_eq!(variance.expected, expected);
        prop_assert_eq!(
            variance.variance,
            money(counted).checked_sub(expected).unwrap()
        );
    }

    #[test]
    fn concurrent_drawers_stay_independent(
        float_one in 0_i64..20_000,
        float_two in 0_i64..20_000,
        extra in 1_i64..5_000,
    ) {
        let one = session("emp-2", "till-1");
        let two = session("emp-2", "till-2");
        let mut book = ShiftBook::new();
        book.open(
            &one,
            ShiftSpec::new(
                shift_id("shift-1"),
                store_id(),
                till("till-1"),
                money(float_one),
                ts(0),
            ),
        )
        .unwrap();
        book.open(
            &two,
            ShiftSpec::new(
                shift_id("shift-2"),
                store_id(),
                till("till-2"),
                money(float_two),
                ts(0),
            ),
        )
        .unwrap();
        let before = book
            .shift(&shift_id("shift-2"))
            .unwrap()
            .expected_cash()
            .unwrap();

        book.shift_mut(&shift_id("shift-1"))
            .unwrap()
            .record_movement(
                &one,
                movement_id("m-1"),
                CashMovementKind::CashIn,
                money(extra),
                ts(1),
                None,
            )
            .unwrap();

        prop_assert_eq!(
            book.shift(&shift_id("shift-1"))
                .unwrap()
                .expected_cash()
                .unwrap(),
            money(float_one + extra)
        );
        prop_assert_eq!(
            book.shift(&shift_id("shift-2"))
                .unwrap()
                .expected_cash()
                .unwrap(),
            before
        );
        prop_assert!(book.open_on(&till("till-2")).is_some());
    }
}
