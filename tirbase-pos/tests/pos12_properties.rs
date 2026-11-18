// SPDX-License-Identifier: AGPL-3.0-only

//! POS-12 properties: no captured intent is ever dropped by reconciliation, a
//! tip split never loses or invents a minor unit, and re-ingesting a processor
//! file cannot change a batch.

use proptest::prelude::*;
use tirbase_pos::{
    CheckId, CreateIntent, Currency, Employee, EmployeeAccess, EmployeeDirectory, EmployeeId,
    EmployeeRole, IdempotencyKey, IntentBinding, Money, Organization, PaymentIntentId,
    PaymentIntentStore, PaymentMethod, PinRef, Processor, ProcessorBatchFile, SettlementBook,
    SettlementDay, SettlementKey, StaffSession, Store, StoreId, Terminal, TerminalId, Timestamp,
    TipLedger, TipMember, TipPoolId, TipPoolPolicy,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn ts(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn employee(id: &str) -> EmployeeId {
    EmployeeId::new(id).unwrap()
}

fn directory() -> EmployeeDirectory {
    let store = StoreId::new("store-1").unwrap();
    let mut org = Organization::new();
    org.add_store(Store::new(store.clone(), "Store One").unwrap())
        .unwrap();
    org.add_terminal(
        Terminal::new(TerminalId::new("till-1").unwrap(), store.clone(), "Till 1").unwrap(),
    )
    .unwrap();
    let mut directory = EmployeeDirectory::new();
    for (id, pin, role) in [
        ("emp-0", "pin-0", EmployeeRole::Supervisor),
        ("emp-1", "pin-1", EmployeeRole::Cashier),
        ("emp-2", "pin-2", EmployeeRole::Cashier),
        ("emp-3", "pin-3", EmployeeRole::Cashier),
        ("emp-4", "pin-4", EmployeeRole::Cashier),
        ("emp-5", "pin-5", EmployeeRole::Cashier),
    ] {
        let record = Employee::new(employee(id), store.clone(), id, vec![role]).unwrap();
        org.add_employee(record.clone()).unwrap();
        directory
            .add(EmployeeAccess::new(record, Some(PinRef::new(pin).unwrap()), None).unwrap())
            .unwrap();
    }
    directory
}

fn session(id: &str) -> StaffSession {
    directory()
        .session(&employee(id), TerminalId::new("till-1").unwrap())
        .unwrap()
}

fn batch_key() -> SettlementKey {
    SettlementKey::new(
        Processor::new("acquirer-1").unwrap(),
        TerminalId::new("till-1").unwrap(),
        SettlementDay::parse("2026-11-18").unwrap(),
    )
}

fn capture(store: &mut PaymentIntentStore, index: usize, minor: i64) {
    let intent = PaymentIntentId::new(format!("intent-{index}")).unwrap();
    let binding = IntentBinding::new(
        CheckId::new(format!("check-{index}")).unwrap(),
        money(minor),
        TerminalId::new("till-1").unwrap(),
        employee("emp-0"),
        PaymentMethod::Card,
    )
    .unwrap();
    store
        .create(CreateIntent::new(
            intent.clone(),
            IdempotencyKey::new(format!("key-{index}")).unwrap(),
            binding,
            ts(1_000),
        ))
        .unwrap();
    let token = tirbase_pos::ProcessorToken::new(format!("tok-{index}")).unwrap();
    store.authorize(&intent, token.clone(), ts(1_001)).unwrap();
    store
        .capture(&intent, money(minor), token, ts(1_002))
        .unwrap();
}

proptest! {
    /// The done-when criterion, over arbitrary mixtures of processor files:
    /// exact settlements, missing records, short settlements, over settlements
    /// and duplicated captures. Every captured intent is still accounted for.
    #[test]
    fn every_captured_intent_is_accounted_for(
        cases in prop::collection::vec((1_i64..5_000, 0_u8..5), 1..8),
    ) {
        let mut intents = PaymentIntentStore::new();
        let mut body = String::new();
        for (index, (amount, mode)) in cases.iter().enumerate() {
            capture(&mut intents, index, *amount);
            match mode {
                0 => body.push_str(&format!(
                    "capture,exact-{index},intent-{index},{amount},0,{index}\n"
                )),
                1 => {}
                2 => body.push_str(&format!(
                    "capture,short-{index},intent-{index},{},0,{index}\n",
                    amount - 1
                )),
                3 => body.push_str(&format!(
                    "capture,over-{index},intent-{index},{},0,{index}\n",
                    amount + 1
                )),
                _ => body.push_str(&format!(
                    "capture,dup-a-{index},intent-{index},{amount},0,{index}\n\
                     capture,dup-b-{index},intent-{index},{amount},0,{index}\n"
                )),
            }
        }

        let text = format!(
            "batch,batch-1,acquirer-1,till-1,2026-11-18,USD\n{body}"
        );
        let file = ProcessorBatchFile::parse(&text).expect("fixture is a valid file");
        let mut book = SettlementBook::new();
        book.ingest(&session("emp-0"), file, ts(9_000)).unwrap();

        let report = book.reconcile(&session("emp-0"), &intents, ts(9_100)).unwrap();
        for (index, (_, mode)) in cases.iter().enumerate() {
            let intent = PaymentIntentId::new(format!("intent-{index}")).unwrap();
            prop_assert!(
                report.accounts_for(&intent),
                "intent {index} (mode {mode}) was not reconciled and not queued"
            );
        }
        // An exact settlement is the only mode that reconciles.
        let exact = cases.iter().filter(|(_, mode)| *mode == 0).count();
        prop_assert_eq!(report.reconciled.len(), exact);
    }

    /// A tip split is exact: no minor unit is created or lost, and no member is
    /// paid a negative share.
    #[test]
    fn tip_allocation_preserves_the_total(
        total in 1_i64..1_000_000,
        weights in prop::collection::vec(1_u64..100, 1..6),
    ) {
        let mut ledger = TipLedger::new();
        ledger
            .record_tip(
                &session("emp-0"),
                CheckId::new("check-1").unwrap(),
                money(total),
                ts(30_000),
            )
            .unwrap();

        let members: Vec<TipMember> = weights
            .iter()
            .enumerate()
            .map(|(index, weight)| TipMember::new(employee(&format!("emp-{index}")), *weight))
            .collect();
        let payout = ledger
            .payout(
                &session("emp-0"),
                TipPoolId::new("pool-1").unwrap(),
                TipPoolPolicy::Weighted,
                &members,
                ts(31_000),
            )
            .unwrap();

        prop_assert_eq!(payout.total(), money(total));
        prop_assert_eq!(payout.allocated_total().unwrap(), money(total));
        let mut sum = money(0);
        for allocation in payout.allocations() {
            prop_assert!(allocation.payout.minor() >= 0);
            sum = sum.checked_add(allocation.payout).unwrap();
        }
        prop_assert_eq!(sum, money(total));
        prop_assert_eq!(ledger.open_total(usd()).unwrap(), money(0));
    }

    /// Ingesting the same file again is a replay: every record is recognised
    /// and the batch totals do not move.
    #[test]
    fn ingesting_the_same_file_twice_changes_nothing(
        amounts in prop::collection::vec(0_i64..10_000, 1..6),
    ) {
        let mut body = String::new();
        for (index, amount) in amounts.iter().enumerate() {
            body.push_str(&format!(
                "capture,rec-{index},intent-{index},{amount},0,{}\n",
                1_000 + index as i64
            ));
        }
        let text = format!("batch,batch-1,acquirer-1,till-1,2026-11-18,USD\n{body}");

        let mut book = SettlementBook::new();
        let first = book
            .ingest(
                &session("emp-0"),
                ProcessorBatchFile::parse(&text).unwrap(),
                ts(9_000),
            )
            .unwrap();
        prop_assert_eq!(first.added, amounts.len());
        prop_assert!(first.is_clean());
        let before = book.batch(&batch_key()).unwrap().totals().unwrap();

        let second = book
            .ingest(
                &session("emp-0"),
                ProcessorBatchFile::parse(&text).unwrap(),
                ts(9_001),
            )
            .unwrap();
        prop_assert_eq!(second.replayed, amounts.len());
        prop_assert_eq!(second.added, 0);
        prop_assert!(second.is_clean());
        let after = book.batch(&batch_key()).unwrap().totals().unwrap();
        prop_assert_eq!(before, after);
        prop_assert_eq!(book.exceptions().len(), 0);
    }
}
