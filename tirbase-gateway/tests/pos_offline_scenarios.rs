// SPDX-License-Identifier: AGPL-3.0-only

//! Offline POS pack integration (POS-09, AGPL).
//!
//! Loads `tirbase-demo/pos-offline` as Apache data and executes every declared
//! command against the real `tirbase-pos` models: the payment intent store and
//! POS-06 envelope for capture/refund/void, the POS-02 operation book for the
//! split conflict, POS-04 versions for the offline price change, and the POS-08
//! KDS endpoint for the duplicate ticket. Observed permits and ledger rows must
//! match `expected/outcomes.toml` exactly.

use std::collections::BTreeMap;
use std::path::PathBuf;

use tirbase_demo::pos_pack::{load_pos_pack, PosCommand, PosPack, PosScenario};
use tirbase_pos::{
    ApprovalAction, ApprovalGuard, BookOp, BookOpKind, CatalogItem, CatalogVersion,
    CatalogVersionId, CheckId, CheckStatus, CreateIntent, Currency, DiscountCap, DiscountCaps,
    EffectiveWindow, Employee, EmployeeId, EmployeeRole, EnvelopeAction, EnvelopePolicy,
    IdempotencyKey, IntentBinding, IntentEvent, JurisdictionId, KdsEndpoint, KdsLine,
    KdsSubmitOutcome, KdsTicket, KdsTicketId, LineItemId, LineStatus, Money, OperationId, Order,
    OrderCommand, OrderId, Organization, Ownership, PaymentDesk, PaymentEnvelope, PaymentError,
    PaymentId, PaymentIntentId, PaymentMethod, PaymentNonce, PaymentOutcome, PosBook,
    PriceBookVersion, PriceBookVersionId, ProcessorToken, Quantity, Rate, RefundCaps, SimulatedKds,
    StackingPolicy, Station, Store, StoreId, TaxApplicability, TaxRule, TaxTableVersion,
    TaxTableVersionId, Terminal, TerminalEpoch, TerminalId, Timestamp, VersionStore,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack() -> PosPack {
    load_pos_pack(workspace_root().join("tirbase-demo/pos-offline"))
        .expect("offline POS pack must load")
}

fn currency(scenario: &PosScenario) -> Currency {
    Currency::from_code(&scenario.initial.currency).expect("pack currency is ISO 4217")
}

fn money(scenario: &PosScenario, minor: i64) -> Money {
    Money::new(currency(scenario), minor)
}

fn ts(ms: i64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn terminal(id: &str) -> TerminalId {
    TerminalId::new(id).expect("terminal id")
}

fn employee(id: &str) -> EmployeeId {
    EmployeeId::new(id).expect("employee id")
}

fn check(id: &str) -> CheckId {
    CheckId::new(id).expect("check id")
}

fn payment(id: &str) -> PaymentId {
    PaymentId::new(id).expect("payment id")
}

fn organization(scenario: &PosScenario) -> Organization {
    let store_id = StoreId::new("store-1").expect("store id");
    let mut org = Organization::new();
    org.add_store(Store::new(store_id.clone(), "Store One").expect("store"))
        .expect("add store");
    for id in ["till-1", "till-2"] {
        org.add_terminal(Terminal::new(terminal(id), store_id.clone(), id).expect("terminal"))
            .expect("add terminal");
    }
    org.add_employee(
        Employee::new(
            employee(&scenario.initial.operator),
            store_id.clone(),
            "Cashier",
            vec![EmployeeRole::Cashier],
        )
        .expect("operator"),
    )
    .expect("add operator");
    org.add_employee(
        Employee::new(
            employee(&scenario.initial.approver),
            store_id,
            "Supervisor",
            vec![EmployeeRole::Supervisor],
        )
        .expect("approver"),
    )
    .expect("add approver");
    org
}

fn approval_guard(scenario: &PosScenario) -> ApprovalGuard {
    let c = currency(scenario);
    let high = Money::new(c, 1_000_000);
    let mut guard = ApprovalGuard::new(
        c,
        RefundCaps::new(Money::new(c, 1_000), high, high, high).expect("refund caps"),
        DiscountCaps::new(
            DiscountCap::new(Rate::ONE_HUNDRED_PERCENT, high).expect("discount cap"),
            DiscountCap::new(Rate::ONE_HUNDRED_PERCENT, high).expect("discount cap"),
            StackingPolicy::BestOf,
        )
        .expect("discount caps"),
        1,
    )
    .expect("approval guard");
    guard.register_approver(
        employee(&scenario.initial.approver),
        tirbase_pos::OperatorRole::Supervisor,
    );
    guard
}

fn processor_token(scenario: &PosScenario) -> ProcessorToken {
    ProcessorToken::new(format!("token-{}", scenario.initial.payment)).expect("test token")
}

fn payment_envelope(
    scenario: &PosScenario,
    command: &PosCommand,
    action: EnvelopeAction,
    reason: &str,
    tip: Money,
) -> PaymentEnvelope {
    let envelope = PaymentEnvelope::new(
        payment(&scenario.initial.payment),
        PaymentIntentId::new(&scenario.initial.intent).expect("intent id"),
        check(&scenario.initial.check),
        terminal(&scenario.initial.terminal),
        TerminalEpoch::new(scenario.initial.epoch),
        employee(&scenario.initial.operator),
        PaymentNonce::new(command.nonce.as_deref().expect("command nonce")).expect("nonce"),
        command.counter.expect("command counter"),
        money(scenario, scenario.initial.check_total_minor),
        tip,
        money(scenario, command.amount_minor.expect("command amount")),
        PaymentMethod::Card,
    )
    .with_action(action, reason)
    .with_check_status(if scenario.initial.check_status == "closed" {
        CheckStatus::Closed
    } else {
        CheckStatus::Open
    });
    match &command.approval {
        Some(id) => envelope.with_approval(tirbase_pos::ApprovalId::new(id).expect("approval id")),
        None => envelope,
    }
}

fn denial_code(error: &PaymentError) -> String {
    match error {
        PaymentError::Envelope(error) => error.code().as_str().to_string(),
        PaymentError::Guard(error) => error.code().as_str().to_string(),
        PaymentError::Pos(error) => format!("pos.{error:?}"),
    }
}

fn payment_ledger(desk: &PaymentDesk, scenario: &PosScenario) -> BTreeMap<String, String> {
    let mut captures = 0_i64;
    let mut captured_minor = 0_i64;
    let mut refunds = 0_i64;
    let mut refunded_minor = 0_i64;
    let mut voids = 0_i64;
    let mut voided_minor = 0_i64;
    for event in desk.intents().journal() {
        match event {
            IntentEvent::Captured { amount, .. } => {
                captures += 1;
                captured_minor += amount.minor();
            }
            IntentEvent::Refunded { amount, .. } => {
                refunds += 1;
                refunded_minor += amount.minor();
            }
            IntentEvent::Voided { .. } => {
                voids += 1;
                voided_minor += scenario.initial.check_total_minor;
            }
            IntentEvent::Created { .. } | IntentEvent::Authorized { .. } => {}
        }
    }
    let intent_id = PaymentIntentId::new(&scenario.initial.intent).expect("intent id");
    let status = desk
        .intent(&intent_id)
        .map(|intent| intent.status().to_string())
        .unwrap_or_else(|| "missing".to_string());
    let mut ledger = BTreeMap::new();
    ledger.insert("capture_count".to_string(), captures.to_string());
    ledger.insert("captured_minor".to_string(), captured_minor.to_string());
    ledger.insert("intent_status".to_string(), status);
    ledger.insert("nonce_count".to_string(), desk.nonce_count().to_string());
    ledger.insert("refund_count".to_string(), refunds.to_string());
    ledger.insert("void_count".to_string(), voids.to_string());
    if refunds > 0 {
        ledger.insert("refunded_minor".to_string(), refunded_minor.to_string());
    }
    if voids > 0 {
        ledger.insert("voided_minor".to_string(), voided_minor.to_string());
    }
    ledger
}

fn run_payment(scenario: &PosScenario) -> (Vec<String>, BTreeMap<String, String>) {
    let c = currency(scenario);
    let policy = EnvelopePolicy::new(c, Money::new(c, 100_000), Money::new(c, 100_000), 16, 64)
        .expect("envelope policy");
    let mut desk = PaymentDesk::new(organization(scenario), policy, approval_guard(scenario))
        .expect("payment desk");
    desk.begin_epoch(
        &terminal(&scenario.initial.terminal),
        TerminalEpoch::new(scenario.initial.epoch),
    )
    .expect("terminal epoch");

    let total = money(scenario, scenario.initial.check_total_minor);
    let tip = money(scenario, scenario.initial.tip_minor);
    let intent_id = PaymentIntentId::new(&scenario.initial.intent).expect("intent id");
    let binding = IntentBinding::new(
        check(&scenario.initial.check),
        total,
        terminal(&scenario.initial.terminal),
        employee(&scenario.initial.operator),
        PaymentMethod::Card,
    )
    .expect("intent binding");
    desk.create_intent(CreateIntent::new(
        intent_id.clone(),
        IdempotencyKey::new(format!("key-{}", scenario.initial.intent)).expect("idempotency key"),
        binding,
        ts(0),
    ))
    .expect("create intent");
    desk.authorize_intent(&intent_id, processor_token(scenario), ts(1))
        .expect("authorize intent");

    // Realise a declared captured initial state through the same envelope path.
    if scenario.initial.intent_status == "captured" {
        let setup = PaymentEnvelope::new(
            payment(&scenario.initial.payment),
            intent_id.clone(),
            check(&scenario.initial.check),
            terminal(&scenario.initial.terminal),
            TerminalEpoch::new(scenario.initial.epoch),
            employee(&scenario.initial.operator),
            PaymentNonce::new("setup-capture").expect("setup nonce"),
            0,
            total,
            tip,
            total,
            PaymentMethod::Card,
        )
        .with_check_status(if scenario.initial.check_status == "closed" {
            CheckStatus::Closed
        } else {
            CheckStatus::Open
        });
        let outcome = desk
            .capture(&setup, processor_token(scenario), ts(2))
            .expect("initial capture");
        assert!(!outcome.is_replayed(), "initial capture must execute once");
    }

    for approval in &scenario.approvals {
        let action = match approval.action.as_str() {
            "refund" => ApprovalAction::Refund,
            "void_payment" => ApprovalAction::VoidPayment(payment(&scenario.initial.payment)),
            other => panic!("unknown approval action '{other}'"),
        };
        let id = tirbase_pos::ApprovalId::new(&approval.id).expect("approval id");
        desk.approvals_mut()
            .request_approval(
                id.clone(),
                action,
                check(&scenario.initial.check),
                money(scenario, approval.amount_minor),
                &approval.reason,
                employee(&approval.requester),
                terminal(&scenario.initial.terminal),
                ts(approval.requested_at_ms),
                ts(approval.expires_at_ms),
            )
            .expect("request approval");
        desk.approvals_mut()
            .approve(
                &id,
                &employee(&approval.approver),
                ts(approval.requested_at_ms + 1),
            )
            .expect("approve");
    }

    let mut permits = Vec::new();
    for command in &scenario.commands {
        let approval_reason = command
            .approval
            .as_ref()
            .and_then(|id| {
                scenario
                    .approvals
                    .iter()
                    .find(|approval| &approval.id == id)
            })
            .map(|approval| approval.reason.as_str())
            .unwrap_or("scenario command");
        let (action, outcome) = match command.kind.as_str() {
            "capture" => {
                let envelope = payment_envelope(
                    scenario,
                    command,
                    EnvelopeAction::Capture,
                    approval_reason,
                    tip,
                );
                (
                    "capture",
                    desk.capture(&envelope, processor_token(scenario), ts(command.at_ms)),
                )
            }
            "refund" => {
                let envelope = payment_envelope(
                    scenario,
                    command,
                    EnvelopeAction::Refund,
                    approval_reason,
                    tip,
                );
                ("refund", desk.refund(&envelope, ts(command.at_ms)))
            }
            "void" => {
                let envelope = payment_envelope(
                    scenario,
                    command,
                    EnvelopeAction::Void,
                    approval_reason,
                    tip,
                );
                ("void", desk.void(&envelope, ts(command.at_ms)))
            }
            other => panic!("unexpected payment command '{other}'"),
        };
        match outcome {
            Ok(PaymentOutcome::Executed(_)) => {
                assert_eq!(
                    command.expect, "accepted",
                    "{action} {} executed",
                    command.id
                );
                permits.push("accepted".to_string());
            }
            Ok(PaymentOutcome::Replayed(_)) => {
                assert_eq!(
                    command.expect, "replayed",
                    "{action} {} unexpectedly replayed",
                    command.id
                );
                permits.push("replayed".to_string());
            }
            Err(error) => {
                let code = denial_code(&error);
                assert_eq!(
                    command.expect, "denied",
                    "{action} {} failed with {code} but expected {}",
                    command.id, command.expect
                );
                assert_eq!(
                    command.denial.as_deref(),
                    Some(code.as_str()),
                    "{action} {} denial code",
                    command.id
                );
                permits.push("denied".to_string());
            }
        }
    }
    (permits, payment_ledger(&desk, scenario))
}

fn wrap(
    operation_id: &str,
    order: &OrderId,
    actor: &str,
    lamport: u64,
    at_ms: i64,
    kind: BookOpKind,
) -> BookOp {
    BookOp::new(
        OperationId::new(operation_id).expect("operation id"),
        order.clone(),
        terminal(actor),
        lamport,
        ts(at_ms),
        kind,
    )
}

fn split_seed(scenario: &PosScenario) -> (PosBook, PosBook) {
    let org = organization(scenario);
    let mut a = PosBook::new(org.clone());
    let mut b = PosBook::new(org);
    let order = OrderId::new("order-split").expect("order id");
    let ownership = Ownership::new(
        StoreId::new("store-1").expect("store id"),
        terminal(&scenario.initial.terminal),
        employee(&scenario.initial.operator),
        None,
    );
    for book in [&mut a, &mut b] {
        book.add_order(order.clone(), ownership.clone(), ts(0))
            .expect("add order");
    }
    let create = wrap(
        "seed-create",
        &order,
        &scenario.initial.terminal,
        1,
        1,
        BookOpKind::Order(OrderCommand::CreateCheck {
            operation_id: OperationId::new("seed-create").expect("operation id"),
            check_id: check(&scenario.initial.check),
            currency: currency(scenario),
            rounding: tirbase_pos::RoundingMode::HalfAwayFromZero,
            at: ts(1),
        }),
    );
    let line = wrap(
        "seed-line",
        &order,
        &scenario.initial.terminal,
        2,
        2,
        BookOpKind::Order(OrderCommand::AddLineItem {
            operation_id: OperationId::new("seed-line").expect("operation id"),
            check_id: check(&scenario.initial.check),
            line: tirbase_pos::LineItem::new(
                LineItemId::new(
                    &scenario
                        .initial
                        .split
                        .as_ref()
                        .expect("split state")
                        .line_item,
                )
                .expect("line id"),
                "Bill",
                Quantity::from_units(1).expect("quantity"),
                money(scenario, scenario.initial.check_total_minor),
            )
            .expect("line item"),
            at: ts(2),
        }),
    );
    for op in [create, line] {
        a.apply(op.clone()).expect("seed a");
        b.apply(op).expect("seed b");
    }
    (a, b)
}

fn run_split(scenario: &PosScenario) -> (Vec<String>, BTreeMap<String, String>) {
    let (mut a, mut b) = split_seed(scenario);
    let source = check(&scenario.initial.check);
    let before = a
        .check(&source)
        .expect("source check")
        .totals()
        .expect("totals");
    let order = OrderId::new("order-split").expect("order id");

    for command in &scenario.commands {
        assert_eq!(command.kind, "split_check");
        let op = wrap(
            &command.id,
            &order,
            &command.actor,
            command.lamport.expect("split lamport"),
            command.at_ms,
            BookOpKind::SplitCheck {
                source_check_id: source.clone(),
                target_check_id: check(command.target_check.as_deref().expect("split target")),
                line_item_ids: vec![LineItemId::new(
                    command.line_item.as_deref().expect("split line"),
                )
                .expect("line id")],
                tip_to_target: Money::zero(currency(scenario)),
                payment_allocations: Vec::new(),
            },
        );
        let book = if command.actor == scenario.initial.terminal {
            &mut a
        } else {
            &mut b
        };
        book.apply(op).expect("apply split");
    }

    a.merge(&b).expect("merge b into a");
    b.merge(&a).expect("merge a into b");
    assert_eq!(a, b, "split replicas must converge");

    let mut permits = Vec::new();
    let mut winner = String::new();
    for command in &scenario.commands {
        let rejected = a
            .rejected_operations()
            .contains_key(&OperationId::new(&command.id).expect("operation id"));
        let target = command.target_check.as_deref().expect("split target");
        if rejected || a.check(&check(target)).is_none() {
            permits.push("loser".to_string());
        } else {
            permits.push("winner".to_string());
            winner = command.actor.clone();
        }
    }

    let after_source = a
        .check(&source)
        .expect("source check")
        .totals()
        .expect("totals");
    let target_a = a
        .check(&check(
            &scenario
                .initial
                .split
                .as_ref()
                .expect("split state")
                .target_a,
        ))
        .expect("winning target");
    let target_a_totals = target_a.totals().expect("target totals");
    let target_b = check(
        &scenario
            .initial
            .split
            .as_ref()
            .expect("split state")
            .target_b,
    );
    let conserved = after_source
        .subtotal
        .checked_add(target_a_totals.subtotal)
        .expect("sum subtotals")
        == before.subtotal;

    let mut ledger = BTreeMap::new();
    ledger.insert("conserved".to_string(), conserved.to_string());
    ledger.insert(
        "rejected_operations".to_string(),
        a.rejected_operations().len().to_string(),
    );
    ledger.insert(
        "source_total_minor".to_string(),
        after_source.subtotal.minor().to_string(),
    );
    ledger.insert(
        "target_a_total_minor".to_string(),
        target_a_totals.subtotal.minor().to_string(),
    );
    ledger.insert(
        "target_b_exists".to_string(),
        a.check(&target_b).is_some().to_string(),
    );
    ledger.insert("winner".to_string(), winner);
    (permits, ledger)
}

fn run_price(scenario: &PosScenario) -> (Vec<String>, BTreeMap<String, String>) {
    let pricing = scenario.initial.pricing.as_ref().expect("pricing state");
    let c = currency(scenario);
    let jurisdiction = JurisdictionId::new("jurisdiction-1").expect("jurisdiction");
    let item = CatalogItem::new(
        tirbase_pos::CatalogItemId::new(&pricing.item).expect("item id"),
        &pricing.item_name,
    )
    .expect("catalog item");
    let item_id = item.id().clone();
    let tax_rate = Rate::from_ppm(pricing.tax_rate_ppm).expect("tax rate");

    let mut store = VersionStore::new();
    let old_catalog = CatalogVersion::new(
        CatalogVersionId::new("catalog-v1").expect("catalog id"),
        EffectiveWindow::new(ts(0), Some(ts(pricing.new_effective_ms))).expect("window"),
        vec![item.clone()],
        Vec::new(),
    )
    .expect("old catalog");
    let new_catalog = CatalogVersion::new(
        CatalogVersionId::new("catalog-v2").expect("catalog id"),
        EffectiveWindow::new(ts(pricing.new_effective_ms), None).expect("window"),
        vec![item],
        Vec::new(),
    )
    .expect("new catalog");
    let mut old_prices = BTreeMap::new();
    old_prices.insert(item_id.clone(), money(scenario, pricing.old_price_minor));
    let old_book = PriceBookVersion::new(
        PriceBookVersionId::new(&pricing.old_version).expect("price id"),
        EffectiveWindow::new(ts(0), Some(ts(pricing.new_effective_ms))).expect("window"),
        c,
        old_prices,
        BTreeMap::new(),
    )
    .expect("old price book");
    let tax = TaxTableVersion::new(
        TaxTableVersionId::new("tax-v1").expect("tax id"),
        EffectiveWindow::new(ts(0), None).expect("window"),
        jurisdiction.clone(),
        vec![TaxRule::new(TaxApplicability::All, tax_rate).expect("tax rule")],
    )
    .expect("tax table");
    store
        .publish_catalog(old_catalog, employee(&scenario.initial.operator), ts(0))
        .expect("publish old catalog");
    store
        .publish_price_book(old_book, employee(&scenario.initial.operator), ts(0))
        .expect("publish old prices");
    store
        .publish_tax_table(tax, employee(&scenario.initial.operator), ts(0))
        .expect("publish tax");
    store
        .publish_catalog(new_catalog, employee(&scenario.initial.operator), ts(1))
        .expect("publish new catalog");

    let org = organization(scenario);
    let mut totals_by_pin: BTreeMap<String, i64> = BTreeMap::new();
    let mut permits = Vec::new();
    for command in &scenario.commands {
        match command.kind.as_str() {
            "publish_price" => {
                let version = PriceBookVersionId::new(&pricing.new_version).expect("price id");
                let mut prices = BTreeMap::new();
                prices.insert(
                    item_id.clone(),
                    money(scenario, command.amount_minor.expect("new price")),
                );
                let book = PriceBookVersion::new(
                    version,
                    EffectiveWindow::new(ts(command.effective_ms.expect("effective time")), None)
                        .expect("window"),
                    c,
                    prices,
                    BTreeMap::new(),
                )
                .expect("published price book");
                store
                    .publish_price_book(
                        book,
                        employee(&scenario.initial.operator),
                        ts(command.at_ms),
                    )
                    .expect("publish new price book");
                permits.push("accepted".to_string());
            }
            "close_check" => {
                let pin = store
                    .pin_at(ts(command.at_ms), c, &jurisdiction)
                    .expect("pin versions");
                let snapshot = store.snapshot(&pin).expect("price snapshot");
                let order = Order::open_pinned(
                    OrderId::new(format!("order-{}", command.at_ms)).expect("order id"),
                    Ownership::new(
                        StoreId::new("store-1").expect("store id"),
                        terminal(&scenario.initial.terminal),
                        employee(&scenario.initial.operator),
                        None,
                    ),
                    &org,
                    ts(command.at_ms),
                    pin.clone(),
                )
                .expect("pinned order");
                let check_id = CheckId::new(format!("check-{}", command.at_ms)).expect("check id");
                let mut order = order;
                order
                    .apply(OrderCommand::CreateCheck {
                        operation_id: OperationId::new(format!("create-{}", command.at_ms))
                            .expect("operation id"),
                        check_id: check_id.clone(),
                        currency: c,
                        rounding: tirbase_pos::RoundingMode::HalfAwayFromZero,
                        at: ts(command.at_ms),
                    })
                    .expect("create check");
                let line = snapshot
                    .line_item(
                        LineItemId::new(format!("line-{}", command.at_ms)).expect("line id"),
                        &item_id,
                        Quantity::from_units(1).expect("quantity"),
                        &[],
                    )
                    .expect("priced line");
                order
                    .apply(OrderCommand::AddLineItem {
                        operation_id: OperationId::new(format!("line-{}", command.at_ms))
                            .expect("operation id"),
                        check_id: check_id.clone(),
                        line,
                        at: ts(command.at_ms + 1),
                    })
                    .expect("add line");
                let due = order
                    .check(&check_id)
                    .expect("check")
                    .totals()
                    .expect("totals")
                    .amount_due;
                order
                    .apply(OrderCommand::LinkPayment {
                        operation_id: OperationId::new(format!("pay-{}", command.at_ms))
                            .expect("operation id"),
                        check_id: check_id.clone(),
                        payment: tirbase_pos::PaymentLink::captured(
                            PaymentId::new(format!("pay-{}", command.at_ms)).expect("payment id"),
                            PaymentMethod::Cash,
                            due,
                        )
                        .expect("payment link"),
                        at: ts(command.at_ms + 2),
                    })
                    .expect("link payment");
                order
                    .apply(OrderCommand::CloseCheck {
                        operation_id: OperationId::new(format!("close-{}", command.at_ms))
                            .expect("operation id"),
                        check_id: check_id.clone(),
                        at: ts(command.at_ms + 3),
                    })
                    .expect("close check");
                let totals = order
                    .check(&check_id)
                    .expect("closed check")
                    .totals()
                    .expect("closed totals");
                totals_by_pin.insert(
                    pin.price_book().as_str().to_string(),
                    totals.grand_total.minor(),
                );
                permits.push("accepted".to_string());
            }
            other => panic!("unexpected price command '{other}'"),
        }
    }

    let old_pin = pricing.old_version.clone();
    let new_pin = pricing.new_version.clone();
    let old_total = *totals_by_pin
        .get(&old_pin)
        .expect("old-price check must have closed");
    let new_total = *totals_by_pin
        .get(&new_pin)
        .expect("new-price check must have closed");
    let mut ledger = BTreeMap::new();
    ledger.insert("closed_new_minor".to_string(), new_total.to_string());
    ledger.insert("closed_old_minor".to_string(), old_total.to_string());
    ledger.insert("new_pin".to_string(), new_pin);
    ledger.insert("old_pin".to_string(), old_pin);
    ledger.insert(
        "unchanged".to_string(),
        (old_total == pricing.old_price_minor).to_string(),
    );
    ledger.insert(
        "versions".to_string(),
        store.price_books().count().to_string(),
    );
    (permits, ledger)
}

fn run_kds(scenario: &PosScenario) -> (Vec<String>, BTreeMap<String, String>) {
    let kds = scenario.initial.kds.as_ref().expect("KDS state");
    let station = Station::from_code(&kds.station).expect("station");
    let ticket = KdsTicket::new(
        KdsTicketId::new(&kds.ticket).expect("ticket id"),
        OrderId::new(&kds.order).expect("order id"),
        check(&kds.check),
        kds.sequence,
        vec![KdsLine::new(
            LineItemId::new(&kds.line).expect("line id"),
            &kds.name,
            Quantity::from_thousandths(kds.quantity_thousandths).expect("quantity"),
            station,
            LineStatus::Queued,
        )
        .expect("KDS line")],
    )
    .expect("KDS ticket");

    let mut endpoint = KdsEndpoint::with_defaults(SimulatedKds::new()).expect("KDS endpoint");
    let mut permits = Vec::new();
    for command in &scenario.commands {
        assert_eq!(command.kind, "kds_submit");
        match endpoint.submit(&ticket).expect("KDS submit") {
            KdsSubmitOutcome::Created { .. } => permits.push("accepted".to_string()),
            KdsSubmitOutcome::Duplicate => permits.push("deduplicated".to_string()),
        }
    }
    let sends = endpoint.sends();
    let retries = endpoint.retries();
    let display = endpoint.into_transport();
    let mut ledger = BTreeMap::new();
    ledger.insert(
        "accepted_tickets".to_string(),
        display.tickets().len().to_string(),
    );
    ledger.insert(
        "duplicate_frames".to_string(),
        display.duplicate_frames().to_string(),
    );
    ledger.insert("frames".to_string(), display.frames().len().to_string());
    ledger.insert("retries".to_string(), retries.to_string());
    ledger.insert("sends".to_string(), sends.to_string());
    (permits, ledger)
}

fn run_scenario(scenario: &PosScenario) -> (Vec<String>, BTreeMap<String, String>) {
    match scenario.id.as_str() {
        "double_charge_on_reconnect" | "replayed_refund" | "void_after_capture" => {
            run_payment(scenario)
        }
        "split_bill_conflict" => run_split(scenario),
        "offline_price_change" => run_price(scenario),
        "duplicate_kds_ticket" => run_kds(scenario),
        other => panic!("no runner for scenario '{other}'"),
    }
}

fn assert_scenario(pack: &PosPack, scenario: &PosScenario) {
    let expected = pack.outcome(&scenario.id).expect("expected outcome");
    let (permits, ledger) = run_scenario(scenario);
    assert_eq!(
        permits, expected.permit,
        "scenario '{}' permits diverged from expected/outcomes.toml",
        scenario.id
    );
    let observed: Vec<String> = ledger
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    assert_eq!(
        observed, expected.ledger,
        "scenario '{}' ledger diverged from expected/outcomes.toml",
        scenario.id
    );
    println!(
        "PASS {} permit=[{}] ledger=[{}] invariant={}",
        scenario.id,
        permits.join(", "),
        observed.join(" "),
        scenario.invariant
    );
}

fn assert_bitmap(commands: &[PosCommand]) -> bool {
    commands.iter().all(|command| {
        command.expect == "accepted"
            || command.expect == "replayed"
            || command.expect == "denied"
            || command.expect == "winner"
            || command.expect == "loser"
            || command.expect == "deduplicated"
    })
}

#[test]
fn all_offline_pos_scenarios_are_defended() {
    let pack = pack();
    for required in tirbase_demo::POS_PACK_REQUIRED_SCENARIOS {
        let scenario = pack
            .scenario(required)
            .unwrap_or_else(|| panic!("missing scenario '{required}'"));
        assert!(assert_bitmap(&scenario.commands));
        assert_scenario(&pack, scenario);
    }
}

#[test]
fn reconnect_never_records_a_second_capture() {
    let pack = pack();
    let scenario = pack
        .scenario("double_charge_on_reconnect")
        .expect("scenario");
    let (_, ledger) = run_payment(scenario);
    assert_eq!(ledger.get("capture_count").map(String::as_str), Some("1"));
    assert_eq!(
        ledger.get("captured_minor").map(String::as_str),
        Some("2400")
    );
    assert_eq!(
        ledger.get("intent_status").map(String::as_str),
        Some("captured")
    );
}

#[test]
fn replayed_refund_and_void_are_denied() {
    let pack = pack();
    for id in ["replayed_refund", "void_after_capture"] {
        let scenario = pack.scenario(id).expect("scenario");
        let (permits, ledger) = match id {
            "replayed_refund" => run_payment(scenario),
            "void_after_capture" => run_payment(scenario),
            _ => unreachable!(),
        };
        assert!(
            permits.iter().any(|permit| permit == "replayed"),
            "{id} must observe a replay"
        );
        assert!(
            permits.iter().any(|permit| permit == "denied"),
            "{id} must deny a fresh nonce"
        );
        let count_key = if id == "replayed_refund" {
            "refund_count"
        } else {
            "void_count"
        };
        assert_eq!(
            ledger.get(count_key).map(String::as_str),
            Some("1"),
            "{id} must move its counter once"
        );
    }
}

#[test]
fn split_conflict_resolves_deterministically() {
    let pack = pack();
    let scenario = pack.scenario("split_bill_conflict").expect("scenario");
    let (first_permits, first_ledger) = run_split(scenario);
    let (second_permits, second_ledger) = run_split(scenario);
    assert_eq!(first_permits, second_permits);
    assert_eq!(first_ledger, second_ledger);
    assert_eq!(
        first_ledger.get("winner").map(String::as_str),
        Some("till-1")
    );
    assert_eq!(
        first_ledger.get("conserved").map(String::as_str),
        Some("true")
    );
}
