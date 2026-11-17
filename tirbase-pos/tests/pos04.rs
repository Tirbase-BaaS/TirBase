// SPDX-License-Identifier: AGPL-3.0-only

//! POS-04 behavioural tests: effective windows, immutable versions, pinning,
//! tax applicability, links, rollback audit and closed-check preservation.

use std::collections::BTreeMap;

use tirbase_pos::{
    BookOp, BookOpKind, CatalogItem, CatalogItemId, CatalogModifier, CatalogVersion,
    CatalogVersionId, CheckId, Currency, EffectiveWindow, Employee, EmployeeId, EmployeeRole,
    JurisdictionId, LineItemId, MenuId, ModifierId, Money, OperationId, Order, OrderCommand,
    OrderId, Organization, Ownership, PaymentId, PaymentLink, PaymentMethod, PosBook, PosError,
    PriceBookVersion, PriceBookVersionId, Quantity, Rate, RecipeComponentId, RecipeLink,
    RoundingMode, Store, StoreId, TaxApplicability, TaxRule, TaxTableVersion, TaxTableVersionId,
    Terminal, TerminalId, Timestamp, VersionAuditEventKind, VersionPin, VersionRef, VersionStore,
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

fn window(from: i64, until: Option<i64>) -> EffectiveWindow {
    EffectiveWindow::new(ts(from), until.map(ts)).unwrap()
}

fn rate(ppm: i32) -> Rate {
    Rate::from_ppm(ppm).unwrap()
}

fn employee(value: &str) -> EmployeeId {
    EmployeeId::new(value).unwrap()
}

fn catalog_id(value: &str) -> CatalogVersionId {
    CatalogVersionId::new(value).unwrap()
}

fn price_id(value: &str) -> PriceBookVersionId {
    PriceBookVersionId::new(value).unwrap()
}

fn tax_id(value: &str) -> TaxTableVersionId {
    TaxTableVersionId::new(value).unwrap()
}

fn item_id(value: &str) -> CatalogItemId {
    CatalogItemId::new(value).unwrap()
}

fn modifier_id(value: &str) -> ModifierId {
    ModifierId::new(value).unwrap()
}

fn menu_id(value: &str) -> MenuId {
    MenuId::new(value).unwrap()
}

fn recipe_id(value: &str) -> RecipeComponentId {
    RecipeComponentId::new(value).unwrap()
}

fn jurisdiction(value: &str) -> JurisdictionId {
    JurisdictionId::new(value).unwrap()
}

fn coffee() -> CatalogItem {
    CatalogItem::new(item_id("coffee"), "Coffee")
        .unwrap()
        .with_sku("SKU-COFFEE")
        .unwrap()
        .with_category("drink")
        .unwrap()
        .with_menu(menu_id("breakfast"))
        .with_modifier(modifier_id("oat-milk"))
        .with_recipe_link(RecipeLink::new(
            recipe_id("bean"),
            Quantity::from_units(1).unwrap(),
        ))
}

fn tea() -> CatalogItem {
    CatalogItem::new(item_id("tea"), "Tea")
        .unwrap()
        .with_category("drink")
        .unwrap()
}

fn oat_milk() -> CatalogModifier {
    CatalogModifier::new(modifier_id("oat-milk"), "Oat milk").unwrap()
}

fn catalog(version: &str, effective: EffectiveWindow) -> CatalogVersion {
    CatalogVersion::new(
        catalog_id(version),
        effective,
        vec![coffee(), tea()],
        vec![oat_milk()],
    )
    .unwrap()
}

fn price_book(
    version: &str,
    effective: EffectiveWindow,
    coffee_minor: i64,
    oat_delta: i64,
) -> PriceBookVersion {
    PriceBookVersion::new(
        price_id(version),
        effective,
        usd(),
        BTreeMap::from([
            (item_id("coffee"), money(coffee_minor)),
            (item_id("tea"), money(200)),
        ]),
        BTreeMap::from([(modifier_id("oat-milk"), money(oat_delta))]),
    )
    .unwrap()
}

fn tax_table(version: &str, effective: EffectiveWindow, coffee_ppm: i32) -> TaxTableVersion {
    TaxTableVersion::new(
        tax_id(version),
        effective,
        jurisdiction("US-CA"),
        vec![
            TaxRule::new(TaxApplicability::All, rate(70_000)).unwrap(),
            TaxRule::new(TaxApplicability::Category("drink".into()), rate(85_000)).unwrap(),
            TaxRule::new(TaxApplicability::Item(item_id("coffee")), rate(coffee_ppm)).unwrap(),
        ],
    )
    .unwrap()
}

fn seed_v1(store: &mut VersionStore) {
    store
        .publish_catalog(
            catalog("catalog-v1", window(0, Some(10))),
            employee("emp-1"),
            ts(0),
        )
        .unwrap();
    store
        .publish_price_book(
            price_book("price-v1", window(0, Some(10)), 300, 50),
            employee("emp-1"),
            ts(0),
        )
        .unwrap();
    store
        .publish_tax_table(
            tax_table("tax-v1", window(0, Some(10)), 90_000),
            employee("emp-1"),
            ts(0),
        )
        .unwrap();
}

fn seed_v2(store: &mut VersionStore) {
    store
        .publish_catalog(
            catalog("catalog-v2", window(10, Some(20))),
            employee("emp-1"),
            ts(10),
        )
        .unwrap();
    store
        .publish_price_book(
            price_book("price-v2", window(10, Some(20)), 400, 75),
            employee("emp-1"),
            ts(10),
        )
        .unwrap();
    store
        .publish_tax_table(
            tax_table("tax-v2", window(10, Some(20)), 100_000),
            employee("emp-1"),
            ts(10),
        )
        .unwrap();
}

fn seed_all(store: &mut VersionStore) {
    seed_v1(store);
    seed_v2(store);
}

fn organization() -> (Organization, Ownership) {
    let store_id = StoreId::new("store-1").unwrap();
    let mut org = Organization::new();
    org.add_store(Store::new(store_id.clone(), "One").unwrap())
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
            employee("emp-1"),
            store_id.clone(),
            "Ada",
            vec![EmployeeRole::Cashier],
        )
        .unwrap(),
    )
    .unwrap();
    let ownership = Ownership::new(
        store_id,
        TerminalId::new("till-1").unwrap(),
        employee("emp-1"),
        None,
    );
    (org, ownership)
}

fn create_check(order: &mut Order, id: &str, at: i64) {
    order
        .apply(OrderCommand::CreateCheck {
            operation_id: OperationId::new(format!("create-{id}")).unwrap(),
            check_id: CheckId::new(id).unwrap(),
            currency: usd(),
            rounding: RoundingMode::HalfAwayFromZero,
            at: ts(at),
        })
        .unwrap();
}

fn add_line(order: &mut Order, check: &str, id: &str, line: tirbase_pos::LineItem, at: i64) {
    order
        .apply(OrderCommand::AddLineItem {
            operation_id: OperationId::new(format!("add-{id}")).unwrap(),
            check_id: CheckId::new(check).unwrap(),
            line,
            at: ts(at),
        })
        .unwrap();
}

fn pay_and_close(order: &mut Order, check: &str, at: i64) {
    let total = order
        .check(&CheckId::new(check).unwrap())
        .unwrap()
        .totals()
        .unwrap()
        .grand_total;
    order
        .apply(OrderCommand::LinkPayment {
            operation_id: OperationId::new(format!("pay-{check}")).unwrap(),
            check_id: CheckId::new(check).unwrap(),
            payment: PaymentLink::captured(
                PaymentId::new(format!("payment-{check}")).unwrap(),
                PaymentMethod::Cash,
                total,
            )
            .unwrap(),
            at: ts(at),
        })
        .unwrap();
    order
        .apply(OrderCommand::CloseCheck {
            operation_id: OperationId::new(format!("close-{check}")).unwrap(),
            check_id: CheckId::new(check).unwrap(),
            at: ts(at + 1),
        })
        .unwrap();
}

#[test]
fn closed_check_keeps_original_price_and_tax_after_a_price_change() {
    let mut store = VersionStore::new();
    seed_v1(&mut store);
    let pin = store.pin_at(ts(0), usd(), &jurisdiction("US-CA")).unwrap();
    let (org, ownership) = organization();
    let mut order = Order::open_pinned(
        OrderId::new("order-1").unwrap(),
        ownership,
        &org,
        ts(0),
        pin.clone(),
    )
    .unwrap();
    assert_eq!(order.version_pin(), Some(&pin));

    let snapshot = order.priced_catalog(&store).unwrap();
    let coffee_line = snapshot
        .line_item(
            LineItemId::new("line-1").unwrap(),
            &item_id("coffee"),
            Quantity::from_units(1).unwrap(),
            &[modifier_id("oat-milk")],
        )
        .unwrap();
    assert_eq!(coffee_line.unit_price(), money(300));
    assert_eq!(coffee_line.tax_rate(), Some(rate(90_000)));

    create_check(&mut order, "check-1", 1);
    add_line(&mut order, "check-1", "line-1", coffee_line, 2);
    pay_and_close(&mut order, "check-1", 3);

    let closed = order.check(&CheckId::new("check-1").unwrap()).unwrap();
    let original_totals = closed.totals().unwrap();
    assert_eq!(original_totals.subtotal, money(350));
    assert_eq!(original_totals.tax_total, money(32));
    assert_eq!(original_totals.grand_total, money(382));
    assert!(closed.sealed_totals_are_consistent().unwrap());

    // The offline price/tax change is a new version with a later window.
    seed_v2(&mut store);
    let closed_after_change = order
        .check(&CheckId::new("check-1").unwrap())
        .unwrap()
        .totals()
        .unwrap();
    assert_eq!(closed_after_change, original_totals);

    // The old order still prices from its pin, not from the new effective
    // versions, even for a new check opened later.
    let old_snapshot = order.priced_catalog(&store).unwrap();
    let old_line = old_snapshot
        .line_item(
            LineItemId::new("line-2").unwrap(),
            &item_id("coffee"),
            Quantity::from_units(1).unwrap(),
            &[],
        )
        .unwrap();
    assert_eq!(old_line.unit_price(), money(300));
    assert_eq!(old_line.tax_rate(), Some(rate(90_000)));
    create_check(&mut order, "check-2", 20);
    add_line(&mut order, "check-2", "line-2", old_line, 21);
    assert_eq!(
        order
            .check(&CheckId::new("check-2").unwrap())
            .unwrap()
            .totals()
            .unwrap()
            .grand_total,
        money(327)
    );

    // A new order at the new effective time sees the new price and tax.
    let new_pin = store.pin_at(ts(10), usd(), &jurisdiction("US-CA")).unwrap();
    let (org, ownership) = organization();
    let mut new_order = Order::open_pinned(
        OrderId::new("order-2").unwrap(),
        ownership,
        &org,
        ts(10),
        new_pin,
    )
    .unwrap();
    let new_snapshot = new_order.priced_catalog(&store).unwrap();
    let new_line = new_snapshot
        .line_item(
            LineItemId::new("line-3").unwrap(),
            &item_id("coffee"),
            Quantity::from_units(1).unwrap(),
            &[modifier_id("oat-milk")],
        )
        .unwrap();
    assert_eq!(new_line.unit_price(), money(400));
    assert_eq!(new_line.tax_rate(), Some(rate(100_000)));
    create_check(&mut new_order, "check-3", 11);
    add_line(&mut new_order, "check-3", "line-3", new_line, 12);
    assert_eq!(
        new_order
            .check(&CheckId::new("check-3").unwrap())
            .unwrap()
            .totals()
            .unwrap()
            .grand_total,
        money(523)
    );
}

#[test]
fn effective_windows_and_overlap_scopes_are_enforced() {
    let early = window(0, Some(10));
    let later = window(10, Some(20));
    assert!(early.contains(ts(0)));
    assert!(!early.contains(ts(10)));
    assert!(!early.overlaps(later), "adjacent windows do not overlap");
    assert!(early.overlaps(window(9, None)));
    assert_eq!(
        EffectiveWindow::new(ts(10), Some(ts(10))),
        Err(PosError::InvalidEffectiveWindow)
    );

    let mut store = VersionStore::new();
    store
        .publish_catalog(catalog("catalog-v1", early), employee("emp-1"), ts(0))
        .unwrap();
    store
        .publish_catalog(catalog("catalog-v2", later), employee("emp-1"), ts(10))
        .unwrap();
    assert_eq!(
        store
            .publish_catalog(
                catalog("catalog-overlap", window(5, Some(15))),
                employee("emp-1"),
                ts(5)
            )
            .unwrap_err(),
        PosError::OverlappingEffectiveWindow {
            existing: "catalog-v1".into()
        }
    );

    store
        .publish_price_book(
            price_book("price-v1", early, 300, 50),
            employee("emp-1"),
            ts(0),
        )
        .unwrap();
    store
        .publish_price_book(
            price_book("price-v2", later, 400, 75),
            employee("emp-1"),
            ts(10),
        )
        .unwrap();
    assert_eq!(
        store
            .publish_price_book(
                price_book("price-overlap", window(5, Some(15)), 350, 60),
                employee("emp-1"),
                ts(5)
            )
            .unwrap_err(),
        PosError::OverlappingEffectiveWindow {
            existing: "price-v1".into()
        }
    );
    // A different currency is a separate scope and may overlap in time.
    let eur_book = PriceBookVersion::new(
        price_id("price-eur"),
        early,
        eur(),
        BTreeMap::from([(item_id("coffee"), Money::new(eur(), 280))]),
        BTreeMap::new(),
    )
    .unwrap();
    store
        .publish_price_book(eur_book, employee("emp-1"), ts(0))
        .unwrap();

    store
        .publish_tax_table(tax_table("tax-v1", early, 90_000), employee("emp-1"), ts(0))
        .unwrap();
    store
        .publish_tax_table(
            tax_table("tax-v2", later, 100_000),
            employee("emp-1"),
            ts(10),
        )
        .unwrap();
    assert_eq!(
        store
            .publish_tax_table(
                tax_table("tax-overlap", window(5, Some(15)), 95_000),
                employee("emp-1"),
                ts(5)
            )
            .unwrap_err(),
        PosError::OverlappingEffectiveWindow {
            existing: "tax-v1".into()
        }
    );
    // A different jurisdiction is a separate scope.
    let ny = TaxTableVersion::new(
        tax_id("tax-ny"),
        early,
        jurisdiction("US-NY"),
        vec![TaxRule::new(TaxApplicability::All, rate(80_000)).unwrap()],
    )
    .unwrap();
    store
        .publish_tax_table(ny, employee("emp-1"), ts(0))
        .unwrap();

    assert_eq!(
        store.effective_catalog(ts(0)).unwrap().id(),
        &catalog_id("catalog-v1")
    );
    assert_eq!(
        store.effective_catalog(ts(9)).unwrap().id(),
        &catalog_id("catalog-v1")
    );
    assert_eq!(
        store.effective_catalog(ts(10)).unwrap().id(),
        &catalog_id("catalog-v2")
    );
    assert_eq!(
        store.effective_catalog(ts(20)),
        Err(PosError::NoEffectiveVersion("catalog"))
    );
    assert_eq!(
        store.effective_price_book(eur(), ts(0)).unwrap().id(),
        &price_id("price-eur")
    );
    let pin = store.pin_at(ts(0), usd(), &jurisdiction("US-CA")).unwrap();
    assert_eq!(pin.catalog(), &catalog_id("catalog-v1"));
    assert_eq!(pin.price_book(), &price_id("price-v1"));
    assert_eq!(pin.tax_table(), &tax_id("tax-v1"));
}

#[test]
fn catalog_links_and_tax_applicability_are_resolved() {
    let coffee = coffee();
    assert_eq!(coffee.sku(), Some("SKU-COFFEE"));
    assert_eq!(coffee.category(), Some("drink"));
    assert_eq!(coffee.menu_links()[0].menu_id(), &menu_id("breakfast"));
    assert_eq!(coffee.modifier_ids(), &[modifier_id("oat-milk")]);
    assert_eq!(coffee.recipe_links()[0].component_id(), &recipe_id("bean"));
    assert_eq!(
        coffee.recipe_links()[0].quantity(),
        Quantity::from_units(1).unwrap()
    );

    let tax = tax_table("tax-links", window(0, Some(10)), 90_000);
    assert_eq!(tax.rate_for(&coffee), Some(rate(90_000)));
    let tea = tea();
    assert_eq!(tax.rate_for(&tea), Some(rate(85_000)));
    let food = CatalogItem::new(item_id("sandwich"), "Sandwich")
        .unwrap()
        .with_category("food")
        .unwrap();
    assert_eq!(tax.rate_for(&food), Some(rate(70_000)));

    let mut store = VersionStore::new();
    store
        .publish_catalog(
            catalog("catalog-links", window(0, Some(10))),
            employee("emp-1"),
            ts(0),
        )
        .unwrap();
    store
        .publish_price_book(
            price_book("price-links", window(0, Some(10)), 300, 50),
            employee("emp-1"),
            ts(0),
        )
        .unwrap();
    store
        .publish_tax_table(tax, employee("emp-1"), ts(0))
        .unwrap();
    let pin = store.pin_at(ts(0), usd(), &jurisdiction("US-CA")).unwrap();
    let snapshot = store.snapshot(&pin).unwrap();
    let plain = snapshot
        .line_item(
            LineItemId::new("plain").unwrap(),
            &item_id("coffee"),
            Quantity::from_units(1).unwrap(),
            &[],
        )
        .unwrap();
    assert_eq!(plain.unit_price(), money(300));
    assert_eq!(plain.tax_rate(), Some(rate(90_000)));
    let with_oat = snapshot
        .line_item(
            LineItemId::new("oat").unwrap(),
            &item_id("coffee"),
            Quantity::from_units(1).unwrap(),
            &[modifier_id("oat-milk")],
        )
        .unwrap();
    assert_eq!(with_oat.effective_unit_price().unwrap(), money(350));
    assert_eq!(
        with_oat
            .compute(RoundingMode::HalfAwayFromZero)
            .unwrap()
            .tax,
        money(32)
    );
    // The modifier exists, but Tea does not link to it.
    assert_eq!(
        snapshot
            .line_item(
                LineItemId::new("tea-oat").unwrap(),
                &item_id("tea"),
                Quantity::from_units(1).unwrap(),
                &[modifier_id("oat-milk")]
            )
            .unwrap_err(),
        PosError::ModifierNotApplicable {
            item: item_id("tea"),
            modifier: modifier_id("oat-milk"),
        }
    );

    // A link to a modifier that is absent from the version is rejected.
    let dangling = CatalogItem::new(item_id("dangling"), "Dangling")
        .unwrap()
        .with_modifier(modifier_id("missing"));
    assert_eq!(
        CatalogVersion::new(
            catalog_id("dangling-catalog"),
            window(0, Some(10)),
            vec![dangling],
            vec![]
        )
        .unwrap_err(),
        PosError::UnknownCatalogModifier(modifier_id("missing"))
    );

    // Duplicate applicability is ambiguous and rejected.
    assert_eq!(
        TaxTableVersion::new(
            tax_id("duplicate-tax"),
            window(0, Some(10)),
            jurisdiction("US-CA"),
            vec![
                TaxRule::new(TaxApplicability::All, rate(70_000)).unwrap(),
                TaxRule::new(TaxApplicability::All, rate(80_000)).unwrap()
            ]
        )
        .unwrap_err(),
        PosError::AmbiguousTaxRule
    );
}

#[test]
fn rollback_reissues_old_content_and_is_auditable() {
    let mut store = VersionStore::new();
    seed_all(&mut store);
    let pin_before = store.pin_at(ts(0), usd(), &jurisdiction("US-CA")).unwrap();
    let snapshot_before = store.snapshot(&pin_before).unwrap();
    assert_eq!(
        snapshot_before.price_book().item_price(&item_id("coffee")),
        Some(money(300))
    );

    store
        .rollback_catalog(
            catalog_id("catalog-rollback"),
            &catalog_id("catalog-v1"),
            window(20, Some(30)),
            "revert menu after bad publish",
            employee("emp-1"),
            ts(20),
        )
        .unwrap();
    store
        .rollback_price_book(
            price_id("price-rollback"),
            &price_id("price-v1"),
            window(20, Some(30)),
            "revert price after bad publish",
            employee("emp-1"),
            ts(20),
        )
        .unwrap();
    store
        .rollback_tax_table(
            tax_id("tax-rollback"),
            &tax_id("tax-v1"),
            window(20, Some(30)),
            "revert tax after bad publish",
            employee("emp-1"),
            ts(20),
        )
        .unwrap();

    assert_eq!(
        store.effective_catalog(ts(20)).unwrap().id(),
        &catalog_id("catalog-rollback")
    );
    assert_eq!(
        store
            .effective_price_book(usd(), ts(20))
            .unwrap()
            .item_price(&item_id("coffee")),
        Some(money(300))
    );
    assert_eq!(
        store
            .effective_tax_table(&jurisdiction("US-CA"), ts(20))
            .unwrap()
            .id(),
        &tax_id("tax-rollback")
    );

    let last = store.audit_events().last().unwrap();
    assert_eq!(last.sequence as usize, store.audit_events().len());
    assert_eq!(last.actor, employee("emp-1"));
    assert_eq!(
        last.kind,
        VersionAuditEventKind::RolledBack {
            replacement: VersionRef::TaxTable(tax_id("tax-rollback")),
            reverted_to: VersionRef::TaxTable(tax_id("tax-v1")),
            reason: "revert tax after bad publish".into(),
        }
    );
    assert_eq!(
        store.audit_events()[6].kind,
        VersionAuditEventKind::RolledBack {
            replacement: VersionRef::Catalog(catalog_id("catalog-rollback")),
            reverted_to: VersionRef::Catalog(catalog_id("catalog-v1")),
            reason: "revert menu after bad publish".into(),
        }
    );
    assert_eq!(
        store.audit_events()[7].kind,
        VersionAuditEventKind::RolledBack {
            replacement: VersionRef::PriceBook(price_id("price-rollback")),
            reverted_to: VersionRef::PriceBook(price_id("price-v1")),
            reason: "revert price after bad publish".into(),
        }
    );

    // The old pin is still explainable after the rollback.
    assert_eq!(
        store
            .snapshot(&pin_before)
            .unwrap()
            .price_book()
            .item_price(&item_id("coffee")),
        Some(money(300))
    );

    let audit_len = store.audit_events().len();
    assert_eq!(
        store
            .rollback_price_book(
                price_id("price-overlap-rollback"),
                &price_id("price-v1"),
                window(15, Some(25)),
                "overlaps v2",
                employee("emp-1"),
                ts(15)
            )
            .unwrap_err(),
        PosError::OverlappingEffectiveWindow {
            existing: "price-v2".into()
        }
    );
    assert_eq!(store.audit_events().len(), audit_len);
    assert_eq!(
        store
            .rollback_price_book(
                price_id("price-missing-rollback"),
                &price_id("does-not-exist"),
                window(40, None),
                "missing target",
                employee("emp-1"),
                ts(40)
            )
            .unwrap_err(),
        PosError::VersionNotFound("does-not-exist".into())
    );
    assert_eq!(
        store
            .rollback_price_book(
                price_id("price-blank-rollback"),
                &price_id("price-v1"),
                window(40, None),
                "   ",
                employee("emp-1"),
                ts(40)
            )
            .unwrap_err(),
        PosError::MissingReason
    );
}

#[test]
fn replicated_book_preserves_a_pinned_order_across_rebuilds() {
    let mut store = VersionStore::new();
    seed_v1(&mut store);
    let pin = store.pin_at(ts(0), usd(), &jurisdiction("US-CA")).unwrap();
    let (org, ownership) = organization();
    let mut book = PosBook::new(org);
    let order_id = OrderId::new("order-pinned").unwrap();
    book.add_order_pinned(order_id.clone(), ownership, ts(0), pin.clone())
        .unwrap();
    let check = CheckId::new("check-pinned").unwrap();
    book.apply(BookOp::new(
        OperationId::new("create-pinned").unwrap(),
        order_id.clone(),
        TerminalId::new("till-1").unwrap(),
        1,
        ts(1),
        BookOpKind::Order(OrderCommand::CreateCheck {
            operation_id: OperationId::new("create-pinned").unwrap(),
            check_id: check.clone(),
            currency: usd(),
            rounding: RoundingMode::HalfAwayFromZero,
            at: ts(1),
        }),
    ))
    .unwrap();
    assert_eq!(book.order(&order_id).unwrap().version_pin(), Some(&pin));
    assert!(book.check(&check).is_some());
}

#[test]
fn plain_orders_are_not_pinned_and_cannot_load_a_priced_catalog() {
    let store = VersionStore::new();
    let (org, ownership) = organization();
    let order = Order::open(OrderId::new("order-plain").unwrap(), ownership, &org, ts(0)).unwrap();
    assert_eq!(order.version_pin(), None);
    assert_eq!(order.priced_catalog(&store), Err(PosError::OrderNotPinned));
    assert_eq!(
        VersionPin::new(
            catalog_id("missing-catalog"),
            price_id("missing-price"),
            tax_id("missing-tax")
        ),
        VersionPin::new(
            catalog_id("missing-catalog"),
            price_id("missing-price"),
            tax_id("missing-tax")
        )
    );
}

#[test]
fn missing_item_price_and_modifier_price_are_rejected() {
    let mut store = VersionStore::new();
    seed_v1(&mut store);
    let pin = store.pin_at(ts(0), usd(), &jurisdiction("US-CA")).unwrap();
    let snapshot = store.snapshot(&pin).unwrap();

    let priced = PriceBookVersion::new(
        price_id("price-missing-item"),
        window(10, Some(20)),
        usd(),
        BTreeMap::from([(item_id("tea"), money(200))]),
        BTreeMap::from([(modifier_id("oat-milk"), money(50))]),
    )
    .unwrap();
    store
        .publish_price_book(priced, employee("emp-1"), ts(10))
        .unwrap();
    let missing_pin = VersionPin::new(
        catalog_id("catalog-v1"),
        price_id("price-missing-item"),
        tax_id("tax-v1"),
    );
    let missing = store.snapshot(&missing_pin).unwrap();
    assert_eq!(
        missing
            .line_item(
                LineItemId::new("missing").unwrap(),
                &item_id("coffee"),
                Quantity::from_units(1).unwrap(),
                &[]
            )
            .unwrap_err(),
        PosError::MissingPrice(item_id("coffee"))
    );

    let no_modifier_price = PriceBookVersion::new(
        price_id("price-missing-modifier"),
        window(20, Some(30)),
        usd(),
        BTreeMap::from([(item_id("coffee"), money(300))]),
        BTreeMap::new(),
    )
    .unwrap();
    store
        .publish_price_book(no_modifier_price, employee("emp-1"), ts(20))
        .unwrap();
    let no_modifier_pin = VersionPin::new(
        catalog_id("catalog-v1"),
        price_id("price-missing-modifier"),
        tax_id("tax-v1"),
    );
    let no_modifier = store.snapshot(&no_modifier_pin).unwrap();
    assert_eq!(
        no_modifier
            .line_item(
                LineItemId::new("no-modifier-price").unwrap(),
                &item_id("coffee"),
                Quantity::from_units(1).unwrap(),
                &[modifier_id("oat-milk")]
            )
            .unwrap_err(),
        PosError::MissingModifierPrice(modifier_id("oat-milk"))
    );

    assert_eq!(
        snapshot
            .line_item(
                LineItemId::new("unknown").unwrap(),
                &item_id("unknown"),
                Quantity::from_units(1).unwrap(),
                &[]
            )
            .unwrap_err(),
        PosError::UnknownCatalogItem(item_id("unknown"))
    );
}
