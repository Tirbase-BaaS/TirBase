# POS-04 — Catalog, price book and tax versioning (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-04 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no persistence or terminal connectivity.

**Record ID:** POS-04-CATALOG-0001
**Date (UTC):** 2026-11-16
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Immutable catalog and price-book versions with effective timestamps | `tirbase-pos/src/catalog.rs` |
| 2 | Tax-table versions with jurisdiction and product applicability | `TaxTableVersion`, `TaxRule`, `TaxApplicability` |
| 3 | Orders pin the versions they used | `Order::open_pinned`, `VersionPin`, `PosBook::add_order_pinned` |
| 4 | Offline price change does not retroactively alter closed checks | `PricedCatalog::line_item` + POS-01 sealed totals |
| 5 | Menu, modifier and recipe links | `MenuLink`, `CatalogItem::with_modifier`, `RecipeLink` |
| 6 | Tests for effective dates, overlaps and rollback | `tirbase-pos/tests/pos04.rs`, `tests/pos04_properties.rs` |

Deliberately unchanged from POS-00/POS-01:

- No jurisdiction default, tax-inclusive pricing rule, fiscal module or receipt
  that claims fiscal validity.
- No persistence adapter, network sync, UI, terminal connectivity or currency
  conversion.
- License remains `AGPL-3.0-only`; the crate remains non-production under
  POS-00.

## 2. Version model

All version types are immutable after construction: their maps, windows and
identifiers are private and there are no mutating accessors.

### Catalog version

`CatalogVersion` carries:

- a `CatalogVersionId`;
- an `EffectiveWindow`;
- catalog items keyed by `CatalogItemId`;
- modifier definitions keyed by `ModifierId`.

`CatalogItem` carries a name, optional SKU and category, menu links, modifier
links and recipe links. A modifier link must resolve inside the same catalog
version; a dangling link is rejected at construction.

### Price-book version

`PriceBookVersion` carries:

- a `PriceBookVersionId`;
- an `EffectiveWindow`;
- one currency for the whole version;
- item prices keyed by `CatalogItemId`;
- modifier price deltas keyed by `ModifierId`.

Item prices must be non-negative. Modifier deltas may be negative. Every price
must use the version's currency.

### Tax-table version

`TaxTableVersion` carries:

- a `TaxTableVersionId`;
- an `EffectiveWindow`;
- a `JurisdictionId`;
- a list of `TaxRule`s.

A `TaxRule` combines a `Rate` with `TaxApplicability`:

| Applicability | Meaning |
|---|---|
| `All` | every item in the table's jurisdiction |
| `Category(String)` | items whose catalog category matches |
| `Item(CatalogItemId)` | one exact catalog item |

Resolution precedence is exact item, then category, then all items. A version
may contain all three for different products; the same applicability twice is
rejected as `AmbiguousTaxRule`.

## 3. Effective windows and overlaps

An `EffectiveWindow` is half-open, `[from, until)`. `until: None` means no
scheduled end. An empty or reversed window is rejected with
`InvalidEffectiveWindow`. Adjacent windows such as `[0, 10)` and `[10, 20)` do
not overlap.

`VersionStore` rejects an overlap in the same scope before inserting a version:

| Version kind | Overlap scope |
|---|---|
| Catalog | all catalog versions |
| Price book | same currency |
| Tax table | same jurisdiction |

For example, a USD price book and an EUR price book may cover the same dates, and
a California tax table and a New York tax table may do the same. Two USD price
books covering the same instant are rejected with
`OverlappingEffectiveWindow { existing }`.

`effective_catalog(at)`, `effective_price_book(currency, at)` and
`effective_tax_table(jurisdiction, at)` return the one version containing the
instant, or `NoEffectiveVersion` in a gap.

## 4. Order pinning and pricing

`VersionStore::pin_at(at, currency, jurisdiction)` resolves the three effective
versions and returns a `VersionPin` containing their exact identifiers.
`Order::open_pinned` stores that pin immutably for the order; `PosBook::add_order_pinned`
does the same in the replicated book genesis, and a canonical rebuild preserves
it.

`Order::priced_catalog(&store)` loads the pinned versions. Its
`PricedCatalog::line_item` looks up the item and price, attaches requested
modifiers and their deltas, resolves the tax rate, and returns an ordinary POS-01
`LineItem`. The item price, modifier deltas and tax rate are copied into the line
item.

Menu, modifier and recipe links are metadata: an item's default modifier links
are not silently applied. The caller supplies the modifier ids it wants
explicitly, so an unrequested add-on cannot appear on a bill. A requested
modifier must be linked to the item; an existing modifier that belongs to a
different item is rejected with `ModifierNotApplicable`.

## 5. Closed-check preservation

POS-01 already stores the unit price and tax rate on each line item and seals
line-derived totals when a check is closed or voided. POS-04 therefore does not
rewrite a historical bill when a new price or tax version is published:

1. An order is opened with a pin.
2. A line is priced through that pin and added to the check.
3. The check is paid and closed; POS-01 seals its totals.
4. A later price/tax version is published.
5. The closed check's totals and line values are unchanged.
6. The old order still prices new lines from its old pin.

The closed-check test also verifies the sealed snapshot against a fresh
recomputation (`sealed_totals_are_consistent`).

## 6. Rollback

A rollback does not mutate an older version. `rollback_catalog`,
`rollback_price_book` and `rollback_tax_table`:

1. load the target version;
2. clone its content under a new version id and a caller-supplied effective
   window;
3. reject the new window if it overlaps an existing version in the same scope;
4. append a `VersionAuditEventKind::RolledBack` event containing the replacement
   version, the version reverted to, the reason, the actor and the caller time.

Publication appends `VersionAuditEventKind::Published`. The audit sequence is
dense and ordered. A rollback with a missing target, blank reason or overlapping
window changes nothing and appends nothing. The target version and any order pin
that references it remain valid and readable.

## 7. Acceptance evidence

| POS-04 "done when" | Evidence |
|---|---|
| A closed check keeps its original price and tax | `closed_check_keeps_original_price_and_tax_after_a_price_change` |
| Overlapping effective windows are rejected | `effective_windows_and_overlap_scopes_are_enforced`, `catalog_publication_accepts_exactly_non_overlapping_windows` |
| A version rollback is auditable | `rollback_reissues_old_content_and_is_auditable`, `rollback_reissues_the_old_price_and_records_it` |

Supporting evidence:

- `catalog_links_and_tax_applicability_are_resolved`
- `missing_item_price_and_modifier_price_are_rejected`
- `plain_orders_are_not_pinned_and_cannot_load_a_priced_catalog`
- `replicated_book_preserves_a_pinned_order_across_rebuilds`
- `effective_windows_contain_boundaries_and_overlap_symmetrically`

Run: `cargo test -p tirbase-pos`.

## 8. Known limits / next

- `VersionStore` and the audit log are in-memory. Durable publication,
  transactional writes, distribution to offline terminals and signed manifests
  are not modelled.
- Price-book scope is currency only; store, channel or customer-segment price
  books are not separate scopes in this record.
- Tax is line-level and exclusive, matching POS-01. Tax-inclusive prices,
  compound tax, exemptions, tax holidays and jurisdiction tax nesting are not
  modelled.
- Rollback reissues content into a new non-overlapping window. It does not
  truncate an existing open-ended version; deployments must publish bounded
  windows or schedule the rollback at the next free effective time.
- F-05 signing/attestation of catalog versions and rollback events is not wired
  in; the audit log is a local record, not a cryptographic attestation.
