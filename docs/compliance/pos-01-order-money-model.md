# POS-01 — Order, check, line-item and money model (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-01 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no processor or terminal connectivity.

**Record ID:** POS-01-MODEL-0001
**Date (UTC):** 2026-11-16
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, F-03, F-07
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Store / terminal / employee / customer ownership | `tirbase-pos/src/ownership.rs` |
| 2 | Order, check, line item, modifier, discount, tax line, tip, payment link | `order.rs`, `check.rs`, `line_item.rs` |
| 3 | Integer minor-unit money + ISO 4217 currency, no float | `money.rs` |
| 4 | Quantity and unit price with explicit rounding | `money.rs`, `rounding.rs`, `line_item.rs` |
| 5 | State machine for open / held / closed / voided / refunded checks | `check.rs` |
| 6 | Audit event for every state change | `audit.rs`, `order.rs` |
| 7 | Property tests for totals, rounding and replay | `tirbase-pos/tests/properties.rs` |

Deliberately out of scope for POS-01 (and unchanged by it):

- No live payment credentials, processor accounts, terminal certifications or
  receipts that claim fiscal validity.
- No card-number, CVV, track-data or card-token field anywhere. A payment link
  stores only an amount, a tender enum and an optional opaque processor
  reference.
- No country, fiscal regime, currency default or customer scenario. The ISO 4217
  table is data; nothing selects a jurisdiction default.
- No persistence adapter, tax engine, discount allocation across checks, split
  tender UI, receipt rendering or POS-02+ work.

## 2. Ownership model

`Organization` is the registry for `Store`, `Terminal`, `Employee` and optional
`Customer`. An `Ownership` record names one store, one terminal, one employee and
an optional customer. `Organization::validate_ownership` enforces:

1. the store exists;
2. the terminal exists and belongs to that store;
3. the employee exists and belongs to that store;
4. the referenced customer, if any, exists.

An `Order` can only be opened with a valid ownership record, and the employee is
the actor recorded on every audit event. Employee roles are coarse data
(`Cashier`, `Supervisor`, `Manager`); authorisation policy is not decided here.

## 3. Money, quantity and rounding

- **Money** is `{ currency: Currency, minor: i64 }`. There is no `f64`
  constructor and no float in the crate. Minor-unit precision comes from the ISO
  4217 table (0, 2, 3 or 4 digits).
- **Quantity** is a positive `i64` in thousandths of a unit.
- **Rate** is an `i32` in parts per million, `0 ..= 1_000_000`, so 8.875% is
  exactly 88 750 ppm.
- **Rounding modes**: `HalfAwayFromZero` (default), `HalfTowardZero`, `HalfEven`,
  `AwayFromZero`, `TowardZero`, `Ceiling`, `Floor`. The mode is chosen when the
  check is created and fixed for its lifetime.
- All division goes through `div_round(i128, i128, RoundingMode)`; overflow is
  an error, never a wrap.

### Per-line calculation order

```
effective_unit_price = unit_price + Σ modifier.price_delta   (must be ≥ 0)
base                 = round(quantity × effective_unit_price)
discount             = fixed amount, or round(base × rate)
taxable_base         = base − discount                       (discount ≤ base)
tax                  = round(taxable_base × tax_rate)
line_total           = taxable_base + tax
```

### Check totals (exact integer identities)

```
subtotal       = Σ line.base
discount_total = Σ line.discount
tax_total      = Σ line.tax = Σ tax_line.tax
grand_total    = subtotal − discount_total + tax_total + tip
net_paid       = paid_total − refunded_total
amount_due     = grand_total − net_paid
```

Tax lines group per distinct rate in ascending rate order. Their `taxable_base`
and `tax` amounts are sums of the per-line values; there is no group-level
re-rounding. The property suite asserts every identity above for all seven modes.

## 4. Check state machine

| From | Allowed to | Notes |
|---|---|---|
| `Open` | `Held`, `Closed`, `Voided` | Content mutable |
| `Held` | `Open`, `Closed`, `Voided` | Content mutable |
| `Closed` | `Refunded` | Reached only by a refund that settles all captured money |
| `Voided` | — | Terminal |
| `Refunded` | — | Terminal |

Guards:

- **Content mutators** (add/update/remove line, set tip, link payment) call
  `ensure_mutable` and fail with `CheckNotMutable` outside `Open`/`Held`.
- **Close** requires at least one line and `amount_due == 0` (captured payments
  cover the grand total). It freezes the line-derived totals in a sealed
  snapshot; `sealed_totals_are_consistent()` recomputes and compares the snapshot.
- **Void** requires a non-blank reason and freezes totals.
- **Refund** is allowed on `Closed` only, for a positive amount not exceeding the
  remaining captured amount. A partial refund leaves the check `Closed`; a refund
  that returns the full captured total moves it to `Refunded`.
- Authorised (uncaptured) payments do not count toward `paid_total`.

A closed check therefore cannot be silently mutated: the only post-close command
the model accepts is a refund, and any content change is rejected without an
audit event or partial write.

## 5. Audit and idempotency

Every successful command appends at least one `AuditEvent` with a dense
`sequence` starting at 1, the caller-supplied `Timestamp`, order/check IDs, the
command's `OperationId`, the employee actor and an `AuditEventKind`
(`CheckCreated`, `StatusChanged`, `LineItemAdded/Updated/Removed`, `TipSet`,
`PaymentLinked`, `RefundRecorded`, `TotalsSealed`). A failed command appends
nothing; the audit log is exposed only as a slice.

Commands carry a caller-supplied `OperationId`. `Order::apply` records each
operation:

- identical command with the same operation id → `ApplyOutcome::Replayed`, no
  state change, no audit event;
- different command with the same operation id → `OperationConflict`, no state
  change;
- a new operation → applied and audited.

`Order::replay` applies a batch and is safe to run repeatedly. The property suite
asserts that a second pass reports every command as replayed and leaves the
order, audit log and applied-operation index identical.

Time is supplied by the caller; the crate never reads the system clock.

## 6. Acceptance evidence

| POS-01 "done when" | Evidence |
|---|---|
| Totals are exact under all supported rounding modes | `prop_totals_are_exact_under_every_rounding_mode` (all 7 modes, exact identities + close + full refund), `prop_rounding_is_bounded_by_floor_and_ceiling`, `prop_rounding_is_monotone` |
| A replayed create/update is idempotent | `prop_replay_of_create_and_updates_is_idempotent`, `order::tests::reusing_an_operation_id_with_different_content_is_rejected` |
| A closed check cannot be silently mutated | `prop_closed_check_rejects_every_mutation`, `order::tests::void_requires_a_reason_and_is_terminal`, `order::tests::partial_refund_keeps_the_check_closed_until_fully_refunded` |

Run: `cargo test -p tirbase-pos`.

## 7. Known limits / next

- Discounts are line-level only; an order-level discount that must be allocated
  across lines with exact remainder handling is not modelled.
- Split and partial tender is representable (multiple payment links), but the
  close rule requires full settlement before close.
- No persistence, signed event envelope, tax-exemption model, service charge,
  price override authorisation or receipt. Those belong to POS-02+.
- The crate is AGPL-3.0-only and remains non-production under POS-00.
