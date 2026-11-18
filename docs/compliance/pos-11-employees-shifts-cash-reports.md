# POS-11 — Employees, shifts, cash management and X/Z reports (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-11 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no persistence, fiscal module, hardware
> drawer or terminal connectivity. No report it produces is a statutory fiscal
> document.

**Record ID:** POS-11-SHIFT-CASH-0001
**Date (UTC):** 2026-11-18
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01, F-03
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Employee, role, PIN/badge and permission model | `tirbase-pos/src/staff.rs` |
| 2 | Shift open/close, float, cash in/out, safe drop, drawer count | `tirbase-pos/src/shift.rs` |
| 3 | X and Z reports with totals, taxes, discounts, voids, refunds, tips | `ShiftReport`, `ShiftTotals` |
| 4 | Cash variance and audit trail | `CashVariance`, `Shift::variances` |
| 5 | Offline shift handling and reconciliation on reconnect | `Shift::reconcile`, `ShiftBook::adopt_offline` |
| 6 | Tests for shift boundaries, variance and concurrent drawers | `tirbase-pos/tests/pos11.rs`, `pos11_properties.rs` |

Deliberately not added:

- No PIN, badge secret, password hash or authentication comparison. `PinRef`
  and `BadgeRef` are opaque references to credentials that F-03 verifies.
- No persistent shift store, database, backup or archival guarantee. The book
  and the shift are in-memory values.
- No cash-drawer hardware transport. POS-07's ESC/POS drawer pulse is a
  separate device path and is not wired to a shift here.
- No statutory report layout, fiscal signature, certified Z, tax-authority
  export or jurisdiction default. The report is a struct, not a filing.
- No bank deposit, safe inventory, change-order or coin/note denomination
  model. A count is one integer minor-unit total.
- No multi-currency drawer. The opening float fixes the shift currency and every
  later amount must match it.
- No employee scheduling, rota, labour costing or payroll.

Licence remains `AGPL-3.0-only`; the crate remains non-production under POS-00.

## 2. Employees and permissions

`Employee` remains the POS-01 ownership record. `EmployeeAccess` adds the
operational profile: a permission set derived from the ownership roles, and at
least one `PinRef` or `BadgeRef`. `EmployeeDirectory` keeps employee, PIN and
badge references unique and refuses a duplicate instead of silently
rebinding a credential.

`PermissionSet` is a deterministic `u32` bit set (widened from `u16` in POS-12,
which added three settlement permissions). Role derivation is:

| Role | Permissions |
|---|---|
| `Cashier` | sell, count drawer, view X report |
| `Supervisor` | every operational permission except employee administration |
| `Manager` | every permission |

A deployment can grant or revoke individual permissions through
`EmployeeAccess::with_permissions`. `EmployeeDirectory::session` snapshots the
resulting set into a `StaffSession` scoped to one store and terminal, so a
session cannot gain a permission after it was issued. Every shift operation
takes the session — never a caller-supplied employee id — which is what makes
the variance and movement attribution trustworthy.

## 3. Shift and drawer

A `Shift` is one operator session on one terminal, opened through
`Shift::open` with an opening float. The float must be non-negative and fixes
the drawer currency. `ShiftSpec` must name the session's own store and terminal,
otherwise the open is rejected rather than attributed to the wrong drawer.

Expected cash is derived, never entered:

```text
expected = opening_float
         + cash_in − cash_out − safe_drops − cash_refunds
         + cash_sales
```

`cash_sales` comes from settled checks; the four movement terms come from
explicit `CashMovement` values. A sale and a movement are different records, so
a sale cannot also be replayed as drawer cash. `CashMovementKind` is
`CashIn`, `CashOut`, `SafeDrop` or `CashRefund`; a safe drop leaves the drawer
but stays in the report totals.

`ShiftBook` allows at most one open shift per terminal. Two terminals keep
independent drawers, and closing one shift releases only its own terminal.
`ShiftBook::open` is the only way to open, so the invariant is not reachable
around.

A `DrawerCount` compares counted cash with the expected cash at that moment. The
difference is a `CashVariance` recording `expected`, `counted`, `variance`, the
operator and the time. Negative variance is short, positive is over.

## 4. X and Z reports

`Shift::x_report` returns an immutable snapshot and changes nothing: it records
no count, moves no cash and leaves the shift open. Any employee in the shift's
store may read it.

`Shift::close` records the closing count as the closing operator's action, then
returns the Z report and stores it on the shift. `ShiftReport` has private
fields, getters only, and no setter, so a report cannot be edited after it is
produced. The Z report additionally seals the shift: every later movement, sale,
count, X report, reconciliation or second close returns
`ShiftError::Closed`.

Both report kinds carry the same aggregate `ShiftTotals`:

| Figure | Source |
|---|---|
| `subtotal`, `discount_total`, `tax_total`, `tip`, `grand_total` | sum over settled checks |
| `cash_sales`, `card_sales`, `other_sales` | captured payments by tender |
| `refunded_total` | refunds recorded against settled checks |
| `voided_lines`, `voided_payments`, `voided_payment_amount` | void records and voided payment links |
| `cash_in`, `cash_out`, `safe_drops`, `cash_refunds` | explicit movements |
| `sale_count` | number of settled checks |

`sale_count`, `voided_lines` and `voided_payments` are counts; every other
figure is an integer minor-unit `Money` in the drawer currency. A sale is built
with `SaleRecord::from_check`, which refuses a check that is not `Closed` or
`Refunded` and reuses the check's sealed totals instead of recomputing them.
`SaleRecord::validate` re-checks the currency, non-negativity and the
`subtotal − discount + tax + tip = grand_total` identity, and reconciliation
runs it on every decoded sale.

## 5. Variance and audit trail

Attribution is structural rather than a caller argument:

- `record_movement` stamps the session's employee on the movement.
- `record_count` stamps the session's employee on the count and on the variance.
- `close` records the final count under the closing session's employee.
- Offline events carry the actor who performed them, and reconciliation
  preserves that actor instead of substituting the reconnecting operator.

`Shift::movements`, `counts`, `variances` and `sales` are append-only for the
life of the shift: there is no remove, update or replace. A replay with the same
identifier and identical content changes nothing; different content under a used
identifier is a `MovementConflict`, `SaleConflict` or `CountConflict`. Nothing
is silently overwritten, so a variance always points at the count that produced
it and an operator.

## 6. Offline shifts and reconciliation

A terminal may open a shift while disconnected and record movements, sales and
counts locally. On reconnect:

- `ShiftBook::adopt_offline` registers the offline shift, reserving its terminal
  if it is still open. A second open shift on that terminal is refused with
  `DrawerAlreadyOpen`.
- `Shift::reconcile` applies an `ShiftEvent` log through the same idempotent
  paths the online API uses. An event already present with identical content is
  reported as `replayed` and changes nothing, so a replayed log cannot duplicate
  a cash movement, a sale or a count.
- Conflicting or malformed events are collected per event in
  `ReconcileReport::rejected` and leave the shift unchanged; one bad event does
  not discard the rest of the log.

Order matters and is the caller's responsibility: a count's variance depends on
the movements and sales recorded before it, so the log must be supplied in the
order the terminal recorded it. Reconciliation refuses a closed shift, because a
Z report is the point after which no drawer event is accepted.

## 7. Evidence

| POS-11 "done when" | Evidence |
|---|---|
| A Z report closes the shift and cannot be edited | `z_report_closes_the_shift_and_cannot_be_edited`, plus the private-field `ShiftReport` |
| Cash variance is attributable to an operator | `drawer_count_variance_is_attributed_to_the_operator` — operators come only from `StaffSession` |
| Offline shifts reconcile without duplicate cash movements | `offline_events_reconcile_without_duplicate_cash_movements`, `conflicting_offline_movement_is_rejected_without_moving_cash`, property `reconciliation_is_idempotent` |

Shift boundaries are covered by `shift_open_requires_permission_and_matching_scope`,
`events_before_opening_are_rejected`, `sale_requires_a_settled_check` and the
`ShiftError::Closed` block of the Z report test. Concurrent drawers are covered
by `drawer_is_exclusive_per_terminal_but_tills_stay_independent`,
`an_offline_shift_is_adopted_once_per_terminal` and property
`concurrent_drawers_stay_independent`. Expected cash and variance arithmetic is
covered by property `expected_cash_follows_the_ledger` over arbitrary movement
sequences.

## 8. Limitations

- `tirbase-pos` performs no authentication. `EmployeeDirectory::session` trusts
  the caller to have verified the PIN or badge through F-03 and records no
  verdict about the credential.
- A cash refund is a `CashRefund` movement because the POS-01 refund record
  does not name a tender. The report shows refund totals from checks and the
  drawer effect from movements; a deployment must record both to reconcile.
- An expected-cash figure can go negative when cash leaves the drawer before the
  matching sale is recorded. It is reported as a short variance rather than
  refused, because refusing it would make an offline log depend on arrival
  order for acceptance.
- A sale recorded after `Shift::close` is refused. A caller must settle checks
  before running the Z report.
- Variance is a report figure, not a financial correction: POS-11 does not post
  an over/short journal, a write-off or a payable to the operator.
- The crate has no clock. Every timestamp, including a report's `generated_at`,
  is caller-supplied.
