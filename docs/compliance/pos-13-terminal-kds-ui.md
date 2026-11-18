# POS-13 — Terminal/tablet UI and KDS UI (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-13 is Apache-2.0 operator-console engineering. It is not a certified POS
> application, has no server-side authority, moves no money, implements no
> processor integration and has no statutory report. The register is a browser
> application that a deployment must review before any commercial use.

**Record ID:** POS-13-TERMINAL-UI-0001
**Date (UTC):** 2026-11-18
**Licence:** `Apache-2.0`
**Package:** `console` (`@tirbase/operator-console`)
**Depends:** POS-01 … POS-12, F-09
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists. Nothing here changes
the POS-00 verdict for the AGPL domain crate.

## 1. Scope

| # | Requirement | Where |
|---|---|---|
| 1 | Order entry, floor, split/transfer/void, payment, refund, shift screens | `console/src/screens/{TerminalScreen,FloorScreen,ShiftScreen}.tsx` |
| 2 | Offline indicator and conflict resolution prompts | `console/src/pos/store.tsx`, `console/src/pos/ui.tsx` |
| 3 | KDS ticket board with bump, recall and routing | `console/src/screens/KdsScreen.tsx`, `console/src/pos/model.ts` |
| 4 | Accessibility, touch targets, keyboard support | design-system primitives, `console/src/styles.css`, `console/e2e/pos13.spec.ts` |
| 5 | Localization and timezone-aware timestamps | `console/src/i18n.ts`, `console/src/format.ts` |
| 6 | Playwright tests for sale, refund, split and offline journeys | `console/e2e/pos13.spec.ts` |

## 2. Licence boundary (the "never bundles AGPL code" criterion)

The POS domain crate `tirbase-pos` is `AGPL-3.0-only`. The console is
`Apache-2.0`. The UI therefore does **not** import, wrap, transpile or copy that
crate: `console/src/pos/model.ts` is an independent Apache-2.0 model of checks,
tenders, splits, shifts and kitchen tickets, written for this UI.

`console/scripts/check-licence.mjs` enforces the boundary and now also rejects a
textual reference to `tirbase-pos`:

- every file under `src/` and `packages/` must carry an
  `SPDX-License-Identifier: Apache-2.0` header;
- an `AGPL` SPDX header fails the check;
- an import that escapes the console directory fails;
- the only permitted bare imports are React and the console's own packages;
- a `tirbase-(gateway|core|guard|admin|pos)` reference fails;
- built `dist/assets/*.js` is scanned for `AGPL-3.0`, `tirbase-gateway` and
  `tirbase-pos` markers.

`npm run build && npm run check:licence` is the evidence for the criterion.

## 3. Local-first register

The terminal is device-owned. Checks, kitchen tickets, the open shift and the
sync queue live in `localStorage` (`tirbase.console.pos.v1`) and every mutation
is applied locally before anything network-shaped is attempted, so a cashier can
ring, split, discount, pay and refund with the interface disabled.

Completed sales are the only networked artefact. On payment the sale is appended
to a queue as `{sku, quantity, unit_price_minor, total_minor}` and pushed to the
documented admin API (`POST /admin/pos/orders` then one
`POST /admin/pos/orders/{id}/lines` per line) when the link is up. The API is
the Apache-2.0 generated SDK; no other endpoint is used, and the mock gateway in
`e2e/mock-gateway.ts` rejects any undocumented path.

Money is an integer count of minor units end to end. There is no floating-point
money: `parseMoneyMinor` accepts at most two decimals, every total is integer
addition, and per-line tax uses half-up rounding on integer basis points
(`taxBps`), which is the only rounding point in the UI.

## 4. Offline indicator, queue and conflicts

`navigator.onLine` plus an explicit **Work offline** switch drive one derived
`linkUp` flag. The switch exists because a tablet can be associated to a Wi-Fi
network that cannot reach the gateway; it also makes the offline state
deliberate rather than invisible. The header badge shows `Online`/`Offline` and
the number of sales waiting to sync.

Two conflicts are modelled, both requiring an explicit operator decision:

| Conflict | Raised when | Options |
|---|---|---|
| `table-occupied` | a transfer targets a table that already has an open check | **Move anyway** (two checks on one table) or **Cancel** |
| `sale-rejected` | the admin API refuses a queued sale (4xx/5xx) | **Retry** the flush or **Discard** the queued sale |

A rejected sale is never dropped silently and never retried in a loop: the queue
keeps the sale, the panel shows the API message, and reconciliation is a human
act. A successful flush removes only the sale it pushed, so a partial flush
cannot duplicate or lose the rest. Duplicate pushes are additionally prevented
by an in-flight identifier set.

## 5. Sale, split, transfer, void, refund

- **Order entry**: menu tiles add lines; adding the same SKU again increments the
  existing line rather than creating a second one; quantities are whole numbers.
- **Void**: a line void needs a reason and stays on the check struck through, so
  the audit trail keeps what was removed; voiding a check is only possible before
  payment.
- **Split**: a check splits into *n* checks by balancing whole lines across the
  buckets (largest line first into the least-loaded bucket), keeping one share on
  the original. Because lines are indivisible, a split is balanced to the line,
  not to an arbitrary amount; the sum of the parts always equals the original
  line total. A single line can also be split by quantity, which is how "one of
  the two coffees" is paid separately.
- **Transfer**: moves the check to another table. The target occupancy check and
  the conflict prompt described above are the only guard.
- **Payment**: cash or card. Card charges the exact total; cash requires
  tendered ≥ total and records the change. Payment freezes the check.
- **Refund**: only a paid check, never more than the unrefunded remainder, always
  with a reason. A full refund moves the check to `refunded`; partial refunds
  keep it `paid` and accumulate. Refunds are device-local, matching a real
  terminal where the drawer and the reversal are local authority.

The **shift** screen opens a drawer with a float, records cash in/out and safe
drops, shows expected cash (`float + cash sales − cash refunds + in − out −
drops`), and closes with a counted amount. The closing variance is stored with
the count and the operator, and the closed shift is read-only.

## 6. Kitchen display

Paying a check routes one ticket per station (`kitchen`, `bar`, `cold`) from the
non-voided lines, so routing follows the item, not the operator. The board has
three columns — Queued, Ready, Served — and a station filter.

- **Item bump** marks one item ready; the ticket becomes Ready when every item is.
- **Ticket bump** marks the whole ticket ready and moves it to Served with a bump
  time.
- **Recall** returns a Served ticket to the board at the state its items earned
  (Ready when everything was already bumped, otherwise Queued), increments its
  recall counter and shows a `Recalled ×n` badge, because a recalled ticket is
  an exception an expediter must be able to see.

Bumping an already served ticket, or recalling a ticket that is not served, is
rejected by the model rather than silently ignored.

## 7. Accessibility, touch and keyboard

- Every interactive control uses a design-system primitive or a native
  `button`/`a`/`input`; there is no click-only `div`.
- `.tb-touch` enforces a minimum 44×44 CSS-pixel target on a tablet, asserted in
  the Playwright suite for every `.tb-touch` element on the terminal.
- The terminal is operable with Tab + Enter alone (menu tile → check line), and
  the prompt panel takes focus on open and cancels on Escape.
- Totals, pending-sync counts and variance previews are `aria-live="polite"`;
  errors use the design-system alert role; conflicts are an `alert` region.
- Field labels are always bound with `htmlFor`/`id`, tables have captions and
  scoped headers, and the board's columns are labelled regions.
- Colour comes from the shared WCAG-AA tokens; the existing contrast test still
  covers the shell.

## 8. Localization and time

Every new string is in both the English and Spanish dictionaries, and the
typed dictionary makes a missing translation a compile error. Keyboard/touch
labels are translated too, so a localized deployment does not fall back to
English on an aria-label.

All timestamps are formatted with `Intl.DateTimeFormat` using the time zone
selected in the shell and the selected locale, never the host default. Ticket
ages, drawer counts and shift times therefore follow the operator's chosen zone.

## 9. Evidence

| POS-13 "done when" | Evidence |
|---|---|
| A cashier can complete a sale and refund with no network | `a cashier completes a sale and a refund with no network` — browser context offline, sale paid, refund recorded, zero `POST /admin/pos/orders`, then the queue flushes on reconnect |
| A KDS ticket is bumped and recalled correctly | `a kitchen ticket is bumped and recalled` — bump moves the ticket to Served, recall returns it to the board with `Recalled ×1` |
| The UI never bundles AGPL code | `npm run build` then `npm run check:licence` (SPDX headers, import allow-list, `tirbase-pos` reference rule, dist marker scan) |

Splitting and transfer are covered by `a check is split and transferred from the
floor`; conflict prompts by `a transfer to an occupied table asks before moving`
and `a rejected queued sale surfaces a conflict that can be discarded`; touch,
keyboard and labelling by `touch targets and keyboard entry meet the tablet
floor`; localization by `the terminal is localized and timestamps follow the
chosen zone`.

## 10. Limitations

- The register has no server authority: two tablets do not share checks, tables
  or tickets, and there is no realtime channel.
- `localStorage` is the only store. It is per browser profile, is not encrypted,
  and can be cleared by the operator; nothing here is a durable record.
- Only paid sales reach the gateway, and only as an order plus lines. Splits,
  voids, refunds, tips, drawer movements and KDS state are not synchronised to
  any server, so back-office reconciliation of those is out of scope.
- The admin API has no idempotency key on order creation, so a flush that
  succeeds server-side but fails on the response could duplicate an order on
  retry. The queue's in-flight guard narrows the window; it does not close it.
- Tax is a single per-item basis-point rate. There is no jurisdiction default, no
  inclusive-tax mode, no exemption handling and no fiscal receipt.
- There is no authentication or role check beyond the existing console token;
  any operator signed into the console can void, refund and close a shift.
- Offline behaviour is browser-scoped: clearing site data loses queued sales.
  A deployment needs a real local database and a service worker before this is
  usable on a shop floor.
