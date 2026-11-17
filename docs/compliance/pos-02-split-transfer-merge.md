# POS-02 — Split, transfer, void and merge with offline convergence (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-02 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no processor or terminal connectivity.

**Record ID:** POS-02-REPLICA-0001
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
| 1 | Split check, split line item, transfer item/check, void line item, void payment, merge checks | `tirbase-pos/src/book.rs`, `check.rs`, `order.rs` |
| 2 | Deterministic conflict rules for concurrent offline edits | `book.rs` canonical rebuild + rejection map |
| 3 | Idempotent replay of every operation | `PosBook::apply`, `PosBook::replay` |
| 4 | Preservation of tax, discount, tip and payment allocation | `book.rs`, `check.rs` |
| 5 | Explicit rejection of ambiguous or lossy merges | `PosError::AmbiguousMerge`, `PosError::LossySplit`, `IncompatibleChecks` |
| 6 | Property tests for commutativity, associativity and replay | `tirbase-pos/tests/pos02_properties.rs` |

Deliberately unchanged from POS-00/POS-01:

- No payment credentials, card-number/CVV/track/token fields, processor
  integration, fiscal module or receipt that claims fiscal validity.
- No jurisdiction, currency default, tax regime or country rule. The ISO 4217
  table remains data only.
- No persistence adapter, clock access, UI or terminal connectivity.

## 2. Replica model

`PosBook` is a deterministic state machine over an operation log:

- **Genesis** is the `Organization` plus the set of orders (id, ownership, open
  time). Orders can only be added before the first operation; afterwards
  `add_order` returns `GenesisLocked`.
- **Operation log** is a map from `OperationId` to `BookOp`. `BookOp` has a
  caller-supplied operation id, order id, actor terminal, Lamport clock, time
  and a kind. The kind is either a POS-01 `OrderCommand` or one of the POS-02
  movements.
- **Rebuild** throws away the derived state and replays the entire log in
  canonical order.
- **Merge** unions two logs and rebuilds. It refuses a different genesis
  (`IncompatibleReplica`) or the same operation id with different content
  (`OperationConflict`).

Every operation is applied to a candidate copy of the orders. A rejected
operation leaves no partial split, transfer or merge behind; the replica's state
is always exactly the canonical rebuild of the operations it stores.

### Canonical order

```text
(lamport, actor terminal id, operation id)
```

All three components are caller-supplied or derived identifiers; the crate never
reads a clock. Because the order is total and independent of arrival order,
replicas that know the same operations produce byte-identical derived state.
The canonical position also decides which concurrent operation wins.

### Actor scope

Every operation is attributed to a terminal registered in the *order's* store.
An unknown terminal fails with `UnknownTerminal`; a terminal from another store
fails with `ActorNotInStore`.

## 3. Operation semantics

### Split check

`SplitCheck { source, target, line_ids, tip_to_target, payment_allocations }`

- Creates a new check in the same order with the source's currency and rounding.
- Moves the named **whole** line items. Each line keeps its unit price, quantity,
  modifiers, discount and tax rate, so its discount and tax move with it without
  re-rounding.
- Moves exactly `tip_to_target` from the source tip; the remainder stays.
- Splits payments by exact amount: `amount` moves from a source payment to a new
  target payment id, and the source payment is reduced by the same amount. A zero
  or over-payment allocation is rejected.
- Rejects: same source/target, existing target, duplicate lines or allocation
  ids, voided or missing lines/payments, negative tip, or a tip/payment
  allocation larger than available.
- A split that moves nothing is rejected as `AmbiguousMerge("split moves
  nothing")` rather than creating an empty duplicate.

Subtotal, discount, tax, tip, grand total and paid total of source plus target
equal the original check.

### Split line item

`SplitLineItem { check, line_id, new_line_item_id, first_quantity, preserve_totals }`

- Rebuilds two lines with the original name, SKU, modifiers, unit price, discount
  and tax rate.
- A percentage discount is recomputed on each part. An **amount** discount is
  allocated in proportion to quantity, with the remainder assigned to the second
  part.
- With `preserve_totals: true`, the command succeeds only if the two parts' base,
  discount and tax sum exactly to the original. Otherwise it fails with
  `LossySplit` and changes nothing.
- With `preserve_totals: false`, recalculation is explicit and the caller accepts
  the rounded result. There is no silent third behaviour.

### Transfer

- `TransferLineItem { from, to, line_id }` moves one active line between two
  mutable checks in the same order. Totals of the two checks sum to the original
  pair.
- `TransferCheck { to_order, check }` moves a mutable check to another order in
  the **same store**. A cross-store move fails with `CrossStoreTransfer`.

### Void

- `VoidLineItem { check, line_id, reason }` records a `VoidRecord` (non-blank
  reason + caller time). The line stays in the check and in the audit trail but is
  excluded from subtotal, discount, taxable base and tax.
- `VoidPayment { check, payment_id, reason }` keeps the payment record and
  excludes it from `paid_total`.
- Voiding an already voided target with a *different* operation id fails with
  `LineItemAlreadyVoided` / `PaymentAlreadyVoided`. Replaying the *same*
  operation id is a replay, not a second void.

### Merge checks

`MergeChecks { source, target }`

- Requires the same currency and rounding, both checks mutable, distinct ids, and
  no line or payment id present on both checks (the target is the surviving
  check).
- Moves every active source line, every non-voided payment and the whole source
  tip to the target. Total content and money are preserved exactly.
- Sets the source to `CheckStatus::Merged`, records `merged_into = target`, and
  seals it to zero totals. `Merged` is terminal.
- Rejects incompatible currency/rounding (`IncompatibleChecks`), duplicate
  identifiers (`AmbiguousMerge`), or a non-mutable source/target
  (`CheckNotMutable`). Rejection is all-or-nothing.

## 4. Replay and idempotency

`PosBook::apply` checks the operation log first:

| Situation | Result |
|---|---|
| Same operation id, identical operation | `ApplyOutcome::Replayed`; no rebuild, no state/audit change |
| Same operation id, different content | `OperationConflict` |
| New operation that rebuilds successfully | `Applied` |
| New operation rejected in canonical order | the stored `PosError`, no state change |

`PosBook::replay(&[BookOp])` applies a batch and reports one outcome per
operation. Replaying the entire log therefore reports `Replayed` for every entry
and leaves the book unchanged. This holds for split, transfer, void and merge
alikes, including the "replayed void does not double-void" case.

## 5. Preservation and rejection rules

Preservation is exact, never approximate:

- Whole-line movement means line discount and tax are unchanged.
- Tip is moved by exact minor-unit amount.
- Payment allocation moves an exact amount and reduces the source by that amount;
  the pair is conserved.
- Merge moves whole records and the whole tip.
- Line split is exact or `LossySplit`; a lossy result requires an explicit
  `preserve_totals: false`.

Rejection is deterministic and stored:

- Conflicting operations are ordered by `(lamport, actor, operation_id)`; the
  first valid operation wins and later invalid ones appear in
  `rejected_operations()` with the same error on every replica.
- Ambiguous merges (duplicate line/payment ids) are rejected rather than
  resolving by overwrite or silent deduplication.
- Incompatible checks and cross-store transfers are rejected rather than
  coerced.

## 6. Acceptance evidence

| POS-02 "done when" | Evidence |
|---|---|
| Two terminals can split the same check offline and converge | `two_terminals_split_the_same_check_offline_and_converge`, `merge_is_commutative`, `merge_is_associative` |
| A replayed void does not double-void | `replayed_void_does_not_double_void`, `replaying_a_log_is_idempotent` |
| Merge conflicts are deterministic or rejected | `concurrent_split_of_the_same_line_has_one_deterministic_winner`, `merge_checks_preserves_totals_and_rejects_ambiguous_or_incompatible_merges` |

Supporting preservation properties:

- `split_check_conserves_every_component`
- `split_line_is_exact_or_rejected`
- `merge_checks_conserves_every_component`
- `void_line_excludes_it_from_totals_but_keeps_it_for_audit`
- `transfer_line_and_check_preserve_content_and_reject_cross_store`

Run: `cargo test -p tirbase-pos`.

## 7. Known limits / next

- The operation log is in-memory. Persistence, transport, authentication and
  signed envelopes are not modelled.
- Conflict detection is structural; there is no policy layer for supervisor
  approval of a void or merge.
- Order-level discounts and service charges that must be reallocated across
  split lines are not modelled.
- Split payments are explicit allocations, not an automatic tender-splitting UI.
- The crate is AGPL-3.0-only and remains non-production under POS-00.
