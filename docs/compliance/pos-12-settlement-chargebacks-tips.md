# POS-12 — Settlement, reconciliation, chargebacks and tips (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-12 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, is
> not a certified settlement integration, moves no money, talks to no acquirer
> and has no persistence. The processor file format is this repository's own
> documented fixture format, not any acquirer's certified specification, and no
> chargeback outcome modelled here is a legal or scheme-rule determination.

**Record ID:** POS-12-SETTLEMENT-0001
**Date (UTC):** 2026-11-18
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-03, POS-11
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Settlement batches per terminal, processor and day | `tirbase-pos/src/settlement.rs` — `SettlementBatch`, `SettlementBook`, `ProcessorBatchFile` |
| 2 | Reconciliation between POS intents and processor records | `SettlementBook::reconcile`, `SettlementMatch` |
| 3 | Chargeback/refund lifecycle with evidence links | `Chargeback`, `ChargebackBook`, `Evidence` |
| 4 | Tip adjustment, pooling and payout rules | `tirbase-pos/src/tip.rs` — `TipLedger`, `TipPayout` |
| 5 | Exception queue for unmatched or duplicated records | `ExceptionQueue`, `SettlementException` |
| 6 | Tests with mock processor files and partial settlements | `tirbase-pos/tests/pos12.rs`, `pos12_properties.rs` |

Deliberately not added:

- No processor connector, HTTP client, API credential, webhook or file upload.
  A settlement file is text the caller already has; this crate parses it.
- No acquirer-specific or scheme-certified file format. The format in
  [`ProcessorBatchFile`] is a documented, validated CSV fixture.
- No bank posting, payout instruction, merchant statement or general ledger
  entry. `BatchTotals::net` is a computed figure, not a transfer.
- No evidence storage, retrieval or signature. An `EvidenceRef` is an opaque
  link to a document another system holds.
- No chargeback deadlines, scheme arbitration windows, representment uploads,
  fee schedules or liability allocation. Only the merchant-side lifecycle.
- No tip tax withholding, payroll export, benefit allocation, service-charge
  rules or jurisdiction tipping law.
- No persistent store, backup or archival guarantee. Every book is in memory.
- No multi-currency batch: the file header fixes one currency per batch, and a
  later file for the same batch with a different currency is refused.

Licence remains `AGPL-3.0-only`; the crate remains non-production under POS-00.

## 2. Batches and processor files

A batch is identified by processor, terminal and settlement day
(`SettlementKey`). `SettlementBook::ingest` creates the batch on the first file
and merges later files into it, so a day that arrives in several parts stays one
batch. A file whose batch identifier disagrees with the open batch is refused
(`BatchIdConflict`) rather than silently mixed, a different currency is refused,
and a closed batch accepts nothing (`BatchClosed`).

The settlement day is a civil date, not a time zone, business-day cut-off or
local-time rule. `SettlementDay` parses `YYYY-MM-DD`, converts to and from a day
index with exact integer arithmetic, and rejects an impossible date such as
`2026-02-30`.

`BatchTotals` keeps the figures separate instead of netting everything:

```text
net = captures − refunds − chargebacks + chargeback_reversals
```

`adjustments` (fees and corrections) and `tips` are reported beside `net`, never
folded into it, so a processor fee cannot silently change a captured total.

A record repeated inside one file is a duplicate and is queued; the batch keeps
the first occurrence and the totals do not move. A record already ingested with
identical content is a replay, counted but not re-added. A record whose
identifier was already used with different content is a conflict: queued, and
the stored record is never overwritten.

## 3. Reconciliation

`SettlementBook::reconcile` takes the POS-03 `PaymentIntentStore` and checks
every intent that has a captured amount against the ingested records:

| Records for one captured intent | Outcome |
|---|---|
| one capture equal to the captured amount | reconciled (`SettlementMatch`) |
| none | `MissingRecord` exception |
| more than one capture | `DuplicateRecord` exception |
| one capture below the captured amount | `PartialSettlement` exception |
| one capture above the captured amount | `OverSettlement` exception |
| different currency | `CurrencyMismatch` exception |
| refund records disagree with `refunded_amount` | `RefundMismatch` exception |

Everything else is queued too: a record naming an intent the POS never
captured, a record with no intent that is not an adjustment, and a failed batch
record all become exceptions. The decision is per intent, so a captured intent
is *either* in `SettlementReconciliation::reconciled` *or* in
`SettlementReconciliation::exceptions`; `accounts_for` states that invariant
directly, and the property test asserts it over arbitrary mixtures of files.

A partial settlement is one capture record below the intent, and a split capture
is two records for one intent — the second is a duplicate, not a legitimate
split, because a scheme that settles one authorisation twice is exactly what the
exception queue exists to surface. A day that only partly settles is handled by
the same rule: the missing intents are queued, nothing is dropped.

Reconciliation is idempotent in the queue: `ExceptionKey` is derived from the
category, intent and record, so a second pass finds the same entries instead of
adding more, and an entry an operator already resolved stays resolved.

## 4. Exception queue

`ExceptionQueue` is keyed by `ExceptionKey` and holds one `SettlementException`
per distinct problem, with the category, the intent, the record identifiers, the
expected and actual amounts, the queue time and a state.

`resolve` is an explicit operator act: it records the time and an optional note
and refuses a second resolution (`AlreadyResolved`). A missing key is
`UnknownException`. Reconciliation never clears or reopens an entry by itself,
so the queue is an audit trail of what was seen, not a transient diff. The queue
is not persisted in this crate; a deployment is responsible for storing it.

## 5. Chargebacks

```text
Opened ──► UnderReview ──► Won
   │            │
   └────────────┴────────► Lost ──► Paid
```

- `Won` requires at least one attached evidence link (`EvidenceRequired`) and is
  not a debit.
- `Lost` is a debit and is what `outstanding_total` reports.
- `Paid` is terminal. A second `pay` returns `ChargebackAlreadyPaid` and the
  paid total is unchanged — the case is never replayed, because replaying a
  debit would move the same money twice.
- Paying before a loss is `ChargebackNotLost`; paying a won case is
  `ChargebackAlreadyWon`.
- Evidence is accepted while the case is `Opened` or `UnderReview`, a reference
  is unique within a case (`DuplicateEvidence`), and a closed case accepts no
  more (`ChargebackClosed`).
- Every case records the operator who opened it, reviewed it, lost it and paid
  it, all taken from the authenticated `StaffSession`, and is scoped to the
  session's store (`StoreMismatch` otherwise).

Refunds are POS-03's full-amount intent refund; POS-12 checks the processor's
refund records against it in reconciliation and reports a disagreement rather
than inventing a partial-refund model POS-03 does not have.

## 6. Tips

A tip is recorded per check and attributed to the operator who rang it (from the
session, never from a caller argument). `adjust_tip` replaces the amount and
appends an immutable `TipAdjustment` with the previous amount, the new amount,
the delta, the operator, the time and an optional note; adjusting to the same
amount is a replay.

A `TipPayout` settles every open tip at once, so no tip can be paid by two
pools, and a tip that has been paid can no longer be adjusted. Every tip in the
ledger must belong to a pool member (`UnpooledTip`); a tip from outside the pool
is refused rather than absorbed into someone else's share.

The split guarantees both identities:

```text
total      = Σ settled tips
Σ payouts  = total
Σ contributed = total
```

The allocation uses the largest-remainder method over `i128` intermediates:
each member gets the floor of their weighted share, then the leftover minor
units go one each in descending remainder order with ties broken by member
order. `TipPayout::validate` re-checks both identities and `payout` refuses to
store a payout that fails, so "payout totals match allocated tips" holds by
construction for any weight vector rather than for convenient numbers.

`Even` ignores supplied weights; `Weighted` requires `1 ..= MAX_TIP_WEIGHT` per
member, which also keeps the share arithmetic inside `i128`. A duplicate member
is refused, and an empty pool or an empty ledger is refused.

## 7. Permissions

POS-12 extends the POS-11 permission model with three operational permissions:

| Permission | Required by |
|---|---|
| `settle_batch` | `SettlementBook::ingest`, `close_batch`, `reconcile` |
| `manage_chargebacks` | every `ChargebackBook` mutation |
| `pay_tips` | `TipLedger::adjust_tip`, `TipLedger::payout` |

`PermissionSet` was widened from `u16` to `u32` so the three additional bits fit;
the role derivation is unchanged, so `Cashier` still has sell, count drawer and
X report, and `Supervisor` still has everything except employee administration.
Recording a tip needs `sell`, because it is part of ringing the sale.

## 8. Evidence

| POS-12 "done when" | Evidence |
|---|---|
| Every captured intent reconciles or appears in an exception queue | `a_partially_settled_day_leaves_the_rest_in_the_queue`, `short_and_over_settlements_are_distinguished`, `two_captures_for_one_intent_are_a_duplicate_not_a_settlement`, `records_for_unknown_or_uncaptured_intents_are_unmatched`, property `every_captured_intent_is_accounted_for` |
| A chargeback cannot be paid twice | `a_chargeback_cannot_be_paid_twice` (`ChargebackAlreadyPaid`, unchanged `paid_total`), `a_chargeback_lost_is_a_debit_and_is_paid_once`, `a_closed_chargeback_is_not_reopened_by_a_later_loss` |
| Tip payout totals match allocated tips | `a_tip_payout_matches_the_allocated_tips`, `a_weighted_pool_splits_by_weight_without_losing_a_cent`, property `tip_allocation_preserves_the_total` |

Mock processor files and partial settlements are covered by
`processor_file_builds_a_batch_from_a_mock_file`,
`continuation_files_merge_into_the_same_batch`,
`batches_are_scoped_by_processor_terminal_and_day`,
`malformed_processor_files_are_rejected`,
`duplicated_records_land_in_the_exception_queue`,
`a_repeated_record_is_a_replay_but_a_changed_one_is_a_conflict`,
`a_closed_batch_accepts_nothing_more` and property
`ingesting_the_same_file_twice_changes_nothing`.

## 9. Limitations

- No processor is contacted. The caller obtains the file; this crate only
  validates and applies it, and every timestamp is caller-supplied.
- Reconciliation trusts the `PaymentIntentStore` as given. It does not verify the
  intent journal, and it does not re-derive a captured amount from a check.
- A chargeback is matched to an intent by the caller when the case is opened; a
  processor chargeback record that no case references is aggregated in the batch
  and reported on the intent's match, but it does not open a case by itself.
- `paid_total` and `outstanding_total` are per currency and include only cases in
  the same book; a deployment with several books must aggregate them itself.
- Counts (`record_count`, `capture_count`) and amounts are both reported, but
  nothing is posted anywhere: no journal, no write-off, no receivable.
- Tip payout settles open tips only. There is no partial payout, no draw against
  future tips, no carry-over balance for an employee, and no payroll export.
- The exception queue, batches, cases and payouts are in-memory values with no
  persistence, concurrency control, backup or retention period.
