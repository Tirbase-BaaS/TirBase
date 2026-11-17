# POS-03 — Idempotent payment intents (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-03 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no processor or terminal connectivity.

**Record ID:** POS-03-INTENT-0001
**Date (UTC):** 2026-11-16
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01, F-05
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | `created → authorized → captured → refunded/voided` state machine | `tirbase-pos/src/intent.rs` |
| 2 | Idempotency key bound to check, amount, currency, terminal and operator | `IntentBinding`, `PaymentIntentStore::create` |
| 3 | Duplicate request returns the original result, never a second charge | `CreateOutcome::Duplicate`, `TransitionOutcome::Replayed` |
| 4 | Amount/currency mismatch rejection | `validate_amount`, `PosError::IntentAmountMismatch`, `CurrencyMismatch` |
| 5 | Processor-token storage only; no PAN/CVV | `ProcessorToken` |
| 6 | Crash recovery and reconciliation hooks | `IntentEvent` journal, `recover`, `reconcile`, `ProcessorReport` |
| 7 | Property tests for duplicate, concurrent and out-of-order requests | `tirbase-pos/tests/pos03_properties.rs` |

Deliberately unchanged from POS-00/POS-01:

- No PAN, CVV, track data, expiry, cardholder data or direct card processing.
- No processor network client, credential store, fiscal module or receipt that
  claims fiscal validity.
- No persistence adapter, clock access, UI or terminal connectivity.
- No production or certification claim.

`F-05` remains the deployment's key-management/custody boundary. This module
stores no private key material and does not sign the journal; it accepts only an
opaque processor token and a reported processor state. It does not establish a
session, collect card data or call a processor itself.

## 2. State machine

```text
             authorize              capture             refund
  Created ───────────────► Authorized ──────► Captured ─────────► Refunded
     │                         │                 │
     └───────── void ──────────┴───── void ──────┴──── void ─────► Voided
```

| From | Request | To | Behaviour |
|---|---|---|---|
| `Created` | authorize | `Authorized` | Stores the opaque token and time |
| `Created` | void | `Voided` | Stores the required reason |
| `Authorized` | capture | `Captured` | Full amount only; token must match |
| `Authorized` | void | `Voided` | Stores the required reason |
| `Captured` | refund | `Refunded` | Full captured amount only |
| `Captured` | void | `Voided` | Same-day reversal shape; terminal |
| `Authorized` / `Captured` / `Refunded` / `Voided` | authorize (same token) | unchanged | `Replayed`, no journal entry |
| `Captured` / `Refunded` / `Voided` | capture (same token and amount) | unchanged | `Replayed`, no second charge |
| `Refunded` | refund | unchanged | `Replayed` |
| `Voided` | void | unchanged | `Replayed` |
| terminal or wrong state | any other edge | unchanged | `InvalidIntentTransition` |

`Refunded` and `Voided` are terminal. Capture before authorization and refund
before capture are rejected. Partial capture and partial refund are not modelled;
the requested amount must equal the intent amount exactly. Voiding after capture
is permitted to match the literal POS-03 state list, and is the model's
processor-reversal shape rather than a refund.

The store is deterministic: every timestamp is caller-supplied and no operation
reads the system clock.

## 3. Idempotency binding

`IntentBinding` contains:

| Component | Purpose |
|---|---|
| `CheckId` | the check being paid |
| `Money` | exact amount and its ISO 4217 currency |
| `TerminalId` | terminal that made the request |
| `EmployeeId` | operator who made the request |
| `PaymentMethod` | tender method (cash/card/voucher/other) |

A `CreateIntent` carries a caller-supplied `IdempotencyKey`, a proposed
`PaymentIntentId` and the binding. On the first request the store creates one
intent, caches its `Created` snapshot under the key and appends a journal event.
An identical retry returns `CreateOutcome::Duplicate` with that original
snapshot, even if the retry proposes a different local intent id. Reusing the key
with any different check, amount, currency, terminal, operator or method returns
`PosError::IdempotencyKeyConflict` before allocating anything.

Authorization, capture, refund and void are also idempotent. Repeating a request
that is already reflected in the intent returns `Replayed`; it appends no journal
event. A conflicting token or an invalid edge is rejected and leaves the intent
unchanged.

## 4. Amount and currency checks

Capture and refund validate in this order:

1. Currency differs → `PosError::CurrencyMismatch`.
2. Amount differs → `PosError::IntentAmountMismatch { expected, actual }`.

The check applies to retries too, so a duplicate capture with a different amount
is rejected rather than being returned as a replay. Reconciliation reports with a
capture or refund amount are validated the same way before any local transition.
Rejected requests do not mutate the store or the journal.

## 5. Processor data rule

`ProcessorToken` is the only processor value stored. Construction requires:

- non-empty, at most 256 bytes, ASCII;
- no whitespace or ASCII control characters;
- not 13–19 digits (optionally separated by spaces or hyphens), which is rejected
  as `PanLikeProcessorToken` because it looks like a card number.

The type has no PAN, CVV, expiry, track or cardholder fields, and its `Debug`
implementation prints `ProcessorToken(<redacted>)`. There is no method that
accepts card data. `as_str()` is available only to pass the opaque token to a
caller-owned processor adapter.

A three- or four-digit token is not rejected as a PAN; the structural guarantee
is that the intent ledger has no CVV field and never asks for one.

## 6. Journal, recovery and reconciliation

Every applied transition appends one `IntentEvent`:

| Event | Contents |
|---|---|
| `Created` | original `CreateIntent` (id, key, binding, time) |
| `Authorized` | intent id, token, time |
| `Captured` | intent id, amount, token, time |
| `Refunded` | intent id, amount, time |
| `Voided` | intent id, reason, time |

`PaymentIntentStore::recover(&journal)` starts from an empty store and replays
events through the same state machine. An invalid transition is rejected and a
repeated transition is a replay, not a second change. A process that crashes
after authorization can therefore restore the
`Authorized` intent and its token; a retry of the original create still returns
the cached original result. Persisting the journal is the caller's responsibility.

When the processor knows more than the local store, `reconcile` accepts a
`ProcessorReport`:

| Report | Local state | Result |
|---|---|---|
| `NotFound` | any | `Unresolved`, unchanged |
| `Authorized { token }` | `Created` | authorize, `Recovered` |
| `Authorized { token }` | matching later state | `Matched`; mismatched token rejected |
| `Captured { token, amount }` | `Created` | authorize + capture, `Recovered` |
| `Captured { token, amount }` | `Authorized` | capture, `Recovered` |
| `Captured { token, amount }` | `Captured` / `Refunded` | `Matched` if token and amount agree |
| `Captured { token, amount }` | `Voided` before capture | `Unresolved` |
| `Refunded { amount }` | `Captured` | refund, `Recovered` |
| `Refunded { amount }` | `Refunded` | `Matched` |
| `Refunded { amount }` | `Created` / `Authorized` / `Voided` | `Unresolved` |
| `Voided` | `Created` / `Authorized` / `Captured` | void, `Recovered` |
| `Voided` | `Voided` | `Matched` |
| `Voided` | `Refunded` | `Unresolved` |

Recovery transitions are applied to a candidate clone and committed only on
success, so a report cannot partially advance an intent. Invalid reports,
mismatched amounts/currencies and mismatched tokens are rejected; the store is
unchanged. `Unresolved` is an explicit manual-reconciliation signal, not a silent
guess. `pending_intents()` lists the `Created` and `Authorized` intents a startup
reconciliation pass should consider.

## 7. Acceptance evidence

| POS-03 "done when" | Evidence |
|---|---|
| A replayed intent produces exactly one charge | `duplicate_request_returns_the_original_result_and_never_charges_twice`, `duplicate_captures_charge_once`, `interleaved_concurrent_retries_converge` |
| A mismatched amount is rejected | `amount_and_currency_mismatches_are_rejected_without_mutation`, `wrong_amount_or_currency_is_rejected_without_mutation` |
| A crash after authorization recovers the intent state | `crash_after_authorization_recovers_the_intent_from_the_journal`, `recovery_is_exact_for_arbitrary_applied_state` |

Supporting evidence:

- `intent_reaches_each_state_and_terminal_states_reject_further_change`
- `idempotency_key_is_bound_to_check_amount_currency_terminal_operator_and_method`
- `a_reused_key_with_any_changed_binding_is_a_conflict`
- `out_of_order_and_conflicting_transitions_are_rejected`
- `arbitrary_out_of_order_requests_never_double_capture`
- `processor_tokens_are_opaque_validated_and_redacted`
- `card_number_like_tokens_are_rejected`
- `reconciliation_recovers_processor_state_after_a_lost_response`
- `reconciliation_can_jump_directly_to_captured_and_leaves_unknown_reports_unresolved`
- `reconciliation_voids_an_authorized_intent_and_refuses_to_regress_a_refund`

Run: `cargo test -p tirbase-pos`.

## 8. Known limits / next

- The journal and store are in-memory. Durable storage, fsync/transaction
  boundaries, transport authentication and signed envelopes are not modelled.
- Journal signing/attestation through the F-05 key domains is not wired in; the
  journal is a recovery record, not a cryptographic attestation.
- There is no processor client, retry scheduler or webhook receiver; the caller
  supplies tokens and reports processor state through `reconcile`.
- Partial capture, partial refund, multiple captures, tips added after
  authorization and currency conversion are not modelled.
- Reconcile handles one intent at a time; no batch sweep or operator workflow is
  included.
- The crate remains AGPL-3.0-only and non-production under POS-00.
