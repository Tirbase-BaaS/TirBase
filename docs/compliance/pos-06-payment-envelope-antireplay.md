# POS-06 — Payment envelope and anti-replay (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-06 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no processor, persistence or terminal
> connectivity.

**Record ID:** POS-06-ENVELOPE-0001
**Date (UTC):** 2026-11-17
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01, POS-03, POS-05
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Payment amount envelope checks total, tip, currency, terminal and operator | `PaymentDesk::check_amounts`, `check_actors`, `PaymentEnvelope` |
| 2 | Reject negative, zero where invalid and out-of-range amounts | `EnvelopePolicy`, `EnvelopeCode::{InvalidTotal, InvalidTip, InvalidAmount, AmountOutOfRange, TotalOutOfRange}` |
| 3 | Nonce/idempotency key plus monotonic counter | `PaymentNonce`, `PaymentEnvelope::counter`, `PaymentDesk::check_nonce` |
| 4 | Reject reuse across terminals and epochs; bounded replay window | `PaymentDesk::nonces`, `last_counters`, `EnvelopePolicy::replay_window` |
| 5 | Bind approval and intent to the exact payment | `PaymentDesk::check_intent`, `check_approval`, `IntentScope` |
| 6 | Property tests for replay, amount mismatch and concurrent terminals | `tirbase-pos/tests/pos06_properties.rs` |

The envelope check is not a library-only helper. `PaymentDesk::capture`,
`PaymentDesk::refund` and `PaymentDesk::void` are the production callers: each
runs the same private `check` before touching the POS-03 intent store, and a
nonce is recorded only after the transition succeeds. There is no public method
that executes an intent transition without the envelope check.

POS-06 adds no card-data field, no processor client, no persistence adapter,
no clock access and no jurisdiction default.

## 2. Amount envelope

A `PaymentEnvelope` carries the check total, the tip portion, the requested
amount, the policy currency, the terminal, the operator and the terminal epoch.
Checks run in this order before any intent state is read:

| Check | Rejection |
|---|---|
| All three amounts share the policy currency | `envelope.currency_mismatch` |
| `total > 0` | `envelope.invalid_total` |
| `tip >= 0` | `envelope.invalid_tip` |
| `tip <= total` | `envelope.tip_exceeds_total` |
| `amount > 0` | `envelope.invalid_amount` |
| `amount <= total` | `envelope.amount_exceeds_total` |
| `amount <= policy.max_amount` | `envelope.amount_out_of_range` |
| `total <= policy.max_total` | `envelope.total_out_of_range` |

A partial tender is allowed (`amount < total`); the envelope does not model the
remaining amount due. Negative, zero and oversized values are rejected before
the nonce table, the intent store or the approval guard is touched, so a
malformed request records no replay state and consumes no approval.

`EnvelopePolicy::new` rejects a non-positive limit, mismatched limit currency, a
maximum total below the maximum amount, a zero replay window and zero nonce
capacity.

## 3. Terminal, operator and epoch

`Organization` remains the ownership authority. The terminal and operator must
exist and belong to the same store:

| Check | Rejection |
|---|---|
| Terminal is registered | `envelope.unknown_terminal` |
| Operator is registered | `envelope.unknown_operator` |
| Terminal and operator share a store | `envelope.actor_mismatch` |
| The terminal has an active epoch | `envelope.epoch_not_registered` |
| The envelope names the active epoch | `envelope.epoch_mismatch` |

Epochs are caller-supplied `TerminalEpoch` values (for example a shift or boot
generation). `PaymentDesk::begin_epoch` re-declares the current epoch as a
no-op and rejects a move backwards; an epoch never recycles. An envelope from a
different terminal or a stale epoch is rejected even if the nonce is new.

## 4. Nonce, counter and bounded replay

Each envelope carries a globally unique `PaymentNonce` and a `u64` counter.
Replay state is split into:

- `nonces: PaymentNonce -> NonceUse` — one entry per executed payment, holding
  the full envelope fingerprint and the resulting intent snapshot.
- `last_counters: (TerminalId, TerminalEpoch) -> u64` — the highest accepted
  counter for that terminal epoch.

Rules:

1. A new nonce must carry a counter strictly greater than the last accepted
   counter for its `(terminal, epoch)`. A counter at or below that value is
   rejected as `envelope.counter_not_monotonic`, so a retransmitted counter
   cannot become a fresh payment under a new nonce. A retransmission of the
   *same* nonce and fingerprint is handled by rule 2, not by this rule.
2. A nonce seen with an identical fingerprint inside the replay window returns
   `PaymentOutcome::Replayed` and does not call the intent store or the guard.
3. A nonce seen with any different field — another terminal, another epoch,
   another intent, amount, action, reason or approval — is rejected as
   `envelope.nonce_reuse`. Cross-terminal and cross-epoch reuse is therefore a
   conflict rather than an independent payment.
4. A nonce seen before but now further behind the last accepted counter than
   `policy.replay_window` is rejected as `envelope.replay_window_expired`. Its
   operation can never execute twice.
5. When `nonces.len() == policy.max_nonce_entries`, a new nonce is rejected as
   `envelope.replay_capacity_exceeded`. The desk fails closed instead of
   evicting an old nonce and silently allowing its replay later.

The window is measured in counters per terminal epoch, not wall-clock time.
`EnvelopePolicy::replay_window` is the number of recent counter positions that
remain replayable; `1` means only the latest counter replays.

## 5. Intent and approval binding

The envelope must reference an existing POS-03 intent. The desk compares every
binding field before the operation:

- check;
- amount and currency;
- terminal;
- operator;
- tender method.

A missing intent or any mismatch is `envelope.intent_mismatch`. On the first
successful envelope the desk also freezes the intent to one
`(payment_id, epoch)` scope; a later envelope for that intent with another
payment or epoch is `envelope.intent_scope_mismatch`.

Intent state must permit the operation:

| Action | Required intent state |
|---|---|
| Capture | `Authorized` |
| Refund | `Captured` |
| Void | `Created`, `Authorized` or `Captured` |

A new envelope that tries to capture, refund or void an intent already in a
terminal state is `envelope.intent_state`. A replay is recognised before this
state check, so replaying an already-refunded or already-voided envelope still
returns the recorded result instead of failing.

A supplied POS-05 approval must match the exact payment:

- actions match: `Refund` for a refund, `VoidPayment(payment_id)` for a void;
- check, amount, reason, terminal and requester match;
- a capture may not carry an approval at all.

Any mismatch is `envelope.approval_mismatch` and does not consume the approval.
The POS-05 guard still decides whether an approval is required for a cap breach,
a captured-payment void or a closed-check void, and consumes it on success.
Because a replay never reaches the guard, a replayed refund or void cannot
consume a second approval.

## 6. Production caller path

```text
PaymentDesk::refund(&envelope, at)
        |
        +-- check(envelope, Refund)
        |     amounts -> actors -> epoch -> nonce/counter
        |     -> intent binding -> approval binding -> intent state
        |
        +-- Replay? -> return recorded intent (no guard, no intent write)
        |
        +-- ApprovalGuard::authorize_refund(...)
        +-- PaymentIntentStore::refund(...)
        +-- record(nonce, counter, intent snapshot)
```

`capture` and `void` follow the same shape. The only public access to the
intent store is through the desk's `create_intent`/`authorize_intent` wrappers
and these three operations, so the envelope check is exercised by the production
payment path rather than being callable as an optional helper.

## 7. Acceptance evidence

| POS-06 "done when" | Evidence |
|---|---|
| A replayed refund/void cannot execute twice | `refund_approval_is_bound_to_the_payment_and_a_replay_cannot_refund_twice`, `captured_void_needs_an_approval_and_a_replay_cannot_void_twice`, `a_replayed_refund_executes_at_most_once` |
| A payment from another terminal or epoch is rejected | `nonce_reuse_across_terminals_epochs_and_amounts_is_a_conflict`, `terminal_operator_and_epoch_bindings_are_enforced`, `epoch_can_only_move_forward_and_rejects_old_epoch_envelopes`, `concurrent_terminals_never_share_a_nonce` |
| The envelope check is a production caller, not a library-only helper | `capture_executes_once_and_an_identical_replay_does_not_touch_the_journal` (capture path), `refund_approval_is_bound_to_the_payment_and_a_replay_cannot_refund_twice` (refund path), `captured_void_needs_an_approval_and_a_replay_cannot_void_twice` (void path) |

Supporting evidence:

- `amount_envelope_rejects_negative_zero_and_out_of_range_values`
- `counters_must_advance_and_the_replay_window_is_bounded`
- `mismatched_approvals_are_rejected_before_guard_consumption`
- `intent_binding_mismatch_is_rejected_without_consuming_the_nonce`
- `replay_capacity_fails_closed_instead_of_evicting_nonces`
- `check_status_is_carried_to_the_void_guard`
- `an_amount_mismatch_is_always_rejected`

Run: `cargo test -p tirbase-pos`.

## 8. Known limits / next

- Replay state is in memory and caller-serialized. A multi-process or
  multi-terminal deployment needs a shared, transactional nonce/counter store;
  that adapter is not included.
- `max_nonce_entries` bounds the nonce table, so a long-lived desk eventually
  rejects new payments until its state is rotated or persisted. That is a
  deliberate fail-closed choice, not a production capacity plan.
- Epochs are opaque caller values. The desk enforces monotonic advancement but
  does not derive them from a boot counter, shift schedule or secure element.
- Approvals are bound to a terminal and requester, not to an epoch; the intent
  scope supplies the epoch binding for the payment itself.
- Partial payments, partial refunds and multiple captures are still outside the
  POS-03 intent model, so only full-amount operations are envelope-checked.
- The desk executes the POS-05 guard before the intent transition. If the intent
  transition then fails, the approval is already consumed; callers should treat
  a guard success plus intent failure as a manual-review state.
- No signature, MAC or secure transport is applied to the envelope. A deployed
  implementation must authenticate the terminal and protect the nonce/counter
  state outside this domain model.
