# POS-05 — Refund, discount and void guard (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-05 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no persistence or terminal connectivity.

**Record ID:** POS-05-GUARD-0001
**Date (UTC):** 2026-11-16
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01, F-03
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Refund caps by operator, terminal, day and check | `ApprovalGuard::authorize_refund`, `RefundCaps` |
| 2 | Percentage/absolute line and check discount caps with stacking | `ApprovalGuard::authorize_discount`, `DiscountCaps`, `StackingPolicy` |
| 3 | Void approval for captured payments and closed checks | `ApprovalGuard::authorize_void`, `VoidRequest` |
| 4 | M-of-N approval bound to check, amount, currency, reason and expiry | `Approval`, `ApprovalAction`, `request_approval` |
| 5 | No self-approval; single-use approvals | `approve`, `consume_approval` |
| 6 | Property tests for caps, expiry, role matrix and single-use concurrency | `tests/pos05_properties.rs` |

POS-05 is an authorization layer. It does not change POS-01's check state
machine, so a closed-check reversal still follows the POS-01 refund path after
the guard has approved the operation.

## 2. Refund caps

`RefundCaps` configures four non-negative amounts in the guard currency:

| Cap | Bucket |
|---|---|
| `per_operator` | `EmployeeId` |
| `per_terminal` | `TerminalId` |
| `per_day` | UTC day derived from the caller time (`BusinessDay`) |
| `per_check` | `CheckId` |

A refund is allowed only when adding its amount would leave every bucket at or
below its cap. Caps are inclusive: exactly at the cap is allowed. A successful
authorization updates all four buckets. A denied authorization updates none of
them, even though it appends a security event.

The day is a deterministic UTC day (`millis.div_euclid(86_400_000)`), not a
jurisdiction-local business day. A deployment needing local midnight must pass a
timestamp adjusted to its chosen day boundary or supply a separate policy layer.

A cap breach requires an approval. If one is supplied, it must be ready,
unexpired, unconsumed and bound to the same check, amount, currency and reason.

## 3. Discount caps and stacking

`DiscountCaps` holds one cap for line scope and one for check scope. Each cap has
a percentage (`Rate`) and an absolute amount (`Money`). The amount caps must use
the guard currency.

`StackingPolicy`:

| Policy | Rule |
|---|---|
| `Deny` | Reject if any existing discount is present |
| `Additive` | Add existing and requested percentages and amounts; both totals must fit the cap |
| `BestOf` | The requested discount must be strictly better than the existing amount total; it replaces the existing discounts for cap checking |

A discount request supplies the base amount, requested `DiscountKind`, existing
discounts on the same base, the check rounding mode and a reason. Percentage
discounts are rounded with that check rounding mode before cap comparison.
Absolute amount discounts must match the guard currency and must not be
negative. The requested and existing totals may not exceed the base.

Cap breaches may be overridden by a matching `Discount` approval. Stacking
policy denials are structural and are not overrideable. If an approval is
supplied for a below-cap discount, it is validated and consumed; an approval is
single-use whenever it is presented.

## 4. Void approval

`VoidRequest` identifies either the whole check or one payment, the amount, the
current check status and, for a payment, its current payment status.

Approval is required when:

- the check status is `Closed`; or
- the payment status is `Captured`.

Voiding an authorized (not captured) payment, or an open/held check, needs no
approval. A payment target without a payment status is rejected as
`InvalidRequest`. The approval action must be `VoidCheck` or the exact
`VoidPayment(PaymentId)`.

The guard records the authorization decision and consumes the approval. The
caller remains responsible for applying the corresponding POS-01/POS-02
operation; a closed check's underlying reversal path is still a refund because
POS-01 does not permit `Closed → Voided`.

## 5. Approvals

Approvals are stored by caller-supplied `ApprovalId`. An approval request is
bound to:

- action (`Refund`, `VoidCheck`, `VoidPayment`, `Discount` + optional line);
- check;
- amount and therefore currency;
- reason;
- requester and terminal;
- expiry.

The eligible approver set is snapshotted from operators registered with an
approving F-03 role, excluding the requester. The role values mirror F-03
`Supervisor`, `Qa`, `Admin` (the roles with the normal `Approve` permission);
`Operator`, `Auditor`, `Integrator` and `BreakGlass` are denied. Registering an
approver after a request does not add them to that request.

M-of-N:

- `ApprovalGuard::new` sets `required_approvals` (M).
- N is the number of eligible approvers in the request snapshot, excluding the
  requester.
- A request is refused with `ApprovalPoolTooSmall` if M exceeds N.
- Each approver may sign once; a duplicate is denied.
- The requester cannot sign their own request.
- The request becomes `Ready` at exactly M signatures. Further signatures are
  denied as `ApprovalNotPending`.

An approval can be consumed once. Consumption checks expiry, readiness,
consumption state and every binding field before marking the approval
`Consumed`. A mismatched operation does not consume it, so the caller can retry
with the correct binding before expiry.

## 6. Security events

Every denied guard operation appends one `SecurityEvent` with a dense sequence
starting at 1. Configuration errors from constructors are the only errors that
do not have an operation context and therefore do not append an event.

Stable denial codes include:

| Code | Meaning |
|---|---|
| `refund.cap.operator` | Operator refund cap exceeded |
| `refund.cap.terminal` | Terminal refund cap exceeded |
| `refund.cap.day` | Day refund cap exceeded |
| `refund.cap.check` | Check refund cap exceeded |
| `refund.usage_overflow` | Usage arithmetic overflow |
| `discount.cap.line.percent` | Line percentage cap exceeded |
| `discount.cap.line.amount` | Line absolute cap exceeded |
| `discount.cap.check.percent` | Check percentage cap exceeded |
| `discount.cap.check.amount` | Check absolute cap exceeded |
| `discount.stacking_denied` | Stacking policy rejected the combination |
| `discount.base_exceeded` | Discounts exceed the base |
| `void.approval_required` | Captured payment/closed check void needs approval |
| `approval.not_found` | Approval id not found |
| `approval.expired` | Approval expired |
| `approval.already_used` | Approval already consumed |
| `approval.not_ready` | Fewer than M signatures |
| `approval.binding_mismatch` | Action/check/amount/reason mismatch |
| `approval.self_not_allowed` | Requester tried to approve their own request |
| `approval.role_denied` | Role not permitted or not in the snapshot |
| `approval.duplicate_approver` | Same approver signed twice |
| `approval.pool_too_small` | Fewer than M eligible approvers |
| `approval.invalid_expiry` | Expiry not after request time |

Display text and details are diagnostic; policy should key on `DenialCode`.

## 7. Acceptance evidence

| POS-05 "done when" | Evidence |
|---|---|
| Above-cap operations fail without a valid approval | `refund_caps_are_enforced_independently_for_each_dimension`, `discount_caps_stack_and_allow_approved_overrides`, `above_cap_refund_needs_m_of_n_and_consumes_the_approval` |
| An expired approval cannot be reused | `expired_and_unready_approvals_are_denied`, `approvals_are_usable_only_before_expiry` |
| Every denial emits a security event with a stable reason code | `role_matrix_and_denial_events_are_stable`, `invalid_request_contexts_are_denied_with_events`, `requester_only_pool_is_too_small_and_denied_with_an_event`, `refund_caps_hold_for_arbitrary_request_sequences` |

Supporting evidence:

- `approval_binding_and_void_rules_are_exact`
- `role_matrix_matches_f03_permissions`
- `a_single_approval_authorizes_at_most_one_refund`

Run: `cargo test -p tirbase-pos`.

## 8. Known limits / next

- The guard is in-memory and caller-serialized. There is no persistence,
  cross-process transaction, or distributed nonce store for concurrent
  terminals; that belongs to the deployment adapter.
- The role enum mirrors F-03 semantics rather than linking the F-03 token
  verifier. Authentication and capability verification happen before the guard.
- Refund day buckets are UTC. Local business-day boundaries are not modelled.
- Discounts are authorized, not applied; POS-01 has line discounts but no
  check-level discount field. A check-level discount adapter is future work.
- A closed-check void approval covers the authorization decision; POS-01 still
  enforces its own `Closed → Refunded` path and rejects `Closed → Voided`.
- Approval consumption occurs at authorization. If the caller's subsequent
  order command fails, the approval is already consumed; callers should apply
  the authorized command immediately or request a new approval.
- F-05 signing of approval/security events is not wired in; the local event log
  is not a cryptographic attestation.
