# ST-08 — Lockdown and M-of-N override

Crate: `tirbase-venue-lockdown` (AGPL-3.0-only). Depends on ST-06
(`tirbase-venue-capacity`) for the venue layout and limit scopes and on ST-05
(`tirbase-venue-ticket`) for approval keys and signatures. The engine reads no
clock and does no I/O; every call carries its instant.

## Signed commands

A `CommandRequest` names one `CommandAction`, one reason, one requester and a
window `[requested_at, expires_at)`, plus its own M:

| Action | Effect |
| --- | --- |
| `Lockdown { scope }` | venue-wide or one-zone lockdown until expiry |
| `ReleaseLockdown { scope }` | removes an active lockdown |
| `CapacityOverride { scope, headroom }` | approves extra headroom for one `LimitScope` until expiry |
| `EmergencyGateOpen { gate_id }` | break-glass for one gate until expiry |

Each approver signs domain-separated canonical bytes
(`TirBase/v1/VenueCommand`) covering:

```
key_id, request_id, action (tag + scope + headroom),
approvals_required, requested_by, reason, requested_at, expires_at,
approver identity, approved_at
```

That is **exact-action binding**: an approval for a venue lockdown cannot
authorise a release, another scope, a different headroom, a longer window or a
different reason. The signature also fixes the approver identity and instant,
so neither can be altered afterwards.

`SignedCommand::verify` enforces:

1. the command is inside its window (`Expired`);
2. no approver identity repeats (`DuplicateApprover`);
3. no signing key repeats (`DuplicateSigner`);
4. the approver is not the requester (`SelfApproval`);
5. approvals are not issued before the request (`ApprovalBeforeRequest`) or
   after its expiry (`ApprovalAfterExpiry`);
6. every signature verifies against the issuer key ring (`Signature`);
7. distinct valid approvals reach
   `max(request.approvals_required, policy.required_for(kind))`
   (`InsufficientApprovals`).

`ApprovalPolicy` sets a threshold per family (default two each). The request's
own `approvals_required` can only raise it, never lower it.

## Lockdown and fail-safe posture

`LockdownEngine::execute` verifies the command first and only then applies it.
A venue lockdown blocks ingress at every gate; a zone lockdown blocks ingress at
that zone's gates only. Egress is **never** blocked (`egress_allowed()` is
always true): the fail-safe posture is "closed to entry, open to leave".

`gate_posture(gate, at)` reports `Normal`, `Locked { reason, since, until }` or
`BreakGlassOpen { until }`. An approved break-glass opening for that gate wins
over a lockdown, so one named lane can be reopened without releasing the venue.

A lockdown cannot be replaced while active (`LockdownActive`); it ends at its
expiry, which `sweep(at)` applies. Releasing needs its own request and its own
approvals.

## Capacity overrides and break-glass

Both are grants with the same shape: an approved request, an exact scope, a
reason, a requester, the approver list, a grant instant and an expiry.
`capacity_override(scope, at)` and `break_glass(gate, at)` return only an active
grant; `sweep(at)` removes expired ones and records the expiry. One active grant
per capacity scope (`CapacityOverrideActive`) or per gate (`BreakGlassActive`).

## Audit and security events

Every execution produces one `SecurityEvent` with a monotonic sequence number,
instant, kind (`lockdown_engaged`, `lockdown_released`,
`capacity_override_granted`, `break_glass_opened`), request id, action, scope
(`venue:venue-1`, `zone:zone-north`, `capacity:gate:gate-n1`, `gate:gate-n2`),
actor (the requester), the full approver list and the reason. Every expiry adds
`lockdown_expired`, `capacity_override_expired` or `break_glass_expired` with
the same attribution. The log retains 1,024 events, dropping the oldest and
counting the drops.

Re-executing an already executed request id returns `AlreadyExecuted` and
changes nothing; the executed-id memory is bounded.

## Tests

`tirbase-venue-lockdown/tests/st08_lockdown.rs` (12 tests):

* lockdown refuses one approval against a policy of two and engages with two,
  recording requester, approvers and reason, and blocking ingress/keeping egress;
* a zone lockdown blocks only its zone;
* release cannot reuse lockdown approvals — both copied signatures and a
  tampered action fail signature verification, and a freshly approved release
  works and names the released request in its audit event;
* self-approval, duplicate approver identities and duplicate signing keys are
  each refused;
* approvals are bound to the exact action: changing a capacity headroom after
  signing fails verification and leaves the original grant intact;
* commands expire, approvals issued after expiry are refused, and break-glass
  closes at its expiry with a sweep event;
* capacity overrides and break-glass need their own two approvals, open one
  gate only, and expire on the sweep;
* four different overrides produce four ordered security events with request
  ids, actor, approvers, action, scope and reason;
* per-family thresholds: release with two approvals fails under a release
  threshold of three, and succeeds with three;
* eight threads executing one approved lockdown command produce exactly one
  execution and one `lockdown_engaged` event; eight distinct break-glass
  commands on different gates all execute;
* invalid requests, unknown zones/gates, venue mismatch, releasing an unlocked
  venue, re-execution and a second active lockdown are all refused.

No live gate hardware or gateway was exercised; the engine is pure and every
path is driven through signed commands and typed decisions.
