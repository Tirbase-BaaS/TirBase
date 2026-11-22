# ST-06 — Capacity envelopes

Crate: `tirbase-venue-capacity` (AGPL-3.0-only). Depends on ST-01
(`tirbase-venue`) for identifiers and on ST-05 (`tirbase-venue-ticket`) so an
admitted ticket is the natural idempotent ingress event. The engine reads no
clock and performs no I/O: every call carries its instant.

## Envelopes

`CapacityConfig` holds one mandatory venue-wide `CapacityLimit`, optional
zone limits with their gate membership, and optional per-gate limits. A gate
must belong to exactly one zone; a gate limit for a gate in no zone, a gate
claimed by two zones, or a zone with no gates is a configuration error.

`CapacityLimit { soft, hard, hard_policy }` with `soft <= hard`:

| Threshold | Decision |
| --- | --- |
| `occupancy > soft` | admit + `Alarm::SoftLimit` |
| `occupancy > hard`, `HardPolicy::Alarm` | admit + `Alarm::HardLimit` |
| `occupancy > hard`, `HardPolicy::Reject` | `Denial::HardLimit` unless an override covers it |

Ingress is checked against the gate, then its zone, then the venue; the first
rejecting envelope refuses the passage and leaves occupancy unchanged. Egress
is always allowed, except that egress with nobody counted in the zone (or
venue) is refused as `Denial::EgressUnderflow`.

Occupancy is tracked per zone and per gate. The venue total is the sum of the
zone counts. A gate's count is the net of ingress and egress *through that
gate* — a lane flow counter, not the physical headcount behind the gate — and
never goes below zero; egress at a gate with no outstanding ingress raises
`Alarm::GateUnbalanced` instead of underflowing.

## Idempotent counting

`PresenceEvent::event_id` is the idempotency key. A repeated event returns
`Decision::Duplicate` and changes nothing, whether it is an ingress or an
egress. Only *counted* events are remembered, so a refused passage can be
retried (after an override or a corrective egress) without being mistaken for
a duplicate.

`PresenceEvent::from_admission` derives the id as
`ticket:<ticket_id>#<nonce>` from an ST-05 `Admission`, so a retried delivery
of the same admitted ticket cannot inflate occupancy, even across a reader
restart. Ticket signature, revocation and replay remain ST-05's job; this layer
trusts a verified admission.

The idempotency memory is bounded: `with_dedupe(capacity, retention_us)`
accepts 1..=1,000,000 ids and 1h..=30 days retention (default 100,000 ids /
24 h), prunes by retention and evicts the oldest when full, counting
`seen_dropped()`. A duplicate older than the retention window can therefore
count again; deployments size retention to the event horizon.

## Reconciliation

`reconcile(&Observation)` compares counted zone occupancy with:

* `ObservationKind::Turnstile { ingress_total, egress_total }` — cumulative
  counters, implying `ingress - egress`;
* `ObservationKind::Occupancy { occupancy }` — an absolute sensor reading.

It returns a `ReconciliationReport` with `tracked`, `observed`, `delta` and
`ReconciliationStatus::{Agree, ObservedHigher, ObservedLower}`. It changes
nothing.

`adopt_observation(observation, actor, reason)` replaces the zone's counted
occupancy with the observation, requires a non-empty actor and reason, writes
an `AuditAction::ReconciliationAdopted` entry, recomputes the venue total, and
re-evaluates the zone and venue envelopes against the adopted figure. An
over-capacity adoption therefore alarms (`Alarm::HardLimit`/`SoftLimit`) and a
disagreeing one raises `Alarm::SensorDisagreement` — a correction cannot hide a
breach.

## Overrides

`OverrideGrant` requires a requester and a *different* approver, a non-empty
reason, `expires_at > granted_at`, a positive headroom and a positive maximum
use count, and a scope that exists in the envelope. A second active override
for the same scope is refused (`OverrideAlreadyActive`).

An active override admits passages whose attempted occupancy is at most
`hard + max_headroom`, for at most `max_uses` passages. Each use increments the
override's use count, records `last_used_at_utc_us`, raises
`Alarm::OverrideUsed`, and writes an audit entry naming the override, the gate
that used it and the event. `CapacityOverride::state(now)` reports `Active`,
`Exhausted`, `Expired` or `Revoked`; revoked and exhausted states are checked
before the deadline.

`sweep(now)` audits newly expired overrides (`AuditAction::OverrideExpired`)
and returns their ids. `revoke_override(id, actor, reason, at)` records an
attributable revocation.

## Audit

`AuditEntry { seq, at_utc_us, action, actor, scope, reference, detail }`
records grants, uses, revocations, expiries and reconciliation adoptions. The
log retains 512 entries, dropping the oldest and counting `audit_dropped()`, so
a reader can see that history was lost.

## Tests

`tirbase-venue-capacity/tests/st06_capacity.rs` (15 tests):

* counting: ingress/egress across gate, zone and venue; duplicate ingress and
  duplicate egress change nothing; a refused event can be retried; egress with
  nobody inside is refused and a gate with no ingress is flagged;
* limits: hard limit rejects at the gate while another gate in the same zone
  still admits; hard-alarm admits and alarms; soft limit alarms without
  refusing; the venue envelope refuses across zones;
* overrides: separation of duties, malformed grants, unknown scope,
  duplicate active scope, attributed use audited, exhaustion, expiry sweep,
  revocation, and that an override does not survive its deadline;
* reconciliation: turnstile and sensor agreement, an over-reading sensor
  adopted with audit and an over-capacity alarm, a low reading adopted
  downwards, lagging turnstile totals, and the actor/reason/zone checks;
* concurrency: eight threads × 250 unique events through one `Mutex`-guarded
  engine reach exactly 2,000 at gate, zone and venue, and eight threads
  presenting the same event count it exactly once;
* bounded duplicate detection: a replay after the retention window counts again
  and is reported through the drop counter.

No live turnstile, sensor or gateway was exercised; the engine is pure and
every source behaviour is exercised through its typed events and observations.
