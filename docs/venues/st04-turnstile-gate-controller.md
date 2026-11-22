# ST-04 — Turnstile and gate controller

Crate: `tirbase-venue-gate` (AGPL-3.0-only). Depends on ST-01
(`tirbase-venue`) and ST-03 (`tirbase-venue-access`). The controller owns no
hardware: it queues `DriveCommand`s for the caller and folds `PositionFeedback`
back in, so the same state machine drives a real lane controller or the
simulator.

## Mechanism

`GatePosition`: `Locked`, `Unlocked` (lock released, nobody passed yet),
`Open` (driven open / free-wheeling), `Unknown` (sensor fault or power-up).

`DriveCommand`: `Unlock` (one authorised passage), `Lock`, `Release` (egress /
fail-safe free-wheel).

Normal flow:

1. `present` authorises the credential, arms a one-shot permit with an expiry
   and queues `Unlock`.
2. the lane reports `Unlocked`;
3. `passage` consumes the permit, reports `Open` and schedules the close at
   `open_hold_us`;
4. `tick` past the hold queues `Lock` and arms the lock timeout;
5. feedback `Locked` clears the timeout, otherwise the lock timeout raises a
   fault.

## Fail mode (explicit)

```rust
pub enum FailMode { FailSafe, FailSecure }
```

`FailMode` has **no default**: both `GateConfig::new` and `serde` deserialization
require it. A configuration document without `fail_mode` is rejected.

| Mode | Safe state | Power-loss position | Actuator |
| --- | --- | --- | --- |
| `FailSafe` | `Released` | `Unlocked` | `Release` |
| `FailSecure` | `Secured` | `Locked` | `Lock` |

`power_loss` withdraws the permit, clears queued commands, drives the configured
safe command and reports `PowerLost { safe_state }`. While unpowered, every
presentation is refused with `PowerOff`, and `power_restore` re-establishes the
position from feedback (or keeps the egress release if a fire alarm is active).

## Offline decision path

`present` calls the ST-03 `AccessController`, which resolves cached grants,
revocation and reader health locally. A reader that has never reached the back
office keeps:

* the versioned revocation list and its cached grants (`OfflineCache`);
* its local audit log (below), which can be persisted with `audit_json` and
  restored with `restore_audit`.

A grant taken from the offline cache is reported as
`GateDecision::grant.offline == true`.

## One passage, no replay

Three independent guards run before any access decision:

1. **Reader nonce** — `Presentation { credential, nonce }` must carry a
   strictly increasing nonce per card fingerprint. A repeated or lower nonce is
   `ReplayRejected` and audited as `Replayed`.
2. **Outstanding permit** — a second presentation while a permit is armed is
   `PassageInProgress` (one lane, one passage).
3. **Local re-use interval** — after a passage, the same card cannot open the
   lane again for `reuse_interval_us`, which holds even when the offline cache
   would otherwise allow it (`ReuseTooSoon`).

A permit is consumed exactly once by `passage`; a passage with no permit is
`NoActivePermit` and audited as `UnpermittedPassage`.

## Bounded timeouts

`GateTimings` validates each value: positive and at most `MAX_TIMEOUT_US` (two
minutes) for permit/open-hold/lock timeouts, and at most `MAX_REUSE_US` (one
hour) for the re-use interval. There is no "unbounded" option.

| Timeout | Effect |
| --- | --- |
| `permit_timeout_us` | permit withdrawn, `Lock` queued, `PermitExpired` |
| `open_hold_us` | `Closing`, `Lock` queued, lock timeout armed |
| `lock_timeout_us` | lock not reported engaged → `LockTimeout` + fault |

## Tamper and fire alarm

* Tamper feedback (or `observe_tamper`) latches immediately; presentations are
  refused with `TamperLatched` until `clear_tamper(true)`. An unauthorised reset
  is an error.
* The fire-alarm input releases egress on **both** fail modes (life safety
  overrides fail-secure, which governs power loss only): `Release` is queued,
  the lane reports `Open`, entry is refused with `FireAlarmActive`, and clearing
  the input re-secures the lane and arms the lock timeout.

## Position faults

Feedback is checked against the positions the current phase allows:

* permit armed or closing → `Unlocked`/`Open`;
* fire alarm → `Open`/`Unlocked`;
* otherwise → `Locked`.

Anything else increments `faults`, sets the position to `Unknown`, and emits
`PositionFault { expected, reported }`. A lane that never releases, a lane that
never re-locks and a dead position sensor all surface this way, and `GateHealth`
becomes `degraded`.

## Local audit

`AuditLog` is bounded (`audit_capacity`) and hash-chained: each entry's SHA-256
digest covers its sequence, time, gate, credential id, card fingerprint, action,
detail and the previous digest. `verify()` recomputes the retained chain;
`from_json` refuses a log whose chain does not verify, and the controller refuses
a log belonging to another gate. Evicted entries are counted in `dropped`.

## Health and events

`GateHealth` (gate, position, fail mode, safe state, power, tamper, fire alarm,
permit outstanding, faults, degraded flag, last event sequence, dropped events,
audit counts) and `GateEvent` (`serde` tagged) are the stream to the guard
console and venue gateway. Both `GateEvent` and `GateHealth` are `Serialize`/
`Deserialize`; `drain_events()` hands the batch to the transport. The stream is
bounded by `event_capacity` and reports `events_dropped`.

## Simulator and fault injection

`GateSim` models the lane: it applies commands, reports position and tamper, and
falls to the configured safe state on `power_cut`. `Faults` injects:

| Fault | Behaviour |
| --- | --- |
| `stuck_locked` | unlock/release ignored |
| `stuck_open` | lock leaves the lane unlocked |
| `no_lock_engage` | lock engages but never reports it |
| `sensor_dead` | feedback reports `Unknown` |

## Tests

`tests/st04_gate.rs` (14 tests):

* offline cached grant opens the lane exactly once, then a replay and a re-use
  are refused without a second `Unlock`;
* power loss lands both fail modes in their configured safe state, refuses
  credentials while off, and the simulator agrees;
* `fail_mode` is required in a configuration document and timeouts are bounded;
* fire alarm releases egress and clears back to a secured lane;
* permit expiry, open-hold re-lock, lock timeout, stuck-locked, stuck-open and
  dead-sensor paths;
* tamper latch and authorised reset; unpermitted passage; wrong-gate refusal;
* audit chain verification, restart restore and detection of an edited entry;
* bounded event stream with a dropped-event count.

## Limits

* No real lane controller, lock or barrier was exercised: all tests use
  `GateSim`. A HIL campaign against the selected lane hardware is the F-13
  deployment step.
* The controller decides and commands; it does not implement the actuator bus,
  the loop detector wiring or the fire panel interface. Those belong to the
  deployment's lane driver, which must map `DriveCommand`/`PositionFeedback`
  faithfully.
