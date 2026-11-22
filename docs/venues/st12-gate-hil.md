# ST-12 — Gate HIL, safety, power and network

**Status:** complete (software bench and evidence pack). **Licence:**
AGPL-3.0-only tests and bench. Physical safety assessment is commercial.
**Crate:** `tirbase-venue-hil`. **Depends on:** ST-03 (`tirbase-venue-access`),
ST-04 (`tirbase-venue-gate`), F-13 lab procedure.

ST-12 turns the ST-04 lane controller into a repeatable HIL bench: the
production controller and access decision path run against a reader with its own
power/link, a physical turnstile with an independent watchdog, a scriptable 24 V
supply and a monotonic safety clock. The bench covers power loss at every
operating stage, brownout, network loss, clock jumps, fail-safe/fail-secure
verification, emergency egress/fire input, long-run durability and event floods.

The **physical lab** remains a separate step. This crate's evidence is
deterministic software evidence; a post-campaign physical safety assessment is a
commercial engagement with a competent assessor. No SIL/ASIL/PL claim is made.

## Bench architecture

```text
 Bench reader ──(card presentation)──▶ ST-03 AccessController
       │                                      │
       │ power / back-office link             ▼
       │                              ST-04 GateController
       │                                      │ DriveCommand
       ▼                                      ▼
 24 V supply ──────────────────────────▶ Turnstile model
       │                                      │
       └──────── power cut ───────────────────┘
                                              │ position/tamper feedback
                                              ▼
                                       safety state audit/event

 SafetyClock: wall jumps are logged; gate decisions use monotonic time only.
```

The controller is the production `GateController`; no duplicated decision or
transition logic exists in the bench. The physical models add the parts the
controller deliberately does not own: the actuator's bounded drive, its safe
state on de-energisation, the reader rail/back-office link and the supply.

### Turnstile watchdog

The turnstile drive has a **12 s** bounded hold, longer than the controller's
5 s open hold and 10 s permit timeout. If controller software stops ticking or
refreshing the drive, a fail-secure lane physically returns to `Locked`; a
fail-safe lane remains `Unlocked` by design. A power cut overrides even an
injected stuck-open actuator and returns the configured safe state. This is the
bench's proof that a software fault cannot hold a fail-secure gate open
indefinitely.

### Power and network

| Event | Behaviour |
|---|---|
| Power cut at any operating stage | Controller queues the safe drive command, both controller and turnstile land in the configured safe position, reader is unpowered. |
| Deep brownout (< 19 V) | Treated as a power cut; configured safe state. |
| Shallow brownout (20 V) | Controller and actuator stay powered; reader back-office link drops; actuator watchdog remains bounded. |
| Back-office loss, no cache | Credential denied, lane stays locked, recovery is online again. |
| Back-office loss, primed cache | Cached offline grant works; lane unlocks once. |
| Back-office loss while open | Lane still re-secures at the open-hold boundary. |
| Wall clock +1 day | Cannot extend a permit. |
| Wall clock −1 day | Cannot extend the passage hold. |

The gate's decision time is monotonic. The wall-clock jump count is recorded in
the bench evidence; it is never substituted for the decision time.

## Safety states

`FailMode` is required explicitly (ST-04) and must be selected for each lane.

| Mode | Safe state | Unpowered position | Safe command |
|---|---|---|---|
| Fail-safe | Released | Unlocked | `Release` |
| Fail-secure | Secured | Locked | `Lock` |

The fire-alarm input is a life-safety override on **both** modes: it queues
`Release`, opens the lane, refuses entry and, when cleared while powered,
re-secures the lane. A fire input after a power cut is honoured on restore.

## Evidence and reproduction

The committed pack is
[`docs/evidence/hil/st12-venue-gate-safety/`](../evidence/hil/st12-venue-gate-safety/):
32 cases, seed 12, SHA-256 digest
`40d212bba98f9358702db814453629b8163c7ff87f21ece6f184984165a35fa6`.

```bash
cargo test -p tirbase-venue-hil
cargo run -p tirbase-venue-hil --bin venue-hil-campaign -- \
  --out docs/evidence/hil/st12-venue-gate-safety
```

The second command rewrites `campaign.json` and `campaign.md`. The test
`committed_evidence_matches_a_fresh_run` recomputes the campaign and fails CI if
the committed digest no longer matches the code.

The physical campaign uses the same six power stages, brownout points, fire
input, watchdog and long-run cases on the bench in
`docs/hil-lab-checklist.md`; capture PDU timestamps, boot/reconciliation logs,
physical positions, and audit/event exports. See the evidence README for the
step-by-step lab procedure. The bench approximates no physical quantities:
actuator force, spring return, PSU hold-up, reader RF/OSDP interoperability and
fire-panel compatibility must be verified on hardware.

## Tests

`tirbase-venue-hil/tests/st12_hil.rs` (6 tests):

- every fail mode × every operating stage reaches the configured safe state on
  power loss;
- a stalled controller leaves a fail-secure turnstile locked via the actuator
  watchdog;
- fail-safe releases on power loss while fire alarm overrides fail-secure;
- wall-clock jumps do not move gate decisions;
- the 32-case campaign is reproducible and covers every category;
- the committed evidence digest matches a fresh run.

## Limits

- No real lane controller, lock, turnstile, reader or PDU is exercised by the
  software bench. That is the physical campaign, and it is not claimed here.
- No physical safety assessment, SIL/PL determination, fire certification or
  site acceptance is included. Those are commercial and external.
- The reader model drives the ST-03 access path, not a vendor OSDP/DESFire
  transport; interoperability still needs the lab.
