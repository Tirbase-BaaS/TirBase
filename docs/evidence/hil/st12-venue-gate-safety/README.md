# ST-12 venue gate HIL safety evidence pack

**Scope:** gate controller, reader, turnstile and 24 V supply bench; power-cut,
brownout, network-loss and clock-jump cases; fail-safe/fail-secure safety-state
verification; emergency egress/fire-alarm input; long-run durability and
event-flood evidence.

**Licence:** the crate, harness, tests and this pack are **AGPL-3.0-only**.
A physical safety assessment (risk assessment, SIL/PL determination, actuator
inspection, fire-panel interface and site acceptance) is a **separate commercial
engagement** with a competent assessor and is not included in this repository.
This pack is test evidence, not a safety certification.

**Reference run:** [`campaign.json`](campaign.json) and
[`campaign.md`](campaign.md), 32 cases, seed `12`, digest
`40d212bba98f9358702db814453629b8163c7ff87f21ece6f184984165a35fa6`.
`tirbase-venue-hil/tests/st12_hil.rs::committed_evidence_matches_a_fresh_run`
fails CI if a behaviour change moves that digest without regenerating this pack.

## 1. Reproduce

```bash
cargo test -p tirbase-venue-hil
cargo run -p tirbase-venue-hil --bin venue-hil-campaign -- \
  --out docs/evidence/hil/st12-venue-gate-safety
```

The campaign is deterministic: all time is supplied explicitly, all cards are
fixtures, and no wall clock or random source is read. Regenerating on the same
commit produces the same digest. The test suite additionally writes
`target/hil-evidence/st12/` on every run.

## 2. Bench composition

| Component | Model / production path |
|---|---|
| Gate controller | Production `tirbase_venue_gate::GateController` (ST-04), unchanged. |
| Reader + access decision | Production `tirbase_venue_access::AccessController` (ST-03); the bench reader has independent power and a back-office link. |
| Turnstile | Physical model with a bounded drive hold and an independent watchdog. A fail-secure lane springs locked when the drive is not refreshed; a fail-safe lane is released. |
| Power supply | Scriptable 24 V supply; shallow sag leaves controller/actuator powered but drops the reader link, deep sag cuts all rails and resets the controller. |
| Safety clock | Monotonic decision time plus an independent wall clock. Wall jumps are recorded and never reach the gate. |

The bench starts locked and powered for both fail modes. `FailMode` is required
by configuration (ST-04); the bench never infers it.

## 3. Safety semantics

| Condition | Fail-safe | Fail-secure |
|---|---|---|
| Power loss at any stage | `Released` / `Unlocked` | `Secured` / `Locked` |
| Deep brownout | same as power loss | same as power loss |
| Shallow brownout | reader link drops; actuator bounded drive | reader link drops; actuator bounded drive |
| Software stops ticking | lane remains passable by design | watchdog returns the lane to `Locked` |
| Fire-alarm input | `Open` (egress) | `Open` (egress overrides fail-secure) |
| Fire alarm cleared | re-secure to `Locked` | re-secure to `Locked` |
| Stuck-open actuator + power cut | released safe state | physically `Locked` despite the fault |

Ingress is refused while the fire alarm is active and while the controller is
unpowered. Egress is never blocked by the gate.

## 4. Case matrix

The committed report contains:

- **Bench:** composed controller, reader, turnstile and supply.
- **Power loss (12):** both fail modes × six operating stages — idle, reader
  tap, permit armed, actuating, passage and re-closing. Every case asserts the
  controller and physical turnstile positions equal the configured safe state,
  the reader is unpowered, and no unlock remains queued.
- **Brownout (4):** shallow and deep, both fail modes. Deep sag asserts the safe
  state; shallow sag asserts the reader link drops and the bounded actuator
  returns to its fail-mode state.
- **Network loss (3):** no cached grant stays locked and recovers online; a
  primed cached grant works offline; losing the back office while open still
  re-secures at the open-hold boundary.
- **Clock jump (2):** wall +1 day cannot extend a permit; wall −1 day cannot
  extend the passage hold. Gate time remains monotonic in both.
- **Safety state (4):** a stalled controller for 13 s leaves a fail-secure lane
  physically locked; a stuck-open mechanism cut from power still reaches the
  configured safe state, in both fail modes.
- **Emergency egress (4):** fire input with power and after a power cut, both
  fail modes; egress opens, entry is refused and clearing re-secures.
- **Durability (2):** 600 passage cycles with bounded audit/event buffers,
  verified audit chain and restore; 5,000 tamper rounds producing 10,000 events
  with bounded retention and an intact chain.

## 5. Physical lab execution

The software bench is the reproducible part. A physical campaign uses the same
case list on the bench in `docs/reference-hardware.md` and
`docs/hil-lab-checklist.md`:

1. Record controller, reader, turnstile and PDU model/serial/firmware; record the
   configuration and fail mode of every lane.
2. Confirm the actuator's de-energised position with a manual power removal
   before connecting any credential path. Do not rely on software for this step.
3. Execute the six power-cut stages for each fail mode with the PDU; for every
   cut capture PDU timestamp, controller boot/reconciliation log, physical
   position, and the audit/event exports.
4. Run shallow (20 V) and deep (16 V) sags at the same points; verify the reader
   link loss and the actuator response.
5. Apply and clear the fire-alarm input while powered and after a power cut;
   verify forced egress and re-secure. The fire panel remains the authority.
6. Hold the controller heartbeat/drive refresh for longer than the watchdog
   window and verify a fail-secure lane physically locks; verify the fail-safe
   lane remains passable.
7. Run the long-run and event-flood profile, archive the audit/event exports and
   verify their chains.
8. Attach the results under `docs/evidence/hil/<date>-venue-gate/` with a
   manifest and summary. Do not mark physical HIL proven until an assessor has
   reviewed it.

## 6. Limits and non-claims

- The bench is a deterministic software model; it does not prove actuator
  force, spring return, wiring, PSU hold-up, reader RF/OSDP interoperability or
  fire-panel electrical compatibility. Those require the physical campaign.
- No SIL/ASIL/PL claim is made. The fire system is external and authoritative;
  this bench only verifies the gate's response to its input.
- The reader transport in the software bench is the ST-03 access decision path;
  a vendor OSDP/DESFire interoperability run is still required.
- The evidence pack is reproducible only for the same commit, fixture seed and
  case list.
