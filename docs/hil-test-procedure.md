# HIL Test Procedure (PV-27, CLAIM-52.4)

**Status:** BLOCKED — lab hardware acquisition required (RD-7). This document defines the lab setup and execution procedure for the maintainer-triggered HIL workflow; it cannot be fully executed until hardware is provisioned per `docs/reference-hardware.md`.

## Scope

Hardware-in-the-loop validation against real devices/bus (not simulation-only), covering:

- Modbus RTU round-trips: FC 03 (Read Holding Registers), FC 04 (Read Input Registers), FC 06 (Write Single Register), FC 16 (Write Multiple Registers) (CLAIM-52.2).
- Envelope rejection with a real out-of-range command observed on hardware (CLAIM-52.2, PV-4.6).
- Power-cut failpoints: cut at intent/actuating boundary and cut at completion boundary; verify ledger reconciliation and no un-audited actuation on restart (CLAIM-52.3, PV-5.3/PV-9.3).

## Lab setup (per `docs/reference-hardware.md`, profile d + c)

1. **Gateway (profiles a/b as applicable):** Raspberry Pi 4 Model B (1 GB) running the release gateway binary/config used for the campaign. For Level 2 assurance tests, provision the TPM2 add-on unit (profile b).
2. **Field bus (profile d):** USB RS-485 adapter connected to a Modbus RTU device or a hardware simulator on a real RS-485 bus. Record adapter chipset/driver, serial parameters (baud, parity, stop bits), unit ID(s), and the register map under test.
3. **Power-fault rig (profile c):** Smart PDU with scriptable power cycling controlling the gateway (and, where required by the scenario, the bus/device). Ensure time-synchronized logging between PDU events and gateway logs.
4. **Network/observability:** Local console or SSH (pre-cut) to collect `/var/lib/tirbase` state, security event logs, and journal output after each cycle. Do not rely on connectivity that the PDU cut will remove unless the scenario explicitly tests partition behavior.

## Pre-flight checklist

- [ ] Hardware inventory recorded (identifiers match `docs/reference-hardware.md` lab checklist).
- [ ] Gateway flashed/deployed with the commit-under-test; config and key material staged; `primary.db`/`derived.db` paths known.
- [ ] Modbus register map and safe envelope/profile installed for the target device; safe-default behavior confirmed.
- [ ] Baseline health: `GET /health` OK, metrics reachable on loopback, device reachable over RS-485, and a known-good read round-trip succeeds.
- [ ] PDU control script verified (cut/restore) without the DUT first.

## Execution

### 1. Modbus FC 03/04/06/16 round-trips (CLAIM-52.2)

Run the maintainer-triggered workflow/job (or local harness) that executes `tests/hil/modbus_roundtrip.rs` against the configured serial endpoint/register map:

1. **FC 03 (Read Holding Registers):** issue a read within envelope; verify decoded values match device/register-map expectations and the transaction is logged.
2. **FC 04 (Read Input Registers):** read input registers; verify values and response framing.
3. **FC 06 (Write Single Register):** write an in-envelope value; read back to confirm actuation/state and `Complete`/expected effect semantics.
4. **FC 16 (Write Multiple Registers):** write a contiguous in-envelope block; read back and verify all registers.
5. Record raw frames/traces and gateway security/audit events for each function code.

**Pass:** all four function-code round-trips succeed with correct read-back and no guard/security violations for in-envelope operations.

### 2. Envelope rejection with a real out-of-range command (CLAIM-52.2)

1. With the same envelope/profile active, submit a command whose target value is outside the permitted bounds (or violates the configured constraint) through the production command path.
2. Observe the guard rejection (coarse reason/category per policy), confirm **no** actuation frame is applied to the device (read-back unchanged/safe), and confirm a `SecurityEvent`/decision record is emitted.

**Pass:** out-of-range command is rejected, device state remains within the prior safe/envelope state, and the rejection is auditable.

### 3. Power-cut failpoints (CLAIM-52.3)

Perform each cut with the PDU while capturing timestamps:

1. **Power-cut at intent/actuating:** trigger an in-envelope actuation and cut power at the actuating boundary (before durable completion). Restore power and allow boot reconciliation to run.
2. **Power-cut at completion:** cut power at/around the completion boundary and restore.

For each run verify:
- `applied_effects_ledger` / reconciliation resolves entries to a terminal/consistent state (no stuck `Actuating` without reconciliation outcome as defined by PV-5.3), with `Unknown` blocking/handling per policy where applicable.
- No duplicate/un-audited actuation beyond idempotent/declared semantics.
- Security/event log and hash-chain integrity checks behave per PV-7 after restart.

**Pass:** deterministic, auditable recovery with no silent loss or unbounded unsafe actuation.

## Evidence to capture

- Commit SHA, binary version, config/profile hashes, device/register-map identifiers.
- Serial traces (FC 03/04/06/16), guard decisions, and read-back snapshots.
- PDU event log with timestamps, gateway boot/reconciliation logs, ledger rows before/after cuts.
- Attach artifacts to the maintainer workflow run (not public PRs).

## Execution trigger

Run only via the maintainer-triggered GitHub Actions workflow `.github/workflows/hil.yml` (`workflow_dispatch`) on provisioned, labeled lab hardware. Do **not** enable for public pull requests.

## CC-22 sensor/controller validation campaign (software bench + lab matrix)

CC-22 extends this procedure to the full transport matrix — DS18B20, 4–20 mA, BLE
GATT, BACnet/IP, Modbus RTU and Modbus TCP — with calibration/accuracy runs against
reference instruments, temperature/humidity/vibration/brownout envelopes, network
loss at every transport and a long-run fault-injection cycle.

- **Reproduce the software bench:** `cargo test -p tirbase-sim --test hil_campaign -- --nocapture`
  writes `target/hil-evidence/cc22/`; the committed reference run and the full
  case list are in `docs/evidence/hil/cc22-sensor-controller-validation/`.
- **Physical lab:** run the same case list on the bench in
  `docs/reference-hardware.md`, using the calibration fixture log in
  `docs/hil-lab-checklist.md` §5 and the evidence layout in §7. Record the
  certificate id of every reference instrument and attach the raw traces.

The power-cut matrix in §3 above is complemented by the software bench's
storage-level cuts (`power-cut.json`): a child process is killed inside an open
write transaction and the reopened database must keep its integrity, calibration
rows and ledger chain consistent.

## Related documents (F-13)

- Repeatable checklist and evidence capture: [`docs/hil-lab-checklist.md`](hil-lab-checklist.md)
- CC-22 evidence pack and case list: [`docs/evidence/hil/cc22-sensor-controller-validation/`](evidence/hil/cc22-sensor-controller-validation/)
- Long-run soak and fault injection: [`docs/soak-test-procedure.md`](soak-test-procedure.md)
- Reference hardware profiles: [`docs/reference-hardware.md`](reference-hardware.md)

## ST-12 gate HIL campaign

The venue gate HIL bench is documented in
[`docs/venues/st12-gate-hil.md`](venues/st12-gate-hil.md) with its evidence at
[`docs/evidence/hil/st12-venue-gate-safety/`](evidence/hil/st12-venue-gate-safety/).
Reproduce the deterministic software bench with:

```bash
cargo test -p tirbase-venue-hil
cargo run -p tirbase-venue-hil --bin venue-hil-campaign -- \
  --out docs/evidence/hil/st12-venue-gate-safety
```

It composes the production ST-04 gate controller and ST-03 access path with a
reader link, turnstile watchdog, 24 V supply and monotonic safety clock. The
physical campaign repeats the six power-cut stages, shallow/deep brownouts,
network loss, clock jumps, fire input and long-run/event-flood cases on the lab
bench. Physical safety assessment is a separate commercial engagement.

## Full vertical journey and power-loss coverage (F-13)

- **Full vertical journey:** execute the end-to-end flow in `docs/hil-lab-checklist.md` §2 for the vertical under test (enroll/profile → ingest → guarded command → rejection → export/UI as applicable) and attach evidence.
- **Power loss at every stage:** execute the stage matrix in `docs/hil-lab-checklist.md` §3 (idle through post-commit/export boundaries) with controlled power cuts; each must yield a recoverable state per PV-5.3/PV-7 reconciliation rules.
