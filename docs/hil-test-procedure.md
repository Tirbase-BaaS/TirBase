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
