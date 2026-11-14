# HIL Lab Checklist and Evidence Capture (F-13)

> **Status:** Operational checklist for maintainer-triggered hardware-in-the-loop (HIL) and field-validation campaigns. Complements [`docs/hil-test-procedure.md`](hil-test-procedure.md), [`docs/soak-test-procedure.md`](soak-test-procedure.md), [`docs/reference-hardware.md`](reference-hardware.md), and workflow [`.github/workflows/hil.yml`](../.github/workflows/hil.yml).  
> **Licence:** AGPL-3.0-only repo content; physical lab execution is commercial/operator responsibility.

## 1. Pre-campaign checklist (repeatable)

### 1.1 Hardware and environment
- [ ] Gateway hardware matches a profile in `docs/reference-hardware.md` (record model, serial, RAM, storage, OS image hash).
- [ ] Field bus/interface hardware recorded (USB RS-485 adapter chipset/driver, baud/parity/stop, unit IDs, wiring photos/notes).
- [ ] Smart PDU or power-control rig verified offline (cut/restore script tested) before DUT connection.
- [ ] Environmental test gear available if running temp/brownout/power-cut campaigns (data logger, AC source/sag generator, or documented manual procedure).
- [ ] Time sync: NTP/chrony disabled or controlled as specified per scenario; logs are timestamped (UTC) and correlated with PDU/fixture events.

### 1.2 Software under test
- [ ] Commit SHA and tags recorded; release/profile build flags documented.
- [ ] Gateway `config.toml`, signed `EnvelopeProfile` (or profile bundle), OTA/channel policy (if exercised) recorded (hashes).
- [ ] Driver binaries/configs for devices under test recorded.
- [ ] UI/console build version recorded if UI journey is part of the campaign.

### 1.3 Device simulators and fixtures (bench)
Use `tirbase-sim` / fixture tooling where available; for physical rigs, document equivalents:

| Simulator / fixture class | Repo / location (typical) | Notes |
|---------------------------|---------------------------|-------|
| Modbus RTU/TCP | `tirbase-sim` Modbus server/model, `tirbase-drivers` Modbus client, `tests/hil/modbus_roundtrip.rs` (gateway) | Real bus + device or certified simulator |
| BACnet | Documented in HIL procedure; simulator planned/scaffolded in `tirbase-sim` | Record object list and profile |
| 1-Wire | `tirbase-sim` scaffolding / lab fixture | Record device IDs |
| 4–20 mA ADC | Calibrated current source or simulator | Record calibration certificate ID |
| BLE GATT | BLE peripheral simulator or reference device | Record GATT profile hash |
| ESC/POS (receipt) | Printer or simulator | Record firmware/model |
| Scale (serial/USB HID variants as applicable) | Calibrated test weights + device | Record weights and tolerances |
| Barcode scanner | Test barcodes (Code128/EAN set) | Record barcode set |
| Gate controller | Relay/IO simulator or physical controller | Record safe-state behavior |

### 1.4 Safety
- [ ] No SIL claims implied; physical safety interlocks remain external.
- [ ] Emergency stop / manual override documented for powered actuators.

## 2. Full vertical journey (done-when: “A full vertical journey runs on the HIL bench”)

Execute at least one end-to-end journey per vertical in scope for the campaign (example for cold chain + POS + stadium/shared as applicable):

1. **Provisioning/enrollment (if in scope):** device enrolled, profile installed, `Normal`/ready state observed.
2. **Ingest:** sensor/read path (simulator or real device) produces data; values recorded.
3. **Guarded command:** submit in-envelope command via production path; verify accept, actuation/effect record, ledger/security events.
4. **Envelope rejection:** submit out-of-range command; verify reject, no unintended actuation, auditable event.
5. **Export/reporting (if in scope):** generate export artifact; verify integrity/signing per product rules.
6. **UI observation (if in scope):** operator UI shows correct state/events for the same journey (screenshot/log bundle captured).

Record pass/fail per step, timestamps, and artifact paths.

## 3. Power loss at every stage (done-when criterion)

For each stage below, perform a controlled power cut (PDU) or equivalent hard stop at the stated boundary, restore power, boot, and verify **recoverable state** (no silent data loss beyond documented semantics; ledger reconciliation consistent; no un-audited actuation):

| Stage | Cut point (example) | Verify |
|-------|---------------------|--------|
| Idle / monitoring | Mid read loop | Boot OK; logs consistent; no partial writes that break chain |
| Command intent received | After auth/parse, before guard commit boundary (per implementation) | No actuation; idempotency/sequence rules hold |
| Guard accept, pre-actuate | Before driver dispatch commit | Reconciled to safe/no-actuate outcome per PV-5.3 |
| Actuating (dispatch in flight) | During driver I/O | Applied-effects reconciliation; no duplicate unsafe actuation |
| Post-actuate, pre-ledger fsync boundary | At durability boundary | Matches `docs/hil-test-procedure.md` power-cut failpoints |
| After commit, before export | After ledger write, before export finalization | Export retry/idempotent behavior documented |

For each run capture: PDU timestamp, boot time, reconciliation summary, security-event chain check result, and operator-observed state.

## 4. Environmental and power tests (F-13.3)

Record conditions and results:

- **Temperature:** operate at specified low/high (per profile) for soak window; record device/gateway temps if sensors available; note any throttling or faults.
- **Brownout:** controlled voltage sag per lab rig; verify graceful behavior or documented safe failure.
- **Power cut:** see §3.
- **Network loss/partition:** disconnect network during operation; verify DEGRADED/lockdown behavior per THREAT_MODEL and runbooks; reconnect and verify reconciliation.
- **Clock jump:** inject step change (NTP off + manual set in controlled test) where supported; verify TimeRatchet/freshness behavior per `docs/time-sync.md`.

## 5. Calibration fixtures and acceptance criteria (F-13.4)

- Maintain a calibration log: fixture ID, type, calibration date, due date, certificate/reference, measured error.
- Acceptance criteria examples (tune per vertical):
  - Modbus round-trip: readback matches written value within register resolution.
  - 4–20 mA: indicated value within ±0.5% FS or per sensor spec (record spec).
  - Scale: within stated tolerance at test weights.
  - Timing: command-to-effect observation within documented SLA for the bench.

## 6. Long-run soak with fault injection (F-13.5)

Follow [`docs/soak-test-procedure.md`](soak-test-procedure.md). Extend fault matrix to include at least: periodic restarts, network faults (partition/delay/drop/reorder/duplicate), and (where safe) simulated device disconnects. Archive time series and summaries.

## 7. Evidence capture (F-13.6) — link from CLAIMS.md

Store evidence under a release/lab folder convention (example):

- `docs/evidence/hil/<YYYY-MM-DD>-<campaign-id>/` containing:
  - `manifest.json` (or YAML): commit SHA, config/profile hashes, hardware IDs, operator, start/end times.
  - `logs/` (gateway journal, security events export, driver logs)
  - `traces/` (bus traces, PCAP if applicable)
  - `photos/` (wiring, PDU setup) — optional
  - `summary.md`: pass/fail table per §2–§6

**Linking rule:** when a campaign completes, add or update a row/note in [`CLAIMS.md`](../CLAIMS.md) referencing the evidence path (or artifact URL in CI) for the relevant CLAIM-52.* / PV-27 claims. Do not claim “Proven” for physical HIL until evidence is attached and reviewed per project policy.
