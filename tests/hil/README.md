# HIL test suite (PV-27, CLAIM-52.2/52.3)

Hardware-in-the-loop tests that run **only** against provisioned lab hardware (real RS-485/Modbus device or real-bus simulator and, for failpoints, a smart PDU). These are not executed on public CI.

- Procedure and lab setup: `docs/hil-test-procedure.md`
- CC-22 sensor/controller matrix (bench, accuracy, environmental, recovery, stability) and its evidence pack: `docs/evidence/hil/cc22-sensor-controller-validation/`; the software bench runs on every CI run via `cargo test -p tirbase-sim --test hil_campaign`
- ST-12 venue gate/reader/turnstile/power bench, procedure and 32-case evidence pack: `docs/venues/st12-gate-hil.md`, `docs/evidence/hil/st12-venue-gate-safety/`; runs on every CI run via `cargo test -p tirbase-venue-hil`
- Workflow: `.github/workflows/hil.yml` (`workflow_dispatch`, maintainer-triggered, trusted lab runners only)

## Layout

- `modbus_tests/` — Modbus FC 03/04/06/16 round-trips and envelope rejection with a real out-of-range command (CLAIM-52.2).
- `failpoint_tests/` — power-cut-at-intent/actuating and power-cut-at-completion failpoint procedures (CLAIM-52.3).

The executable, ignored integration tests wired to the workflow live in:
- `tirbase-gateway/tests/hil_modbus_roundtrip.rs`
- `tirbase-gateway/tests/hil_power_cut.rs`

Both tests fail closed with a clear "hardware not configured/provisioned" error unless the required `HIL_*` environment variables and lab assets are present, preventing accidental execution without hardware.
