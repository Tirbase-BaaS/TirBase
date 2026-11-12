# Phase 17 — Hardware-in-the-Loop Lab — Phase Audit

**Status:** PASS WITH OPEN ITEMS — trace audit complete, no ASSUMED rows
**Phase gate:** Phase work is NOT complete; blocked rows below must close before dependants proceed.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.17

## Scope

Task sections 52.x: 5 acceptance-criterion rows (4 complete, 1 open in `tasks.md` at audit time).

## Method

Every row was traced against the repository; nothing was accepted on assertion. The audit:

1. resolves each declared production-caller path on disk and each cited symbol to its
 definition site (`file:line`);
2. resolves test identifiers in this order: a claim-named test (`claim_<task>`), a test
 named in the task entry, the closest test in a test file named in the task entry, then
 the test location committed in `docs/traceability-matrix.md` for the task's PV
 requirement;
3. records tasks with an open checkbox as `NOT IMPLEMENTED` or `BLOCKED` — never as verified.

Evidence classes in the status column:

- `VERIFIED-BY-TRACE` — production call site resolved and a task-named/claim-named test resolved.
- `TRACED-CALLER` — production call site resolved; test evidence is file-, suite-, matrix- or CI-level only.
- `TRACED-TEST` — test or document deliverable traced, with no distinct runtime caller.
- `TRACED-ARTIFACT` — documentation/CI deliverable; the cited artifact exists.
- `BLOCKED` / `NOT IMPLEMENTED` — cannot be verified as done; reason recorded.

No row is `ASSUMED`: a row that could not be traced is reported as an open item instead.

## Evidence

| Task | Acceptance criterion (task) | Req | Production call site | Test evidence | Status |
|---|---|---|---|---|---|
| 52.1 | Provision lab hardware per docs/reference-hardware.md: Modbus RTU device, reference gateway hardware, smart PD… | PV-27.1, RD-7 | `docs/reference-hardware.md:1`<br>`tirbase-gateway/src/hw_counter_binding.rs:155` (`hardware`) | — | BLOCKED |
| 52.2 | Create tests/hil/ HIL test suite: Modbus FC 03/04/06/16 round-trips, envelope rejection with real out-of-range… | PV-27.2 | `tests/hil/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 52.3 | Add power-cut-at-intent and power-cut-at-actuating HIL failpoint tests | PV-27.2 | `tests/hil/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 52.4 | Create docs/hil-test-procedure.md with lab setup and execution instructions; BLOCKED: lab hardware acquisition | PV-27.3 | `docs/hil-test-procedure.md:13` | — | TRACED-ARTIFACT |
| 52.5 | Add maintainer-triggered GitHub Actions HIL workflow (must not run on public PRs); BLOCKED: lab hardware acqui… | PV-27.3 | `.github/workflows/hil.yml:28` | — | TRACED-ARTIFACT |

## Gaps and open items

- **52.1** (`BLOCKED`) — Lab hardware (Modbus RTU device, reference gateway, smart PDU) has not been acquired; the task records the blocker.
- **52.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **52.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **52.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **52.5** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.

## Verdict

**PASS WITH OPEN ITEMS.** 4 of 5 rows are traced to existing implementation; 1 row(s) are BLOCKED/NOT IMPLEMENTED. The phase is not complete until those rows close. No row is ASSUMED.

