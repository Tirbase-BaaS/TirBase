# Phase 13 — Resource Budgets and Performance Validation — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.13

## Scope

Task sections 44.x, 45.x: 9 acceptance-criterion rows (9 complete, 0 open in `tasks.md` at audit time).

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
| 44.1 | Create docs/reference-hardware.md: (a) RPi 4B 1 GB RAM for aarch64/armv7 baseline; (b) second gateway with TPM… | PV-15.1, RD-2, RD-7 | `docs/reference-hardware.md:10`<br>`tirbase-gateway/src/hw_counter_binding.rs:155` (`hardware`) | — | TRACED-CALLER |
| 44.2 | Run measure-first benchmarks on reference hardware; record baselines in docs/perf-baseline.md; set all numeric… | PV-15.2 | `docs/perf-baseline.md:1` | — | TRACED-ARTIFACT |
| 44.3 | Implement Criterion benchmarks: guard decision latency, Ed25519 signature verification latency, effects-ledger… | PV-15.3 | `tirbase-sim/tests/runbook_fault_verification.rs:1` | — | TRACED-CALLER |
| 44.4 | Wire iai-callgrind instruction-count gating on all Criterion benchmarks | PV-15.3 | `.github/workflows/ci.yml:647` | — | TRACED-ARTIFACT |
| 44.5 | Implement flash-write budget tracking at the Linux block layer (not SQLite level); default 100 MB/day configur… | PV-15.4 | `tirbase-gateway/src/flash_budget.rs:25` | — | TRACED-CALLER |
| 44.6 | Implement flash-wear throttle: when projected daily writes exceed budget, throttle non-critical writes by incr… | PV-15.4 | `tirbase-gateway/src/flash_budget.rs:25` | — | TRACED-CALLER |
| 44.7 | Implement failure-injection tests: (a) ENOSPC via small tmpfs → SQLITE_FULL → High SecurityEvent; (b) fsync fa… | PV-9.5 | `docs/failure-injection-catalog.md:1`<br>`tirbase-core/src/events.rs:558` (`SecurityEvent`)<br>`tirbase-drivers/src/driver_trait.rs:20` (`TimeoutError`) | — | TRACED-CALLER |
| 45.1 | Implement virtual-time soak: 72h simulated via tirbase-sim accelerated clock with fault injection; must fit wi… | PV-15.5 | `tirbase-sim/src/soak.rs:18` | `tirbase-sim/tests/soak.rs:28` (`virtual_time_soak_runs_72h_with_fault_injection_within_budget`) — via PV-15.5 | TRACED-CALLER |
| 45.2 | Create docs/soak-test-procedure.md for real 72h lab soak (per-release, maintainer-triggered); document heap gr… | PV-15.6 | `docs/soak-test-procedure.md:1` | — | TRACED-ARTIFACT |

## Gaps and open items

- **44.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **44.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **44.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **44.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **44.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **44.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **44.7** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **45.1** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **45.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 9 rows have a resolved production call site or deliverable; 9 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

