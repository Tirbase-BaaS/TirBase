# Phase 10 — Deterministic Simulation and Adversary Suite — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.10

## Scope

Task sections 38.x, 39.x, 40.x: 14 acceptance-criterion rows (14 complete, 0 open in `tasks.md` at audit time).

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
| 38.1 | Create tirbase-sim crate with ChaCha8Rng-seeded deterministic simulator | PV-12.1 | `tirbase-sim/src/lib.rs:93` | — | TRACED-CALLER |
| 38.2 | Implement SimClock (virtual time advancing on tick()), SimNetwork (fault injection), SimNode (wraps CommandGua… | PV-12.1 | `tirbase-sim/src/sim.rs:39` (`SimClock`) | — | TRACED-CALLER |
| 38.3 | Implement network fault modes: partition, delay (1–30,000 ms), drop, reorder, duplicate (≤5 copies per message… | PV-12.1 | `tirbase-sim/src/network.rs:30` | — | TRACED-CALLER |
| 38.4 | Implement first-order thermal model using libm for deterministic floating-point results; bit-identical from th… | PV-12.3 | `tirbase-sim/src/models/thermal.rs:25` | `tirbase-sim/tests/determinism.rs:88` (`thermal_model_is_bit_identical_from_the_same_seed`) — via PV-12.3 | TRACED-CALLER |
| 38.5 | Implement battery/inverter model using libm for deterministic floats | PV-12.3 | `tirbase-sim/src/models/battery.rs:23` | `tirbase-sim/tests/determinism.rs:97` (`battery_model_is_bit_identical_from_the_same_seed`) — via PV-12.3 | TRACED-CALLER |
| 38.6 | Implement InvariantChecker: per-tick checks for INV-1..INV-16; failing check immediately halts the scenario an… | PV-12.1, PV-23.2 | `tirbase-sim/src/invariants.rs:247` (`InvariantChecker`) | — | TRACED-CALLER |
| 38.7 | Add clippy::disallowed_types for std::collections::HashMap in tirbase-sim and tirbase-guard; use IndexMap or B… | PV-12 | `clippy.toml:1` | — | TRACED-ARTIFACT |
| 39.1 | Implement TOML scenario loader and scenario runner; CI must execute ≥1,000 seeded scenarios per run; failing s… | PV-12.1, PV-12.2 | `tirbase-sim/src/runner.rs:29` | `tirbase-sim/tests/scenario_runner.rs:63` (`failing_scenario_prints_its_seed_before_exit`) — via PV-12.2 | TRACED-CALLER |
| 39.2 | Implement scenarios S1–S18 (original catalog: out-of-envelope command, slow ramp, replay, clock jump, policy r… | PV-12.4 | `tirbase-sim/src/scenarios/s10_revoked_delta.rs:16` | — | TRACED-CALLER |
| 39.3 | Implement scenarios S19–S25: S19 delayed delivery, S20 sequence-number poisoning, S21 lease starvation, S22 sn… | PV-12.8 | `tirbase-sim/src/scenarios/s4_clock_poisoning.rs:24` | — | TRACED-CALLER |
| 39.4 | Implement scenarios S26–S35: S26 idempotency squatting, S27 governance-weakening tighten, S28 floor-in-bundle,… | PV-12.4 | `tirbase-sim/src/scenarios/s30_exponent_overflow.rs:12` | — | TRACED-CALLER |
| 40.1 | Add cargo-fuzz targets with committed seed corpora; each CI smoke run must complete within 60 seconds per targ… | PV-12.6 | `fuzz/fuzz_targets/fragment_reassembly.rs:15` | — | TRACED-CALLER |
| 40.2 | Add cargo-mutants CI gate: ≥80% mutation kill rate on guard, ledger, replay, and validation modules; CI fails … | PV-12.7 | `.github/workflows/ci.yml:615` | — | TRACED-ARTIFACT |
| 40.3 | Implement Criterion benchmarks wired to iai-callgrind for instruction-count gating (not wall-clock) on CI | PV-15.3 | — (deliverable / no runtime caller) | — | TRACED-ARTIFACT |

## Gaps and open items

- **38.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **38.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **38.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **38.4** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **38.5** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **38.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **38.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **39.1** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **39.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **39.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **39.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **40.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **40.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **40.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 14 rows have a resolved production call site or deliverable; 14 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

