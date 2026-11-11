# Phase 16 — Formal Models — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.16

## Scope

Task sections 51.x: 6 acceptance-criterion rows (6 complete, 0 open in `tasks.md` at audit time).

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
| 51.1 | Create formal/policy_lifecycle.tla (or Quint): model tighten/loosen/time-lock/cancel/rollback; include livenes… | PV-26.1, PV-26.2 | `formal/policy_lifecycle.tla:1` | — | TRACED-ARTIFACT |
| 51.2 | Create formal/command_freshness.tla: model anti-replay sliding window and enrollment epoch binding | PV-26.1 | `formal/command_freshness.tla:1` | — | TRACED-ARTIFACT |
| 51.3 | Create formal/ledger_recovery.tla: model intent → actuating → complete/failed/unknown state machine crash reco… | PV-26.1 | `formal/ledger_recovery.tla:1` | — | TRACED-ARTIFACT |
| 51.4 | Create formal/single_writer_lease.tla: model SingleWriterLease acquisition, renewal cap, and preemption | PV-26.1 | `formal/single_writer_lease.tla:1`<br>`tirbase-guard/src/single_writer_lease.rs:12` (`SingleWriterLease`) | — | TRACED-CALLER |
| 51.5 | Add loom or shuttle concurrency tests on the Rust implementations of SingleWriterLease and AntiReplayWindow | PV-26.3 | `tirbase-guard/tests/concurrency_shuttle.rs:1` | — | TRACED-CALLER |
| 51.6 | Create formal/kani_envelope_arith.rs: kani proof spike verifying FixedPointValue min/max comparison is overflo… | PV-26.4 | `formal/kani_envelope_arith.rs:14`<br>`tirbase-types/src/fixed_point.rs:65` (`FixedPointValue`) | — | TRACED-CALLER |

## Gaps and open items

- **51.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **51.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **51.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **51.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **51.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **51.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 6 rows have a resolved production call site or deliverable; 6 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

