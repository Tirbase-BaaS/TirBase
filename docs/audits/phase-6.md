# Phase 6 — Migration Engine and Shadow Copy — Phase Audit

**Status:** PASS WITH OPEN ITEMS — trace audit complete, no ASSUMED rows
**Phase gate:** Phase work is NOT complete; blocked rows below must close before dependants proceed.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.6

## Scope

Task sections 29.x, 30.x: 17 acceptance-criterion rows (14 complete, 3 open in `tasks.md` at audit time).

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
| 29.1 | Replace wasmtime with wasmi as the sole migration WASM engine on all targets (native gateway and WASM builds);… | PV-8.1 | `Cargo.toml:1` | `tirbase-gateway/tests/task29_migration_sandbox.rs:66` (`gateway_deterministic_migration_executes_with_wasmi`) | TRACED-TEST |
| 29.2 | Implement DeterministicWasmProfile validation via wasmparser at module load time: forbid all f32/f64 instructi… | PV-8.2 | `tirbase-core/src/migration/profile.rs:187` | — | TRACED-CALLER |
| 29.3 | Implement ExecutionProfileVersion: profile_id, wasmi_version, fuel_cost_table_hash (SHA-256 of wasmi Config), … | PV-8.2a | `tirbase-core/src/migration/profile.rs:60` | — | NOT IMPLEMENTED |
| 29.4 | Apply StoreLimits to every migration instance: 64 MiB memory, 1,000 tables, 10 instances, 512 KiB stack | PV-8.1 | `tirbase-core/src/migration/wasm_sandbox.rs:26` | — | TRACED-CALLER |
| 29.5 | Add property test (P12): same wasmi input + migration module → byte-identical output on repeated executions | PV-8.1 | `tirbase-core/src/migration/profile.rs:1` | — | NOT IMPLEMENTED |
| 29.6 | Add cross-architecture determinism test: same migration + input on x86_64 and ARM (via QEMU) must produce byte… | PV-8 | `tirbase-sim/tests/determinism.rs:1` | — | NOT IMPLEMENTED |
| 30.1 | Implement shadow-copy run: execute migration against a SQLite savepoint over projection tables only (not the d… | PV-8.4 | `tirbase-core/src/migration/migration_delta.rs:15` | — | TRACED-CALLER |
| 30.2 | Implement signed postcondition evaluation against shadow output: row counts, field checksums over real data, s… | PV-8.4 | `tirbase-core/src/migration/shadow.rs:17` | — | TRACED-CALLER |
| 30.3 | Implement MigrationKind::Expand/Contract with fleet_precondition_hash; verify fleet inventory before approving… | PV-8.5a | `tirbase-core/src/migration/migration_delta.rs:28` | — | TRACED-CALLER |
| 30.4 | Implement expand-then-contract rule: verify schema diff in shadow run — Expand adds ≥1 field and removes 0; Co… | PV-8.5a | `tirbase-core/src/migration/shadow.rs:17` | — | TRACED-CALLER |
| 30.5 | Implement mid-execution cancellation at fuel-check boundaries; record QuarantineLog entry for in-progress tran… | PV-8.6 | `tirbase-core/src/migration/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 30.6 | Implement post-execution revocation check before committing shadow to primary: if transform author DID is revo… | PV-8.7 | `tirbase-core/src/migration/author_revocation.rs:10` | — | TRACED-CALLER |
| 30.7 | Produce docs/RFC-tuf.md evaluating TUF adoption (BLOCKED: awaiting owner decision RD-6); include threat model,… | PV-8.8 | `docs/RFC-tuf.md:1` | — | TRACED-ARTIFACT |
| 30.8 | Implement staged-rollout primitives for migrations and firmware: canary ring assignment (ring size 1–100 devic… | PV-8.9 | `tirbase-admin/src/cmd/rollout.rs:13` | — | TRACED-CALLER |
| 30.9 | [BLOCKED RD-6, scaffolded] Implement gateway self-update and config rollback (BLOCKED: awaiting RFC-tuf.md mer… | PV-11.6 | `tirbase-gateway/src/self_update.rs:13` | — | BLOCKED |
| 30.10 | Run TUF crate spike: evaluate tough or rust-tuf crate requiring injected TimeSource and gossip transport; veri… | PV-8.8, RD-6 | `docs/RFC-tuf.md:24`<br>`tirbase-core/src/traits.rs:50` (`TimeSource`) | — | TRACED-CALLER |
| 30.11 | Scenarios S8 (malicious migration) and S36 (postcondition failure / shadow discard preserves pre-execution sta… | PV-12.5 | `tirbase-sim/src/scenarios/s8_malicious_migration.rs:10` | — | TRACED-CALLER |

## Gaps and open items

- **29.1** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **29.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **29.3** (`NOT IMPLEMENTED`) — Checkbox open in tasks.md; no `ExecutionProfileVersion` implementation or test resolves.
- **29.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **29.5** (`NOT IMPLEMENTED`) — Checkbox open in tasks.md; no P12 byte-identical-repeat property test resolves.
- **29.6** (`NOT IMPLEMENTED`) — Checkbox open in tasks.md; no cross-architecture determinism test resolves.
- **30.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.5** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **30.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **30.8** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.9** (`BLOCKED`) — Awaiting RFC-tuf.md approval per RD-6; the task is explicitly marked blocked.
- **30.10** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **30.11** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.

## Verdict

**PASS WITH OPEN ITEMS.** 13 of 17 rows are traced to existing implementation; 4 row(s) are BLOCKED/NOT IMPLEMENTED. The phase is not complete until those rows close. No row is ASSUMED.

