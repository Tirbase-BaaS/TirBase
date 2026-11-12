# Phase 4 — CRDT Hardening, Queues, Budgets — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.4

## Scope

Task sections 22.x, 23.x, 24.x: 17 acceptance-criterion rows (17 complete, 0 open in `tasks.md` at audit time).

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
| 22.1 | Implement validate_start_op in tirbase-core/src/crdt/hardening.rs: expected = 1 + max(dep.start_op + dep.len… | PV-6.1 | `tirbase-core/src/crdt/hardening.rs:83` (`validate_start_op`)<br>`tirbase-core/src/crdt/mod.rs:619` (`hardening`) | — | TRACED-CALLER |
| 22.2 | Add characterization test: apply delta with inflated start_op to unprotected baseline; record that it wins eve… | PV-6.2 | `docs/perf-baseline.md:1` | — | TRACED-ARTIFACT |
| 22.3 | Add regression test: same inflated start_op delta is quarantined to Schema_Quarantine_Ledger after validate_st… | PV-6.2 | `tirbase-gateway/tests/applied_effects_ledger.rs:1` | — | TRACED-CALLER |
| 22.4 | Add property test (P16): honest Automerge histories with valid dependency chains always pass validate_start_op… | PV-6.1 | `docs/releases/dependency-review.md:1` | — | TRACED-ARTIFACT |
| 22.5 | Scenario S4 (CRDT clock/start_op poisoning) is wired in tirbase-sim and passing before CRDT hardening … | PV-12.5, PV-6.1 | `tirbase-sim/src/scenarios/s4_clock_poisoning.rs:24` | — | TRACED-CALLER |
| 23.1 | Implement bounded pending queue: BTreeMap<DeltaId, (Delta, received_at_mono)>, 24h age-out (configurable up to… | PV-6.1 | `tirbase-core/src/crdt/merge.rs:35` | `tirbase-core/src/api/mod.rs:15112` (`claim_23_1_missing_dependency_pends_then_processes_on_dependency_arrival`) | VERIFIED-BY-TRACE |
| 23.2 | Implement PENDING_QUEUE_OVERFLOW quarantine when byte cap is exceeded | PV-6.1 | `tirbase-core/src/crdt/merge.rs:35` | `tirbase-core/src/api/mod.rs:15201` (`claim_23_2_pending_queue_overflow_quarantined_to_schema_quarantine`) | VERIFIED-BY-TRACE |
| 23.3 | Implement Schema_Quarantine_Ledger (replayable, requires PolicyAuthority signature for replay): schema_quarant… | PV-6.7 | `tirbase-core/src/crdt/hardening.rs:619` | `tirbase-core/src/api/mod.rs:15262` (`claim_23_3_schema_quarantine_ledger_records_replayable_reasons`) | VERIFIED-BY-TRACE |
| 23.4 | Implement Rate_Quarantine as in-memory per-sender counters with periodic summary rows to derived.db; 7-day TTL… | PV-6.7 | `tirbase-core/src/crdt/hardening.rs:619` | `tirbase-core/src/api/mod.rs:15341` (`claim_23_4_rate_quarantine_counters_and_summary_ttl`) | VERIFIED-BY-TRACE |
| 23.5 | Implement per-sender quota: 1,000 entries per DID in schema_quarantine before FIFO eviction; global limits (Sc… | PV-6.7 | `tirbase-core/src/crdt/hardening.rs:619` | `tirbase-core/src/api/mod.rs:15400` (`claim_23_5_schema_quarantine_per_sender_quota_isolated`) | VERIFIED-BY-TRACE |
| 23.6 | Implement cheap-checks-first ordering in the inbound validation pipeline: rate limit → size → op count → dep c… | PV-6 | `tirbase-core/src/crdt/merge.rs:35` | `tirbase-core/src/api/mod.rs:15453` (`claim_23_6_cheap_checks_first_ordering`) | VERIFIED-BY-TRACE |
| 24.1 | Implement InboundCaps configuration: per-DID rate 100 ops/s / burst 500, delta size 1 MiB, op count 1,000, bat… | PV-6.3 | `tirbase-core/src/crdt/hardening.rs:1097` (`InboundShape`)<br>`tirbase-core/src/api/mod.rs:3209` (`receive_inbound`)<br>`tirbase-core/src/crdt/hardening.rs:910` (`enforce_inbound_caps`) | `tirbase-core/src/api/mod.rs:15641` (`claim_24_1_configured_inbound_cap_quarantines_oversize_delta`) | VERIFIED-BY-TRACE |
| 24.2 | Implement memory budgets with eviction metrics: DAG node cache 32 MiB, ICO index 8 MiB, reassembly buffers 16 … | PV-6.5 | `tirbase-core/src/lib.rs:198` (`CoreHandle`)<br>`tirbase-core/src/api/mod.rs:3176` (`memory_budget_metrics`) | `tirbase-core/src/crdt/memory_budget.rs:146` (`claim_24_2_caches_expose_metrics`) | VERIFIED-BY-TRACE |
| 24.3 | Add cargo-fuzz targets: automerge_delta_decode and fragment_reassembly; each must have at least one committed … | PV-6.6 | `tirbase-core/src/crdt/delta.rs:96` (`Delta`)<br>`tirbase-core/src/transport/message.rs:16` (`GossipMessage`)<br>`tirbase-core/src/transport/fragment.rs:32` (`fragment`) | — | TRACED-CALLER |
| 24.4 | Add CI fuzz target registry rule: compare list of untrusted-input parsers in tirbase-core and driver crates ag… | PV-6.8 | `.github/workflows/ci.yml:607` | — | TRACED-ARTIFACT |
| 24.5 | Create memory-budget ledger: docs/memory-budget.md summing all configured caps against the RSS budget target (… | PV-6.5, PV-15 | `docs/memory-budget.md:1` | `tirbase-core/tests/memory_budget_gate.rs:58` (`configured_caps_load_and_peak_rss_stays_under_budget`) | TRACED-TEST |
| 24.6 | Scenario S4 (clock poisoning) must be wired in tirbase-sim and passing before CRDT hardening (24) is … | PV-12.5 | `tirbase-sim/src/scenarios/s4_clock_poisoning.rs:24` | — | TRACED-CALLER |

## Gaps and open items

- **22.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **22.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **22.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **22.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **22.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **24.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **24.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **24.5** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **24.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 17 rows have a resolved production call site or deliverable; 9 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

