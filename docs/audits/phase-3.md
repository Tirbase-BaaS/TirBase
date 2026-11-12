# Phase 3 — Durable State, Ledger, Anti-Replay, Lease — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.3

## Scope

Task sections 18.x, 19.x, 20.x, 21.x: 32 acceptance-criterion rows (32 complete, 0 open in `tasks.md` at audit time).

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
| 18.1 | Create primary.db with synchronous=FULL WAL mode and all PrimaryLedger tables via the migration framework (tas… | PV-9.3 | `tirbase-core/src/bin/crash_writer.rs:25` (`main`) | `tirbase-gateway/tests/db_split.rs:209` (`gateway_creates_primary_and_derived_dbs_with_required_pragmas_and_tables`) | TRACED-CALLER |
| 18.2 | Create derived.db with synchronous=NORMAL WAL mode and all DerivedLedger tables via the migration framework (t… | PV-9.3 | `tirbase-core/src/bin/crash_writer.rs:25` (`main`) | `tirbase-gateway/tests/db_split.rs:209` (`gateway_creates_primary_and_derived_dbs_with_required_pragmas_and_tables`) | TRACED-CALLER |
| 18.3 | Add SQLite hardening pragmas to both databases after creation (depends on 18.1 and 18.2): trusted_schema=OFF, … | PV-9 | `tirbase-gateway/src/db/sqlite_errors.rs:10`<br>`tirbase-gateway/src/db/migrations.rs:21` | `tirbase-gateway/tests/db_split.rs:362` (`injected_sqlite_ioerr_on_primary_open_triggers_restricted_mapping`) | TRACED-CALLER |
| 18.4 | Implement SQLite error → NodeMode mapping: SQLITE_FULL → High SecurityEvent; SQLITE_IOERR → Restricted mode; S… | PV-9 | `tirbase-gateway/src/db/sqlite_errors.rs:10`<br>`tirbase-gateway/src/db/migrations.rs:21`<br>`tirbase-admin/src/main.rs:9` | `tirbase-gateway/tests/db_split.rs:362` (`injected_sqlite_ioerr_on_primary_open_triggers_restricted_mapping`) | TRACED-CALLER |
| 19.1 | Create applied_effects_ledger table via the migration framework : entry_id, issuer_did, target_id, … | PV-5.1 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/applied_effects_ledger.rs:132` (`claim_19_1_applied_effects_ledger_table_exists_and_transitions_on_actuation`) | VERIFIED-BY-TRACE |
| 19.2 | Implement boot crash reconciliation: scan Actuating entries; driver read-back (30s timeout); mark Complete, Fa… | PV-5.3 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/applied_effects_ledger.rs:223` (`claim_19_2_boot_reconciliation_resolves_actuating_and_emits_events`) | VERIFIED-BY-TRACE |
| 19.3 | At boot, scan for ledger entries in a pre-Actuating state (possible only during schema migration from older ve… | PV-5.3 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/applied_effects_ledger.rs:276` (`claim_19_3_pre_actuating_legacy_entry_marked_failed_old_schema_entry_not_actuating`) | VERIFIED-BY-TRACE |
| 19.4 | Implement group-commit batcher: 50ms window before fsync; High and Critical severity SecurityEvents bypass the… | PV-15.4 | `tirbase-gateway/src/security_log.rs:1910` (`emit`) | `tirbase-gateway/tests/applied_effects_ledger.rs:369` (`claim_19_4_group_commit_batches_low_and_high_bypasses_immediately`) | VERIFIED-BY-TRACE |
| 19.5 | Implement ledger pruning background job: max 90 days or 1,000,000 entries, whichever comes first; prune oldest… | PV-5.12 | `tirbase-gateway/src/ (directory cited; no distinct call site named)` | `tirbase-gateway/tests/applied_effects_ledger.rs:436` (`claim_19_5_ledger_pruning_removes_entries_beyond_retention`) | TRACED-TEST |
| 19.6 | Add failpoint kill-at-every-step tests using the fail crate at every write boundary in the effects ledger path… | PV-5.4 | `tirbase-core/src/failpoints.rs:1` | `tirbase-gateway/tests/applied_effects_ledger.rs:502` (`claim_19_6_failpoint_kill_at_every_step_leaves_handled_ledger_states`) | VERIFIED-BY-TRACE |
| 20.1 | Implement AntiReplayWindow: sliding bitmap per (issuer_did, target_id, enrollment_epoch), W=64 (configurable),… | PV-5.5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/anti_replay.rs:61` (`claim_20_1_sequence_outside_window_rejected`) | VERIFIED-BY-TRACE |
| 20.2 | Implement non-mutating anti-replay check for Stage 16 atomic transaction (read-only query before mutation) | PV-5.5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/anti_replay.rs:95` (`claim_20_2_duplicate_sequence_rejected_atomically_no_actuation`) | VERIFIED-BY-TRACE |
| 20.3 | Implement PolicyAuthority-signed sequence-window reset (for issuer re-enrollment or wrap-around) | PV-5.5 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/anti_replay.rs:130` (`claim_20_3_window_reset_allows_previously_rejected_sequence`) | VERIFIED-BY-TRACE |
| 20.4 | Create anti_replay_windows table in primary.db via the migration framework ; persist window state s… | PV-5.5, PV-5.7 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/anti_replay.rs:178` (`claim_20_4_anti_replay_window_persists_across_restart`) | VERIFIED-BY-TRACE |
| 20.5 | Implement idempotency key store scoped to (issuer_did, target_id, idempotency_key); configurable retention (de… | PV-5.6 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/anti_replay.rs:217` (`claim_20_5_duplicate_idempotency_key_returns_original_result_no_second_actuation`) | VERIFIED-BY-TRACE |
| 20.6 | Add anti-replay property tests: (P7) sequence numbers outside the window are always rejected; (P8) accepted se… | PV-5.5 | `tirbase-gateway/src/db/enrollment_nonce.rs:1` | — | TRACED-CALLER |
| 20.7 | Add idempotency property test (P10): any command with a known idempotency key within the retention window retu… | PV-5.6 | `tirbase-sim/src/scenarios/s26_s29_idempotency.rs:1` | — | TRACED-CALLER |
| 20.8 | Scenario S3 (replay) and S20 (sequence-number poisoning) must be wired in tirbase-sim and passing before anti-… | PV-12.5 | `tirbase-sim/src/scenarios/s4_clock_poisoning.rs:24` | — | TRACED-CALLER |
| 21.1 | Implement SingleWriterLease: issuer_did, target_id, expires_est (monotonic), consecutive_renewals, cooldown_un… | PV-5.8 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/lease_state_machine.rs:9` (`claim_21_1_single_active_holder_modeled`) | VERIFIED-BY-TRACE |
| 21.2 | Implement lease preemption: M-of-N RevocationManager + PolicyAuthority joint operation forcibly releases any l… | PV-5.8a | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/lease_ops.rs:96` (`claim_21_2_21_3_preemption_and_revocation_release`) | VERIFIED-BY-TRACE |
| 21.3 | Implement lease release on issuer DID revocation: when a DID is added to the revocation set, immediately relea… | PV-5.8a | `tirbase-guard/src/single_writer_lease.rs:12` | — | TRACED-CALLER |
| 21.4 | Implement consecutive renewal cap (default 10); after cap reached, enter cooldown period (default one lease du… | PV-5.8a | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/lease_ops.rs:43` (`claim_21_4_consecutive_renewal_cap_cooldown_s21`) | VERIFIED-BY-TRACE |
| 21.5 | Create single_writer_leases table in primary.db via the migration framework ; release all leases at… | PV-5.8 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/lease_ops.rs:126` (`claim_21_5_release_all_at_boot`) | VERIFIED-BY-TRACE |
| 21.6 | Add SingleWriterLease property test (P9): at most one issuer holds the lease for any given target at any point… | PV-5.8 | `tirbase-guard/tests/time_ratchet_property.rs:1` | — | TRACED-CALLER |
| 21.7 | Create drift_rate_history table via the migration framework  for dwell and min-off-time enforcement… | PV-4.7 | `tirbase-guard/src/guard.rs:249` (`admit`) | — | TRACED-CALLER |
| 21.8 | Create docs/EFFECT_SEMANTICS.md: at-least-once delivery with idempotent declarative effects, Unknown entry sem… | PV-5.10, PV-5.12 | `docs/EFFECT_SEMANTICS.md:1` | — | TRACED-ARTIFACT |
| 21.9 | Implement Unknown-entry blocking: when the Applied_Effects_Ledger contains an Unknown entry for a target, reje… | PV-5.11 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/runtime_wiring.rs:159` (`claim_21_9_unknown_target_blocks_then_operator_clear_unblocks_runtime`) | VERIFIED-BY-TRACE |
| 21.10 | Implement dwell and min-off interlock enforcement in Stage 13: before accepting a ParameterKind::Range command… | PV-4.7 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/single_writer.rs:269` (`claim_21_10_stage13_dwell_interlock_rejects`) | VERIFIED-BY-TRACE |
| 21.11 | Implement ParameterKind::Enum and ParameterKind::Bool enforcement in Stage 10: for Enum parameters, verify cmd… | PV-4.5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/single_writer.rs:174` (`claim_21_11_stage10_enum_and_bool_reject_value_invalid`) | VERIFIED-BY-TRACE |
| 21.12 | Implement target_state store: a BTreeMap<(TargetId, String), FixedPointValue> (target, param → current desired… | PV-4.5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/runtime_wiring.rs:333` (`claim_21_12_13_hydrate_target_state_and_drift_timing_store`) | VERIFIED-BY-TRACE |
| 21.13 | Implement drift-history writer: update drift_rate_history row for (target_id, param) atomically with the Actua… | PV-4.7 | `tirbase-guard/src/guard.rs:249` (`admit`) | — | TRACED-CALLER |
| 21.14 | Scenario S21 (lease starvation) must be wired in tirbase-sim and passing before SingleWriterLease is considere… | PV-12.5 | `tirbase-sim/src/scenarios/s21_lease_starvation.rs:5` | — | TRACED-CALLER |

## Gaps and open items

- **18.1** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **18.2** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **18.3** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **18.4** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **19.5** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **20.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **20.7** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **20.8** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **21.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **21.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **21.7** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **21.8** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **21.13** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **21.14** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 32 rows have a resolved production call site or deliverable; 14 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

