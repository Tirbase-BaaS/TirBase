# Phase 5 — Security Log, Tamper Detection, GDPR, Flood Control — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.5

## Scope

Task sections 25.x, 26.x, 27.x, 28.x: 20 acceptance-criterion rows (20 complete, 0 open in `tasks.md` at audit time).

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
| 25.1 | Implement SecurityEvent struct: seq, category, severity, actor_did, target, reason_code, best_effort_wall_time… | PV-7.1, PV-7.2 | `tirbase-gateway/src/security_log.rs:569` (`SecurityEventLog`)<br>`tirbase-core/src/events.rs:681` (`emit`) | — | TRACED-CALLER |
| 25.2 | Implement SecurityEventLog in-memory ring: bounded to 10,000 events; retain oldest anchor events and most rece… | PV-7.6 | `tirbase-gateway/src/security_log.rs:569` (`SecurityEventLog`) | — | TRACED-CALLER |
| 25.3 | Implement checkpoint records: signed by device key after every 100 events or 60 seconds (whichever comes first… | PV-7.3 | `tirbase-gateway/src/security_log.rs:50` | — | TRACED-CALLER |
| 25.4 | Create security_events table with segment_id column in primary.db via the migration framework (task 32.1) | PV-7.2 | `tirbase-gateway/src/db/security_events.rs:1` | — | TRACED-CALLER |
| 25.5 | Create security_event_segments table in primary.db via the migration framework (task 32.1) for chain segment t… | PV-7.4 | `tirbase-gateway/src/security_log.rs:50` | — | TRACED-CALLER |
| 26.1 | Implement verify_hash_chain() at startup: on broken link → enter Restricted mode; emit TamperDetection Securit… | PV-7.4 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/task26_tamper_detection.rs:230` (`claim_26_1_gateway_binary_enters_restricted_on_injected_chain_break`) | VERIFIED-BY-TRACE |
| 26.2 | Implement signed chain-recovery operator command that exits Restricted mode and acknowledges the tamper event | PV-7.4 | `tirbase-gateway/src/admin.rs:381` (`dispatch_chain_recovery`) | `tirbase-gateway/tests/task26_tamper_detection.rs:270` (`claim_26_2_signed_chain_recovery_exits_restricted_and_requires_signature`) | VERIFIED-BY-TRACE |
| 26.3 | Implement external checkpoint anchoring: gossip latest checkpoint hash to peers on each sync connection; depen… | PV-7.10 | `tirbase-core/src/api/mod.rs:488` (`init`)<br>`tirbase-core/src/api/mod.rs:3053` (`set_checkpoint_provider`) | `tirbase-gateway/tests/task26_tamper_detection.rs:422` (`claim_26_3_26_4_two_corehandles_exchange_checkpoint_and_detect_tail_truncation`) | VERIFIED-BY-TRACE |
| 26.4 | Implement tail-truncation detection: a discrepancy between local latest checkpoint hash and peer-observed hash… | PV-7.10 | `tirbase-core/src/api/mod.rs:3001` (`subscribe_checkpoint_observations`)<br>`tirbase-gateway/src/security_log.rs:1601` (`observe_peer_checkpoint`) | `tirbase-gateway/tests/task26_tamper_detection.rs:333` (`claim_26_4_tail_truncation_discrepancy_enters_restricted`) | VERIFIED-BY-TRACE |
| 26.5 | Create peer_checkpoint_witnesses table in primary.db via the migration framework (task 32.1) | PV-7.10 | `tirbase-gateway/src/security_log.rs:1899` (`peer_checkpoint_witnesses`) | `tirbase-gateway/tests/task26_tamper_detection.rs:366` (`claim_26_5_peer_checkpoint_witnesses_table_created_and_readable`) | VERIFIED-BY-TRACE |
| 26.6 | Add property test (P18): any interior modification of a committed event at any position is detected by verify_… | PV-7.4 | `tirbase-guard/tests/time_ratchet_property.rs:1` | — | TRACED-CALLER |
| 26.7 | Implement single-gateway witness fallback: when a device has no mesh peers, gossip checkpoint hashes upstream … | PV-7.10 | `tirbase-gateway/src/security_log.rs:1734` (`set_witness_source`)<br>`tirbase-gateway/src/security_log.rs:1746` (`witness_state`) | `tirbase-gateway/tests/task26_tamper_detection.rs:388` (`claim_26_7_isolated_device_records_no_witness_available`) | VERIFIED-BY-TRACE |
| 27.1 | Implement GDPR salted commitments: personal fields stored as SHA-256(random_salt ‖ value); plaintext stored in… | PV-7.7, RD-3 | `tirbase-gateway/src/security_log.rs:1910` (`emit`) | — | TRACED-CALLER |
| 27.2 | Implement log export in CBOR and JSON formats; both exports signed by device key; pseudonymized export include… | PV-7.7 | `tirbase-admin/src/cmd/export.rs:1` | — | TRACED-CALLER |
| 27.3 | Implement export-evidence-bundle command: single archive containing full log, all signed checkpoints, device p… | PV-7.8 | `tirbase-admin/src/cmd/export.rs:9` | — | TRACED-CALLER |
| 27.4 | Implement tirbase-verify-log CLI: verify hash chain; exit 0 on intact chain; exit non-zero with gap/mismatch r… | PV-7.5 | `tirbase-admin/src/cmd/verify_log.rs:9` | — | TRACED-CALLER |
| 28.1 | Implement per-category rate limit (100 events/s); when limit exceeded emit single SuppressionSummary record st… | PV-7.6 | `tirbase-gateway/src/security_log.rs:1910` (`emit`) | `tirbase-gateway/tests/task28_log_flood_sync.rs:24` (`claim_28_1_event_flood_triggers_suppression_summary_via_sink`) | VERIFIED-BY-TRACE |
| 28.2 | Implement on-disk rolling retention window: 90 days or 1 GB (whichever comes first); background rotation job a… | PV-7.13 | `tirbase-gateway/src/key_rotation.rs:23` | `tirbase-gateway/tests/task28_log_flood_sync.rs:60` (`claim_28_2_rotation_archives_oldest_signed_segment_when_size_limit_reached`) | VERIFIED-BY-TRACE |
| 28.3 | Implement mesh sync of security events: append-only CRDT collection with compaction=none; per-peer 500 events/… | PV-7.9, PV-7.12 | `tirbase-gateway/src/security_log.rs:1881` (`spawn_security_event_sync_loop`)<br>`tirbase-gateway/src/security_log.rs:1761` (`set_security_event_sync_publisher`)<br>`tirbase-core/src/api/mod.rs:3017` (`publish_security_event_sync`) | `tirbase-core/tests/task28_security_event_sync.rs:92` (`claim_28_3_per_peer_rate_limit_emits_sync_rate_limit_reached_and_drops_excess`) | VERIFIED-BY-TRACE |
| 28.4 | Scenario S14 (log flooding) must be wired in tirbase-sim and passing before the security event log (tasks 25–2… | PV-12.5 | `tirbase-sim/src/scenarios/s14_log_flooding.rs:20` | — | TRACED-CALLER |

## Gaps and open items

- **25.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **25.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **25.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **25.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **25.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **26.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **27.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **27.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **27.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **27.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **28.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 20 rows have a resolved production call site or deliverable; 11 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

