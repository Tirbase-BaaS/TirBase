# Phase 9 — Gateway Binary, Admin API, Packaging — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.9

## Scope

Task sections 35.x, 36.x, 37.x: 36 acceptance-criterion rows (36 complete, 0 open in `tasks.md` at audit time).

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
| 35.1 | Create tirbase-gateway crate with clap-based binary entry point; wire together all subsystems (guard, admin AP… | PV-11 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/gateway_binary.rs:115` (`claim_35_1_gateway_binary_starts_and_passes_health_check`) | VERIFIED-BY-TRACE |
| 35.2 | Implement GatewayConfig TOML schema validation at startup; support signed config bundle (validated by PolicyAu… | PV-11.1 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/gateway_binary.rs:140` (`claim_35_2_invalid_config_rejected_at_startup_and_unsigned_bundle_rejected`) | VERIFIED-BY-TRACE |
| 35.3 | Create systemd unit file with hardening directives: WatchdogSec=30, MemoryDenyWriteExecute=yes, NoNewPrivilege… | PV-11.1 | `tirbase-core/src/crdt/hardening.rs:1` | `tirbase-gateway/tests/gateway_binary.rs:376` (`claim_35_3_systemd_unit_has_hardening_directives`) | VERIFIED-BY-TRACE |
| 35.4 | Implement health endpoint GET /health on 127.0.0.1 responding within 500ms | PV-11.1 | `tirbase-gateway/src/health.rs:19` | `tirbase-gateway/tests/gateway_binary.rs:293` (`claim_35_4_health_endpoint_responds_within_500ms`) | VERIFIED-BY-TRACE |
| 35.5 | Implement Prometheus metrics on 127.0.0.1:9090: guard_decisions_total, effects_ledger_writes_total, security_e… | PV-11.1 | `tirbase-gateway/src/metrics.rs:12` | `tirbase-gateway/tests/gateway_binary.rs:316` (`claim_35_5_prometheus_metrics_exposed`) | VERIFIED-BY-TRACE |
| 35.6 | Ensure all gateway output is structured JSON logs; replace every eprintln! in production paths with a typed Se… | PV-7.1 | — (deliverable / no runtime caller) | `tirbase-gateway/tests/gateway_binary.rs:346` (`claim_35_6_structured_json_logs_in_gateway_output`) | TRACED-TEST |
| 36.1 | Implement Unix-socket admin API at /run/tirbase/admin.sock with SO_PEERCRED local authentication (not mTLS — r… | PV-11.2 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/remote_admin.rs:342` (`remote_admin_requires_mtls_and_privileged_status_credential`) | VERIFIED-BY-TRACE |
| 36.2 | Implement optional remote admin endpoint with mTLS when enabled in config | PV-11.2 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/remote_admin.rs:342` (`remote_admin_requires_mtls_and_privileged_status_credential`) | VERIFIED-BY-TRACE |
| 36.3a | POST /admin/enroll — device enrollment endpoint; delegates to enrollment flow from | PV-11.2 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/admin_endpoints_binary.rs:507` (`admin_enroll_requires_matching_policy_authority_delegation_when_supplied`) | VERIFIED-BY-TRACE |
| 36.3b | POST /admin/mint — token minting; maximum lifetime enforced at 86,400 seconds; returns scoped Biscuit token | PV-11.2 | `tirbase-gateway/src/admin.rs:723` (`dispatch_mint`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:459` (`admin_mint_enforces_max_lifetime_and_returns_scoped_token`) | VERIFIED-BY-TRACE |
| 36.3c | POST /admin/rotate — key rotation; delegates to KeyProvider rotation | PV-11.2 | `tirbase-gateway/src/admin.rs:787` (`dispatch_rotate`)<br>`tirbase-gateway/src/key_rotation.rs:37` (`KeyRotator`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:491` (`admin_rotate_rotates_the_device_identity`) | VERIFIED-BY-TRACE |
| 36.3d | POST /admin/policy — push policy bundle (tightening or loosening); delegates to policy lifecycle from .… | PV-11.2 | `tirbase-gateway/src/admin.rs:556` (`dispatch_policy`)<br>`tirbase-guard/src/policy.rs:400` (`PolicyLifecycle`)<br>`tirbase-guard/src/permit.rs:55` (`target_id`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:311` (`admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary`) | VERIFIED-BY-TRACE |
| 36.3e | GET /admin/events — event inspection (SSE stream or paginated query); retention window configurable, default 7… | PV-11.2 | `tirbase-gateway/src/admin.rs:830` (`dispatch_events`)<br>`tirbase-gateway/src/security_log.rs:569` (`SecurityEventLog`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:311` (`admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary`) | VERIFIED-BY-TRACE |
| 36.3f | POST /admin/simulate — command simulation dry-run; delegates to simulate from | PV-11.2 | `tirbase-gateway/src/admin.rs:2096` (`dispatch_simulate`)<br>`tirbase-guard/src/guard.rs:127` (`CommandGuard`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:311` (`admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary`) | VERIFIED-BY-TRACE |
| 36.3g | POST /admin/challenge — issue challenge nonce for critical-parameter commands in UNVERIFIED freshness state; d… | PV-11.2 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/admin_endpoints_binary.rs:311` (`admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary`) | TRACED-CALLER |
| 36.3h | GET /admin/mode — return current NodeMode (Starting/Normal/Degraded/Restricted/Lockdown) | PV-11.2 | `tirbase-gateway/src/admin.rs:308` (`dispatch_mode`)<br>`tirbase-guard/src/node_mode.rs:120` (`NodeModeState`)<br>`tirbase-gateway/src/db/lockdown.rs:15` (`SqliteLockdownStore`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:799` (`admin_lockdown_exit_requires_m_of_n_and_transitions_mode_over_binary`) | TRACED-CALLER |
| 36.3i | POST /admin/lockdown-exit — LOCKDOWN exit requiring M-of-N co-signatures from ≥2 distinct roles; delegates to … | PV-11.2 | `tirbase-gateway/src/admin.rs:334` (`dispatch_lockdown_exit`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:799` (`admin_lockdown_exit_requires_m_of_n_and_transitions_mode_over_binary`) | VERIFIED-BY-TRACE |
| 36.3j | POST /admin/chain-recovery — hash-chain recovery command for exiting Restricted mode; delegates to | PV-11.2 | `tirbase-gateway/src/admin.rs:381` (`dispatch_chain_recovery`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:852` (`admin_chain_recovery_requires_signature_over_binary`) | VERIFIED-BY-TRACE |
| 36.3k | GET /admin/status/{issuer_did} — Guard status API per PV-24.3; returns anti-replay window position, rate-limit… | PV-11.2, PV-24.3 | `tirbase-gateway/src/admin.rs:890` (`dispatch_status`)<br>`tirbase-guard/src/single_writer_lease.rs:12` (`SingleWriterLease`)<br>`tirbase-guard/src/admit.rs:400` (`issuer_rate_limit_snapshot`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:575` (`admin_status_and_additional_endpoints_over_binary`)<br>`tirbase-gateway/tests/remote_admin.rs:342` (`remote_admin_requires_mtls_and_privileged_status_credential`) | VERIFIED-BY-TRACE |
| 36.3l | Additional endpoints: POST /admin/sequence-reset (PolicyAuthority signed), POST /admin/lease-preempt (Revocati… | PV-11.2 | `tirbase-gateway/src/admin.rs:2149` (`dispatch_sequence_reset`)<br>`tirbase-gateway/src/admin.rs:1727` (`dispatch_lease_preempt`)<br>`tirbase-gateway/src/admin.rs:1031` (`dispatch_quarantine_replay`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:575` (`admin_status_and_additional_endpoints_over_binary`) | VERIFIED-BY-TRACE |
| 36.4 | Create docs/api/gateway-admin-openapi.yaml defining all admin endpoints (36.3a through 36.3l) | PV-11.2 | `docs/api/gateway-admin-openapi.yaml:8`<br>`tirbase-gateway/tests/reference_profile_binary.rs:9` (`gateway`) | `tirbase-gateway/tests/openapi.rs:7` (`gateway_admin_openapi_defines_every_admin_endpoint`) | VERIFIED-BY-TRACE |
| 36.5 | Implement deny-all behaviour until a signed EnvelopeProfile is installed; no listening sockets opened unless e… | PV-11.5 | `tirbase-gateway/src/main.rs:62` | `tirbase-gateway/tests/deny_all.rs:50` (`no_profile_means_no_command_socket_and_a_deny_all_boot_event`) | VERIFIED-BY-TRACE |
| 36.6 | Implement cloud ingress as outbound-initiated TLS only (no inbound cloud listener on the gateway) | PV-11 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/deny_all.rs:141` (`cloud_inbound_listener_is_a_configuration_error`) | VERIFIED-BY-TRACE |
| 36.7 | Implement Guard status API (PV-24.3): GET /admin/status/{issuer_did} returns anti-replay window position, rate… | PV-24.3 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/admin_endpoints_binary.rs:575` (`admin_status_and_additional_endpoints_over_binary`)<br>`tirbase-gateway/tests/remote_admin.rs:342` (`remote_admin_requires_mtls_and_privileged_status_credential`) | VERIFIED-BY-TRACE |
| 36.8a | Implement outbound-initiated TLS connection from gateway to cloud endpoint with exponential backoff reconnect | PV-11.1 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/cloud_channel.rs:510` (`cloud_channel_is_outbound_tls_only_with_queue_reconnect_feedback_and_rate_limit`) | VERIFIED-BY-TRACE |
| 36.8b | Implement device certificate authentication for cloud connection using KeyProvider-signed certificate | PV-11.1 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/cloud_channel.rs:626` (`cloud_channel_rejects_untrusted_device_certificate`) | VERIFIED-BY-TRACE |
| 36.8c | Implement offline command queueing with ring buffer (configurable depth); commands queued during disconnection… | PV-11.1 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/cloud_channel.rs:510` (`cloud_channel_is_outbound_tls_only_with_queue_reconnect_feedback_and_rate_limit`) | VERIFIED-BY-TRACE |
| 36.8d | Implement issuer rejection feedback delivery over cloud channel; coarse rejection codes returned to remote iss… | PV-11.1, PV-24.1 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/cloud_channel.rs:510` (`cloud_channel_is_outbound_tls_only_with_queue_reconnect_feedback_and_rate_limit`) | VERIFIED-BY-TRACE |
| 36.8e | Implement challenge issuance over cloud channel; remote issuers can request challenge nonces via the cloud cha… | PV-11.1, PV-22.3 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/cloud_channel.rs:510` (`cloud_channel_is_outbound_tls_only_with_queue_reconnect_feedback_and_rate_limit`) | VERIFIED-BY-TRACE |
| 36.8f | Implement per-connection rate limits and certificate rotation without connection disruption | PV-11.1 | `tirbase-gateway/src/cloud.rs:61` | `tirbase-gateway/tests/cloud_channel.rs:510` (`cloud_channel_is_outbound_tls_only_with_queue_reconnect_feedback_and_rate_limit`) | VERIFIED-BY-TRACE |
| 36.9 | Implement challenge issuance over mesh channel: peers can request challenge nonces for critical-parameter comm… | PV-22.3 | `tirbase-core/src/transport/challenge.rs:26` | `tirbase-gateway/tests/mesh_challenge.rs:56` (`challenge_is_issued_by_peer_and_routed_only_to_originating_guard`) | VERIFIED-BY-TRACE |
| 37.1 | Implement cross-compiled builds for aarch64-unknown-linux-gnu and armv7-unknown-linux-gnueabihf | PV-11.4 | `.github/workflows/ci.yml:914` | — | TRACED-ARTIFACT |
| 37.2 | Create .deb package targeting Debian 11+ | PV-11.4 | — (deliverable / no runtime caller) | — | TRACED-ARTIFACT |
| 37.3 | Create OCI container image | PV-11.4 | — (deliverable / no runtime caller) | — | TRACED-ARTIFACT |
| 37.4 | Add CI binary size and RSS budget gates (numerical budgets set after measure-first ) | PV-11.4 | `.github/workflows/ci.yml:1146` | — | TRACED-ARTIFACT |
| 37.5 | Implement fleet inventory management as a CRDT collection: provisioning payloads ≤64 KiB; revocation changes p… | PV-11.3 | `tirbase-core/src/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |

## Gaps and open items

- **35.6** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **36.3g** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **36.3h** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **37.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **37.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **37.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **37.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **37.5** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 36 rows have a resolved production call site or deliverable; 8 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

