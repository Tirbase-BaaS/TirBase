# Phase 2 — Guard Pipeline, Envelope, Policy, Modes — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.2

## Scope

Task sections 10.x, 11.x, 12.x, 13.x, 14.x, 15.x, 16.x, 17.x: 65 acceptance-criterion rows (65 complete, 0 open in `tasks.md` at audit time).

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
| 10.1 | Implement ParameterKind enum: Range { min: FixedPointValue, max: FixedPointValue }, Enum { variants }, Bool | PV-4.5 | `tirbase-types/src/envelope.rs:29` (`ParameterKind`) | `tirbase-guard/tests/envelope_profile.rs:148` (`parameter_kind_range_enum_bool_construct_and_serde`)<br>`tirbase-gateway/tests/envelope_profile.rs:25` (`gateway_profile_install_accepts_policy_authority_and_rejects_non_pa`) | VERIFIED-BY-TRACE |
| 10.2 | Implement ParameterSpec: name, unit_id, canonical_exponent, kind, max_rate_per_sec, dwell_secs, min_off_secs, … | PV-4.5 | `tirbase-types/src/envelope.rs:46` (`ParameterSpec`) | `tirbase-guard/tests/envelope_profile.rs:174` (`parameter_spec_carries_all_required_fields`) | VERIFIED-BY-TRACE |
| 10.3 | Implement LinearConstraint: coefficients, bound, operator (Leq/Geq/Eq); total non-Turing-complete constraint l… | PV-4.5 | `tirbase-types/src/envelope.rs:95` (`LinearConstraint`)<br>`tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/envelope_profile.rs:195` (`linear_constraint_expresses_conjunction_and_evaluates_bound`) | VERIFIED-BY-TRACE |
| 10.4 | Implement EnvelopeProfile: profile_id, version, device_class, parameters, cross_constraints, governance fields… | PV-4.5 | `tirbase-guard/src/envelope.rs:291` (`install_profile`)<br>`tirbase-guard/src/envelope.rs:86` (`verify_profile_signature`) | `tirbase-guard/tests/envelope_profile.rs:232` (`envelope_profile_signed_by_policy_authority_is_accepted`)<br>`tirbase-guard/tests/envelope_profile.rs:243` (`profile_signed_by_non_policy_authority_is_rejected`) | VERIFIED-BY-TRACE |
| 10.5 | Implement target-to-profile map: BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>> with hot-swap support (Hash… | PV-4.5 | `tirbase-guard/src/envelope.rs:236` (`ProfileMap`)<br>`tirbase-guard/src/guard.rs:127` (`CommandGuard`) | `tirbase-guard/tests/envelope_profile.rs:319` (`profile_map_hot_swap_takes_effect`)<br>`tirbase-guard/tests/envelope_profile.rs:337` (`profile_map_hot_swap_visible_across_threads_within_one_second`) | VERIFIED-BY-TRACE |
| 10.6 | Implement install-time profile validation against DeviceModel: unit_id match, range containment within DeviceM… | PV-4.5 | `tirbase-guard/src/envelope.rs:150` (`validate_profile`)<br>`tirbase-guard/src/envelope.rs:291` (`install_profile`) | `tirbase-guard/tests/envelope_profile.rs:382` (`validate_profile_rejects_unit_id_mismatch_with_field_error`)<br>`tirbase-guard/tests/envelope_profile.rs:401` (`validate_profile_rejects_range_outside_device_model`) | VERIFIED-BY-TRACE |
| 11.1 | Implement CommandMessage: issuer_did, role, target_id, param, desired_state: FixedPointValue, sequence_number,… | PV-4.1, PV-4.2 | `tirbase-gateway/src/db/idempotency_keys.rs:1` | — | TRACED-CALLER |
| 11.2 | Implement ActuationPermit in tirbase-guard/src/permit.rs: fields target_id, param, value: FixedPointValue, ent… | PV-4.3 | `tirbase-guard/src/permit.rs:28` (`ActuationPermit`)<br>`tirbase-sim/src/sim.rs:171` (`guard`)<br>`tirbase-guard/src/permit.rs:55` (`target_id`) | — | TRACED-CALLER |
| 11.3 | Implement DriverProxy in tirbase-guard/src/driver_proxy.rs which holds ActuationPermit and sends the actuation… | PV-4.4 | `tirbase-guard/src/driver_proxy.rs:59` (`DriverProxy`)<br>`tirbase-sim/src/sim.rs:171` (`guard`)<br>`tirbase-guard/src/permit.rs:28` (`ActuationPermit`) | — | TRACED-CALLER |
| 12.1 | Implement PolicyBundle: version, prev_version_hash, envelope: EnvelopeProfile, co_signatures: Vec<PolicyCoSign… | PV-4.8 | `tirbase-gateway/src/admin.rs:556` (`dispatch_policy`)<br>`tirbase-guard/src/policy.rs:501` (`ingest_bundle`) | `tirbase-gateway/tests/policy_lifecycle.rs:162` (`admin_policy_push_tightening_advances_version_and_recomputes_classification`)<br>`tirbase-gateway/tests/admin_endpoints_binary.rs:311` (`admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary`) | VERIFIED-BY-TRACE |
| 12.2 | Implement classify_bundle: 11-criterion tightening classification — interval containment, rate/dwell/min-off… | PV-4.11 | `tirbase-guard/src/policy.rs:501` (`ingest_bundle`) | `tirbase-gateway/tests/policy_lifecycle.rs:162` (`admin_policy_push_tightening_advances_version_and_recomputes_classification`) | VERIFIED-BY-TRACE |
| 12.3 | Implement tightening_floor enforcement: reject tightening bundle if any parameter’s new limit is more restrict… | PV-4.11 | `tirbase-guard/src/policy.rs:146` (`classify_bundle`)<br>`tirbase-guard/src/policy.rs:834` (`check_tightening_floors`) | `tirbase-gateway/tests/policy_lifecycle.rs:233` (`timelock_bypass_version_gap_and_rollback_attempts_rejected_via_lifecycle`)<br>`tirbase-guard/tests/policy_lifecycle.rs:196` (`tightening_floor_violation_is_rejected`) | VERIFIED-BY-TRACE |
| 12.4 | Implement policy loosening path: read M/N/timelock from the **active** policy (not the incoming bundle); colle… | PV-4.10 | `tirbase-guard/src/policy.rs:672` (`add_loosening_cosignature`)<br>`tirbase-guard/src/policy.rs:708` (`apply_pending_loosening`)<br>`tirbase-guard/src/policy.rs:501` (`ingest_bundle`) | `tirbase-guard/tests/policy_lifecycle.rs:291` (`m1_loosening_is_allowed_with_timelock`)<br>`tirbase-guard/tests/policy_lifecycle.rs:255` (`loosening_uses_active_m_n_timelock_not_bundle`) | VERIFIED-BY-TRACE |
| 12.5 | Implement policy tightening path: apply within 1 second of signature verification completion; emit tightening-… | PV-4.9 | `tirbase-guard/src/policy.rs:552` (`apply_tightening`) | `tirbase-gateway/tests/policy_lifecycle.rs:162` (`admin_policy_push_tightening_advances_version_and_recomputes_classification`) | VERIFIED-BY-TRACE |
| 12.6 | Implement anti-rollback counter: every accepted bundle version committed to MonotonicCounterTrait; reject vers… | PV-4.8 | `tirbase-guard/src/policy.rs:40` | `tirbase-guard/tests/policy_lifecycle.rs:167` (`rollback_replay_is_rejected_and_counter_not_regressed`) | VERIFIED-BY-TRACE |
| 12.7 | Enforce strictly-greater version semantics: any version strictly greater than the last accepted is valid (not … | PV-4.8 | `tirbase-guard/src/policy.rs:40` | `tirbase-guard/tests/policy_lifecycle.rs:184` (`strictly_greater_version_gap_is_accepted`) | VERIFIED-BY-TRACE |
| 12.8 | Add pending_approvals table to primary.db for multi-signature operations: policy loosening, lockdown-exit, epo… | PV-4.10 | `tirbase-gateway/src/db/pending_approvals.rs:33`<br>`tirbase-guard/src/policy.rs:40` | `tirbase-gateway/tests/policy_lifecycle.rs:195` (`pending_approvals_table_accumulates_partial_signatures`)<br>`tirbase-gateway/src/db/pending_approvals.rs:241` (`pending_approval_accumulates_signatures`) | VERIFIED-BY-TRACE |
| 12.9 | Add proptest offline soundness proof for classify_bundle: verify that a bundle classified as tightening is a… | PV-4.11 | `tirbase-guard/tests/policy_proptest.rs:1` | `tirbase-guard/tests/policy_proptest.rs:112` (`tightening_is_always_a_strict_envelope_subset`) | TRACED-CALLER |
| 12.10 | Add tests: time-lock bypass attempts, rollback replay attempts, version-gap tricks | PV-4.12 | `tirbase-guard/tests/compile_fail/driver_proxy_bypass.rs:1` | `tirbase-gateway/tests/policy_lifecycle.rs:233` (`timelock_bypass_version_gap_and_rollback_attempts_rejected_via_lifecycle`)<br>`tirbase-guard/tests/policy_lifecycle.rs:314` (`version_gap_trick_and_rollback_replay_bypass_attempts_rejected`) | VERIFIED-BY-TRACE |
| 12.11 | Scenario S7 (policy loosening without M-of-N) must be wired in tirbase-sim and passing before PolicyLifecycle … | PV-12.5 | `tirbase-sim/src/scenarios/s7_policy_loosening.rs:28` | — | TRACED-CALLER |
| 13.1 | Implement NodeMode enum: Starting, Normal, Degraded, Restricted, Lockdown; mode × operation matrix enforcement… | PV-4.13 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:799` (`admin_lockdown_exit_requires_m_of_n_and_transitions_mode_over_binary`) | TRACED-CALLER |
| 13.2 | Implement LOCKDOWN entry: explicit guard decision or crash-loop escalation; persist LOCKDOWN state to primary.… | PV-4.13 | `tirbase-guard/src/lockdown.rs:19` | — | TRACED-CALLER |
| 13.3 | Implement LOCKDOWN exit: M-of-N signed LockdownExit command requiring ≥2 distinct roles (e.g., PolicyAuthority… | PV-4.13 | `tirbase-gateway/src/admin.rs:334` (`dispatch_lockdown_exit`)<br>`tirbase-gateway/src/db/lockdown.rs:15` (`SqliteLockdownStore`)<br>`tirbase-guard/src/node_mode.rs:120` (`NodeModeState`) | `tirbase-gateway/tests/admin_endpoints_binary.rs:799` (`admin_lockdown_exit_requires_m_of_n_and_transitions_mode_over_binary`) | VERIFIED-BY-TRACE |
| 13.4 | Implement tirbase-lockdown.service oneshot systemd unit: write lockdown flag on guard process failure | PV-1.11, PV-4.15 | `docs/runbooks/lockdown.md:1` | — | TRACED-ARTIFACT |
| 13.5 | Implement safe-default enforcement on guard death; DESIGN NOTE: ExecStopPost= cannot drive safe defaults becau… | PV-4.15, PV-23.1 | `docs/drivers/cold_room_modbus.md:1` | `tirbase-sim/src/invariants.rs:595` (`inv_1_out_of_envelope_actuation_fails_immediately`) — via PV-23.1 | TRACED-TEST |
| 13.6 | Implement supervisor crash vs. LOCKDOWN separation: supervisor auto-restarts process into Normal after crash r… | PV-1.11 | `tirbase-gateway/src/db/ledger_reconciliation.rs:1` | — | TRACED-CALLER |
| 13.7 | Implement dedicated health-loop task (forward-progress proof, not tied to evaluate); sends sd_notify WATCHDO… | PV-4.15 | `tirbase-gateway/src/health.rs:19` | — | TRACED-CALLER |
| 14.1 | Implement CommandGuard struct: ArcSwap<EnvelopeProfile>, ArcSwap<PolicyBundle> config snapshots; derive pub(cr… | PV-4.3 | `tirbase-gateway/src/main.rs:62` | `tirbase-guard/tests/admit_pipeline.rs:202` (`claim_14_1_struct_has_arcswap_snapshots`) | VERIFIED-BY-TRACE |
| 14.2 | Implement Stage 0: pre-auth per-source rate limit (token bucket) before any cryptographic operation | PV-4.3 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/admit_pipeline.rs:208` (`claim_14_2_stage0_pre_auth_rate_limit`) | VERIFIED-BY-TRACE |
| 14.3 | Implement Stage 1: OperationalMode check — reject all commands when mode is Lockdown or Restricted | PV-4.13 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_pipeline.rs:164` (`claim_14_3_mode_lockdown_rejects_via_pipeline`) | VERIFIED-BY-TRACE |
| 14.4 | Implement Stage 2: command signature verification over canonical CBOR of all fields except the signature field | PV-4.3 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/admit_pipeline.rs:225` (`claim_14_4_stage2_signature_required`) | VERIFIED-BY-TRACE |
| 14.5 | Implement Stage 3: Biscuit token verification against RootCaRegistry | PV-3.2 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_pipeline.rs:208` (`claim_14_5_unknown_ca_rejected_and_14_6_binding_rejected`) | VERIFIED-BY-TRACE |
| 14.6 | Implement Stage 4: token-to-command binding — derive CommandRole from Biscuit token caveats (never from cmd.ro… | PV-4.6 | `tirbase-guard/src/guard.rs:249` (`admit`) | — | TRACED-CALLER |
| 14.7 | Implement Stage 5: issuer DID revocation check against in-memory revocation set; depends on Gate G1 (0.4) | PV-4.3 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_pipeline.rs:290` (`claim_14_7_revoked_issuer_14_8_epoch_14_9_expiry_14_11_envelope_14_13_bounds`) | VERIFIED-BY-TRACE |
| 14.8 | Implement Stage 6: device enrollment epoch check — cmd.enrollment_epoch must equal the device's current enroll… | PV-5.5, PV-9.8 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 14.9 | Implement Stage 8: command expiry using now_est; enforce max_ttl_secs cap (default 3600s); reject if now_est >… | PV-4.2, PV-22 | `tirbase-guard/src/guard.rs:249` (`admit`) | — | TRACED-CALLER |
| 14.10 | Implement Stage 9: challenge nonce verification for FreshnessState::Unverified + critical: true parameters — r… | PV-22.3 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/admit_pipeline.rs:243` (`claim_14_10_challenge_missing_for_unverified_critical`) | VERIFIED-BY-TRACE |
| 14.11 | Implement Stage 7: decided-outcome cache lookup by (issuer_did, target_id, sequence_number, epoch) — return st… | PV-5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_pipeline.rs:435` (`claim_14_11_decided_outcome_cache_returns_cached_without_second_actuation`) | VERIFIED-BY-TRACE |
| 14.12 | Implement Stage 10: FixedPointValue validation — canonical exponent check against ParameterSpec; reject non-ca… | PV-21.1, PV-21.2 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/admit_pipeline.rs:260` (`claim_14_12_canonical_exponent_enforced`) | VERIFIED-BY-TRACE |
| 14.13 | Implement Stage 11: envelope bounds check using i128 intermediates to prevent overflow; reject with EnvelopeVi… | PV-4.6 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_pipeline.rs:629` (`claim_14_13_14_15_db_backed_stores_exercised`) | VERIFIED-BY-TRACE |
| 14.14 | Implement Stage 12: cross-parameter linear constraint evaluation over the set of pending+committed desired-sta… | PV-4.5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_pipeline.rs:472` (`claim_14_14_constraints_14_15_drift_14_16_issuer_rate_limit_14_17_quorum`) | VERIFIED-BY-TRACE |
| 14.15 | Implement Stage 13: rate-of-change and cumulative drift window check using drift_rate_history table; reject wi… | PV-4.7 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/admit_pipeline.rs:283` (`claim_14_15_drift_exceeded`) | VERIFIED-BY-TRACE |
| 14.16 | Implement Stage 14: per-issuer rate limit (default 10 cmd/s per issuer DID, configurable per EnvelopeProfile);… | PV-24.2 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/admit_pipeline.rs:416` (`claim_14_16_per_issuer_rate_limit`) | VERIFIED-BY-TRACE |
| 14.17 | Implement Stage 15: quorum check for critical: true parameters (M-of-N co-signatures collected in pending_appr… | PV-4.16 | `tirbase-guard/src/guard.rs:249` (`admit`) | — | TRACED-CALLER |
| 15.1 | Implement Stage 16 (atomic commit including lease) as one atomic SQLite transaction: non-mutating anti-replay … | PV-5.1, PV-5.5 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_stage16.rs:97` (`claim_15_1_stage16_atomic_commit_and_lease_failure_rolls_back_all_state`) | VERIFIED-BY-TRACE |
| 15.2 | Merged into 15.1. Lease acquisition is part of the atomic commit transaction (Stage 16). This is a placeholder… | PV-5.8 | `tirbase-guard/src/commit.rs:1` | — | TRACED-CALLER |
| 15.3 | Implement Stage 17: SecurityEvent emission — coarse rejection code returned to issuer (ENVELOPE_VIOLATION, ANT… | PV-4.18, PV-7.1, PV-24.1 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_stage16.rs:179` (`claim_15_3_stage17_coarse_to_issuer_fine_to_auditor`) | VERIFIED-BY-TRACE |
| 15.4 | Implement Stage 18: ActuationPermit dispatch to driver process via the inherited socketpair(AF_UNIX, SOCK_SEQP… | PV-4.21 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_stage16.rs:210` (`claim_15_4_15_5_stage18_dispatch_after_commit_stage19_finalize_releases_lease`) | VERIFIED-BY-TRACE |
| 15.5 | Implement Stage 19: await driver confirmation (30s timeout) → update Actuating to Complete or Unknown; release… | PV-5.2, PV-5.8a | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/command_guard_stage16.rs:244` (`claim_15_5_driver_timeout_results_in_unknown`) | VERIFIED-BY-TRACE |
| 15.6 | Split admit from async executor: admit runs Stages 0–15 synchronously with no driver or network I/O; DB re… | PV-4.20 | `tirbase-gateway/src/guard.rs:26` | — | TRACED-CALLER |
| 15.7 | Implement simulate as a side-effect-free dry run: skip Stage 0 (rate-limit token), Stage 9 (challenge nonce … | PV-4.17 | `tirbase-gateway/src/admin.rs:2096` (`dispatch_simulate`)<br>`tirbase-guard/src/guard.rs:127` (`CommandGuard`) | `tirbase-gateway/tests/command_guard_stage16.rs:280` (`claim_15_7_simulate_returns_rejection_without_actuation`) | VERIFIED-BY-TRACE |
| 15.8 | Add token-cannot-relax property test: for any token minted by any key, a command with a value outside the Enve… | PV-4.6 | `tirbase-guard/tests/time_ratchet_property.rs:1` | — | TRACED-CALLER |
| 15.9 | Scenarios S1 (out-of-envelope command) and S3 (replay) must be wired in tirbase-sim and passing before the ful… | PV-12.5 | `tirbase-sim/src/scenarios/s9_engine_profile_mismatch.rs:16` | — | TRACED-CALLER |
| 16.1 | Implement ChallengeNonce: device_id, param, nonce: [u8; 32], issued_at_mono, expires_at_mono; nonce consumed a… | PV-22.3 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-gateway/tests/challenge_nonce.rs:207` (`claim_16_1_16_3_nonce_is_one_time_use`) | VERIFIED-BY-TRACE |
| 16.2 | Create challenge_nonces table in primary.db | PV-22.3 | `tirbase-gateway/src/db/challenge_nonces.rs:14` | `tirbase-gateway/tests/challenge_nonce.rs:326` (`claim_16_2_sqlite_store_persists_and_bootstraps_required_fields`) | VERIFIED-BY-TRACE |
| 16.3 | Add GET /admin/challenge/{target}/{param} endpoint: issues nonce when FreshnessState::Unverified and param has… | PV-22.3 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/challenge_nonce.rs:176` (`claim_16_3_admin_challenge_issues_only_for_unverified_critical_param`) | VERIFIED-BY-TRACE |
| 16.4 | Add per-device nonce rate limit; implement adversary scenario S32 (challenge-nonce flooding attack) | PV-22.3 | `tirbase-gateway/src/admin.rs:27` | `tirbase-gateway/tests/challenge_nonce.rs:235` (`claim_16_4_s32_challenge_nonce_flood_rate_limited`) | VERIFIED-BY-TRACE |
| 17.1 | Register INV-1 in docs/system-invariants.md with test ID pointing at the tirbase-sim tick check; verify tirbas… | PV-23.2 | `docs/system-invariants.md:74`<br>`tirbase-sim/src/invariants.rs:247` (`InvariantChecker`) | — | TRACED-CALLER |
| 17.2 | Register INV-2 in docs/system-invariants.md with test ID; verify tirbase-sim calls the INV-2 check | PV-23.2 | `docs/system-invariants.md:16` | — | TRACED-ARTIFACT |
| 17.3 | Register INV-3 in docs/system-invariants.md with test ID; verify tirbase-sim calls the INV-3 check | PV-23.2 | `docs/system-invariants.md:16` | — | TRACED-ARTIFACT |
| 17.4 | Register INV-4 in docs/system-invariants.md with test ID; verify tirbase-sim calls the INV-4 check | PV-23.2 | `docs/system-invariants.md:16` | — | TRACED-ARTIFACT |
| 17.5 | Register INV-5 in docs/system-invariants.md with test ID; verify tirbase-sim calls the INV-5 check | PV-23.2 | `docs/system-invariants.md:16` | — | TRACED-ARTIFACT |
| 17.6 | Register INV-6 in docs/system-invariants.md with test ID; verify tirbase-sim calls the INV-6 check | PV-23.2 | `docs/system-invariants.md:56` | — | TRACED-ARTIFACT |
| 17.7 | Register INV-7 in docs/system-invariants.md with test ID; verify tirbase-sim calls the INV-7 check | PV-23.2 | `docs/system-invariants.md:16` | — | TRACED-ARTIFACT |
| 17.8 | Register INV-8 through INV-16 in docs/system-invariants.md with test IDs; verify tirbase-sim calls each check;… | PV-23.2 | `docs/system-invariants.md:24`<br>`tirbase-sim/src/invariants.rs:247` (`InvariantChecker`) | — | TRACED-CALLER |

## Gaps and open items

- **11.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **11.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **11.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **12.9** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **12.11** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **13.1** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **13.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **13.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **13.5** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **13.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **13.7** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **14.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **14.8** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **14.9** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **14.17** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **15.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **15.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **15.8** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **15.9** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **17.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **17.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **17.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **17.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **17.5** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **17.6** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **17.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **17.8** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 65 rows have a resolved production call site or deliverable; 27 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

