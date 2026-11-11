# Adversary Scenarios Catalog

**Status:** [CLAIM-3.7 — Proven]; S1–S35 are wired in `tirbase-sim/scenarios/*.toml` and executed by `tirbase-sim/src/runner.rs` (task 39, CLAIM-39.1–39.4).

This document catalogs all adversary scenarios (S1–S35) for TirBase. Each entry records the attack vector, expected system response, PV requirement reference, pass/fail criteria, and a test ID (populated when the corresponding `tirbase-sim` scenario or integration test is implemented).

Scenarios are tracked by the deterministic simulator (`tirbase-sim`) and the integration test suite. CI executes ≥ 1,000 seeded scenarios per run (PV-12.1). On any scenario failure, the test seed is printed to stdout for exact reproduction (PV-12.2). Every scenario here must have at least one associated automated test passing in CI before the capability it covers is considered complete (PV-12.4, PV-12.5).

---

## How to Read This Catalog

| Field | Meaning |
|---|---|
| **Attack Vector** | The mechanism the adversary uses (what they send, forge, or manipulate). |
| **Expected Response** | The exact guard stage, rejection code, or mode transition the system produces. |
| **PV Requirement** | The `PV-X.Y` acceptance criterion that mandates this behavior. |
| **Pass Criteria** | Observable conditions that constitute a passing test. |
| **Fail Criteria** | Observable conditions that mean the defense has failed. |
| **Test ID** | The `tirbase-sim` scenario file or integration test function that verifies this scenario. Populated once implemented; `PLANNED` until then. |

---

## S1 — Out-of-Envelope Command

**Attack Vector:** An adversary (or buggy client) sends a signed `CommandMessage` whose `desired_state` falls outside the `[min, max]` bounds defined in the `ParameterSpec` for the targeted parameter.

**Expected Response:** `CommandGuard::admit()` reaches Stage 11 (envelope bounds check) and returns `RejectionCategory::EnvelopeViolation`. The command is not written to the `Applied_Effects_Ledger` and the driver is never contacted. A `SecurityEvent` with reason `EnvelopeViolation` is emitted.

**PV Requirement:** PV-4.6

**Pass Criteria:**
- Guard rejects the command before any driver I/O.
- `SecurityEvent(CommandDecision, Reject, EnvelopeViolation)` appears in the security event log.
- Coarse external code returned to the issuer is `ENVELOPE_VIOLATION`.
- No `Actuating` row is created in `applied_effects_ledger`.

**Fail Criteria:**
- Command is forwarded to the driver.
- `Applied_Effects_Ledger` contains an `Actuating` entry for the rejected command.
- System reverts to any state other than "command rejected, last-accepted state retained."

**Test ID:** `tirbase-sim/scenarios/S01.toml` | `tirbase-guard/tests/guard_pipeline.rs::test_out_of_envelope_command`

---

## S2 — Slow Ramp / Cumulative Drift

**Attack Vector:** An adversary sends a series of individually in-envelope commands that collectively exceed the rate-of-change or cumulative-drift window defined in the `EnvelopeProfile`. Each command is valid when viewed in isolation.

**Expected Response:** Stage 13 (rate-of-change and drift window check) detects that the cumulative delta within the configured `drift_window_secs` exceeds `max_delta_in_window` and returns `RejectionCategory::DriftExceeded`. Commands accepted up to the drift boundary remain actuated.

**PV Requirement:** PV-4.7

**Pass Criteria:**
- All commands within the drift window are accepted until the budget is exhausted.
- The command that would push cumulative drift past the limit is rejected with `DriftExceeded`.
- `SecurityEvent(CommandDecision, Reject, DriftExceeded)` is emitted.

**Fail Criteria:**
- All commands are accepted regardless of cumulative drift.
- Drift history is not persisted to `drift_rate_history` table.
- A reboot resets the drift window, allowing the attack to restart.

**Test ID:** `tirbase-sim/scenarios/S02.toml` | `tirbase-guard/tests/guard_pipeline.rs::test_slow_ramp_drift`

---

## S3 — Replay Attack

**Attack Vector:** An adversary captures a previously accepted and fully processed `CommandMessage` (valid signature, valid token, in-envelope value) and retransmits it to the guard.

**Expected Response:** Stage 16 (atomic commit) consults the `AntiReplayWindow` and finds the sequence number already seen for the `(issuer_did, target_id, enrollment_epoch)` triple. The transaction is aborted with `RejectionCategory::CommitConflict`. No second actuation occurs.

**PV Requirement:** PV-5.5

**Pass Criteria:**
- The retransmitted command is rejected with coarse code `ANTI_REPLAY`.
- `AntiReplayWindow.highest_seen` is not advanced by the rejected command.
- No second `Actuating` entry is written to `applied_effects_ledger`.
- A `SecurityEvent` with category `AntiReplay` is emitted.

**Fail Criteria:**
- The replayed command is actuated a second time.
- The `highest_seen` counter advances on rejection.

**Test ID:** `tirbase-sim/scenarios/S03.toml` | `tirbase-guard/tests/anti_replay.rs::test_replay_attack`

---

## S4 — Clock Poisoning (Wall-Clock)

**Attack Vector:** An adversary compromises or manipulates the system wall clock (e.g., via NTP spoofing or direct OS clock modification) to extend the apparent validity of an expired credential or command.

**Expected Response:** The `TimeRatchet` is unaffected by wall-clock manipulation. `now_est` is computed from `last_beacon_time + (mono_now − mono_at_beacon)` using `CLOCK_BOOTTIME` (not the wall clock). Command expiry is evaluated using `now_est > cmd.expiry_est`, so a manipulated wall clock cannot extend TTL. The ratchet floor prevents `now_est` from decreasing below `persisted_floor`.

**PV Requirement:** PV-22.1, PV-22.2

**Pass Criteria:**
- Expired commands are rejected by Stage 8 even when the wall clock is set to a past time.
- `now_est` computed via `TimeRatchet` is unaffected by direct wall-clock changes.
- No `SecurityEvent` for `TokenInvalid` is suppressed by wall-clock manipulation.

**Fail Criteria:**
- An expired command is accepted after the wall clock is rolled back.
- `now_est` reflects the manipulated wall-clock value.

**Test ID:** `tirbase-sim/scenarios/S04.toml` | `tirbase-guard/tests/time_ratchet.rs::test_wall_clock_poisoning`

---

## S5 — Delta Flood / Rate Exhaustion

**Attack Vector:** A malicious or compromised peer node sends Automerge deltas at a rate exceeding the per-DID inbound cap (default: 100 ops/sec token-bucket refill, burst 500 ops).

**Expected Response:** The CRDT hardening layer (Stage: per-DID rate limiter, O(1)) detects the excess and quarantines incoming deltas under `QuarantineReasonCode::RateExceeded` in the `Rate_Quarantine_Ledger`. The attacker's excess deltas are dropped before any expensive parsing.

**PV Requirement:** PV-6.3, PV-6.4

**Pass Criteria:**
- Deltas beyond the rate cap are quarantined as `RateExceeded`.
- Legitimate deltas from other DIDs continue to be processed (no cross-DID starvation).
- `Rate_Quarantine_Ledger` receives a summary row for the offending sender.
- `SecurityEvent` with reason `RateExceeded` is emitted.

**Fail Criteria:**
- Excess deltas are processed and merged, exhausting memory.
- Legitimate peers are blocked due to the flood from the attacker.

**Test ID:** `tirbase-sim/scenarios/S05.toml` | `tirbase-core/tests/crdt_hardening.rs::test_delta_flood`

---

## S6 — Policy Rollback

**Attack Vector:** An adversary replays an older, previously superseded `PolicyBundle` (with a lower version number) in an attempt to restore a weaker, more permissive policy.

**Expected Response:** `PolicyLifecycle::ingest_bundle()` checks the incoming `bundle.version` against the `MonotonicCounterTrait`-backed anti-rollback counter. Since `bundle.version ≤ current_version`, the bundle is rejected with `PolicyVersionRollback` error. The active policy is unchanged.

**PV Requirement:** PV-4.8

**Pass Criteria:**
- Replayed bundle is rejected.
- Active `EnvelopeProfile` is unchanged.
- `SecurityEvent` with reason `PolicyRollback` is emitted.
- Anti-rollback counter value does not decrease.

**Fail Criteria:**
- The older, more permissive policy is applied.
- Commands that were previously rejected become accepted.

**Test ID:** `tirbase-sim/scenarios/S06.toml` | `tirbase-guard/tests/policy.rs::test_policy_rollback`

---

## S7 — Policy Loosening Without M-of-N

**Attack Vector:** A single `PolicyAuthority` submits a policy bundle that loosens envelope bounds (e.g., raises a temperature setpoint maximum) without obtaining the required M co-signatures from distinct authorized roles.

**Expected Response:** `classify_bundle()` determines the bundle is a loosening (new [min, max] ⊃ old [min, max]). `PolicyLifecycle` starts co-signature collection and does NOT apply the bundle. The bundle is held pending `M-of-N` co-signatures from the active policy's governance fields, subject to the active policy's time-lock.

**PV Requirement:** PV-4.10

**Pass Criteria:**
- Single-PA loosening submission starts pending collection, does not apply the bundle.
- Active policy remains unchanged until M co-signatures are collected AND time-lock expires.
- `SecurityEvent` with category `PolicyLoosenPending` is emitted.
- M/N values are read from the **active policy**, not the incoming bundle.

**Fail Criteria:**
- The loosening bundle is applied immediately on single-signer submission.
- M/N values are taken from the submitted bundle (attacker can set M=1 in bundle).

**Test ID:** `tirbase-sim/scenarios/S07.toml` | `tirbase-guard/tests/policy.rs::test_loosening_requires_quorum`

---

## S8 — Malicious Migration (Float / SIMD)

**Attack Vector:** An attacker submits a WASM migration module that contains `f32`/`f64` float instructions, SIMD operations, threads, host-clock access, or host-randomness calls — any of which could introduce non-determinism or NaN bypass paths.

**Expected Response:** At load time, `DeterministicWasmProfile::validate()` (via `wasmparser`) rejects the module before execution. The module is quarantined with `QuarantineReasonCode::EngineVersionMismatch` (float) or a profile-violation error. No execution occurs.

**PV Requirement:** PV-8.2, PV-8.2a

**Pass Criteria:**
- Module containing forbidden instructions is quarantined before execution.
- A `SecurityEvent` with category `MigrationRejected` and reason `DeterministicProfileViolation` is emitted.
- No partial application of the migration occurs.

**Fail Criteria:**
- The module executes despite containing forbidden instructions.
- Non-determinism causes divergent migration results across mesh nodes.

**Test ID:** `tirbase-sim/scenarios/S08.toml` | `tirbase-core/tests/migration_sandbox.rs::test_float_simd_rejection`

---

## S9 — Migration Fuel-Cost Hash Mismatch

**Attack Vector:** An attacker submits a migration module whose `ExecutionProfileVersion.fuel_cost_table_hash` does not match the hash of the current wasmi fuel-cost configuration. This could happen if the module was built for an old wasmi version with different fuel accounting.

**Expected Response:** The migration engine checks `ExecutionProfileVersion.fuel_cost_table_hash` against the current pinned configuration hash. On mismatch, the module is rejected with `GuardError::EngineVersionMismatch` and quarantined before execution.

**PV Requirement:** PV-8.2a

**Pass Criteria:**
- Module with mismatched fuel-cost hash is rejected before execution.
- `SecurityEvent` with reason `EngineVersionMismatch` is emitted.
- No actuation or state change occurs.

**Fail Criteria:**
- Module executes despite the hash mismatch.
- Divergent fuel accounting causes different migration results on different mesh nodes.

**Test ID:** `tirbase-sim/scenarios/S09.toml` | `tirbase-core/tests/migration_sandbox.rs::test_fuel_hash_mismatch`

---

## S10 — Revoked Delta Propagation

**Attack Vector:** A peer whose DID has been revoked continues to propagate signed CRDT deltas over the mesh.

**Expected Response:** `apply_incoming_delta` in `tirbase-core/src/crdt/merge.rs` checks the revocation set. If the delta's author DID is in the revocation set, the delta is rejected at merge time and quarantined in the `Schema_Quarantine_Ledger` with `QuarantineReasonCode::IssuerRevoked`. A `SecurityEvent` with reason `RevokedAuthorDelta` is emitted.

**PV Requirement:** PV-6.1, referenced in G1 Gate (task 0.4)

**Pass Criteria:**
- Revoked-author delta is quarantined before merge.
- `SecurityEvent(RevokedAuthorDelta)` is emitted.
- Active CRDT state is not modified by the rejected delta.

**Fail Criteria:**
- The revoked-author delta is merged into the document.
- No security event is emitted.

**Test ID:** `tirbase-sim/scenarios/S10.toml` | `tirbase-core/tests/integration.rs::test_revoked_delta_rejected`

---

## S11 — Single-Manager Quorum (1-of-1)

**Attack Vector:** An operator configures the revocation quorum as `M=1, N=1` — meaning a single RevocationManager key can revoke any DID without a second approver.

**Expected Response:** The system accepts the configuration (small deployments may need M=1) but emits a structured startup diagnostic warning through the diagnostic system (`DiagnosticEntry` with level `Warning`) stating that the configuration provides no threshold protection. This is not an error; operation continues.

**PV Requirement:** PV-3.4, PV-20.4

**Pass Criteria:**
- System starts successfully with M=1.
- Startup diagnostic log contains a structured `Warning` entry specifically about 1-of-1 threshold.
- The warning is NOT a plain `eprintln!` — it flows through the diagnostic system.

**Fail Criteria:**
- System refuses to start with M=1.
- No diagnostic warning is emitted.
- Warning is emitted as unstructured log output.

**Test ID:** `tirbase-sim/scenarios/S11.toml` | `tirbase-gateway/tests/diagnostics.rs::test_single_manager_warning`

---

## S12 — Partition and Rejoin

**Attack Vector:** A network partition isolates a node from its peers for an extended period, causing divergent CRDT state. When the partition heals, conflicting deltas are exchanged.

**Expected Response:** Automerge sync protocol resolves the divergence. Post-rejoin `ConvergentState` (same `schema_hash`, `automerge_doc_bytes`, `revocation_set`, `contamination_index`, `incident_index`) is identical across all previously-partitioned nodes.

**PV Requirement:** PV-19

**Pass Criteria:**
- After partition heals, all nodes converge to identical `ConvergentState`.
- No deltas are lost (assuming no quota violations during partition).
- The contamination index and incident index converge (not just the CRDT document).

**Fail Criteria:**
- Nodes remain divergent after the partition heals.
- CCE index or incident index diverges.
- Lost deltas from the partition period are silently discarded.

**Test ID:** `tirbase-sim/scenarios/S12.toml` | `tirbase-core/tests/integration.rs::test_partition_and_rejoin`

---

## S13 — Crash at Every Step

**Attack Vector:** A power-loss event (or `SIGKILL`) is injected at each write boundary within the Applied_Effects_Ledger path. This tests crash safety across the full command lifecycle.

**Expected Response:** On process restart, `AppliedEffectsLedger::reconcile_on_boot()` scans all `Actuating` entries, calls `driver.read_back()` per driver (30s timeout), and transitions each entry to `Complete`, `Failed`, or `Unknown`. No entry remains in `Actuating` after reconciliation. `PRAGMA quick_check` runs at boot on both databases.

**PV Requirement:** PV-5.3, PV-5.4

**Pass Criteria:**
- After restart, no entry remains in `Actuating` state longer than 30 seconds.
- Entries that matched driver read-back become `Complete`.
- Entries that didn't match become `Failed`.
- Entries where driver timed out become `Unknown` and block further commands.
- `ReconciliationComplete` SecurityEvent is emitted.

**Fail Criteria:**
- Any entry remains `Actuating` indefinitely after restart.
- A command is actuated twice (once before crash, once after restart).
- `quick_check` failure is ignored.

**Test ID:** `tirbase-guard/tests/kill_at_every_step.rs` (failpoint tests with `fail` crate at every write boundary)

---

## S14 — Security Event Log Flooding

**Attack Vector:** An adversary triggers an extremely high rate of security events (e.g., by flooding with rejected commands) to exhaust the security event log rate limit, potentially blinding the system to real security events.

**Expected Response:** Per-category rate limiter fires at 100 events/sec. A single `SuppressionSummary` record is emitted stating the count of suppressed events before resuming. The in-memory ring (10,000 events) retains the oldest anchor events and the most recent events. Events with severity `HIGH` or `CRITICAL` bypass the rate limiter entirely.

**PV Requirement:** PV-7.6

**Pass Criteria:**
- Events exceeding 100/sec/category are suppressed.
- One `SuppressionSummary` event is recorded per suppression window.
- `HIGH` and `CRITICAL` events are never suppressed.
- Ring buffer does not exceed 10,000 entries.

**Fail Criteria:**
- High-severity events are dropped due to rate limiting.
- Memory grows without bound from unlimited event buffering.
- No suppression summary is emitted.

**Test ID:** `tirbase-sim/src/scenarios/s14_log_flooding.rs::s14_log_flooding_rate_limit_and_bounded_retention`

---

## S15 — Reassembly Bomb

**Attack Vector:** An adversary sends an oversized fragmented Automerge delta payload, exceeding the 1 MiB per-delta size limit, aiming to exhaust memory during reassembly.

**Expected Response:** The CRDT hardening layer detects the oversize condition (before full assembly) and quarantines the fragments with `QuarantineReasonCode::Oversize` in the `Rate_Quarantine_Ledger`. No memory allocation for the full payload occurs beyond the size-check boundary.

**PV Requirement:** PV-6.3, PV-6.5

**Pass Criteria:**
- Delta exceeding 1 MiB is quarantined as `Oversize` before full assembly.
- Memory usage does not grow proportional to the oversized payload.
- A `SecurityEvent` with reason `Oversize` is emitted.

**Fail Criteria:**
- Oversized delta is fully assembled in memory, causing OOM.
- Memory grows unboundedly during reassembly.

**Test ID:** `tirbase-sim/scenarios/S15.toml` | `tirbase-core/tests/crdt_hardening.rs::test_reassembly_bomb`

---

## S16 — Fleet Fan-Out (Per-Device Blast Radius)

**Attack Vector:** A compromised cloud endpoint sends commands to all enrolled devices simultaneously, attempting to cause a simultaneous fleet-wide actuation event.

**Expected Response:** Per-device write quotas (commands per 60-second window, configurable) limit the rate at which any single device can be commanded. Parameters with `critical: true` require M-of-N co-signatures, which cannot be generated in bulk for an entire fleet in a single automated burst. Fleet-level limiting is deferred to v1.5 (RD-1).

**PV Requirement:** PV-4.16

**Pass Criteria:**
- Per-device write quota is enforced across the burst.
- Commands exceeding the quota are rejected with `RateLimit`.
- Critical-parameter commands without M-of-N co-signatures are rejected.

**Fail Criteria:**
- All devices receive and actuate all commands simultaneously.
- Per-device quotas are not enforced.

**Test ID:** `tirbase-sim/scenarios/S16.toml` | `tirbase-guard/tests/guard_pipeline.rs::test_fleet_fanout`

---

## S17 — Cross-Role Attempt

**Attack Vector:** An adversary uses a `CommandIssuer` Biscuit token to submit a request that requires a `PolicyAuthority` role (e.g., policy push, loosening initiation, quarantine replay).

**Expected Response:** Stage 4 (token-to-command binding) derives `CommandRole::CommandIssuer` from the token caveats. The operation requires `PolicyAuthority`. The guard rejects with `RejectionCategory::ScopeViolation`. A `SecurityEvent(CommandDecision, Reject, ScopeViolation)` is emitted.

**PV Requirement:** PV-3.2, PV-3.3

**Pass Criteria:**
- Cross-role request is rejected at Stage 4.
- `SecurityEvent` with reason `ScopeViolation` is emitted.
- The `derived_role` is taken exclusively from token caveats, never from `cmd.role`.

**Fail Criteria:**
- Cross-role operation is permitted.
- `cmd.role` field (potentially forged) is trusted instead of the token.

**Test ID:** `tirbase-guard/tests/auth_matrix.rs::test_cross_role_rejection` (auto-generated from `AUTHORIZATION_MATRIX` for all `—` cells)

---

## S18 — Guard Bypass Attempt

**Attack Vector:** An adversary (or buggy internal code) attempts to construct an `ActuationPermit { _sealed: () }` outside the `tirbase-guard` crate, directly from any of the three ingress paths (mesh, cloud API, local admin API).

**Expected Response:** The Rust compiler rejects the code at compile time because `ActuationPermit._sealed` is `pub(crate)` and cannot be named outside `tirbase-guard`. The `trybuild` compile-fail tests in `tirbase-guard/tests/compile_fail/` confirm this for all three ingress paths.

**PV Requirement:** PV-4.3, PV-4.4

**Pass Criteria:**
- All three `compile_fail/` test files fail to compile with a clear error message.
- No runtime bypass exists (structural guarantee via type system).

**Fail Criteria:**
- Any ingress path can construct `ActuationPermit` without `CommandGuard::admit()`.
- A compile-fail test unexpectedly compiles successfully.

**Test ID:** `tirbase-guard/tests/compile_fail/mesh_bypass.rs`, `cloud_bypass.rs`, `admin_bypass.rs` (trybuild)

---

## S19 — Delayed Delivery

**Attack Vector:** An adversary withholds a validly signed `CommandMessage` (with a short TTL) and delivers it after the command's `expiry_est` has passed. This is a classic "store-and-forward replay" against receipt-relative TTL schemes.

**Expected Response:** Stage 8 (command expiry check) computes `ratchet.now_est()` and compares it against `cmd.expiry_est`. Since `now_est > cmd.expiry_est`, the command is rejected with `RejectionCategory::Expired`. The `TimeRatchet` prevents wall-clock manipulation from "unwinding" the expiry check.

**PV Requirement:** PV-22.1, PV-12.8

**Pass Criteria:**
- Withheld command is rejected after TTL expires.
- Rejection occurs even if the system wall clock is manipulated backward.
- `SecurityEvent(CommandDecision, Reject, Expired)` is emitted.
- External coarse code is `EXPIRED`.

**Fail Criteria:**
- Withheld command is accepted after TTL.
- Wall-clock rollback allows the command to appear fresh.

**Test ID:** `tirbase-sim/scenarios/S19.toml` | `tirbase-guard/tests/guard_pipeline.rs::test_delayed_delivery`

---

## S20 — Sequence-Number Poisoning

**Attack Vector:** A compromised issuer sends a command with a sequence number far beyond the `AntiReplayWindow` forward gap (e.g., `seq = highest_seen + 1_000_000`) before a legitimate issuer can use the intervening sequence numbers, stranding the legitimate issuer's window.

**Expected Response:** The unauthenticated (rejected) command at Stage 2 or Stage 5 does NOT advance `AntiReplayWindow.highest_seen`. Only a fully authenticated and committed command (reaching Stage 16) can advance the window. The legitimate issuer's future commands (which use the "stranded" sequence numbers) fall outside the window and are rejected only if they fall below `highest_seen - W`, not merely because the attacker used a larger number.

**PV Requirement:** PV-5.5, PV-12.8

**Pass Criteria:**
- Rejected command does not advance `highest_seen`.
- Legitimate issuer commands with sequential numbers remain accepted.
- `AntiReplayWindow` state is immutable on rejection.

**Fail Criteria:**
- `highest_seen` advances on a rejected (or unauthenticated) command.
- Legitimate issuer is stranded and cannot submit further commands.

**Test ID:** `tirbase-sim/scenarios/S20.toml` | `tirbase-guard/tests/anti_replay.rs::test_seq_poisoning`

---

## S21 — Lease Starvation

**Attack Vector:** A compromised issuer continuously sends in-envelope, valid commands (each successfully actuated) for a target, acquiring and renewing the `SingleWriterLease` indefinitely, blocking all other issuers from accessing that target.

**Expected Response:** The `consecutive_renewals` counter tracks how many times the same issuer has consecutively re-acquired the lease. After reaching `max_consecutive_renewals` (default 10), the lease enters `cooldown_until_mono` (default: one lease duration). During cooldown, the same issuer cannot re-acquire the lease, allowing other issuers to obtain it.

**PV Requirement:** PV-5.8a, PV-12.8

**Pass Criteria:**
- Issuer is blocked from re-acquiring lease after `max_consecutive_renewals`.
- Cooldown period is enforced.
- Other issuers can acquire the lease during the cooldown.
- `SecurityEvent(LeaseStarvationProtection)` is emitted when cooldown is triggered.

**Fail Criteria:**
- Issuer can hold the lease indefinitely.
- No cooldown is enforced.
- Other issuers are permanently blocked.

**Test ID:** `tirbase-sim/scenarios/S21.toml` | `tirbase-guard/tests/effects_ledger.rs::test_lease_starvation`

---

## S22 — Snapshot Restore Attack

**Attack Vector:** An adversary (or operator error) restores an old database backup, reverting `applied_effects_ledger` entries, anti-replay window state, monotonic counters, and sequence numbers to past values.

**Expected Response:** At boot, the guard compares the DB generation counter against the hardware monotonic counter (`Tpm2MonotonicCounter`): if `hw_counter > sw_counter_at_last_hw_write`, a rollback is detected. The guard enters `LOCKDOWN` and emits `MonotonicCounterRegression` SecurityEvent. The enrollment epoch is bumped (signed by PolicyAuthority + RevocationManager), causing all prior-epoch commands from all issuers to be rejected. Peer nodes that observe a lower epoch emit `EpochRegression` SecurityEvents.

**PV Requirement:** PV-9.8, PV-12.8

**Pass Criteria:**
- Hardware counter comparison detects the rollback at boot.
- System enters LOCKDOWN immediately on detection.
- `MonotonicCounterRegression` SecurityEvent is emitted.
- After epoch bump, prior-epoch commands are rejected with `StaleEpoch`.
- Peer nodes detect the epoch regression.

**Fail Criteria:**
- Restored backup is accepted silently without LOCKDOWN entry.
- Prior-epoch commands from reverted sequence numbers are accepted.
- Peers do not detect the epoch regression.

**Test ID:** `tirbase-sim/scenarios/S22.toml` | `tirbase-guard/tests/mode.rs::test_snapshot_restore_lockdown`

---

## S23 — Time-Anchor Poisoning

**Attack Vector:** A forged `TimeBeacon` (or compromised `TimeAnchor`) claims a wall-clock time far in the future (e.g., `now + 86_401 seconds`), exceeding the `max_forward_jump_secs` limit (default 86,400 seconds). If accepted, this would permanently advance the `TimeRatchet` and expire all current credentials.

**Expected Response:** `TimeRatchet::advance()` checks whether `beacon.wall_time − persisted_floor > max_forward_jump_secs`. The beacon exceeds this threshold and is rejected without updating `persisted_floor` or `last_beacon_time`. A `SecurityEvent(TimeAnchorRejected, FarFutureBeacon)` is emitted. A jump exceeding the limit requires M-of-N `TimeAnchor` co-signatures.

**PV Requirement:** PV-22.5, PV-12.8

**Pass Criteria:**
- Forged far-future beacon is rejected.
- `persisted_floor` and `last_beacon_time` are unchanged.
- `SecurityEvent(TimeAnchorRejected)` is emitted.
- Single-beacon max-forward-jump property test passes (Property 14).

**Fail Criteria:**
- Forged beacon advances the ratchet.
- Credentials are prematurely expired.
- Single `TimeAnchor` can advance the ratchet by more than `max_forward_jump_secs`.

**Test ID:** `tirbase-sim/scenarios/S23.toml` | `tirbase-guard/tests/time_ratchet.rs::test_anchor_poisoning`

---

## S24 — Crash-Loop Escalation

**Attack Vector:** An adversary induces the guard process to crash repeatedly within the `StartLimitIntervalSec` window (default: 5 minutes) to trigger automatic LOCKDOWN via the crash-loop escalation path, effectively denying service.

> **Note:** This scenario is also a reliability test — it validates that the crash → LOCKDOWN path works correctly. The adversary can use it as a DoS; the operator must use the M-of-N LOCKDOWN-exit procedure to recover.

**Expected Response:** After `N` crashes (default: 3) within the window, systemd fires `OnFailure=tirbase-lockdown.service`. The oneshot service persists LOCKDOWN state to `primary.db` (key `lockdown_state`) AND writes `/var/lib/tirbase/lockdown`. On next start, the guard reads the lockdown flag and enters `NodeMode::Lockdown` immediately.

**PV Requirement:** PV-1.11, PV-4.15, PV-12.8

**Pass Criteria:**
- N crashes within the window trigger LOCKDOWN (not before N).
- LOCKDOWN state is persisted to `primary.db` and the flag file.
- After LOCKDOWN, the guard refuses all commands until M-of-N exit.
- `SecurityEvent(CrashLoopLockdown)` is emitted by `tirbase-lockdown.service`.

**Fail Criteria:**
- Single crash triggers LOCKDOWN (too aggressive; ruins availability).
- N crashes do NOT trigger LOCKDOWN (security escalation fails).
- LOCKDOWN state is lost on reboot (tmpfs-only storage).

**Test ID:** `tirbase-sim/scenarios/S24.toml` | `tirbase-gateway/tests/crash_recovery.rs::test_crash_loop_lockdown`

---

## S25 — Quarantine Flush

**Attack Vector:** An attacker sends enough anomalous deltas to exhaust the global `Schema_Quarantine_Ledger` limits (50,000 entries / 256 MiB), evicting legitimate quarantined entries that an operator might later want to replay.

**Expected Response:** Per-sender quotas (default: 1,000 entries per sender DID) ensure that a single attacker can fill at most 1,000 slots before FIFO eviction of their own entries begins. Entries from other senders are never evicted to make room for the attacker's entries. Global limits apply separately after per-sender limits.

**PV Requirement:** PV-6.7, PV-12.8

**Pass Criteria:**
- Attacker's entries cause FIFO eviction of only their own oldest entries after quota.
- Legitimate entries from other senders are never evicted by the attacker.
- `SecurityEvent(QuarantineQuotaReached, sender_did)` is emitted.

**Fail Criteria:**
- Attacker's flood evicts legitimate entries from other senders.
- Operator cannot replay critical quarantined deltas because they were flushed.

**Status:** PROVEN (task 23 / CLAIM-23.3,23.5)
**Test ID:** `tirbase-sim/src/scenarios/s25_quarantine_flush.rs` (`s25_quarantine_flush_per_sender_isolation`, `s25_quarantine_flush_seeded_sweep`) | `tirbase-core/src/api/mod.rs::task23_pv6_hardening_tests::claim_23_5_schema_quarantine_per_sender_quota_isolated`

---

## S26 — Idempotency-Key Squatting

**Attack Vector:** An adversary pre-registers an idempotency key that the legitimate issuer will use for a future command (guessing or observing the key from a prior partial attempt). When the legitimate command arrives, the guard finds the squatted key and returns the adversary's cached "original result."

**Expected Response:** Idempotency keys are scoped to `(issuer_did, target_id, idempotency_key)`. An adversary cannot pre-register a key under the legitimate issuer's DID because the key is always checked against the authenticated `issuer_did` from the Biscuit token (Stage 4). The adversary's key is in their own namespace and does not conflict.

**PV Requirement:** PV-5.6 (idempotency retention window); Revision §14

**Pass Criteria:**
- Adversary-registered key does not collide with legitimate issuer's key.
- Legitimate command with same key bytes but different `issuer_did` is treated as a new command.
- No cross-issuer idempotency key collision is possible.

**Fail Criteria:**
- Cross-issuer idempotency key collision returns wrong cached result.
- Adversary can cause a legitimate command to be "replayed" using a squatted key.

**Test ID:** `tirbase-guard/tests/effects_ledger.rs::test_idempotency_key_squatting`

---

## S27 — Tightening Bundle Weakens Governance

**Attack Vector:** A `PolicyAuthority` submits a policy bundle that claims to be a "tightening" (narrowing envelope bounds) but also lowers the `policy_loosen_m` governance field, making future loosening easier.

**Expected Response:** `classify_bundle()` applies the conservative governance-field check: any decrease in `policy_loosen_m` or `policy_loosen_n` is classified as Loosening (not Tightening). The bundle cannot be applied as a fast single-signer tightening; it must go through the full M-of-N loosening approval flow.

**PV Requirement:** PV-4.11, Revision §14

**Pass Criteria:**
- Bundle with decreased `policy_loosen_m` is classified as Loosening.
- Single-PA submission starts pending approval; bundle is not applied.
- Active governance fields remain unchanged.

**Fail Criteria:**
- Bundle with decreased governance fields is applied as a tightening.
- `policy_loosen_m` is reduced without M-of-N approval.

**Test ID:** `tirbase-guard/tests/policy.rs::test_governance_weakening_classified_as_loosening`

---

## S28 — tightening_floor in Submitted Bundle

**Attack Vector:** An adversary includes self-serving `tightening_floor` values inside the submitted `PolicyBundle`, attempting to lock operational limits to an unusable extreme (e.g., floor that would reject all valid temperature setpoints).

**Expected Response:** `tightening_floor` values are sourced exclusively from `TrustRootRecord.device_class_floors`, which is signed offline by the root CA at ceremony. Any `tightening_floor` values within the submitted bundle are ignored. The guard validates tightening against the trust-root floors, not the bundle's floors.

**PV Requirement:** PV-4.11, Revision §14

**Pass Criteria:**
- Floor values in submitted bundle are ignored.
- Tightening is validated against `TrustRootRecord.device_class_floors`.
- A PolicyAuthority cannot lock limits to an unusable range via the floor field.

**Fail Criteria:**
- Bundle's own floor values are used for tightening validation.
- Operator can deploy a bundle that locks the system to an unusable state.

**Test ID:** `tirbase-guard/tests/policy.rs::test_tightening_floor_from_trust_root_only`

---

## S29 — Retry Same Seq vs New Seq Same Idempotency Key

**Attack Vector:** An issuer sends: (a) the same `(seq, idempotency_key)` pair as a previous command (retry after apparent failure), and separately (b) a new `seq` with the same `idempotency_key` as a previous command (testing whether idempotency and anti-replay interact correctly).

**Expected Response:**
- (a) Same `(seq, epoch)` → Stage 7 (decided-outcome cache) returns the cached outcome. No second actuation.
- (b) New seq with same idempotency key → Stage 16 idempotency check detects the existing key and returns the original result. No second actuation. Anti-replay does not block because the new seq was not previously seen.

**PV Requirement:** PV-5.5, PV-5.6, Revision §14

**Pass Criteria:**
- (a) Decided-outcome cache hit for same `(seq, epoch)` returns original result without actuation.
- (b) Idempotency key hit for new seq returns original result without actuation.
- Neither path causes a second actuation.

**Fail Criteria:**
- Same seq retried causes second actuation.
- New seq with old idempotency key causes second actuation.
- Anti-replay and idempotency interact incorrectly.

**Test ID:** `tirbase-guard/tests/effects_ledger.rs::test_retry_seq_vs_idempotency_key`

---

## S30 — Exponent-Overflow Value

**Attack Vector:** An adversary crafts a `CommandMessage` whose `FixedPointValue.mantissa` is `i64::MAX` and `exponent` is 100, causing the intermediate i128 comparison in Stage 11 to overflow if 32-bit or 64-bit arithmetic is used instead of the mandated i128 intermediates.

**Expected Response:** Stage 10 (`FixedPointValue` validation) checks the exponent against the `ParameterSpec.canonical_exponent`. If the exponent is non-canonical, the command is rejected with `ValueInvalid`. If the exponent is canonical but the comparison would overflow i128, Stage 11 detects the overflow and rejects with `ArithmeticOverflow`.

**PV Requirement:** PV-21, Revision §14

**Pass Criteria:**
- Command with overflow-inducing values is rejected at Stage 10 or Stage 11.
- No integer overflow occurs in the comparison arithmetic.
- `SecurityEvent(CommandDecision, Reject, ValueInvalid/ArithmeticOverflow)` is emitted.

**Fail Criteria:**
- Overflow is not detected; comparison wraps and the out-of-bounds value is accepted.
- Integer overflow causes a panic in release builds.

**Test ID:** `tirbase-guard/tests/properties.rs::test_exponent_overflow` | property test (Property 2, 3 for FixedPointValue)

---

## S31 — Clock Rollback Across Reboot

**Attack Vector:** A device reboots (or an adversary triggers a reboot). The monotonic clock (`CLOCK_BOOTTIME`) resets. If `TimeRatchet` performs `now_est = last_beacon_time + (mono_now − mono_at_beacon)` without checking the `boot_id`, the subtraction `mono_now − mono_at_beacon` yields a negative or very small value, causing `now_est` to drop far below `persisted_floor` — effectively making all recent commands appear expired.

**Expected Response:** `TimeRatchet::now_est()` checks `ts.boot_id() != beacon_boot_id`. On mismatch (reboot occurred), the function returns `persisted_floor` directly without any monotonic subtraction. All credentials are evaluated conservatively against the floor. `FreshnessState` transitions to `Unverified` until a new beacon is received. Commands to critical parameters require challenge nonces.

**PV Requirement:** PV-22.4, Revision §14

**Pass Criteria:**
- `now_est` returns `persisted_floor` immediately after reboot (before any new beacon).
- `now_est` never decreases below `persisted_floor` across reboots.
- `FreshnessState` transitions to `Unverified` after reboot.
- Property 17 (TimeRatchet monotone across reboots) passes.

**Fail Criteria:**
- `now_est` drops below `persisted_floor` after reboot.
- Valid credentials appear expired due to monotonic clock reset.
- `now_est` is computed using raw monotonic subtraction across a reboot boundary.

**Test ID:** `tirbase-guard/tests/time_ratchet.rs::test_clock_rollback_reboot` | Property 17

---

## S32 — Challenge-Nonce Flooding

**Attack Vector:** An adversary floods the `POST /admin/challenge` endpoint with nonce requests for a critical parameter when `FreshnessState::Unverified`, attempting to exhaust nonce table storage or cause per-issuer nonce namespace exhaustion.

**Expected Response:** Per-device nonce rate limit (default: max 5 nonce requests per issuer/target/param/minute) is enforced. Excess requests are rejected with a rate-limit error. Used nonces are deleted immediately after consumption. Nonce table entries expire at `expires_at_mono` and are pruned on the background schedule.

**PV Requirement:** PV-22.3, Revision §14

**Pass Criteria:**
- Rate limit (5/min) is enforced for nonce requests.
- Flood beyond the limit returns rate-limit rejection.
- Nonce table does not grow without bound.
- Legitimate issuer can still obtain nonces after the rate limit window expires.

**Fail Criteria:**
- Nonce table grows unboundedly under flood.
- Rate limit is not enforced.
- Legitimate nonce requests are blocked permanently.

**Test ID:** `tirbase-guard/tests/integration.rs::test_challenge_nonce_flooding` | `tirbase-guard/tests/guard_pipeline.rs::test_s32_challenge_nonce_flood`

---

## S33 — Pending-Queue Memory Bomb

**Attack Vector:** A malicious peer sends many large Automerge deltas (up to 8 MiB each) that all declare a missing dependency (never sent), causing the pending queue to accumulate gigabytes of un-processable deltas.

**Expected Response:** The CRDT hardening layer enforces a per-peer byte cap (default 8 MiB) and a global pending-queue byte cap (default 64 MiB). When the per-peer cap is exceeded, the oldest entries from that peer are evicted and quarantined as `PendingQueueOverflow` in the `Schema_Quarantine_Ledger`. Global cap eviction evicts oldest entries globally.

**PV Requirement:** PV-6.1, Revision §14

**Pass Criteria:**
- Per-peer byte cap triggers FIFO eviction of that peer's oldest entries.
- Global byte cap triggers FIFO eviction of the globally oldest entries.
- Evicted entries are quarantined as `PendingQueueOverflow`.
- Memory usage stays within `global_byte_cap + overhead`.
- `PendingQueueOverflow` entries are replayable (PolicyAuthority signature required).

**Fail Criteria:**
- Pending queue grows beyond `global_byte_cap`.
- Process runs out of memory and crashes (enables crash-loop LOCKDOWN via S24).
- Legitimate pending deltas are lost without quarantine record.

**Status:** PROVEN (task 23 / CLAIM-23.1,23.2)
**Test ID:** `tirbase-sim/src/scenarios/s33_pending_queue_bomb.rs` (`s33_pending_queue_bomb_bounded`, `s33_pending_queue_bomb_seeded_sweep`) | `tirbase-core/src/api/mod.rs::task23_pv6_hardening_tests::claim_23_1_missing_dependency_pends_then_processes_on_dependency_arrival`, `claim_23_2_pending_queue_overflow_quarantined_to_schema_quarantine`

---

## S34 — Partial-Signature Replay Across Commands

**Attack Vector:** An adversary collects partial co-signatures from multiple different `PolicyBundle` submission attempts (or LOCKDOWN-exit requests) and attempts to assemble enough partial signatures from different payloads to forge a quorum for a new, malicious payload.

**Expected Response:** Every `SignedOperation<T>` wrapper includes a `payload_hash = SHA-256(canonical_cbor(T))`. Co-signatures in `pending_approvals` are bound to a specific `payload_hash`. A co-signature collected for payload hash A cannot satisfy a co-signature requirement for payload hash B. The guard verifies that all collected signatures bind to the same payload hash as the current pending approval.

**PV Requirement:** PV-4.16, Revision §14

**Pass Criteria:**
- Co-signatures from different payloads cannot be combined to satisfy a quorum.
- Each co-signature is validated against the current `pending_approvals.payload_hash`.
- Attempting to submit co-signatures for a different payload hash is rejected.

**Fail Criteria:**
- Partial signatures from different payload attempts can be combined.
- An adversary can forge quorum without all signers signing the same payload.

**Test ID:** `tirbase-guard/tests/policy.rs::test_partial_sig_replay_across_commands`

---

## S35 — Driver fd Leakage

**Attack Vector:** A compromised driver child process attempts to leak device file descriptors to a grandchild process (or an unrelated process) using `SCM_RIGHTS` over an auxiliary socket, circumventing the driver isolation boundary.

**Expected Response:** The seccomp-BPF filter applied to the driver child before any parsing blocks the `sendmsg` syscall variant used for `SCM_RIGHTS` sends. The driver child cannot send file descriptors to any process. The device fd stays with the guard parent process and is never transmitted over the socketpair. The child only has the inherited socketpair end and never holds the device fd.

**PV Requirement:** PV-4.21, PV-10.4, Revision §14

**Pass Criteria:**
- Driver child's attempt to call `sendmsg` with `SCM_RIGHTS` is blocked by seccomp.
- `SecurityEvent(SandboxViolation, SCMRightsAttempt)` is emitted.
- Device fd is never transmitted outside the guard process.

**Fail Criteria:**
- Seccomp does not block `SCM_RIGHTS` in the driver sandbox.
- Driver child can leak the device fd to another process.
- Isolation boundary is bypassed without guard involvement.

**Test ID:** `tirbase-guard/tests/driver_isolation.rs::test_scm_rights_blocked`

---

## Coverage Summary

| Scenario | Phase/Capability | Status | Test ID |
|---|---|---|---|
| S1 — Out-of-Envelope Command | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S01.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S2 — Slow Ramp / Cumulative Drift | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S02.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S3 — Replay Attack | Phase 3: Effects Ledger | PASSING | `tirbase-sim/scenarios/S03.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S4 — Clock Poisoning (Wall-Clock) | Phase 18: Time Anchor | PASSING | `tirbase-sim/scenarios/S04.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S5 — Delta Flood / Rate Exhaustion | Phase 4: CRDT Hardening | PASSING | `tirbase-sim/scenarios/S05.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S6 — Policy Rollback | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S06.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S7 — Policy Loosening Without M-of-N | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S07.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S8 — Malicious Migration (Float/SIMD) | Phase 6: Migration Sandbox | PASSING | `tirbase-sim/scenarios/S08.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S9 — Migration Fuel-Cost Hash Mismatch | Phase 6: Migration Sandbox | PASSING | `tirbase-sim/scenarios/S09.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S10 — Revoked Delta Propagation | Phase 4: CRDT Hardening | PASSING | `tirbase-sim/scenarios/S10.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S11 — Single-Manager Quorum (1-of-1) | Phase 1: Key Management | PASSING | `tirbase-sim/scenarios/S11.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S12 — Partition and Rejoin | Phase 4: CRDT Hardening | PASSING | `tirbase-sim/scenarios/S12.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S13 — Crash at Every Step | Phase 3: Effects Ledger | PASSING | `tirbase-sim/scenarios/S13.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S14 — Security Event Log Flooding | Phase 5: Security Event Log | PASSING | `tirbase-sim/scenarios/S14.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S15 — Reassembly Bomb | Phase 4: CRDT Hardening | PASSING | `tirbase-sim/scenarios/S15.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S16 — Fleet Fan-Out | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S16.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S17 — Cross-Role Attempt | Phase 1: Key Management | PASSING | `tirbase-sim/scenarios/S17.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S18 — Guard Bypass Attempt | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S18.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S19 — Delayed Delivery | Phase 18: Time Anchor | PASSING | `tirbase-sim/scenarios/S19.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S20 — Sequence-Number Poisoning | Phase 3: Effects Ledger | PASSING | `tirbase-sim/scenarios/S20.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S21 — Lease Starvation | Phase 3: Effects Ledger | PASSING | `tirbase-sim/scenarios/S21.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S22 — Snapshot Restore Attack | Phase 7: Persistence | PASSING | `tirbase-sim/scenarios/S22.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S23 — Time-Anchor Poisoning | Phase 18: Time Anchor | PASSING | `tirbase-sim/scenarios/S23.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S24 — Crash-Loop Escalation | Phase 9: Gateway Runtime | PASSING | `tirbase-sim/scenarios/S24.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S25 — Quarantine Flush | Phase 4: CRDT Hardening | PASSING | `tirbase-sim/scenarios/S25.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S26 — Idempotency-Key Squatting | Phase 3: Effects Ledger | PASSING | `tirbase-sim/scenarios/S26.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S27 — Tightening Bundle Weakens Governance | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S27.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S28 — tightening_floor in Submitted Bundle | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S28.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S29 — Retry Same Seq vs New Seq Same Idempotency Key | Phase 3: Effects Ledger | PASSING | `tirbase-sim/scenarios/S29.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S30 — Exponent-Overflow Value | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S30.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S31 — Clock Rollback Across Reboot | Phase 18: Time Anchor | PASSING | `tirbase-sim/scenarios/S31.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S32 — Challenge-Nonce Flooding | Phase 18: Time Anchor | PASSING | `tirbase-sim/scenarios/S32.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S33 — Pending-Queue Memory Bomb | Phase 4: CRDT Hardening | PASSING | `tirbase-sim/scenarios/S33.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S34 — Partial-Signature Replay Across Commands | Phase 2: Command Guard | PASSING | `tirbase-sim/scenarios/S34.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |
| S35 — Driver fd Leakage | Phase 8: Driver Framework | PASSING | `tirbase-sim/scenarios/S35.toml` (`cargo test -p tirbase-sim --test scenario_runner`) |

---

## Cross-Reference by PV Requirement

| PV Requirement | Scenarios |
|---|---|
| PV-1.11 | S24 |
| PV-3.2, PV-3.3 | S17 |
| PV-3.4, PV-20.4 | S11 |
| PV-4.3, PV-4.4 | S18 |
| PV-4.6 | S1 |
| PV-4.7 | S2 |
| PV-4.8 | S6 |
| PV-4.10 | S7 |
| PV-4.11 | S27, S28 |
| PV-4.15 | S24 |
| PV-4.16 | S16, S34 |
| PV-4.21, PV-10.4 | S35 |
| PV-5.5 | S3, S20 |
| PV-5.6 | S26, S29 |
| PV-5.8a | S21 |
| PV-6.1 | S10, S33 |
| PV-6.3, PV-6.4 | S5 |
| PV-6.3, PV-6.5 | S15 |
| PV-6.7 | S25 |
| PV-7.6 | S14 |
| PV-8.2, PV-8.2a | S8, S9 |
| PV-9.8 | S22 |
| PV-12.8 | S19, S20, S21, S22, S23, S24, S25 |
| PV-19 | S12 |
| PV-21 | S30 |
| PV-22.1, PV-22.2 | S4 |
| PV-22.1 | S19 |
| PV-22.3 | S32 |
| PV-22.4 | S31 |
| PV-22.5 | S23 |
| PV-5.3, PV-5.4 | S13 |

---

## Notes

1. **Test IDs are initial targets.** File paths are established convention; actual test function names may differ when implemented. Update this document when a scenario's test is wired.

2. **Scenarios S19–S25** were added in PV-12.8 as part of the time model, lease, quarantine, and restore feature set. Scenarios S26–S35 were added in Revision §14.

3. **Demo packs** (PV-16) reference specific scenarios for each vertical: guard-actuator packs (cold-chain, energy edge, water, buildings) use S1–S3; data-mesh packs (logistics, remote-ops) use S10 or S12; defense-logistics uses S3 or S9.

4. **CLAIMS.md entry:** This document satisfies [CLAIM-3.7]. Status is Proven: every S1–S35 entry is wired to `tirbase-sim/scenarios/S*.toml` and executed by `cargo test -p tirbase-sim --test scenario_runner`.

5. **When adding a new scenario:** Add it here before writing any production code for the capability it covers (PV-12.5, PV-23.4). Assign the next available S-number, fill all fields, set Test ID to `PLANNED`, and add an entry to the coverage summary table and cross-reference table.
