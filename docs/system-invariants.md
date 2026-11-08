# System Invariants Catalog

**Version:** 2.0  
**Last Updated:** 2026-11-08  
**CLAIMS Entry:** CLAIM-3.8  
**Requirement:** PV-23.1

---

## Introduction

This document is the normative catalog of all system invariants for TriBase Guard. Each invariant is a property that must hold at all times in a correctly operating system.

Invariants are enforced at three levels:

1. **Per-tick simulation checks** (PV-23.2) — `tirbase-sim/src/invariants.rs::InvariantChecker::check_all()` runs every simulated tick and asserts every invariant against the current world state. Any violation immediately fails the simulation run.
2. **`debug_assert!` in production code** (PV-23.3) — each invariant maps to one or more `debug_assert!` macros in the production codebase. These are compiled in for debug builds and stripped in release, providing zero-cost safety nets during development and CI.
3. **Merge gate** (PV-23.4) — a new invariant entry in this file must be committed and reviewed before the capability it guards is merged. This prevents capabilities from landing without a corresponding simulation check.

### Test IDs

Test IDs in this catalog point at the tirbase-sim `InvariantChecker` tick checks (tasks 17.x/38.6, CLAIM-17.1..CLAIM-17.8, CLAIM-38.6). Each identifier names the test that proves the corresponding invariant violation fails immediately with the invariant ID, seed, and triggering state. INV-13 also retains its time-ratchet property test.

- `tirbase-sim/src/invariants.rs` defines `InvariantChecker` and is called by simulation tick paths; task 17 registers every INV and wires those calls.
- Full simulator runtime integration (SimClock/SimNetwork/SimNode tick loop) continues under task 38.



---

## Invariant Catalog

| ID | Invariant Statement | Simulation Check Description | `debug_assert!` Location | Test ID |
|----|---------------------|------------------------------|--------------------------|---------|
| INV-1 | No actuator write occurs outside the installed `EnvelopeProfile` for that target. | Every `sim_tick` asserts no driver write bypasses envelope bounds. | `tirbase-guard/src/guard.rs` Stage 11 (envelope bounds check) `[Planned]` | `tirbase_sim::invariants::tests::inv_1_out_of_envelope_actuation_fails_immediately` |
| INV-2 | No idempotency key `(issuer, target, key)` is actuated more than once within its retention window. | Records all accepted tuples; asserts no duplicate actuation. | `tirbase-guard/src/effects_ledger.rs::check_idempotency()` `[Planned]` | `tirbase_sim::invariants::tests::inv_2_duplicate_actuation_fails_immediately` |
| INV-3 | Policy version numbers are strictly monotonically increasing per device. | After each policy apply, asserts `new_version > prev_version`. | `tirbase-guard/src/policy.rs::ingest_bundle()` `[Planned]` | `tirbase_sim::invariants::tests::inv_3_version_regression_fails_immediately` |
| INV-4 | The security event log hash chain is intact at all times. | Calls `verify_hash_chain()` after every event emission. | `tirbase-guard/src/security_log.rs::append()` `[Planned]` | `tirbase_sim::invariants::tests::inv_4_chain_break_fails_immediately` |
| INV-5 | LOCKDOWN mode actuates only `safe_default` values, never a commanded value. | In Lockdown state, verifies only `safe_default` transitions occur. | `tirbase-guard/src/guard.rs` `NodeMode::Lockdown` arm `[Planned]` | `tirbase_sim::invariants::tests::inv_5_non_safe_default_in_lockdown_fails_immediately` |
| INV-6 | No command reaches a driver without passing through the Guard evaluation function. | Simulator only exposes driver writes via guard socketpair. | Enforced structurally by `ActuationPermit::_sealed` (compile-time; no `debug_assert!` needed) | `tirbase_sim::invariants::tests::inv_6_bypass_attempt_fails_immediately` |
| INV-7 | No Biscuit token can cause the Guard to accept a value outside the authorizer-side `EnvelopeProfile`. | Property 5 covers all token shapes. | `tirbase-guard/src/guard.rs` Stage 11 `[Planned]` | `tirbase_sim::invariants::tests::inv_7_token_relax_attempt_fails_immediately` |
| INV-8 | A policy loosening bundle never takes effect before its time-lock expires. | Asserts `now_est < timelock_until_est` is never the trigger for applying a loosening bundle. | `tirbase-guard/src/policy.rs::add_co_signature()` `[Planned]` | `tirbase_sim::invariants::tests::inv_8_early_loosening_fails_immediately` |
| INV-9 | No expired credential or command is accepted when `now_est` is in VERIFIED state (i.e., `FreshnessState::Verified` and `now_est ≥ ratchet.persisted_floor`). | Advances time past expiry; verifies rejection at Stages 3 and 8. | `tirbase-guard/src/guard.rs` Stages 3 (token expiry) and 8 (command expiry) `[Planned]` | `tirbase_sim::invariants::tests::inv_9_expired_acceptance_fails_immediately` |
| INV-10 | A `(issuer, target, sequence, enrollment_epoch)` tuple is accepted at most once per enrollment epoch. | Tracks all accepted tuples per epoch; duplicate triggers immediate failure. | `tirbase-guard/src/anti_replay.rs::check_and_advance()` `[Planned]` | `tirbase_sim::invariants::tests::inv_10_tuple_reuse_fails_immediately` |
| INV-11 | An Unknown ledger entry for a target blocks all new commands to that target until resolved. | After an Unknown entry is inserted, subsequent commands to the same target are rejected. | `tirbase-guard/src/effects_ledger.rs::can_accept_command()` `[Planned]` | `tirbase_sim::invariants::tests::inv_11_unknown_blocks_command_fails_immediately` |
| INV-12 | Every dispatched actuation (stage 18 reached) has a durable `Actuating` record in `primary.db` committed before dispatch. | Verifies no driver write occurs without a prior `Actuating` row in the sim ledger. | Stage 16 SQLite commit before Stage 18 dispatch in `tirbase-guard/src/guard.rs` `[Planned]` | `tirbase_sim::invariants::tests::inv_12_dispatch_without_durable_record_fails_immediately` |
| INV-13 | `now_est` never decreases across beacons or reboots (ratchet + `boot_id` logic). | Simulates reboots; verifies `now_est` at boot ≥ `persisted_floor` (Property 17). | `tirbase-guard/src/time.rs::TimeRatchet::now_est()` (implemented; guard stage assertion pending) | `tirbase_sim::invariants::tests::inv_13_now_est_regression_fails_immediately`; `tirbase-guard/tests/time_ratchet_property.rs::ratchet_floor_is_monotonically_non_decreasing_across_beacons_and_reboots` |
| INV-14 | Governance fields (`policy_loosen_m`, `policy_loosen_n`, `timelock_secs`, `cancel_window_secs`) never weaken without a completed Loosening approval (M-of-N + time-lock satisfied). | Verifies that governance-field weakening requires the full approval flow to complete. | `tirbase-guard/src/policy.rs::ingest_bundle()` and `classify_bundle()` `[Planned]` | `tirbase_sim::invariants::tests::inv_14_governance_weakening_fails_immediately` |
| INV-15 | At most one in-flight actuation per target at any time (`SingleWriterLease` exclusivity while in `Actuating` state). | Verifies at most one `Actuating` entry per `target_id` in the sim ledger at any tick. | `tirbase-guard/src/guard.rs` Stage 16 (lease acquired inside atomic commit) `[Planned]` | `tirbase_sim::invariants::tests::inv_15_multiple_inflight_actuations_fail_immediately` |
| INV-16 | The `(issuer_did, target_id, sequence_number, enrollment_epoch)` tuple is written to the decided-outcome cache atomically with the `Actuating` record; once written, it never changes. | Verifies atomic write and immutability across all scenarios; any mid-flight mutation triggers failure. | Stage 16 SQLite transaction in `tirbase-guard/src/guard.rs` `[Planned]` | `tirbase_sim::invariants::tests::inv_16_cache_mutation_fails_immediately` |

---

## Key Exceptions and Design Notes

### INV-6 Exception: `tirbase-safe-writer`

INV-6 states that no command reaches a driver without passing through the Guard evaluation function. There is one explicitly scoped exception: **`tirbase-safe-writer`**.

`tirbase-safe-writer` is a minimal binary invoked by `tirbase-safe-writer.service` via systemd's `OnFailure=` directive when the Guard process exits unexpectedly. Its sole purpose is to drive all actuators to their `safe_default` values. Because this path operates after Guard exit — by definition, when the Guard is no longer running — it cannot pass through the Guard evaluation function.

This exception is bounded and safe:

- `tirbase-safe-writer` is restricted to emitting `safe_default` values only; it has no mechanism to emit commanded values.
- The path is only reachable on Guard exit, not during normal operation.
- The exception is documented here per the design note in §4.6 of `design.md`.

INV-5 (LOCKDOWN actuates only `safe_default`) and INV-6 (all commands pass through Guard) are therefore complementary: INV-5 covers the Guard-running path, and `tirbase-safe-writer` covers the Guard-exited path, both bounding output to `safe_default`.

### INV-9 Scope: Freshness State Condition

INV-9 applies **only when `FreshnessState::Verified`** (i.e., `now_est ≥ ratchet.persisted_floor` and a fresh beacon has been processed). When freshness is `Unverified`, the freshness policy documented in `docs/freshness-policy.md` (task 3.12) governs expiry handling. In the `Unverified` state, expired credentials for critical parameters are handled via the challenge-nonce flow rather than outright rejection, allowing the system to remain operational under intermittent connectivity while still requiring proof of liveness for sensitive actuations.

### INV-13 Boot Behavior: `persisted_floor` as Lower Bound

After a reboot where no fresh time beacon is available, `now_est` returns `persisted_floor` — the maximum ratchet value that was committed to persistent storage before the reboot. This is correct behavior.

`persisted_floor` is a **lower bound** on actual wall-clock time, not a precise estimate. Immediately after a reboot without a fresh beacon:

- `now_est == persisted_floor`
- `persisted_floor` ≥ the last `now_est` value observed before the reboot (by the ratchet guarantee)

This satisfies INV-13 ("`now_est` never decreases") because the post-reboot `now_est` equals `persisted_floor`, which is at least as large as the pre-reboot floor. As fresh beacons arrive, `now_est` advances above `persisted_floor` normally.

---

## Task 17 registration

Task 17.1–17.8 registers INV-1..INV-16 with tirbase-sim test IDs and verifies `tirbase-sim/src/invariants.rs::InvariantChecker` is the production caller for every check (CLAIM-17.1..CLAIM-17.8, CLAIM-38.6). `scripts/check-system-invariants.sh` is the CI catalog check: removing any INV-N entry from this file fails CI.

## Changelog

| Revision | Date | Changes |
|----------|------|---------|
| 1.0 | 2025-07-14 | Initial catalog: INV-1 through INV-7 (core envelope, idempotency, policy monotonicity, hash chain, lockdown, Guard bypass, token envelope). |
| 1.1 | 2025-07-14 | Added INV-8 through INV-11: policy time-lock (INV-8), expiry under verified freshness (INV-9), per-epoch anti-replay (INV-10), Unknown-entry command block (INV-11). |
| 2.1 | 2026-11-08 | Registered INV-1..INV-16 with tirbase-sim `InvariantChecker` test IDs (tasks 17.1-17.8/38.6); added CI catalog check. |
| 2.0 | 2025-07-14 | Added INV-12 through INV-16: durable-before-dispatch (INV-12), `now_est` monotonicity (INV-13), governance weakening gate (INV-14), single-writer lease (INV-15), atomic decided-outcome cache write (INV-16). Added key exceptions section and this changelog. |
