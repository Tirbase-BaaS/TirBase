# Freshness Policy for Non-Critical Commands When `FreshnessState::Unverified`

**Version:** 1.0 
**Last Updated:** 2025-07-14 
**CLAIMS Entry:** CLAIM-3.12 
**Requirement:** PV-22.3

---

## 1. Purpose

### What is `FreshnessState::Unverified`?

The TirBase `TimeRatchet` maintains an authenticated-time estimate (`now_est`) derived from the most
recently accepted `TimeBeacon`. When the authenticated-time estimate is considered stale or
unavailable, the system enters `FreshnessState::Unverified`.

`FreshnessState::Unverified` occurs in the following situations:

- **No beacon has been received since boot.** After a reboot the system cannot reconstruct a
 trusted monotonic offset relative to a new beacon; `now_est` falls back to `persisted_floor` but
 freshness is unknown.
- **Beacon gap exceeds the staleness window.** No `TimeBeacon` has been accepted within the
 configurable staleness window (default: 3600 seconds / 1 hour; set by `staleness_window_secs` in
 `DeploymentConfig`). This covers satellite link loss, NTS server unavailability, or Galileo
 OSNMA signal outage.
- **Cross-boot monotonic subtraction is invalid.** If `current_boot_id != beacon_boot_id`, the
 `mono_now − mono_at_beacon` subtraction is invalid (different boot session). The ratchet falls
 back to `persisted_floor` and freshness becomes Unverified until a new beacon arrives in this
 boot.

While in `Unverified` state the system cannot reliably evaluate command expiry using `now_est`
(PV-22.1). This does not mean the system must halt; it must apply a defined degraded-operation
policy.

---

## 2. Options Considered

Three policy options were evaluated for handling non-critical commands (i.e., commands targeting an
`EnvelopeProfile` parameter with `critical: false`) when `FreshnessState::Unverified`.

### Option (a) — Reject All Commands

**Behaviour:** While `FreshnessState::Unverified`, the Guard rejects every command regardless of
the parameter's criticality level.

**Pros:**
- Simplest implementation; no timer tracking required.
- No actuation occurs when time is uncertain.
- Easiest to audit: the policy has no parameterization.

**Cons:**
- Unacceptable for cold-chain, energy-edge, or building-automation deployments where devices must
 remain operational during intermittent NTS/Roughtime/Galileo outages.
- A brief beacon gap (e.g., a 10-minute NTS reconnect) would halt all non-safety-critical
 actuation across the site.
- This effectively makes beacon availability a hard availability dependency.

### Option (b) — Flag with `UNVERIFIED` SecurityEvent and Allow with Narrowed Envelope

**Behaviour:** While `FreshnessState::Unverified`, non-critical commands are accepted but the Guard
enforces a tighter envelope (e.g., ±5 % of the normal bounds). A `FreshnessUnverified` SecurityEvent
(Medium severity) is emitted for each allowed command.

**Pros:**
- Keeps the system operational with a visible safety margin.
- Envelope narrowing provides a bounded degradation guarantee.

**Cons:**
- Requires a second set of narrowed envelope parameters per profile, doubling the policy surface.
- Operators must manage and update both normal and narrowed bounds per device class.
- The narrowed envelope is not currently defined in `EnvelopeProfile`; adding it would be a
 significant schema change.
- Envelope narrowing does not address the core problem: the system does not know *how long* it has
 been operating without a beacon.

### Option (c) — Allow Within a Configurable Timeout After Last Beacon (CHOSEN)

**Behaviour:** Non-critical commands are allowed for up to `beacon_signal_loss_threshold_secs`
(default 300 seconds) after the most recent accepted beacon's monotonic timestamp. Once that window
expires, non-critical commands are rejected with the same `ChallengeMissing` rejection category used
for critical parameters. A `FreshnessUnverified` SecurityEvent (Medium severity) is emitted for
every command that is accepted while the window is open.

**Pros:**
- Decouples short intermittent beacon gaps from hard command rejection.
- A concrete, auditable decision boundary: allowed for N seconds, then rejected.
- No schema changes to `EnvelopeProfile`.
- Consistent with the challenge-nonce model already used for critical parameters.
- The threshold parameter (`beacon_signal_loss_threshold_secs`) already exists in the design's
 `DeploymentConfig`.

**Cons:**
- Commands accepted near the end of the tolerance window use an increasingly stale time estimate.
- A brief `Verified → Unverified → Verified` flicker (e.g., NTS reconnect mid-command) may cause
 a short burst of `FreshnessUnverified` events that operators must distinguish from a sustained
 outage.

---

## 3. Chosen Policy: Option (c) — Configurable Staleness Tolerance Window

TirBase adopts **option (c)** as the non-critical freshness policy.

### Decision Rationale

European critical infrastructure sites regularly experience short-duration NTS or Roughtime
connectivity gaps (satellite handover, NTS server maintenance). Rejecting all actuation during a
5–10 minute gap would be operationally unacceptable for cold-chain and energy-edge deployments
(PV-22.3 motivation). Option (c) provides a bounded tolerance window with full auditability
(SecurityEvent emitted per command) and a clear cutoff after which the system degrades to the same
posture as for critical parameters.

Option (a) is correct for systems where uptime is never more valuable than time-certainty. It is
available by setting `beacon_signal_loss_threshold_secs = 0` in the deployment configuration.

---

## 4. Policy Parameters

### 4.1 `beacon_signal_loss_threshold_secs` (default: 300 s)

| Parameter | Type | Default | Min | Max |
|---|---|---|---|---|
| `beacon_signal_loss_threshold_secs` | `u32` | `300` | `0` | `86400` |

Defined in `DeploymentConfig`. Setting this to `0` makes the policy equivalent to option (a):
every non-critical command in `Unverified` state is rejected immediately.

### 4.2 Skew Tolerance Note

The ±300 second default means the device will tolerate up to **5 minutes** of beacon absence before
degrading non-critical command acceptance.

This value is chosen to:

- Absorb normal NTS server jitter and brief link interruptions in European infrastructure.
- Remain well within the 3600-second staleness window (`staleness_window_secs`) that governs the
 transition from `Verified` to `Unverified`.
- Provide a measurable audit trail: every command accepted in this window carries a
 `FreshnessUnverified` SecurityEvent.

Operators in high-assurance deployments who want a tighter window should set
`beacon_signal_loss_threshold_secs` to a smaller value (e.g., `60`). Operators who need longer
tolerance (e.g., deep-field remote sites) may raise it, up to the `staleness_window_secs` value.
Raising `beacon_signal_loss_threshold_secs` above `staleness_window_secs` is a configuration
error; the Guard SHALL emit a startup diagnostic warning in that case.

### 4.3 Elapsed Time Measurement

The elapsed time since the last beacon is computed using the monotonic clock only:

```
elapsed_secs = mono_now - mono_at_beacon
```

- If `current_boot_id != beacon_boot_id` (post-reboot cross-boot case), `mono_at_beacon` is from a
 different boot session and the subtraction is invalid. In this case `elapsed_secs` is treated as
 **infinite** (i.e., the tolerance window is considered already expired). The device must receive a
 fresh beacon in the new boot session before non-critical commands are accepted while in Unverified
 state.
- This is the same boot-ID-awareness already applied in `TimeRatchet::now_est`.

---

## 5. Critical vs Non-Critical Parameter Distinction

`EnvelopeProfile.parameters[param].critical: bool` controls which freshness policy applies.

| Freshness State | Parameter Criticality | `elapsed <= threshold` | Guard Decision |
|---|---|---|---|
| `Verified` | Any | — | Normal evaluation (no freshness concern) |
| `Unverified` | `critical: false` | Yes | **Allow**; emit `FreshnessUnverified` SecurityEvent (Medium) |
| `Unverified` | `critical: false` | No | **Reject** (`ChallengeMissing`) |
| `Unverified` | `critical: true` | Any | **Reject** (`ChallengeMissing`) unless a valid challenge nonce is present |

**Critical parameters always require a challenge nonce when freshness is Unverified, regardless of
the staleness tolerance window.** The tolerance window applies only to non-critical parameters.

Challenge nonces for critical parameters are issued by the Guard via `POST /admin/challenge` and
must be included by the issuer in `cmd.challenge_nonce`. See §4.5 of `design.md` for the full
`ChallengeNonce` structure and issuance flow.

---

## 6. SecurityEvent Emitted

Every command accepted while `FreshnessState::Unverified` (within the tolerance window) triggers a
`FreshnessUnverified` SecurityEvent:

| Field | Value |
|---|---|
| Category | `TimeRatchet` |
| Reason | `FreshnessUnverified` |
| Severity | `Medium` |
| Payload | `target_id`, `param`, `elapsed_secs` since last beacon, `threshold_secs` |

This event is emitted at **Stage 17** of the command pipeline (see `design.md` §4.5), after the
command is accepted by the guard but before actuation dispatch. Operators and Auditor-role
subscribers SHOULD monitor the frequency and `elapsed_secs` of these events to detect sustained
beacon outages.

The `FreshnessUnverified` reason code MUST be documented in `docs/security-event-catalog.md`
(CLAIM-3.9) under the `TimeRatchet` category with `Medium` severity.

---

## 7. Guard Stage 9 Pseudocode

Stage 9 of the command pipeline (`design.md` §4.5) implements the freshness and challenge-nonce
check. The pseudocode for non-critical parameters under this policy is:

```rust
// Stage 9: Freshness + challenge nonce check
let freshness = ratchet.freshness_state(time_source, deployment_config.staleness_window_secs);

match freshness {
 FreshnessState::Verified => {
 // No freshness concern; critical and non-critical proceed normally.
 }
 FreshnessState::Unverified => {
 if param.critical {
 // Critical params always require a challenge nonce in Unverified state.
 let nonce = cmd.challenge_nonce.ok_or(ChallengeMissing)?;
 verify_challenge_nonce(nonce, &cmd)?;
 } else {
 // Non-critical params: apply the staleness tolerance window.
 let elapsed = if time_source.boot_id != ratchet.beacon_boot_id {
 // Cross-boot: treat elapsed as infinite.
 u64::MAX
 } else {
 time_source.monotonic_now.saturating_sub(ratchet.mono_at_beacon)
 };

 if elapsed > deployment_config.beacon_signal_loss_threshold_secs as u64 {
 // Window expired: reject with the same code as critical parameters.
 return Err(RejectionCategory::ChallengeMissing);
 }

 // Within tolerance window: allow, but emit a FreshnessUnverified SecurityEvent.
 // (Event is emitted at Stage 17 by the caller; this stage returns Ok.)
 ctx.mark_freshness_unverified(elapsed); // deferred to Stage 17
 }
 }
}
```

Note: `simulate` returns the exact `RejectionCategory` that would be used without performing any
actuation, SecurityEvent emission, or nonce consumption (per the `simulate` contract in
`design.md` §4.5).

---

## 8. `tirbase-sim` Test Scenario

The following scenario is to be implemented in `tirbase-sim` to exercise this policy. It forms part
of the verification for CLAIM-3.12 and PV-22.3.

### Scenario: `freshness_policy_non_critical_tolerance_window`

**Setup:**

1. Initialize the simulator with a fully enrolled device, a valid `EnvelopeProfile` containing:
 - A non-critical parameter `temperature_setpoint` (`critical: false`)
 - A critical parameter `emergency_shutoff` (`critical: true`)
2. Issue a valid `TimeBeacon` at `T=0`. The `TimeRatchet` advances; `FreshnessState` becomes
 `Verified`.
3. Set `beacon_signal_loss_threshold_secs = 300` in `DeploymentConfig`.

**Step 1 — Baseline in Verified state:**

- At `T=10s` (no beacon gap), send a non-critical command (`temperature_setpoint`).
- **Expected:** Command accepted. No `FreshnessUnverified` SecurityEvent. `FreshnessState::Verified`.

**Step 2 — Advance clock to within the tolerance window (T=290s, elapsed=290s < 300s):**

- Stop issuing beacons. Advance the mock monotonic clock by 290 seconds so that
 `mono_now - mono_at_beacon = 290`.
- At this point, `staleness_window_secs` has NOT been exceeded (1 hour default), so strictly
 `FreshnessState` depends on the staleness window. To ensure `Unverified` state for the test,
 configure `staleness_window_secs = 60` so the system enters `Unverified` after 60s without a
 beacon.
- **Verify `FreshnessState::Unverified`** (elapsed since beacon > `staleness_window_secs`).
- Send a non-critical command (`temperature_setpoint`).
- **Expected:**
 - Command **accepted** (elapsed 290s < threshold 300s).
 - One `FreshnessUnverified` SecurityEvent emitted with `elapsed_secs ≈ 290`, `threshold_secs = 300`.
 - `simulate` called with the same command returns `Simulated { would_accept: true, rejection_reason: None }`.

**Step 3 — Advance clock past the tolerance window (T=310s, elapsed=310s > 300s):**

- Advance the mock monotonic clock by an additional 20 seconds (total elapsed = 310s).
- `FreshnessState::Unverified` (still no beacon).
- Send a non-critical command (`temperature_setpoint`).
- **Expected:**
 - Command **rejected** with `RejectionCategory::ChallengeMissing` (external code: `CHALLENGE_REQUIRED`).
 - No actuation occurs.
 - No `FreshnessUnverified` SecurityEvent (command was rejected before Stage 17).
 - `simulate` returns `Simulated { would_accept: false, rejection_reason: Some(ChallengeMissing) }`.

**Step 4 — Critical parameter rejects throughout (T=10s, Verified state):**

- Reset to `T=10s` (fresh beacon at `T=0`, `FreshnessState::Verified`).
- Send a critical command (`emergency_shutoff`) **without** a challenge nonce.
- **Expected:** Command **rejected** with `ChallengeMissing`. (Critical params always need a nonce in Unverified; in Verified state they follow the normal quorum path — for this test, send in Verified state to confirm Stage 15 quorum, not Stage 9 freshness.)

**Step 4b — Critical parameter rejects in Unverified state without a nonce:**

- With `FreshnessState::Unverified` and elapsed = 10s (within the 300s window for non-critical),
 send a critical command (`emergency_shutoff`) **without** a challenge nonce.
- **Expected:** Command **rejected** with `ChallengeMissing`. The tolerance window does not apply.

**Step 5 — Cross-boot: tolerance window expired immediately:**

- Simulate a reboot: increment the `boot_id` of the mock `TimeSource` without issuing a new beacon.
- `TimeRatchet` detects `current_boot_id != beacon_boot_id`; freshness is `Unverified`.
- `elapsed` is treated as infinite (cross-boot guard).
- Send a non-critical command at `elapsed = 1s` (i.e., 1s after the simulated reboot).
- **Expected:** Command **rejected** with `ChallengeMissing` (window considered expired).

### Invariant Verification

At every tick throughout this scenario, the `InvariantChecker` MUST verify:

- **INV-10** — no `(issuer, target, sequence, epoch)` tuple is accepted more than once.
- **INV-12** — no actuation occurs without a durable `Actuating` record.
- **INV-13** — `now_est` does not decrease (ratchet monotonicity holds through the reboot).

The scenario SHALL reference INV-10, INV-12, and INV-13 in its tick-check configuration.

---

## 9. INV-10 Reference (System Invariants Catalog)

**INV-10:** A `(issuer, target, sequence, enrollment_epoch)` tuple is accepted at most once per
enrollment epoch.

This invariant applies directly to the freshness policy scenario. If a command is rejected with
`ChallengeMissing` (either because the tolerance window expired, or because the parameter is
critical), the rejection must be recorded in the decided-outcome cache. A subsequent retry of the
same command:

- **If the cache entry was not written** (rejection before Stage 16): the command may be
 re-submitted with a fresh sequence number or (for critical params) with a challenge nonce after
 one is issued.
- **If the cache entry was written** (idempotent retry path): the cached outcome (rejected) is
 returned without re-evaluating Stage 9.

The freshness-related rejection occurs at **Stage 9**, which is before the Stage 16 atomic commit.
Therefore freshness-rejected commands do NOT consume sequence numbers or idempotency keys.
Idempotent retry of a freshness-rejected command will re-evaluate Stage 9 using the current
monotonic time — which may succeed if a new beacon has arrived in the meantime.

**INV-10 scope note** (from `docs/system-invariants.md`): when freshness is `Unverified`, the
command guard applies the staleness tolerance window policy documented here, not the general VERIFIED
expiry path of INV-9. INV-9 applies only in `FreshnessState::Verified`.

---

## 10. Configuration Reference

```toml
# DeploymentConfig (tirbase-gateway TOML)

# How long after the last accepted beacon before FreshnessState becomes Unverified.
# Default: 3600 seconds (1 hour).
staleness_window_secs = 3600

# How long non-critical commands remain allowed after FreshnessState becomes Unverified.
# Default: 300 seconds (5 minutes). Set to 0 to reject all non-critical commands immediately
# (equivalent to option (a)).
beacon_signal_loss_threshold_secs = 300
```

If `beacon_signal_loss_threshold_secs > staleness_window_secs`, the Guard emits a startup
diagnostic warning `FreshnessThresholdExceedsStalenessWindow` because the tolerance window would
never be reached — `FreshnessState` would remain `Verified` for the entire threshold duration.

---

## Changelog

| Revision | Date | Changes |
|---|---|---|
| 1.0 | 2025-07-14 | Initial policy document. Defines option (c) with ±300s default, Stage 9 pseudocode, tirbase-sim test scenario, INV-10 reference, and configuration reference. |
