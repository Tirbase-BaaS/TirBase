# Runbook: Time-Anchor Failure / UNVERIFIED Freshness Operation

> **Status:** Procedure documented and verified against `tirbase-sim` simulated faults (see **Verification**). Applies to `UNVERIFIED` freshness mode, beacon loss/poisoning resistance, and reboot recovery (PV-22, S19/S23/S31).
>
> **[CLAIM-55.6]** — **Proven** (procedure + simulated-fault verification `tirbase-sim/tests/runbook_fault_verification.rs::runbook_time_anchor_failure_unverified_and_recovery`).

## When to use

- No fresh authenticated time beacons within staleness window, or node rebooted before receiving a beacon (freshness becomes **Unverified**).
- Suspected time-anchor poisoning or far-future beacon attempts (must be rejected; ratchet must not advance on invalid/insufficiently authorized jumps).
- Delayed/withheld command delivery concerns (expiry evaluated against authenticated `now_est`).

## Expected behavior in UNVERIFIED freshness

- `TimeRatchet::freshness()` reports `Unverified` when beacons are stale or after reboot before new-beacon binding to current boot context (per ratchet state). `now_est` is floored at `persisted_floor` (never decreases; no monotonic subtraction across boot boundary) — S31.
- **Critical-parameter commands** require challenge nonce / freshness gating per policy (Stage 9 / PV-22.3); non-critical handling follows configured freshness policy. Do not assume wall clock correctness.
- Expired/withheld commands are rejected based on `now_est` even if wall clock is manipulated backwards (S19).

## Detection

1. **Operational indicators:** increased `CHALLENGE_REQUIRED` / freshness-related rejections, inability to satisfy critical command freshness, absence of recent valid beacons.
2. **Logs/events:** time-anchor/beacon validation failures, `Unverified` state observations (deployment-specific telemetry).
3. **Admin/status checks:** use guard/status endpoints where available (Auditor/PolicyAuthority) to inspect freshness-related posture; confirm node mode is not masking the issue.

## Operator procedure

### 1. Confirm scope and safety

- If commands cannot be safely admitted, keep affected targets in safe state per envelope/profile and consider restricting operations; do not bypass freshness/challenge controls.
- Preserve diagnostics (event exports, config, beacon source status).

### 2. Restore authenticated time

- **Verify time-anchor sources:** ensure M-of-N authorized `TimeAnchor` signers/beacons are available and reachable; check network/partition issues (see comms failure handling).
- **Re-establish beacons:** once a valid beacon is accepted for the current context, freshness can return to `Verified` and `now_est` advances monotonically within constraints (S31 recovery path).
- **Reject poisoning:** far-future jumps require required quorum/constraints; single-anchor or out-of-bounds jumps must be rejected without advancing ratchet state (S23).

### 3. Command issuance under UNVERIFIED state

- For **critical parameters:** obtain and use required challenge nonce flow as specified (`POST /admin/challenge` / mesh or cloud challenge path where enabled); nonces are single-use and rate-limited (S32).
- For non-critical operations, follow the documented freshness policy and expect conservative rejection/expiry behavior.
- Avoid retry storms; respect `retry_after`/rate limits.

### 4. Post-recovery verification

- Confirm beacons accepted, `now_est` monotonic, freshness `Verified` when expected.
- Re-test a representative non-critical and (if applicable) challenged critical command path.

## Rollback / escalation

- If valid beacons cannot be obtained, operate in degraded-but-safe mode per policy; do not weaken expiry/ratchet checks.
- If poisoning attempts persist or keys may be compromised, follow `docs/runbooks/key-compromise.md`.
- If reboot/restore anomalies coincide with epoch/rollback indicators, follow `docs/runbooks/restore.md` and S22-related guidance.

## Verification

- **Simulated faults:** delayed delivery rejected despite wall-clock rollback (S19), time-anchor poisoning/quorum behavior (S23), reboot yields Unverified with `now_est == persisted_floor` and recovery after new beacon (S31) — `tirbase-sim/src/scenarios/s19_s23_s31_time.rs::{run_s19,run_s23,run_s31}`.
- **Procedure verification (Unverified floor semantics + recovery):** `tirbase-sim/tests/runbook_fault_verification.rs::runbook_time_anchor_failure_unverified_and_recovery`.
