# Soak Test Procedure (Real 72h Lab Soak)

> PV-15.6 / CLAIM-45.2 — per-release, maintainer-triggered. Not run in CI.
> The automated CI coverage for endurance is the virtual-time soak
> (`tirbase-sim/src/soak.rs`, `tirbase-sim/tests/soak.rs`), which simulates 72h
> on the accelerated clock with fault injection inside a 2-hour CI job.

## Purpose

Validate long-run stability of a real `tirbase-gateway` deployment on reference
hardware: no unbounded memory growth, no file-descriptor/handle leaks, and no
invariant or crash-loop regressions over 72 continuous hours of operation with
fault injection.

## When to run

- Once per release candidate, before tagging the release.
- Maintainer-triggered only (lab hardware required). Do **not** run on public PRs.
- Record results in the release notes / audit artifact for the release.

## Prerequisites

- Reference gateway hardware per `docs/reference-hardware.md` (profile a).
- Built release binaries for the target (`tirbase-gateway`, drivers as needed).
- A cold-chain (or representative) `EnvelopeProfile` installed and validated.
- Fault-injection controls available: network partition/delay/drop tooling and a
  power-cut or process-restart mechanism equivalent to the crash-loop scenarios.
- Baseline measurement captured at t=0 (RSS/heap and open handles).

## Setup

1. Install the release build and configuration on the reference gateway.
2. Verify the device boots to `Normal` mode with a signed `EnvelopeProfile`
   installed (`/health` 200, metrics endpoint reachable).
3. Enable the metrics/telemetry collection needed for the thresholds below
   (process RSS, heap if available, and open file descriptors/handles).
4. Start the workload driver: a steady command/admission mix plus the S1/S2/S3
   adversary traffic used by the cold-chain demo pack, at a rate representative
   of the target deployment.

## Fault injection during the run

Apply deterministic, periodic faults across the 72h window (mirroring the
virtual-time soak's coverage):

- Network: partition, delay (1–30,000 ms), drop, reorder, duplicate (≤5 copies).
- Process: supervised restarts consistent with crash-loop escalation bounds
  (must not escalate to unintended LOCKDOWN under the configured window).
- Time/rate churn representative of normal operation (no forged time anchors).

Log every injected fault with a wall-clock timestamp so observed behaviour can be
correlated with the injection schedule.

## Pass/fail thresholds (measured over 72 hours)

| Metric | Threshold | How to measure |
|---|---|---|
| Heap / RSS growth | **≤ 5 MiB** over 72h | Compare process RSS (and allocator heap, if instrumented) at steady-state checkpoints to the t=0 baseline; the net growth at 72h must not exceed 5 MiB. |
| Handle / file-descriptor growth | **≤ 50 handles** over 72h | Compare open FD/handle count (`/proc/<pid>/fd` count or platform equivalent) at steady-state checkpoints to the t=0 baseline; net growth at 72h must not exceed 50 handles. |
| Invariants / crashes | 0 unhandled invariant violations; no unrecovered crash-loop escalation outside the injected schedule | Gateway remains healthy (`/health` 200), no unexpected LOCKDOWN, security-event log chain intact. |

## Execution

1. Record t=0 baseline (RSS, heap, handle count).
2. Run continuously for **72 hours** under the workload and fault schedule.
3. Sample RSS/heap and handle counts at a fixed cadence (recommended: every 15
   minutes) and retain the time series.
4. At 72h, stop fault injection, quiesce the workload, and record the final
   measurements.
5. Compute net growth (final − baseline, using a steady-state baseline after warmup
   if startup transients are present; document the baseline point chosen).

## Reporting

Produce a short report containing:

- Release/version under test, hardware profile, and exact binary/config hashes.
- Full 72h time series for RSS/heap and handle counts, with net growth values.
- Pass/fail against each threshold above.
- Any injected faults that produced unexpected behaviour (with timestamps).
- Confirmation that `docs/soak-test-procedure.md` thresholds (≤5 MiB heap growth,
  ≤50 handle growth over 72h) were met.

Archive the report with the release audit artifacts. A failure blocks the release
until investigated and resolved (or the threshold is re-baselined via the
measure-first process with justification).
