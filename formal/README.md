# Formal models (Phase 16, PV-26)

This directory contains executable protocol models and proof spikes referenced by CLAIM-51.1–51.4 and CLAIM-51.6.

## TLA+ models

- `policy_lifecycle.tla` / `policy_lifecycle.cfg` — tighten/loosen/time-lock/cancel/rollback policy lifecycle.
  - Safety: no rollback/activation below committed counter, no timelock-bypass activation.
  - Liveness: a ready, quorum-satisfied, non-cancelled loosening eventually applies under fairness.
- `command_freshness.tla` / `command_freshness.cfg` — anti-replay sliding window and enrollment-epoch binding.
  - Safety: no `(issuer,target,epoch,seq)` accepted twice; epoch binding preserved.
  - Liveness: in-window fresh sequences can eventually be accepted.
- `ledger_recovery.tla` / `ledger_recovery.cfg` — `Actuating -> Complete|Failed|Unknown` crash recovery.
  - Safety: durable-first-state/unknown-is-durable invariants.
  - Liveness: crash leads to reconciliation; no stuck `Actuating` after recovery.
- `single_writer_lease.tla` / `single_writer_lease.cfg` — acquisition, renewal cap/cooldown, revocation release, preemption.
  - Safety: at most one active holder per target; no revoked active holder.
  - Liveness: active leases eventually expire.

Run all four with TLC via the checked-in script (used by the `formal-models` CI job):

```bash
curl -fsSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.7.1/tla2tools.jar
bash ../scripts/check-formal-models.sh tla2tools.jar
```

The script exits non-zero if TLC reports a violation **or if TLC cannot start**, so a
missing JVM is a failure rather than a silent pass.

**Status (2026-11-11): all four specs pass TLC 2.16 locally** (`policy_lifecycle`
143,312 states generated / 23,950 distinct with `Safety` + `Progress`; the other
three exit 0 with their invariants and liveness properties). Running them for the
first time exposed real model defects — an unapplied `Expire` argument, a timelock
that could exceed `MaxTime`, a recovery invariant scoped past the boot that
established it, and two parse errors — all fixed in the specs above. The
`formal-models` CI job re-runs this script on every push.

## Kani proof spike

- `kani_envelope_arith.rs` — Kani harness for the production fixed-point arithmetic. It `include!`s `tirbase-types/src/fixed_point_core.rs`, the exact module `FixedPointValue::compare_with_bounds` compiles, so the proof covers shipping code (not a copy).

**Status (2026-11-11): Verified.** Kani 0.68 with its pinned nightly reports `VERIFICATION:- SUCCESSFUL` on all four harnesses (`scale_mantissa_is_panic_free_in_full_domain`, `scale_mantissa_matches_exact_product_for_small_deltas`, `compare_scaled_is_total_and_sound`, `boundary_values_are_within_bounds`) with `--default-unwind 40`. The `kani-envelope-arith` CI job re-runs it.
