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

Run with TLC (example):

```bash
java -jar tla2tools.jar -config policy_lifecycle.cfg policy_lifecycle.tla
java -jar tla2tools.jar -config command_freshness.cfg command_freshness.tla
java -jar tla2tools.jar -config ledger_recovery.cfg ledger_recovery.tla
java -jar tla2tools.jar -config single_writer_lease.cfg single_writer_lease.tla
```

## Kani proof spike

- `kani_envelope_arith.rs` — bounded proof harness for `FixedPointValue` bound comparison arithmetic (i128 scaling/comparison path) showing overflow-free comparison for all i64 mantissas within modeled exponent deltas.
