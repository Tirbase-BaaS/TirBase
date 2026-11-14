# Chaos Tests (F-14)

> Run in lab or controlled environments. Network/clock faults use `tirbase-sim` where possible; disk-full and crash-loop tests require host-level fault injection.

## Matrix

| Scenario | Method | Expected behavior | Evidence |
|----------|--------|-------------------|----------|
| Network partition | `tirbase-sim` network faults (partition/delay/drop/reorder/duplicate) or `tc netem`/firewall rules in integration lab | No accepted in-envelope commands lost (queued/reconciled per design); system enters DEGRADED as specified; on heal, CRDT/ledger reconcile without invariant violations | `cargo test -p tirbase-sim` soak/scenario tests; lab logs + invariant report |
| Disk full | Fill data partition (tmpfs/c loop) while gateway writes ledger/events | Graceful failure: writes fail safely, no corruption of existing SQLite/WAL beyond documented behavior; alerts emitted; recovery after space freed per runbooks | Integration test script + runbook notes; captured logs |
| Clock jump | Step system/virtual clock forward/backward beyond ratchet limits (controlled) | TimeRatchet/freshness rules enforced; unsafe acceptance blocked per policy (`UNVERIFIED`/challenge rules as designed); no silent acceptance of expired commands | `tirbase-sim` time scenarios (S23 etc.), `docs/time-sync.md` verification |
| Crash loops | Repeated kill -9 / power cuts during actuation windows (supervised restarts) | Bounded restart behavior; no escalation to unintended LOCKDOWN outside policy; applied-effects reconciliation correct; no un-audited actuation | `tests/hil` power-cut patterns + supervised runner; `docs/runbooks/crash-loop.md` |

## Automated coverage (virtual)

- **Partition/delay/drop/reorder/duplicate:** `tirbase-sim/src/network.rs`, `tirbase-sim/src/soak.rs` fault injection, integration tests under `tirbase-sim/tests/`.
- **Clock jump/poisoning:** see `tirbase-sim` time-related scenarios and `docs/adversary-scenarios.md` (S-series).

## Lab/host procedures

1. **Disk full:** use a dedicated test volume; monitor free space; restore by truncating test file or unmounting loop device. Never run on production data.
2. **Crash loops:** use process supervisor (systemd) with restart limits matching deployment; capture journal and `applied_effects_ledger` state before/after.
3. **Clock jump:** prefer virtual clock in sim for determinism; for real hosts, document NTP state and steps.

## CI vs nightly

- **CI:** fast sim-based chaos smoke where feasible (subset of soak faults, short duration).
- **Nightly:** extended virtual soak (`.github/workflows/fuzz-nightly.yml` style long runs) and, when hardware available, scheduled HIL/chaos windows with artifacts uploaded.

## Pass criteria

- No invariant violations reported by `tirbase-sim` invariant checker.
- No accepted command lost across partition heal in tested scenarios (replay/idempotency rules satisfied).
- After disk-full recovery, gateway starts and reconciles without manual DB surgery except documented repair runbooks.
- After clock jumps, freshness/expiry enforcement matches `docs/time-sync.md`.
- Crash loops do not produce unbounded restarts beyond supervisor policy and do not silently drop audited effects.
