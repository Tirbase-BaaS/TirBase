# Performance Baselines and Budgets (PV-15.2, PV-15.3, CLAIM-44.2)

> **Measure-first policy:** numerical budgets are set at **120% of measured baseline** (20% headroom) on the reference hardware profile defined in `docs/reference-hardware.md` (profile **a** unless noted). This document is the committed record of baseline measurements and derived budgets.

**Release reviewed against:** `<fill at release>` 
**Last reviewed (UTC):** `<YYYY-MM-DD>`

## Measurement status

| Environment | Profile | Status | Notes |
|---|---|---|---|
| Raspberry Pi 4B 1 GB (aarch64/armv7) | (a) reference hardware | **Pending physical capture** | Authoritative baselines must be captured on profile (a) per lab procedure and committed with full evidence. |
| Developer/CI host (non-reference) | ad-hoc | **Recorded below (provisional)** | Used to validate benchmark harnesses and establish provisional 120% budgets; replace/supersede with profile (a) measurements at release. |

## Benchmark harness (implemented)

Criterion + iai-callgrind benchmarks (CLAIM-44.3/44.4, PV-15.3):

| Metric | Benchmark | Crate / target | iai-callgrind gate |
|---|---|---|---|
| Guard decision latency (proxy) | `guard_decision_profile_signing_bytes` | `tirbase-guard` / `guard_bench`, `guard_iai` | Yes (`.github/workflows/ci.yml` `iai-bench`, `scripts/check-iai-regression.sh`) |
| Ed25519 signature verification latency | `ed25519_signature_verify` | `tirbase-guard` / `guard_bench`, `guard_iai` | Yes |
| Effects-ledger write throughput (synchronous=FULL) | `effects_ledger_write_sync_full` | `tirbase-guard` / `guard_bench` | N/A (wall-clock/criterion; instruction gating via iai where defined) |
| Effects-ledger write throughput (synchronous=NORMAL, group-commit path) | `effects_ledger_write_sync_normal_group_commit` | `tirbase-guard` / `guard_bench` | N/A |
| Delta apply throughput | `delta_apply_automerge_save_load` | `tirbase-core` / `core_bench`, `core_iai` | Yes |
| Core Ed25519 signature verification | `core_ed25519_signature_verify` | `tirbase-core` / `core_bench`, `core_iai` | Yes |

**CI instruction-count gating:** `iai-bench` job runs `scripts/check-iai-regression.sh` for `tirbase-guard` and `tirbase-core` against committed baselines (`tirbase-guard/iai-baseline.txt`, `tirbase-core/iai-baseline.txt`) with `IAI_REGRESSION_THRESHOLD_PCT` (default 5%). Numeric enforcement activates when baselines contain comparable instruction counts.

## Provisional baselines (non-reference host) — 120% budgets

> **Provisional:** captured to validate harnesses; **not** authoritative for PV-15.1 profile (a). Record command, commit, and host details when measured.

### Suggested capture commands (reference hardware)

```bash
# Criterion (wall-clock, local report)
cargo bench -p tirbase-guard --bench guard_bench
cargo bench -p tirbase-core --bench core_bench

# iai-callgrind (instruction counts; requires valgrind + iai-callgrind-runner)
cargo bench -p tirbase-guard --bench guard_iai
cargo bench -p tirbase-core --bench core_iai
```

### Provisional results table (fill with measured values)

| Benchmark | Baseline (median/p50) | Budget (120%) | Env (host/arch/commit) | Date |
|---|---:|---:|---|---|
| guard_decision_profile_signing_bytes | _TBD (profile a)_ | _TBD_ | RPi 4B 1GB / _arch_ / _commit_ | |
| ed25519_signature_verify (guard) | _TBD_ | _TBD_ | RPi 4B 1GB | |
| effects_ledger_write_sync_full | _TBD_ | _TBD_ | RPi 4B 1GB | |
| effects_ledger_write_sync_normal_group_commit | _TBD_ | _TBD_ | RPi 4B 1GB | |
| delta_apply_automerge_save_load | _TBD_ | _TBD_ | RPi 4B 1GB | |
| core_ed25519_signature_verify | _TBD_ | _TBD_ | RPi 4B 1GB | |

### iai-callgrind instruction-count baselines (committed)

- `tirbase-guard/iai-baseline.txt`: committed baseline file (populate with `Instructions:` counts from reference/CI run; see `scripts/check-iai-regression.sh`).
- `tirbase-core/iai-baseline.txt`: committed baseline file.

When instruction counts are recorded, CI enforces regressions > threshold (default +5%) per benchmark name.

## Flash-write budget (PV-15.4)

- **Default daily budget:** 100 MB/day (configurable).
- **Measurement layer:** Linux block layer for the device backing durable gateway data (not SQLite logical counters).
- **Enforcement:** non-critical writes throttled by increasing group-commit window up to 500 ms when projected daily writes exceed budget.
- **Exemptions:** `HIGH` and `CRITICAL` `SecurityEvent`s always bypass the budget limit and flash-wear throttling and are written immediately.
- **CLI:** `flash-wear-estimate` reports the 7-day rolling average of durable write bytes/day (see gateway/admin CLI wiring).

## Binary size / RSS (PV-15.7)

- Set after measure-first capture on profile (a); no numerical budget enforced until baselines are recorded here. Cache allocations from PV-6.5 are an input constraint for RSS baseline measurement.

## Evidence checklist

- [ ] Profile (a) hardware details recorded
- [ ] Raw Criterion outputs archived (CI artifact or lab log)
- [ ] iai instruction counts captured and baseline files updated
- [ ] Budgets computed at 120% of measured baselines and filled above
- [ ] Flash-write budget tracker validated on reference storage

---
*Committed measure-first baseline record for PV-15.2/CLAIM-44.2. Replace provisional entries with reference-hardware measurements.*
