# Capacity Planning Guidance (F-14)

> **Measure-first:** numeric targets below are **provisional** until captured on reference hardware (`docs/reference-hardware.md`, profile **a**) and recorded in [`docs/perf-baseline.md`](perf-baseline.md). Use these as sizing starting points, then validate in a pilot.

## Load profiles (reference)

### Single site (small edge node)

- **Topology:** 1 gateway, 1–5 drivers/devices, optional local admin/console.
- **Command rate (typical):** ≤ 10 commands/min sustained, bursts ≤ 60 commands/min for < 30 s.
- **Telemetry/events:** ≤ 100 security/operational events/min; export batches hourly.
- **Ledger:** SQLite WAL on local storage; expect modest growth; apply flash-write budget (default 100 MB/day) and monitor `flash-wear-estimate`.
- **Resources (guidance):** ≥ 512 MB RAM free after OS, SD/eMMC with health monitoring, CPU headroom for TLS + guard evaluation.

### Multi-site (hub-and-spoke / regional)

- **Topology:** 10–100 sites, each a gateway; optional regional aggregator/cloud sync.
- **Command rate (per site):** same as single site; **aggregate:** design for N×peak with backoff.
- **Sync:** outbound-initiated cloud sync or mesh relay; plan for partition tolerance (queues bounded per THREAT_MODEL).
- **Operations:** centralized log/alert aggregation recommended; stagger OTA rollouts (use F-11 staged rollout + health gates).

### Large fleet (hundreds+)

- **Topology:** ≥ 100 gateways; mandatory fleet management discipline (channels, canary rings, monitoring).
- **Control plane:** avoid synchronous fan-out from a single operator; use staged operations and rate limits.
- **Data:** plan export/archival pipelines; ledger retention and compaction per deployment policy.
- **Observability:** metrics aggregation, alerting on queue depth, flash wear, reconciliation failures, and partition duration.

## Latency and throughput budgets (provisional)

Record measured values in `docs/perf-baseline.md`. Until then, treat these as **design budgets** (targets to validate):

| Path | Metric | Provisional target (p95, reference class) | Notes |
|------|--------|---------------------------------------------|-------|
| Command admission (guard) | End-to-end decision latency | ≤ 50 ms (local, in-envelope) | Excludes slow device I/O after accept; see `guard_decision_*` benches |
| Ledger append (effects/security log) | Append+fsync effective latency | ≤ 200 ms (sync=FULL, small record) | Use group-commit tuning where safe; `effects_ledger_write_*` benches |
| Alarm delivery | Time from event to delivered notification channel | ≤ 5 s (best effort) | Depends on external channels; measure end-to-end in integration tests |
| Gate decision (physical/access) | Decision to actuator command issued | ≤ 100 ms (soft target) | Vertical-specific; validate with HIL |
| Payment intent (if applicable) | Intent accepted to confirmed (external PSP) | Out of scope for on-device-only budget | Track separately with PSP SLAs |

**Throughput (provisional):** a single reference gateway should sustain ≥ 1 in-envelope command/s continuously with headroom; burst handling relies on rate limits and queues (must be bounded).

## Resource sizing checklist

- **Memory:** track RSS in soak; budget ≤ 5 MiB growth over 72h virtual soak plus real soak validation (see `docs/soak-test-procedure.md`).
- **Flash/storage:** daily write budget (default 100 MB/day), monitor wear estimates, size for retention + headroom (≥ 2× expected 30-day growth).
- **File descriptors/handles:** ≤ 50 net growth over 72h soak target; alert on approaching OS limits.
- **CPU:** reserve headroom for crypto (sign/verify), TLS, and JSON/TOML parsing under fault injection.

## Tuning knobs (operator-facing)

- `flash_wear_daily_budget_bytes` (gateway config) — lower on constrained eMMC.
- Group-commit / sync policy — trade durability latency vs write amplification (documented in runbooks/perf notes).
- Rate limits and queue caps — must remain bounded (see THREAT_MODEL pending-queue limits).

## Validation workflow

1. Pick a load profile above.
2. Run `tirbase-sim` scenarios + soak (`cargo test -p tirbase-sim --test soak ...`) for regression smoke.
3. Run device-mix tests for your vertical (drivers you deploy).
4. Capture metrics and update `docs/perf-baseline.md` with measured baselines and 120% budgets.
5. Revisit after firmware/OS/storage changes.
