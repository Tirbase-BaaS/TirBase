# Runbook: Effects-ledger append latency SLO

**SLO:** 99% of durable effects-ledger appends complete within 100 ms over
30 days.
**Severity:** critical on `TirBaseLedgerAppendSLOBreach`; warning on
`TirBaseLedgerAppendLatencyHigh`.
**Alerts:** `TirBaseLedgerAppendLatencyHigh` (p99 > 150 ms, 10m),
`TirBaseLedgerAppendSLOBreach` (< 99% under 100 ms, 5m).
**Dashboard:** `TirBase — SLOs and error budgets` / Ledger append.
**Escalation:** on-call SRE → storage/database owner at 10 minutes. If the
ledger is in Restricted mode or writes fail, escalate to the security on-call
and incident commander immediately.

## Why this matters

Stage 16 commits the `Actuating` row with `synchronous=FULL` before any driver
dispatch (INV-12). Slow appends delay admissions and, if they fail, can move
the node into Restricted mode. Availability is not a substitute for this SLO:
a gateway that answers health checks but cannot append is unsafe.

## Triage

1. Confirm the metric is moving:
   ```promql
   histogram_quantile(0.99, sum by (le) (rate(tirbase_ledger_append_seconds_bucket[5m])))
   sum(rate(tirbase_ledger_append_seconds_count[5m]))
   ```
2. Check disk health and fsync latency on the `primary.db` volume:
   ```bash
   df -h /var/lib/tirbase
   iostat -x 1 5
   sqlite3 /var/lib/tirbase/primary.db 'PRAGMA quick_check; PRAGMA wal_checkpoint(PASSIVE);'
   ```
   Do not run `VACUUM` or destructive maintenance during an incident.
3. Inspect gateway logs for `SQLITE_IOERR`, `SQLITE_FULL`, `database is locked`,
   WAL checkpoint errors, or filesystem read-only errors. Any of these can
   require Restricted-mode handling; see `docs/runbooks/lockdown.md` and use
   `docs/runbooks/restore.md` for corruption.
4. Check for unbounded WAL growth and concurrent long-running readers. Move
   read-only exports off the primary host if they hold snapshots.
5. Confirm the p99 is not an artifact of a low-traffic window: compare
   `_count` with the baseline and inspect per-operation latency in traces.

## Stabilization

- Free disk space or replace the failing volume. Never delete the WAL or
  `primary.db` to "reset" latency.
- If flash-wear or storage budget throttling is active, follow the storage
  runbook; HIGH/CRITICAL audit events still bypass throttling.
- Scale down non-essential exports, backups and compaction jobs until p99
  returns below 100 ms.

## Escalation and rollback

- If appends fail or the node enters Restricted/LOCKDOWN, escalate to security
  on-call. Do not force writes or disable `synchronous=FULL`.
- Roll back the most recent binary/config change through the signed release
  process. If the ledger is corrupt, restore the last verified backup with
  `docs/runbooks/restore.md` and re-run reconciliation.
- Re-check `tirbase_effects_ledger_writes_total` and the canary after recovery.

## Verification

- `tirbase:slo_ledger_append:ratio_under_100ms_5m` ≥ 0.99 and p99 ≤ 100 ms for
  15 minutes.
- No new `Restricted`/`LOCKDOWN` mode transitions, and the audit chain verifies.
- A cold-chain canary append and a POS line append succeed.
