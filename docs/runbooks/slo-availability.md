# Runbook: Gateway availability SLO

**SLO:** 99.9% of gateway scrapes are `up` over 30 days (43m 12s error budget).
**Severity:** critical for fast burn; warning for slow burn.
**Alerts:** `TirBaseAvailabilityFastBurn` (critical, 2m), `TirBaseAvailabilitySlowBurn` (warning, 15m).
**Dashboard:** `TirBase — SLOs and error budgets` / Availability.
**Escalation:** on-call SRE → platform lead at 15 minutes → incident commander if customer traffic is affected.

## Symptoms

- `up{job="tirbase-gateway"}` is 0, or availability burn-rate alerts fire.
- `/health` is unreachable or does not return 200 within 500 ms.
- Restart count, watchdog or crash-loop alerts may be firing at the same time.

## Triage (first 10 minutes)

1. Confirm the target and scrape path:
   ```bash
   curl -fsS http://127.0.0.1:8080/health
   curl -fsS http://127.0.0.1:9090/metrics | head
   systemctl status tirbase-gateway
   journalctl -u tirbase-gateway --since '-15 min' --no-pager
   ```
2. If `/health` fails, treat as a process outage: check exit status, OOM,
   disk full, watchdog timeout, config validation failure and certificate
   expiry. Do **not** bypass LOCKDOWN to restore liveness.
3. If `/health` succeeds but Prometheus marks the target down, inspect the
   Prometheus target error (network policy, loopback proxy, TLS, DNS) and the
   scrape timeout. The gateway intentionally binds metrics to loopback.
4. Check `tirbase_build_info` to confirm the running version matches the
   expected release.
5. If availability is dropping only in one AZ/host, correlate node saturation,
   disk latency and supervisor restarts before changing the application.

## Escalation

- One failed scrape is not an incident. A 2-minute fast burn is SEV-2; a
  customer-visible outage or confirmed data-safety risk is SEV-1.
- Page the platform lead if the gateway cannot boot twice in a row or enters
  LOCKDOWN/Restricted unexpectedly. Use `docs/runbooks/lockdown.md` for mode
  changes; availability recovery never bypasses the guard.

## Rollback

1. Revert the most recent configuration, profile or binary change through the
   signed release process; do not edit databases or clear lockdown markers.
2. If the previous release is known-good, follow the deployment rollback
   procedure and confirm `/health`, `/metrics`, and a canary journey.
3. If the host itself is unhealthy, move traffic to a healthy replica or
   restore from the last verified backup using `docs/runbooks/restore.md`.
4. Record the incident start/end, affected tenants, and the burn observed in
   the 5m/1h/6h windows.

## Verification

- `/health` returns 200 within 500 ms for five consecutive minutes.
- `up{job="tirbase-gateway"}` is 1 and `tirbase:slo_availability:ratio_5m`
  recovers above 0.999.
- All three canary journeys succeed.
