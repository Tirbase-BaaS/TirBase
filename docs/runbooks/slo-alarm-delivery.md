# Runbook: Alarm delivery SLO

**SLO:** 99% of alarm/webhook deliveries succeed within 60 seconds over 30 days.
**Severity:** critical on failure-budget burn; warning on latency.
**Alerts:** `TirBaseAlarmDeliveryLatencyHigh` (p95 > 60 s, 10m),
`TirBaseAlarmDeliveryFailureBudgetBurn` (success < 99%, 10m).
**Dashboard:** `TirBase — SLOs and error budgets` / Alarm delivery.
**Escalation:** on-call SRE → integration/notification owner at 10 minutes.
If alarms for safety-critical cold-chain excursions are affected, notify the
operations lead and treat as SEV-1.

## Triage

1. Check whether the drain is running. Delivery is performed by
   `tirbase-admin webhook drain` on an operator timer; a stopped timer produces
   pending rows, not transport errors:
   ```bash
   systemctl list-timers --all | grep -i tirbase
   tirbase-admin webhook --db-path /var/lib/tirbase/primary.db list
   tirbase-admin webhook --db-path /var/lib/tirbase/primary.db drain
   ```
2. Inspect pending/dead deliveries and last errors. Delivery payloads are
   customer data: do not paste them into tickets or chat.
   ```sql
   SELECT status, COUNT(*) FROM webhook_deliveries GROUP BY status;
   SELECT endpoint_id, COUNT(*) FROM webhook_deliveries WHERE status='dead' GROUP BY endpoint_id;
   ```
3. Check endpoint reachability, TLS certificate validity, DNS and receiver
   status codes. The requester is the gateway; egress allowlists and proxy
   settings are common causes.
4. Correlate `tirbase_alarm_deliveries_total{outcome="failed"}` with the
   endpoint id in logs. Check retry backoff; dead deliveries require operator
   action after the endpoint is fixed.
5. If p95 is high but success is 100%, inspect receiver latency and the drain
   interval before changing retry policy.

## Stabilization

- Restart the drain timer and process the backlog in bounded batches. Do not
  raise `MAX_WEBHOOK_ATTEMPTS` during an incident.
- Disable a failing endpoint (`webhook disable`) to protect other endpoints,
  then re-enable after the receiver is healthy.
- For safety-critical alarms, use the operator console/out-of-band escalation
  while webhook delivery is degraded.

## Escalation and rollback

- If credentials or endpoint URLs changed, roll back to the previous signed
  endpoint configuration; never put secrets in logs or tickets.
- If a bad gateway release caused the regression, roll back using the signed
  release process. Keep already-persisted deliveries; they will drain after
  rollback.
- Escalate to the receiver owner if their endpoint returns 5xx for more than
  10 minutes.

## Verification

- `tirbase:slo_alarm_delivery:success_ratio_5m` ≥ 0.99 and p95 ≤ 60 s.
- `webhook_deliveries` has no growing pending backlog and dead count is stable.
- A venue/cold-chain canary event reaches the test receiver.
