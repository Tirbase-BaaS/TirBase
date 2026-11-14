# Runbook: Venue gate decision latency SLO

**SLO:** 99% of venue gate decisions complete within 250 ms and 99.5% succeed
over 30 days.
**Severity:** warning on latency; critical on breach.
**Alerts:** `TirBaseGateDecisionLatencyHigh` (p99 > 250 ms, 5m),
`TirBaseGateDecisionSLOBreach` (p99 > 500 ms or success < 99.5%, 5m).
**Dashboard:** `TirBase — SLOs and error budgets` / Venue gate decision.
**Escalation:** on-call SRE → venue/POS integration owner at 10 minutes.
If a gate cannot make a decision at an event, notify the venue operations lead
and switch to the manual access procedure immediately.

## Triage

1. Confirm the latency and success series:
   ```promql
   histogram_quantile(0.99, sum by (le) (rate(tirbase_gate_decision_seconds_bucket[5m])))
   sum(rate(tirbase_gate_decisions_total{outcome="accepted"}[5m]))
   /
   sum(rate(tirbase_gate_decisions_total[5m]))
   ```
2. Check the venue API request latency and error rate, then SQLite health:
   ```promql
   histogram_quantile(0.95, sum by (vertical, le) (rate(tirbase_vertical_request_seconds_bucket{vertical="venues"}[5m])))
   ```
   See `slo-ledger-append.md` for disk/lock checks; gate writes share the
   primary database.
3. Inspect gateway logs for `vertical`/`venues` errors and 5xx responses. Never
   log the gate payload or attendee data; use the trace id for correlation.
4. Check whether a large venue or burst of gate events is saturating a single
   gateway. Validate tenant scoping before assuming a code regression.
5. Confirm the canary venue journey is failing or slow; it exercises venue +
   gate create/read.

## Stabilization

- Shed non-essential reads/exports and reduce concurrent gate writes if the
  database is saturated.
- If one tenant is causing the burst, apply the tenant rate limit or isolate
  that tenant; do not disable authorization or audit logging.
- Use the venue's manual access fallback while decisions are unavailable, and
  reconcile access records afterwards.

## Escalation and rollback

- Roll back the most recent venue/API release via the signed release process.
- If gate objects are corrupt, restore from a verified backup per
  `docs/runbooks/restore.md`; do not delete gate rows manually.
- Escalate to the venue operations lead if manual access is required for more
  than 10 minutes.

## Verification

- p99 ≤ 250 ms and success ≥ 99.5% for 15 minutes.
- The venue canary succeeds and the manual fallback is stood down.
- No unexplained 5xx or authorization failures remain.
