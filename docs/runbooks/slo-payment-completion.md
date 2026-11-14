# Runbook: POS payment intent completion SLO

**SLO:** 99% of POS payment intents reach a terminal successful state within
5 minutes over 30 days.
**Severity:** critical on failure-budget burn; warning on latency.
**Alerts:** `TirBasePaymentIntentCompletionLatencyHigh` (p95 > 300 s, 10m),
`TirBasePaymentIntentFailureBudgetBurn` (success < 99%, 10m).
**Dashboard:** `TirBase — SLOs and error budgets` / Payment intent completion.
**Escalation:** on-call SRE → payments/POS owner at 10 minutes. Financial
reconciliation or duplicate-charge risk is SEV-1; involve finance immediately.

## Triage

1. Confirm completion latency and terminal outcomes:
   ```promql
   histogram_quantile(0.95, sum by (le) (rate(tirbase_payment_intent_completion_seconds_bucket[5m])))
   sum(rate(tirbase_payment_intents_total{outcome="completed"}[5m]))
   /
   sum(rate(tirbase_payment_intents_total{outcome=~"completed|failed"}[5m]))
   ```
2. Inspect POS orders stuck in a non-terminal `payment_status`. Use the admin
   API with tenant scoping; do not export full order payloads.
3. Check the downstream payment provider status page, API latency and error
   codes. Distinguish provider outage, credential expiry and gateway-local
   timeouts.
4. Verify idempotency: retries must reuse the order/idempotency key. Never
   create a second charge to "fix" a stuck intent.
5. If p95 is high but success is 100%, check whether the provider is slow or
   the order transition is waiting on an operator action.

## Stabilization

- Retry completion with the original idempotency key after the provider
  recovers.
- If a provider credential expired, rotate it through the secret store and
  restart the integration; never put keys in a ticket or log.
- Pause new POS captures only with the payments owner's authorization; keep
  existing intents recoverable and auditable.

## Escalation and rollback

- Roll back the most recent POS/payment integration release via the signed
  release process.
- Reconcile all affected orders against the provider's ledger before resuming.
  A duplicate-charge risk requires finance and incident-commander involvement.
- If local data is corrupt, restore from a verified backup per
  `docs/runbooks/restore.md`; do not edit payment rows directly.

## Verification

- Success ratio ≥ 99% and p95 ≤ 300 s for 15 minutes.
- The POS canary completes its order/line/payment journey.
- Reconciliation shows no duplicate or lost charges.
