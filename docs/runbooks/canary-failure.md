# Runbook: Synthetic canary failure

**SLO:** one synthetic journey per vertical (cold chain, POS, venues) succeeds
every 30 seconds; a failure is visible within one minute.
**Severity:** critical (canary failures are early indicators of vertical
regressions).
**Alerts:** `TirBaseCanaryStale`, `TirBaseCanaryFailing`,
`TirBaseCanaryMissing`.
**Dashboard:** `TirBase — SLOs and error budgets` / Synthetic canaries,
`TirBase — Verticals and adapters`.
**Escalation:** on-call SRE → vertical owner at 5 minutes. A canary failure with
a customer-visible symptom is SEV-1.

## Detection guarantee

`TirBaseCanaryStale` uses
`time() - tirbase_canary_last_success_timestamp_seconds{vertical} > 45`,
evaluated every 15 seconds with `for: 0m`, so a failure is visible within 60
seconds. `TirBaseCanaryFailing` fires on the first failing scrape;
`TirBaseCanaryMissing` covers a missing target with a 1-minute delay.

## Triage

1. Determine whether the canary itself or the gateway is failing:
   ```bash
   curl -fsS http://127.0.0.1:9101/metrics | grep tirbase_canary
   journalctl -u tirbase-canary --since '-10 min' --no-pager
   ```
2. Run the journey manually against the same base URL and token:
   ```bash
   node ops/canary/vertical-canary.mjs \
     --base-url "$TIRBASE_CANARY_BASE_URL" \
     --token-file /run/secrets/tirbase-canary-token \
     --vertical cold-chain
   ```
   Repeat for `pos` and `venues`. A single vertical failing usually indicates a
   route or data-model regression; all three failing points at gateway
   availability/auth/ingress.
3. Check `/health`, `up`, and the vertical request metrics. If all verticals
   fail, follow `slo-availability.md` first.
4. Check the token: an expired or revoked canary credential produces 401s on
   every vertical. Rotate through the secret store, never paste the token.
5. Inspect the exact HTTP status from the canary log. 404 means route drift;
   409 means leftover canary objects (clean up `canary-*`); 5xx means the
   vertical store or database is failing.
6. Do not use the canary's failure to bypass authorization or audit logging.

## Stabilization

- Clean up stale `canary-*` objects only after confirming they belong to the
  canary tenant.
- If the canary target is down, restore the canary process and confirm
  `tirbase_canary_last_success_timestamp_seconds` advances.
- If one vertical is broken, disable that vertical's customer writes only with
  the vertical owner's authorization, and use the documented manual fallback.

## Rollback

- Roll back the most recent gateway/vertical release or configuration through
  the signed release process.
- Restore the canary token/endpoint from the secret store if credentials or
  routing changed.
- Re-run all three journeys and confirm the alert resolves.

## Verification

- All three `tirbase_canary_success` series are 1 and last-success age is < 45 s.
- `TirBaseCanaryStale`, `TirBaseCanaryFailing` and `TirBaseCanaryMissing` are
  resolved.
- The vertical owner confirms the customer journey manually if the failure was
  customer-visible.
