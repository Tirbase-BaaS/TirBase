# Observability, SLOs, alerting, and on-call (F-10)

> **Licence:** the runtime (`tirbase-gateway`, `tirbase-guard`,
> `tirbase-drivers`) is AGPL-3.0-only. The Prometheus rules, Alertmanager
> routing and Grafana dashboards under `ops/` are Apache-2.0. Dashboard JSON
> carries `_license` and an `apache-2.0` tag.
>
> **Status:** implemented. Metrics/log/trace instrumentation is in
> `tirbase-gateway/src/{metrics,telemetry,vertical_api,webhooks}.rs`,
> `tirbase-gateway/src/guard.rs`, and the driver/adapters in
> `tirbase-drivers`. Rules, dashboards and routing are in `ops/`.

## 1. The four signals

| Signal | Where | Notes |
|---|---|---|
| Metrics | `GET /metrics` on `127.0.0.1:9090` | Prometheus text format. Existing CLAIM-35.5 counters are unchanged. |
| Structured logs | JSON on stdout / journald | Every line is passed through the redacting writer in `telemetry.rs` before output. |
| Traces | JSONL at `TIRBASE_TRACE_EXPORT_PATH` | W3C `traceparent` compatible; spans cover vertical API, admin mTLS, guard/ledger and webhook delivery. |
| Audit events | Hash-chained `security_events` log | Existing `SecurityEventSink`/`SecurityEventLog`; operational audit lines carry `audit=true`. |

Drivers and adapters log structured `adapter.modbus.*` / `adapter.mqtt.*`
spans and expose driver/adapter operation counters through the gateway. The
gateway never logs a command body, card number, key material, or precise
location.

## 2. SLOs, alerts, and runbooks

Every SLO has a recording rule, at least one alert, a dashboard panel, and a
runbook. `scripts/check-observability.mjs` enforces the mapping in CI.

| SLO | Target | Primary alerts | Runbook |
|---|---|---|---|
| Gateway availability | 99.9% of scrapes up / 30d | `TirBaseAvailabilityFastBurn`, `TirBaseAvailabilitySlowBurn` | [slo-availability](runbooks/slo-availability.md) |
| Effects-ledger append latency | 99% ≤ 100 ms / 30d | `TirBaseLedgerAppendLatencyHigh`, `TirBaseLedgerAppendSLOBreach` | [slo-ledger-append](runbooks/slo-ledger-append.md) |
| Alarm delivery | 99% ≤ 60 s / 30d | `TirBaseAlarmDeliveryLatencyHigh`, `TirBaseAlarmDeliveryFailureBudgetBurn` | [slo-alarm-delivery](runbooks/slo-alarm-delivery.md) |
| Venue gate decision latency | 99% ≤ 250 ms and 99.5% success / 30d | `TirBaseGateDecisionLatencyHigh`, `TirBaseGateDecisionSLOBreach` | [slo-gate-latency](runbooks/slo-gate-latency.md) |
| POS payment intent completion | 99% ≤ 5 min / 30d | `TirBasePaymentIntentCompletionLatencyHigh`, `TirBasePaymentIntentFailureBudgetBurn` | [slo-payment-completion](runbooks/slo-payment-completion.md) |
| Synthetic canary per vertical | Success every 30 s; stale visible ≤ 60 s | `TirBaseCanaryFailing`, `TirBaseCanaryStale`, `TirBaseCanaryMissing` | [canary-failure](runbooks/canary-failure.md) |

### Metric contract

| Metric | Type | Labels | Used by |
|---|---|---|---|
| `tirbase_guard_decision_seconds` | histogram | none | guard latency, dashboards |
| `tirbase_ledger_append_seconds` | histogram | none | ledger SLO |
| `tirbase_alarm_delivery_seconds` | histogram | none | alarm SLO |
| `tirbase_gate_decision_seconds` | histogram | none | gate SLO |
| `tirbase_payment_intent_completion_seconds` | histogram | none | payment SLO |
| `tirbase_vertical_request_seconds` | histogram | `vertical` | per-vertical latency |
| `tirbase_alarm_deliveries_total` | counter | `vertical`, `outcome` | alarm success ratio |
| `tirbase_payment_intents_total` | counter | `vertical`, `outcome` | payment success ratio |
| `tirbase_gate_decisions_total` | counter | `vertical`, `outcome` | gate success ratio |
| `tirbase_vertical_appends_total` | counter | `vertical` | ledger appends |
| `tirbase_driver_operations_total` | counter | `driver`, `operation`, `outcome` | driver health |
| `tirbase_adapter_operations_total` | counter | `adapter`, `operation`, `outcome` | adapter health |
| `tirbase_gateway_requests_total` | counter | `surface`, `method`, `status` | admin traffic |
| `tirbase_build_info` | gauge | `version`, `licence` | version/rollout |

Labels are bounded enums. Never add tenant, object id, DID, email, PAN,
latitude/longitude, URL, or free-form error text as a label.

## 3. Redaction rules

The redacting tracing writer is installed in `main.rs`; it is not optional.
Before any log byte reaches stdout (journald captures it):

- **Secrets:** PEM private-key blocks, 64+ hex secrets, `Bearer`/`Basic`
  tokens, `token=` values and JWT-shaped strings are replaced with
  `[REDACTED]`.
- **Card data:** 13–19 digit PANs with spaces/hyphens are Luhn-checked and
  redacted. `pan`, `card_number`, `cvv`, `cvc` JSON keys are always redacted
  even when a value is not Luhn-valid.
- **Personal data:** email addresses, E.164 phone numbers, `ssn`,
  `date_of_birth`/`dob` keys are redacted.
- **Location data:** `latitude`, `longitude`, `lat`, `lon`, `lng`, `gps`,
  `precise_location` and `address` keys are redacted.
- **Unnecessary data:** request/response bodies are never logged by the
  vertical API; operational audit lines contain only method, vertical, kind,
  and outcome.

`tirbase-gateway/src/telemetry.rs` tests cover a full JSON log line containing a
PAN and email, PEM blocks, bearer/JWT tokens, phone numbers, and nested JSON.
If you add a new log site, do not log the payload; the writer is a last line of
defence, not permission to log sensitive values.

## 4. Traces

Set `TIRBASE_TRACE_EXPORT_PATH=/var/log/tirbase/traces.jsonl`. Completed spans
are appended as one JSON object per line:

```json
{"timestamp_unix_ms":1770000000000,"trace_id":"...","span_id":"...","parent_span_id":"...","name":"vertical_api.dispatch","duration_ms":3.2,"status":"ok","attributes":{"vertical":"cold-chain"},"resource":{"service.name":"tirbase-gateway","service.version":"0.1.0"}}
```

Remote admin accepts an incoming `traceparent` header and preserves its trace
id. The vertical API exposes `dispatch_with_trace` for HTTP surfaces that parse
headers. Traces are not required for alerting; metrics and the hash-chained
audit log remain authoritative.

## 5. Dashboards and routing

- `ops/prometheus/prometheus.yml` — 15s scrape/evaluation, gateway and canary
  jobs.
- `ops/prometheus/rules/tirbase-slo.yml` — recording rules + alerts.
- `ops/alertmanager/alertmanager.yml` — critical → pager, warning → chat,
  inhibit duplicate warnings, 30m repeat for critical.
- `ops/grafana/dashboards/tirbase-slo.json` — availability, ledger, alarm,
  gate, payment and canary.
- `ops/grafana/dashboards/tirbase-verticals.json` — per-vertical traffic,
  appends, adapters and canary.
- `ops/grafana/provisioning/` — datasource and dashboard provider.

Replace the example Alertmanager webhook URLs with your rotation's endpoints
(or expand `*_WEBHOOK_URL` environment variables); never commit credentials.

## 6. Synthetic canaries

`ops/canary/vertical-canary.mjs` runs one real F-08 journey per vertical:

- **cold chain** — create site → append reading → list reading → clean up;
- **POS** — create order → append line → complete payment intent → read back;
- **venues** — create venue → create gate decision → list gates → clean up.

Deploy it as a Deployment (or systemd unit) next to Prometheus:

```bash
node ops/canary/vertical-canary.mjs --serve --port 9101 \
  --base-url "$TIRBASE_CANARY_BASE_URL" \
  --token-file /run/secrets/tirbase-canary-token
```

It exposes `/metrics` and runs every 30 seconds. One-shot mode writes a
node_exporter textfile and exits non-zero on failure:

```bash
node ops/canary/vertical-canary.mjs --vertical all \
  --base-url "$TIRBASE_CANARY_BASE_URL" \
  --token-file /run/secrets/tirbase-canary-token \
  --output /var/lib/node_exporter/textfile/tirbase-canary.prom
```

Use a dedicated canary principal scoped to the three verticals and their
canary tenants. The token is read from a file or environment; it is never
printed. The journeys use `canary-*` ids and clean up best-effort.

### One-minute visibility

`TirBaseCanaryStale` fires at 45 seconds of staleness, evaluated every 15
seconds, so detection is bounded at 60 seconds. `TirBaseCanaryFailing` fires on
the first failing scrape. `TirBaseCanaryMissing` catches a canary target that
was never scraped after one minute.

## 7. Verification

```bash
cargo test -p tirbase-gateway telemetry::tests
cargo test -p tirbase-gateway metrics::tests
node --test ops/canary/vertical-canary.test.mjs
node scripts/check-observability.mjs
```

The CI job `observability` runs the canary contract test and the SLO/runbook
mapping check. A real Prometheus `promtool check rules` is recommended where
the binary is available; the repository check validates YAML/JSON structure,
SLO coverage, runbook links and the one-minute canary rule without requiring a
Prometheus install.
