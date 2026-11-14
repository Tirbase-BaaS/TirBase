# TirBase synthetic canaries (F-10)

`vertical-canary.mjs` performs one real F-08 journey per vertical:

| Vertical | Journey |
|---|---|
| `cold-chain` | create site → append reading → list reading |
| `pos` | create order → append line → complete payment intent → read back |
| `venues` | create venue → create gate decision → list gates |

Every object uses a `canary-*` id/tenant and is deleted best-effort. The canary
never reads another tenant, logs a token, or writes request/response payloads.

## Run as a service (recommended)

The service exposes Prometheus metrics on `127.0.0.1:9101` and runs every 30
seconds. A failed journey leaves `tirbase_canary_last_success_timestamp_seconds`
at its previous value and sets `tirbase_canary_success{vertical="…"} 0`, so
`TirBaseCanaryStale` / `TirBaseCanaryFailing` fire within one minute.

```bash
sudo install -d -m 0755 /opt/tirbase
sudo cp -r ops /opt/tirbase/
sudo install -m 0644 ops/canary/tirbase-canary.service /etc/systemd/system/
sudo install -m 0600 ops/canary/tirbase-canary.env.example /etc/tirbase/canary.env
# Edit /etc/tirbase/canary.env (token file path, base URL).
sudo systemctl daemon-reload
sudo systemctl enable --now tirbase-canary
curl -fsS http://127.0.0.1:9101/metrics | grep tirbase_canary
```

The token must be a dedicated canary principal scoped to the three verticals.
Store it in a root-readable file (for example `/run/secrets/tirbase-canary-token`),
not in the environment, the repo, or a dashboard.

## One-shot / node_exporter textfile

```bash
node ops/canary/vertical-canary.mjs --vertical all \
  --base-url "$TIRBASE_CANARY_BASE_URL" \
  --token-file /run/secrets/tirbase-canary-token \
  --output /var/lib/node_exporter/textfile/tirbase-canary.prom
```

A failed journey exits 1. `--state-file` preserves the last-success timestamp
across one-shot runs; without it, the textfile only reflects this run.

## Contract test

```bash
node --test ops/canary/vertical-canary.test.mjs
```

This serves the route shapes in-process and asserts both a successful journey
and a failing journey's metric output. It does not replace a real canary against
a deployed gateway.

## Alert threshold

`TirBaseCanaryStale` uses a 45-second staleness threshold with a 15-second
evaluation interval, bounding detection at 60 seconds. `TirBaseCanaryFailing`
fires on the first failing scrape; `TirBaseCanaryMissing` catches a canary that
is not being scraped at all. See `docs/runbooks/canary-failure.md`.
