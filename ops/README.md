# TirBase observability operations (F-10)

Everything in `ops/` is Apache-2.0 (see the repository's `LICENSE-APACHE`).
The runtime binaries remain AGPL-3.0-only; the dashboards are a separate,
permissively licensed artifact.

| Path | Purpose |
|---|---|
| `prometheus/prometheus.yml` | 15s scrape/evaluation; gateway + canary jobs |
| `prometheus/rules/tirbase-slo.yml` | SLO recording rules and alerts |
| `alertmanager/alertmanager.yml` | critical → pager, warning → chat, inhibition |
| `grafana/dashboards/` | SLO and vertical/adapters dashboards (Apache-2.0) |
| `grafana/provisioning/` | datasource and dashboard provider |
| `canary/` | synthetic journey per vertical, service unit and contract test |

## Deploy

1. Copy `ops/prometheus` and `ops/alertmanager` to the monitoring host and
   replace the example Alertmanager webhook URLs with your rotation's
   endpoints. Keep receiver secrets in the secret store.
2. Copy the Grafana dashboards to `/var/lib/grafana/dashboards` and provision
   the datasource/dashboard provider.
3. Install `ops/canary/tirbase-canary.service` and its environment file; the
   canary exposes `/metrics` on loopback.
4. Run `node scripts/check-observability.mjs` and
   `node --test ops/canary/vertical-canary.test.mjs` in CI.
5. Where available, run `promtool check rules ops/prometheus/rules/*.yml` and
   `amtool check-config ops/alertmanager/alertmanager.yml` before rollout.

See [`docs/observability.md`](../docs/observability.md) for the SLO table,
metric/log/trace contract, redaction rules and canary guarantees.
