# Configuration Reference

## Gateway configuration (`GatewayConfig` TOML)

`tirbase-gateway` validates configuration at startup (and supports signed config
bundles where applicable). Key configuration areas include:

| Area | Examples |
|---|---|
| Identity/keys | `key_path`, `KeyProvider` selection (file / feature-gated backends) |
| Storage | `counter_db_path` (`primary.db`), `derived_db_path`, WAL/checkpoint settings |
| Admin | `admin_socket` (`/run/tirbase/admin.sock`), optional remote mTLS admin settings |
| Health/metrics | `health_addr` (default local), `metrics_addr` (default `127.0.0.1:9090`) |
| Policy/profile | installed signed `EnvelopeProfile` / policy bundle paths and trust roots |
| Time/freshness | time ratchet, beacon/anchor settings, challenge/freshness parameters |
| Cloud | outbound-only `cloud_endpoint` TLS settings (no inbound cloud listener) |
| Drivers/targets | device transport targets, profile-to-target mapping, watchdog/limits |

The gateway denies commands until a valid signed `EnvelopeProfile` is installed and
opens only explicitly configured listeners/sockets.

## Envelope profiles and demo packs

Per-device envelopes live in profile TOML documents (e.g. `profiles/*.toml`) with
parameters, ranges/rates/dwell/interlocks, cross-constraints, and governance fields.
Demo pack examples: `tirbase-demo/*/profiles/*.toml`.

## Systemd and deployment

See `tirbase-gateway.service`, `deploy/`, and `docs/src/deployment-hardening/overview.md`
for hardened service and packaging configuration.
