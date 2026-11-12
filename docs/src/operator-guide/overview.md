# Operator Guide

This guide summarizes operational use of TirBase for gateway operators.

## Core tools

- **`tirbase-gateway`**: edge binary (config, guard, drivers, admin socket, health/metrics).
- **`tirbase-admin`**: operator CLI for enrollment, token minting, rotation, policy operations,
 event inspection/export, and rollout/status operations exposed by the gateway.

## Daily operations

1. **Verify health**: `GET /health` on the configured local health endpoint (default 127.0.0.1).
2. **Inspect metrics**: Prometheus endpoint (default `127.0.0.1:9090/metrics`).
3. **Review security events**: use `tirbase-admin` event inspection/export against the admin socket.
4. **Policy changes**: tightening applies quickly after verification; loosening requires M-of-N
 co-signatures and time-lock/cancel windows per the active policy/trust root.

## Administrative API

The gateway admin API is served over `/run/tirbase/admin.sock` with kernel peer-credential
authentication (and optional remote mTLS endpoint when configured). The machine-readable
definition is [`docs/api/gateway-admin-openapi.yaml`](../../api/gateway-admin-openapi.yaml).

Key operations include: enroll, mint, rotate, policy push, events, simulate, challenge,
mode/status, lockdown-exit, chain-recovery, sequence-reset, lease-preempt, quarantine-replay,
time-reset, unknown-clear, restore, epoch-bump, and rollout-status.

## Incident posture

- **Lockdown**: commands/actuation are restricted; exit requires M-of-N co-signatures from
 distinct roles and a valid envelope/profile state.
- **Restricted**: entered on tamper/corruption indicators; mesh sync/log export remain available
 for diagnosis; recovery requires signed chain-recovery flow.
- **Unknown effects**: targets with `Unknown` ledger entries are blocked until reconciled/cleared
 per operator procedure.

Refer to `docs/runbooks/` and security event documentation for detailed procedures.
