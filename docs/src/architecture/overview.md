# Architecture Overview

TirBase is organized as an 8-crate Rust workspace:

| Crate | Responsibility |
|---|---|
| `tirbase-types` | Shared `no_std`-capable types, IDs, units, `FixedPointValue`, roles |
| `tirbase-core` | CRDT engine, schema, auth/identity, migration, store, transport, traits |
| `tirbase-guard` | Command Guard, envelope/policy enforcement, effects ledger, anti-replay, time ratchet |
| `tirbase-drivers` | `DriverTrait`, device models, protocol drivers (Modbus/MQTT/sim) |
| `tirbase-gateway` | Hardened edge binary, config, admin API, metrics/health, cloud ingress |
| `tirbase-admin` | Operator CLI (enroll, mint, rotate, inspect, rollout, etc.) |
| `tirbase-sim` | Seeded deterministic simulator, fault injection, adversary scenarios, invariants |
| `tirbase-demo` | Vertical demo packs and scenario wiring |

## Guarded command path

All command ingress (mesh, cloud, local admin) converges on
`CommandGuard::admit` before any actuation. Accepted commands yield an
`ActuationPermit` that is only constructible inside `tirbase-guard` and
dispatched to sandboxed driver processes over guard-owned channels.

## Evidence and traceability

- Security/behavior claims: [`CLAIMS.md`](../../CLAIMS.md)
- Adversary scenarios: [`docs/adversary-scenarios.md`](../../adversary-scenarios.md)
- System invariants: [`docs/system-invariants.md`](../../system-invariants.md)
- Threat model: [`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md)
