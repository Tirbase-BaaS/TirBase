# Vertical Demo Packs

TirBase includes vertical demo packs under `tirbase-demo/` demonstrating defended
adversary scenarios for representative edge domains (PV-16).

| Pack | Scenarios | Notes |
|---|---|---|
| `cold-chain` (flagship) | S1, S2, S3 | Temperature/compressor envelope with Modbus register map |
| `energy-edge` | S1, S2 | Inverter/battery envelope and drift/rate defense |
| `water-pumping` | S1, S3 | Modbus simulator/register map, replay defense |
| `logistics-node` | S10, S12 | CRDT BaaS: revoked-delta rejection and partition/rejoin convergence |
| `buildings-bms` | S1, S2 | BACnet simulator placeholder, HVAC envelope defense |
| `remote-ops-mesh` | S12 | Mesh partition+rejoin convergence |
| `defense-logistics` | S3 | M-of-N movement orders simulation, replay/idempotency defense |

Each pack provides `profiles/` (where applicable), `scenarios/`, `sim/config.toml`,
`run.sh`, and `docs/` including register/placeholder maps and a
"What TirBase does not protect against in this scenario" section.
