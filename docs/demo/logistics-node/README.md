# Logistics Node Demo Pack (CRDT BaaS)

Demonstrates TirBase as an offline-first CRDT BaaS for a logistics node:
revoked-author rejection and partition/rejoin convergence (CLAIM-48.3, PV-16.2).

Pack source: `tirbase-demo/logistics-node/`.

## Contents

- `profiles/` — (no actuator profile; CRDT-focused pack)
- `docs/modbus-register-map.md` — documents that no fieldbus applies.
- `scenarios/S10.toml`, `S12.toml` — adversary scenarios wired into this pack.
- `sim/config.toml` — two-node mesh simulator configuration.
- `run.sh` — entry point producing observable defended output.

## Defended scenarios

| ID | Attack | Expected TirBase response |
|---|---|---|
| S10 | Revoked delta propagation | Delta from revoked DID rejected; document state unchanged |
| S12 | Network partition and rejoin | Nodes converge to identical state after heal |

## Running

From `tirbase-demo/logistics-node/`:

```sh
./run.sh
```

## What TirBase does not protect against in this scenario

- **Compromise of the signing keys before revocation.** Deltas signed prior to revocation may already be applied per CRDT rules.
- **A root-compromised gateway host/OS.** Local enforcement and key material can be subverted.
- **Byzantine data correctness.** CRDT convergence ensures consistency, not semantic truth of submitted data.
- **Permanent partition or data loss on all replicas.** Convergence requires eventual communication and surviving replicas.
- **Availability under sustained DoS.** Mesh flooding can delay synchronization.
- **Application-level authorization logic.** This pack demonstrates revocation/convergence primitives, not business workflow policy.
- **Attacks outside S10,S12.** Other adversary classes are covered by their respective scenarios/packs.
