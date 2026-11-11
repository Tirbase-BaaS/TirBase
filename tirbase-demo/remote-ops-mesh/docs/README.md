# Remote-Ops Mesh Demo Pack

Demonstrates TirBase mesh **partition and rejoin** convergence for remote
operations (CLAIM-48.5, PV-16.2).

## Contents

- `docs/modbus-register-map.md` — documents that no fieldbus applies (mesh-focused).
- `scenarios/S12.toml` — adversary scenario wired into this pack.
- `sim/config.toml` — two-node mesh simulator with partition/heal faults.
- `run.sh` — entry point producing observable defended output.

## Defended scenarios

| ID | Attack / condition | Expected TirBase response |
|---|---|---|
| S12 | Network partition and rejoin | Independent writes converge to identical state after heal |

## Running

```sh
./run.sh
```

## What TirBase does not protect against in this scenario

- **Permanent network partitions with no eventual heal.** Convergence requires eventual communication.
- **Compromise of node keys or host OS.** A compromised node can emit malicious but signed data until revoked.
- **Byzantine semantic correctness.** CRDTs guarantee convergence, not truth of application data.
- **Message confidentiality beyond configured transport security.** This demo focuses on convergence under partition.
- **Availability under sustained DoS or radio jamming.** Delivery and rejoin may be delayed or prevented.
- **Data loss if all replicas are destroyed.** Durability depends on surviving replicas/backups.
- **Attacks outside S12.** Other adversary classes are covered by their respective scenarios/packs.
