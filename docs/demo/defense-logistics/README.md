# Defense-Logistics Demo Pack

Demonstrates a **M-of-N movement orders simulation** with replay defense in a
defense-logistics context (CLAIM-48.6, PV-16.2).

Pack source: `tirbase-demo/defense-logistics/`.

## Contents

- `docs/modbus-register-map.md` — documents that no fieldbus applies.
- `scenarios/S3.toml` — replay scenario wired into this pack.
- `sim/config.toml` — deterministic simulator configuration.
- `run.sh` — entry point producing observable defended output.

## Defended scenarios

| ID | Attack | Expected TirBase response |
|---|---|---|
| S3 | Replay of a previously accepted movement order | Deduplicated (anti-replay/idempotency); no second actuation/effect |

## Running

From `tirbase-demo/defense-logistics/`:

```sh
./run.sh
```

## What TirBase does not protect against in this scenario

- **Compromise of the required M-of-N authorizing keys.** If an adversary holds sufficient legitimate keys, authorized orders can be issued.
- **A root-compromised gateway host/OS.** Local enforcement and key handling can be subverted.
- **Physical compromise or coercion of authorized operators.** Human/process controls are out of scope.
- **Mission correctness of an authorized order.** TirBase enforces replay/idempotency and policy, not tactical validity.
- **Availability under sustained DoS or contested comms.** Order delivery may be delayed.
- **Side-channel or out-of-band command paths.** Only guard-mediated commands are protected.
- **Attacks outside S3.** Other adversary classes are covered by their respective scenarios/packs.
