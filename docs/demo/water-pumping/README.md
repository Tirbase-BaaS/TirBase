# Water/Pumping Station Demo Pack

Demonstrates TirBase defending a simulated pumping station controller
(device class `water_pumping`) with a Modbus simulator (CLAIM-48.2, PV-16.2).

Pack source: `tirbase-demo/water-pumping/`.

## Contents

- `profiles/water_pumping.toml` — pump speed/pressure `EnvelopeProfile`.
- `docs/modbus-register-map.md` — Modbus register map (simulator-backed).
- `scenarios/S1.toml`, `S3.toml` — adversary scenarios wired into this pack.
- `sim/config.toml` — deterministic Modbus simulator configuration.
- `run.sh` — entry point producing observable defended output.

## Defended scenarios

| ID | Attack | Expected TirBase response |
|---|---|---|
| S1 | Out-of-envelope command (speed/pressure outside range) | Rejected by envelope bounds; no actuation |
| S3 | Replay of a previously accepted command | Deduplicated (anti-replay/idempotency); no second actuation |

## Running

From `tirbase-demo/water-pumping/`:

```sh
./run.sh
```

## What TirBase does not protect against in this scenario

- **Physical compromise of pumps, valves, or sensors.** False readings or forced mechanical states are out of scope.
- **A root-compromised gateway host/OS.** Userspace enforcement can be bypassed by a privileged attacker.
- **Direct actuation bypassing the guard.** Unmediated local control paths are out of scope.
- **Hydraulic safety and process protection.** TirBase does not replace pressure relief, dry-run protection, or safety interlocks.
- **Availability under sustained DoS.** Legitimate commands may be delayed during attack.
- **Correctness of the installed profile.** Misconfigured but signed envelopes are enforced as specified.
- **Attacks outside S1,S3.** Other adversary classes are covered elsewhere.
