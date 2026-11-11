# Energy Edge Demo Pack

Demonstrates TirBase defending a simulated inverter/battery edge controller
(device class `energy_edge`) against guard-relevant adversary behaviour (CLAIM-48.1, PV-16.2).

Pack source: `tirbase-demo/energy-edge/`.

## Contents

- `profiles/energy_edge.toml` — inverter/battery `EnvelopeProfile` (power, SOC target).
- `docs/modbus-register-map.md` — Modbus register map.
- `scenarios/S1.toml`, `S2.toml` — adversary scenarios wired into this pack.
- `sim/config.toml` — deterministic simulator configuration.
- `run.sh` — entry point producing observable defended output.

## Defended scenarios

| ID | Attack | Expected TirBase response |
|---|---|---|
| S1 | Out-of-envelope command (power/SOC outside allowed range) | Rejected by envelope bounds; no actuation |
| S2 | Slow ramp / cumulative drift of setpoints | Rejected by rate-of-change / drift window |

## Running

From `tirbase-demo/energy-edge/`:

```sh
./run.sh
```

## What TirBase does not protect against in this scenario

- **Physical compromise of inverter, BMS, or sensors.** Tampered hardware can report false SOC/power or ignore commands.
- **A root-compromised gateway host/OS.** Kernel/root attackers can bypass userspace guard enforcement.
- **Direct actuation paths bypassing the guard.** Local or legacy control paths not mediated by `CommandGuard::admit()` are out of scope.
- **Grid-safety and electrical protection functions.** TirBase is not a protection relay, safety PLC, or anti-islanding device.
- **Availability under sustained DoS.** Rate limits bound abuse but cannot guarantee delivery during attack.
- **Correctness of the installed profile.** A legitimately signed but misconfigured envelope is enforced as specified.
- **Attacks outside S1–S2.** Other adversary classes are covered by their respective packs/scenarios.
