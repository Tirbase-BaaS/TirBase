# Buildings/BMS Demo Pack

Demonstrates TirBase defending a simulated BMS/HVAC controller (device class
`buildings_bms`) using a **BACnet simulator placeholder** (CLAIM-48.4, PV-16.2).

Pack source: `tirbase-demo/buildings-bms/`.

## Contents

- `profiles/buildings_bms.toml` — zone temperature and AHU fan `EnvelopeProfile`.
- `docs/modbus-register-map.md` — BACnet placeholder/register map documentation.
- `scenarios/S1.toml`, `S2.toml` — adversary scenarios wired into this pack.
- `sim/config.toml` — deterministic simulator configuration.
- `run.sh` — entry point producing observable defended output.

## Defended scenarios

| ID | Attack | Expected TirBase response |
|---|---|---|
| S1 | Out-of-envelope command (setpoint outside allowed range) | Rejected by envelope bounds; no actuation |
| S2 | Slow ramp / cumulative drift of setpoints | Rejected by rate-of-change / drift window |

## Running

From `tirbase-demo/buildings-bms/`:

```sh
./run.sh
```

## What TirBase does not protect against in this scenario

- **Physical compromise of BMS controllers, sensors, or actuators.** Tampered devices can misreport or ignore commands.
- **A root-compromised gateway host/OS.** Userspace guard enforcement can be bypassed.
- **Direct BACnet/fieldbus writes bypassing the guard.** Unmediated control paths are out of scope.
- **Life-safety and fire/smoke control functions.** TirBase is not a life-safety system and must not replace certified safety controls.
- **Availability under sustained DoS.** Legitimate commands may be delayed during attack.
- **Correctness of the installed profile.** A legitimately signed but misconfigured envelope is enforced as specified.
- **Attacks outside S1–S2.** Other adversary classes are covered by their respective scenarios/packs.
