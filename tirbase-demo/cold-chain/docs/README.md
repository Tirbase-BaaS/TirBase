# Cold-Chain Retail Demo Pack (Flagship)

This pack demonstrates TirBase defending a simulated cold-room controller
(device class `cold_chain`) against guard-relevant adversary behaviour. It is
the flagship vertical demo (PV-16.1, CLAIM-47.1–47.4).

## Contents

- `profiles/cold_chain.toml` — `EnvelopeProfile` (temperature setpoint, compressor
 on/off, rate-of-change and drift limits), signed by a PolicyAuthority fixture.
- `docs/modbus-register-map.md` — Modbus register map for the simulated controller.
- `scenarios/S1.toml`, `S2.toml`, `S3.toml` — adversary scenarios wired into this pack.
- `sim/config.toml` — deterministic simulator configuration.
- `run.sh` — entry point; produces observable output demonstrating the defended
 attack scenario within 120 seconds of launch.

## Defended scenarios

| ID | Attack | Expected TirBase response |
|---|---|---|
| S1 | Out-of-envelope command (setpoint outside the allowed range) | Rejected by envelope bounds; no actuation |
| S2 | Slow ramp / cumulative drift | Rejected by rate-of-change / drift window; cumulative change bounded |
| S3 | Replay of a previously accepted command | Deduplicated (anti-replay / idempotency cache); no second actuation |

## Running

```sh
./run.sh
```

The script runs the cold-chain S1/S2/S3 defences and prints observable
ACCEPT/REJECT outcomes for each defended attack.

## What TirBase does not protect against in this scenario

- **Physical compromise of the controller or sensors.** If the Modbus device,
 its wiring, or temperature probes are tampered with, TirBase cannot guarantee
 truthful readings or that the physical actuator obeys the commanded state.
- **A root-compromised gateway host/OS.** TirBase assumes the guard process and
 its trust anchors run on an uncompromised host; a kernel/root attacker can
 bypass userspace enforcement.
- **Direct actuation paths that bypass the TirBase guard.** Commands issued over
 a legacy/local channel not mediated by `CommandGuard::admit` (and not
 producing an `ActuationPermit`) are out of scope for this envelope.
- **Safety/SIL guarantees.** TirBase enforces command envelopes and policy; it is
 not a safety-instrumented system and does not replace hardware safety controls,
 alarms, or independent thermal cut-outs required for food safety.
- **Availability under sustained denial of service.** Rate limiting and
 quarantine bound resource use, but a determined network or compute DoS can still
 delay legitimate commands.
- **Correctness of the installed profile/policy.** TirBase enforces the signed
 `EnvelopeProfile` as installed; a legitimately signed but misconfigured profile
 (wrong limits/rates) will be enforced as specified.
- **Attacks outside S1–S3.** This pack wires the guard-focused scenarios S1–S3
 only; other adversary classes (mesh, migration, time-anchor, etc.) are covered
 by their respective scenarios/packs, not demonstrated here.
