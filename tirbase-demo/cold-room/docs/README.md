# Cold-room pack (Apache-2.0)

A data-only TirBase pack for walk-in cold-room controllers. It binds one
`EnvelopeProfile` (`profiles/cold_room.toml`) to two vendor register maps and
ships six adversary scenarios with their expected defended output.

The pack contains no executable code. Every file is `.toml`, `.md`, or the
single launcher `run.sh`; `scripts/check-pack-purity.py` enforces that, and
`tests/cold_room_pack_structure.rs` re-checks the same rule locally.

## What is in the pack

| Path | Purpose |
| --- | --- |
| `pack.toml` | Versioned manifest (schema version 1) |
| `profiles/cold_room.toml` | The protective envelope for `device_class = cold_room` |
| `register-maps/cold_room_reference.register-map.toml` | Reference controller map |
| `register-maps/cold_room_legacy.register-map.toml` | Legacy controller map (different addresses, 32-bit temperature) |
| `scenarios/*.toml` | S1/S2/S3 adversary scenarios |
| `expected/outcomes.toml` | Machine-readable defended output per scenario |
| `sim/config.toml` | Simulator configuration |
| `docs/register-maps.md` | Register/unit tables for both controllers |
| `run.sh` | Launcher (prints the pack summary and runs the structural checks) |

## Intended use

- Commission a TirBase gateway for a walk-in cold room whose controller exposes
  the five parameters below over Modbus.
- Demonstrate, in review or in a lab, that TirBase rejects the specific attacks
  in `scenarios/` and that the rejections match `expected/outcomes.toml`.
- Provide the signing input for an Authority `EnvelopeProfile`: the profile is
  committed with a test-fixture signature and must be re-signed by an offline
  PolicyAuthority key before production use.

Parameters (units per `docs/unit-registry.md`):

| Parameter | Unit | Envelope |
| --- | --- | --- |
| `temperature_setpoint_c` | degC | -25.0 … +8.0 °C, ≤ 0.5 °C/s, ≤ 2.0 °C per 300 s, 30 s dwell |
| `door_open` | boolean | 60 s dwell, 300 s min-off (closed time before reopening) |
| `defrost_mode` | boolean | 60 s dwell, 600 s min-off (restart window) |
| `defrost_termination_c` | degC | 0.0 … +8.0 °C, ≤ 0.2 °C/s |
| `compressor_on` | boolean | 300 s min-off (short-cycle protection) |

## Assumptions

1. The controller is reachable over Modbus RTU/TCP and the register map in
   `register-maps/` matches the installed firmware revision.
2. A single gateway holds the PolicyAuthority trust root and the command-issuer
   keys; the device clock is not trusted for envelope decisions.
3. `mono_secs` for dwell/min-off comes from the gateway's monotonic clock and
   the persisted drift-rate summary, so interlocks survive a restart.
4. The room is a single-zone, single-compressor unit; there is no second-stage
   cooling or independent evaporator fan to coordinate.
5. Commands carry an idempotency key plus sequence number, and the gateway's
   decided-outcome cache is enabled.
6. The pack's `device_class` (`cold_room`) matches the installed device model
   exactly; parameter names are the binding contract, not register numbers.

## Expected defended output

Running the scenarios through the guard produces exactly this, and the
integration test `tirbase-gateway/tests/cold_room_pack.rs` asserts it:

| Scenario | Class | Defense | Actuations | Step outcomes |
| --- | --- | --- | --- | --- |
| `S1_out_of_envelope_setpoint` | S1 | envelope range | 0 | rejected |
| `S1_defrost_manipulation` | S1 | envelope range + min-off | 2 | rejected, accepted, accepted, rejected |
| `S2_slow_ramp` | S2 | cumulative drift | 5 | accepted ×5, rejected |
| `S2_door_abuse` | S2 | dwell + min-off | 2 | accepted, rejected, accepted, rejected |
| `S2_compressor_short_cycling` | S2 | min-off | 3 | accepted, accepted, rejected, accepted |
| `S3_replay` | S3 | idempotency cache | 1 | accepted, deduplicated |

Rejected steps produce no actuation. Deduplicated steps return the cached
decision without a second dispatch.

## Non-goals: What TirBase does not protect against in this scenario

- Not a safety-rated control system. Nothing here is certified to IEC 61508,
  ISO 13849, or any functional-safety standard, and the pack must not be used
  as a safety instrumented function.
- Not a substitute for the controller's own protection: high-pressure cut-outs,
  overloads, door heaters, and mechanical defrost timers remain the equipment
  vendor's responsibility.
- Not a food-safety or HACCP compliance artifact. The pack does not record
  temperature logs, produce audit reports, or claim regulatory conformance.
- Not a refrigerant-leak, fire, or personnel-safety detector.
- Not a network-security control. It constrains *authorized* command paths; it
  does not protect the controller's serial bus or the gateway host from a
  privileged attacker.
- Not a multi-zone, cascade, or CO₂ transcritical model. The thermal model in
  `sim/config.toml` is a single-zone placeholder for scenario timing only.
