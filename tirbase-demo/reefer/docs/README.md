# Reefer/container pack (Apache-2.0)

A data-only TirBase pack for transport containers (reefers) on trailers and
chassis. It binds one `EnvelopeProfile` (`profiles/reefer.toml`) to two
controller register maps, carries the container/trailer identity and trip
metadata (`trip.toml`), and ships five S1/S2 adversary scenarios with their
expected defended output — including the trip-level quarantine disposition.

The pack contains no executable code. Every file is `.toml`, `.md`, or the
single launcher `run.sh`; `scripts/check-pack-purity.py` enforces that, and
`tirbase-demo/tests/reefer_pack_structure.rs` re-checks the same rule locally.

## What is in the pack

| Path | Purpose |
| --- | --- |
| `pack.toml` | Versioned manifest (schema version 1) |
| `profiles/reefer.toml` | The protective envelope for `device_class = reefer` |
| `trip.toml` | Container/trailer identity, location, cargo band, and excursion rule |
| `register-maps/reefer_reference.register-map.toml` | Reference transport controller map |
| `register-maps/reefer_legacy.register-map.toml` | Legacy trailer controller map (different addresses, little-endian bits) |
| `scenarios/*.toml` | S1/S2 adversary scenarios |
| `expected/outcomes.toml` | Machine-readable defended output per scenario, plus `[trip]` |
| `sim/config.toml` | Thermal-mass and ambient-variation simulator configuration |
| `docs/register-maps.md` | Register/unit tables for both controllers |
| `run.sh` | Launcher (prints the pack summary and runs the structural checks) |

## Intended use

- Commission a TirBase gateway for a reefer container whose controller exposes
  the six parameters below over Modbus, and book the trip against `trip.toml`.
- Demonstrate, in review or in a lab, that TirBase rejects the specific attacks
  in `scenarios/`, that the rejections match `expected/outcomes.toml`, and that
  the defended door timeline quarantines the trip.
- Provide the signing input for an Authority `EnvelopeProfile`: the profile is
  committed with a test-fixture signature and must be re-signed by an offline
  PolicyAuthority key before production use.

Parameters (units per `docs/unit-registry.md`):

| Parameter | Unit | Envelope |
| --- | --- | --- |
| `ambient_c` | degC | -45.0 … +50.0 °C, ≤ 5.0 °C/s, ≤ 10.0 °C per 300 s |
| `temperature_setpoint_c` | degC | -30.0 … -18.0 °C, ≤ 0.5 °C/s, ≤ 2.0 °C per 300 s, 30 s dwell |
| `door_open` | boolean | 45 s dwell, 600 s min-off (closed time before reopening) |
| `power_state` | boolean | 300 s dwell (no mains flap), 600 s min-off before restart |
| `defrost_mode` | boolean | 120 s dwell, 900 s min-off (restart window) |
| `compressor_on` | boolean | 300 s min-off (short-cycle protection) |

Trip metadata (`trip.toml`, data only): container `MSCU1234567` of class
`reefer_40ft` on trailer `TRL-0081`, trip `TRIP-2026-1115-0042`, Rotterdam Cold
Store 4 → Lyon Distribution Centre, frozen berries, cargo band -25.0 … -18.0 °C,
location `A15 motorway, km 42` (51.82 N, 4.53 E). A door-open interval longer
than **120 s** quarantines the trip.

## Assumptions

1. The controller is reachable over Modbus RTU/TCP and the register map in
   `register-maps/` matches the installed firmware revision.
2. A single gateway holds the PolicyAuthority trust root and the command-issuer
   keys; the container clock is not trusted for envelope decisions.
3. `mono_secs` for dwell/min-off comes from the gateway's monotonic clock and
   the persisted drift-rate summary, so interlocks survive a power cut and a
   gateway restart.
4. The container is a single-zone, single-compressor unit with one ambient
   probe; there is no second evaporator, no multi-temperature compartment, and
   no independent fan control to coordinate.
5. The ambient feed is written by the gateway's probe poller, so a spoofed or
   stale feed is a *command* on the same path as operator commands and is
   defended by the same envelope.
6. Commands carry an idempotency key plus sequence number, and the gateway's
   decided-outcome cache is enabled.
7. The pack's `device_class` (`reefer`) matches the installed device model
   exactly; parameter names are the binding contract, not register numbers.
8. The thermal model in `sim/config.toml` is a lumped-capacitance placeholder
   for scenario timing, not a calibrated container model.

## Expected defended output

Running the scenarios through the guard produces exactly this, and
`tirbase-gateway/tests/reefer_pack.rs` asserts it:

| Scenario | Class | Defense | Actuations | Step outcomes |
| --- | --- | --- | --- | --- |
| `S1_ambient_spike` | S1 | envelope range + cumulative drift | 1 | accepted, rejected, rejected |
| `S1_setpoint_tampering` | S1 | envelope range | 2 | accepted, rejected, rejected, accepted |
| `S2_door_open_in_transit` | S2 | dwell + min-off | 2 | accepted, rejected, accepted, rejected |
| `S2_power_loss` | S2 | min-off + dwell | 3 | accepted, accepted, rejected, accepted, rejected |
| `S2_sensor_dropout` | S2 | cumulative drift + min-off | 4 | accepted, accepted, accepted, rejected, rejected, accepted |

Rejected steps produce no actuation.

**Trip disposition.** The accepted steps of `S2_door_open_in_transit` open the
door at 1000 s and close it at 1300 s. The 30 s early close is refused by the
45 s dwell, so the door really stays open for 300 s — longer than the 120 s
excursion rule. The trip is therefore **quarantined** with mechanism
`door_open_in_transit`, and the excursion record is the persisted door state and
drift/timing summary that Stage 16 wrote; the gateway integration test proves
that record survives a simulated power loss and restart.

## Non-goals: What TirBase does not protect against in this scenario

- Not a safety-rated control system. Nothing here is certified to IEC 61508,
  ISO 13849, or any functional-safety standard, and the pack must not be used
  as a safety instrumented function.
- Not a substitute for the controller's own protection: high-pressure cut-outs,
  compressor overloads, door heaters, and mechanical defrost timers remain the
  equipment vendor's responsibility.
- Not a food-safety, HACCP, or GDP compliance artifact. The pack does not
  compute MKT, produce temperature logs, emit audit reports, or claim
  regulatory conformance; it dispositions *commands*, not cargo.
- Not a cargo-release decision. A quarantined trip means "do not silently
  release"; the release, rework, or destruction decision stays with the
  operator and the customer's quality system.
- Not a refrigerant-leak, fire, or personnel-safety detector, and not a
  telematics/GPS integrity control: `trip.toml` records a last-known location,
  it does not authenticate the position source.
- Not a network-security control. It constrains *authorized* command paths; it
  does not protect the controller's serial bus, the probe wiring, or the
  gateway host from a privileged attacker.
- Not a thermal model of the cargo. `sim/config.toml` is a single-zone lumped
  capacitance for repeatable scenario timing, not a validated cool-down or
  ambient-ingress model.
