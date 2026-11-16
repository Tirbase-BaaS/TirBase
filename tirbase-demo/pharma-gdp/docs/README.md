# Pharma GDP pack (Apache-2.0)

A data-only TirBase pack for pharmaceutical wholesale storage under GDP. It
binds three storage classes to three `EnvelopeProfile` documents, carries the
lot identity, mean-kinetic-temperature constants, calibration records, and a
qualification checklist, and ships command scenarios plus lot-release checks with
their expected dispositions.

The pack contains no executable code. Every file is `.toml`, `.md`, or the single
launcher `run.sh`; `scripts/check-pack-purity.py` enforces that, and
`tirbase-demo/tests/pharma_gdp_pack_structure.rs` re-checks the same rule
locally.

## What is in the pack

| Path | Purpose |
| --- | --- |
| `pack.toml` | Versioned manifest (schema version 1) |
| `profiles/gdp_2_8c.toml` | 2–8 °C cold-chain envelope |
| `profiles/gdp_frozen.toml` | Frozen (−25 … −15 °C) envelope |
| `profiles/gdp_controlled_room.toml` | Controlled room (15–25 °C) envelope |
| `gdp.toml` | Lot identity, storage classes, MKT constants, calibration and lane-risk policy |
| `calibration.toml` | Monitoring-sensor calibration records |
| `qualification.toml` | DQ/IQ/OQ/PQ checklist with an explicit evidence boundary |
| `register-maps/*.register-map.toml` | Reference and legacy controller maps |
| `scenarios/*.toml` | Command-path scenarios (excursion, cumulative drift, sensor failure) |
| `expected/outcomes.toml` | Per-scenario defended output plus the lot-release checks |
| `sim/config.toml` | Thermal, humidity, and MKT-reporting simulator configuration |
| `docs/register-maps.md` | Register/unit tables for both controllers |
| `run.sh` | Launcher (prints the pack summary and runs the structural checks) |

## Intended use

- Configure a TirBase gateway for GDP storage rooms where the controller exposes
  the five parameters below over Modbus, and book the lot against `gdp.toml`.
- Show, in a regulatory or customer review, how an accepted excursion differs
  from cumulative drift, and how a release is blocked when the evidence behind it
  is stale.
- Provide the signing input for Authority `EnvelopeProfile` documents: each
  profile is committed with a test-fixture signature and must be re-signed by an
  offline PolicyAuthority key before production use.
- Provide the release disposition vocabulary that the excursion workflow (CC-11)
  records against a lot, so a pack, a gateway decision, and a QA disposition all
  refer to the same codes.

### Storage classes

| Storage class | Profile | Labelled band | Transient allowance | Cumulative budget | MKT limit |
| --- | --- | --- | --- | --- | --- |
| 2–8 °C cold chain | `profiles/gdp_2_8c.toml` | 2.0 … 8.0 °C | 900 s | 600 °C·s | 8.0 °C |
| Frozen / deep-frozen | `profiles/gdp_frozen.toml` | −25.0 … −15.0 °C | 600 s | 300 °C·s | −12.0 °C |
| Controlled room | `profiles/gdp_controlled_room.toml` | 15.0 … 25.0 °C | 1800 s | 1200 °C·s | 25.0 °C |

The **command envelope is deliberately wider than the labelled band**: the guard
bounds what the plant may be told to do (0 … 25 °C for the 2–8 °C room), and the
GDP policy decides what that meant for the product. Without that separation a
pack could not tell a short excursion from a slow ramp.

### Mean kinetic temperature

`gdp.toml` declares the calculation the excursion workflow performs:

| Parameter | Value |
| --- | --- |
| Activation energy ΔH | 83 144 J/mol |
| Gas constant R | 8 314 mJ/(mol·K) |
| Reference temperature | +5.0 °C |
| Reporting interval | 3600 s |
| Sampling interval | 300 s |

The pack declares the constants and cadence; it does not fold the series into an
MKT. That computation, and the reporting it drives, belongs to CC-11.

### Release dispositions (aligned with CC-11)

| Code | Disposition | Blocked | Meaning |
| --- | --- | --- | --- |
| `GDP-REL-001` | release | no | In band, calibration valid, MKT within limit |
| `GDP-BLK-002` | hold | yes | A monitoring sensor's calibration expired before release |
| `GDP-BLK-003` | hold | yes | Open lane-risk level at or above the hold threshold |
| `GDP-BLK-005` | hold | yes | A monitoring sensor failed; the record is incomplete |
| `GDP-HLD-004` | hold | no | Transient excursion inside the allowance, pending QA assessment |
| `GDP-REJ-006` | reject | yes | Cumulative excursion exceeded the budget |
| `GDP-REJ-007` | reject | yes | Mean kinetic temperature exceeded the product limit |

Evaluation order is fixed: **calibration expiry, sensor failure, lane risk, MKT,
then excursion class**. An expired calibration therefore wins over a clean
temperature record — a lot cannot be released on evidence from a sensor that is
out of calibration.

### Transient excursion vs cumulative drift

The pack makes the distinction on the *accepted* timeline, not on intent:

- `S2_transient_excursion` walks the setpoint from 7.5 °C to 9.0 °C for 300 s and back. Every
  command is inside the 5.0 °C/hour drift budget, so all three steps are
  dispatched; the accepted timeline is 300 s out of band at 1.0 °C excess — 300
  degree-seconds, inside the 900 s / 600 degree-second allowance. It is a
  **transient** excursion, and the lot is **held** (`GDP-HLD-004`).
- `S2_cumulative_drift` walks 1.5 °C steps five minutes apart. Individually they
  look harmless, but they add up to 6.0 °C inside the one-hour window, so the
  fifth command is refused by the drift window and never reaches the plant. The
  refused step classifies the timeline as **cumulative**, and the lot is
  **rejected** (`GDP-REJ-006`).

### Qualification checklist

`qualification.toml` is a DQ/IQ/OQ/PQ checklist of the evidence a site must hold.
It is **not** a validation report and **not** a certification: the document must
declare `certification = "none"`, and the loader refuses a pack that claims
otherwise. PQ-01 is deliberately marked `not-applicable`: performance
qualification with the real product is site evidence that no pack can ship.

## Assumptions

1. The controller is reachable over Modbus RTU/TCP and the register map in
   `register-maps/` matches the installed firmware revision.
2. A single gateway holds the PolicyAuthority trust root and the command-issuer
   keys; room clocks are not trusted for envelope decisions.
3. `mono_secs` for dwell and the drift window comes from the gateway's monotonic
   clock and its persisted timing summary, so interlocks survive a restart.
4. One monitoring sensor per storage class is bound to the pack's calibration
   records; probe mapping studies and placement are site evidence.
5. The temperature series are sampled at 300 s and reported hourly, per
   `gdp.toml`; the workflow that folds the series into MKT is CC-11.
6. `device_class = gdp_room` matches the installed device model exactly;
   parameter names are the binding contract, not register numbers.
7. The thermal and humidity model in `sim/config.toml` is a lumped placeholder
   for scenario timing, not a validated room model.

## Expected defended output

`tirbase-gateway/tests/pharma_gdp_pack.rs` asserts each row below against the
guard.

| Scenario | Class | Defense | Actuations | Step outcomes | Release |
| --- | --- | --- | --- | --- | --- |
| `S2_transient_excursion` | S2 | recorded (accepted, out of band 300 s) | 3 | accepted ×3 | hold `GDP-HLD-004` |
| `S2_cumulative_drift` | S2 | cumulative drift | 4 | accepted ×4, rejected | reject `GDP-REJ-006` |
| `S2_sensor_failure` | S2 | envelope range + cumulative drift | 1 | accepted, rejected, rejected | hold `GDP-BLK-005` |

Release checks in `expected/outcomes.toml` (re-derived by the loader, then
re-asserted by the gateway test):

| Check | Storage class | Why | Disposition |
| --- | --- | --- | --- |
| `release_clear` | 2–8 °C | clean record, valid calibration | release `GDP-REL-001` |
| `transient_excursion` | 2–8 °C | 300 s / 300 °C·s inside allowance | hold `GDP-HLD-004` |
| `cumulative_drift` | 2–8 °C | refused step, cumulative class | reject `GDP-REJ-006` |
| `calibration_expiry` | 2–8 °C | release time past `expires_at_est` | hold, blocked `GDP-BLK-002` |
| `lane_risk_event` | 2–8 °C | lane-risk level 4 ≥ threshold 4 | hold, blocked `GDP-BLK-003` |
| `sensor_failure` | 2–8 °C | one failed monitoring sensor | hold, blocked `GDP-BLK-005` |
| `mkt_exceeded` | 2–8 °C | MKT 9.5 °C > 8.0 °C limit | reject `GDP-REJ-007` |
| `frozen_clear` | frozen | MKT −20.0 °C within the −12.0 °C limit | release `GDP-REL-001` |
| `controlled_room_mkt_limit` | controlled room | MKT 25.5 °C > 25.0 °C limit | reject `GDP-REJ-007` |

## Evidence boundary

What the pack's evidence covers: profile content and signing input, register
mapping, scenario data, the guard's defended output, and the release-policy
derivation asserted by the tests.

What it does not cover: site utilities and HVAC capability, probe mapping and
placement studies, analytical method validation, operator training records,
supplier audits, product-specific stability data, cold-chain shipping validation,
or any regulatory submission. A passing pack is evidence that the *configuration*
was exercised, not that the *product* is fit for release.

## Non-goals: What TirBase does not protect against in this scenario

- Not a validated computerised system. Nothing here is 21 CFR Part 11 compliant,
  GAMP 5 categorised, or certified to any GxP scheme; the checklist is a
  template, not a validation report.
- Not a certificate of GDP/GMP compliance, and not a substitute for the licence
  holder's quality system, Qualified Person, or Responsible Person.
- Not an MKT calculator or temperature logger. The pack declares the constants
  and cadence; computing MKT, storing the series, and reporting excursions belong
  to the excursion workflow (CC-11) and the site's monitoring system.
- Not a product-release decision. A `release` disposition means "the pack found
  no blocking condition in the defended record"; the Qualified Person's decision
  is still required and may override it.
- Not a substitute for the controller's own safety protection: high-pressure
  cut-outs, compressor overloads, defrost timers, and electrical protection
  remain the equipment vendor's responsibility.
- Not a network-security control. It constrains *authorized* command paths; it
  does not protect the controller bus, probe wiring, or the gateway host from a
  privileged attacker.
- Not a stability study. Excursion budgets in `gdp.toml` are placeholders that
  must be replaced with product-specific stability data before use.
