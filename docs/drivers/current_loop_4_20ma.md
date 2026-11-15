# 4–20 mA Transducer Driver (CC-05)

Calibrated 4–20 mA current-loop input for pressure, level, flow, and other
industrial transducers. The driver converts raw ADC counts to loop current,
then to a fixed-point engineering value in a registered unit, and classifies
open-loop, under-range, over-range, noisy, and stuck-value faults. It builds on
the CC-01 driver split and extends the F-13 simulator catalogue.

| Layer | Crate | Contents |
|---|---|---|
| Pure conversion (Apache-2.0) | `tirbase_driver_api::current_loop` | Validated calibration table, piecewise-linear counts→µA, µA→`FixedPointValue`, bounded fault detector, drift comparison |
| Persistence (AGPL-3.0-only) | `tirbase_guard::current_loop` | Versioned JSON calibration store with atomic writes, load-time re-validation, baseline drift report |
| Simulator (AGPL-3.0-only) | `tirbase_sim::Sim4To20MaAdc` | 12-bit ADC counts with open/under/over-range, noise, and stuck-value injection |

## Pipeline

```text
ADC counts --calibration points--> loop current (µA) --engineering span--> FixedPointValue
```

All arithmetic is integer (`i128` intermediates) and deterministic; there is no
I/O and no clock in the conversion path.

- **Calibration points** map ADC counts to loop current in µA. A table has
  2–16 points, strictly increasing counts, strictly increasing current, and
  every current within `0..=24_000` µA.
- **Engineering span** maps 4 mA to `eng_min` and 20 mA to `eng_max`, expressed
  as mantissas at an exponent in `-9..=9` for a unit ID from the existing
  registry (`docs/unit-registry.md`). Descending spans are allowed. Values
  outside the 4–20 mA span clamp to the engineering endpoints.
- Counts outside the calibration table extrapolate along the nearest segment
  first, then clamp to `0..=MAX_LOOP_UA` (24 mA). This keeps a disconnected
  loop distinguishable from an over-range loop.

Reference vectors (12-bit counts, 0–24 mA scale, engineering 0–100.0 %):

| ADC counts | Loop current | Engineering |
|---:|---:|---:|
| 683 | 4 000 µA | 0.0 % |
| 1 366 | 8 000 µA | 25.0 % |
| 2 048 | 12 000 µA | 50.0 % |
| 2 730 | 16 000 µA | 75.0 % |
| 3 413 | 20 000 µA | 100.0 % |

## Fault classification

`FaultDetector` keeps a bounded window and classifies the converted current.
Priority is **open loop → over-range → under-range → noisy → stuck value**, so
range faults are never hidden by noise or a flat trace.

| Fault | Default trigger | Meaning |
|---|---|---|
| `OpenLoop` | current < 3 600 µA | disconnected or open circuit |
| `UnderRange` | 3 600 µA ≤ current < 3 800 µA | live loop below nominal |
| `OverRange` | current > 20 500 µA | live loop above nominal |
| `Noisy` | window of 8, peak-to-peak > 500 µA | unstable signal |
| `StuckValue` | 8 consecutive samples within 2 µA | frozen ADC or transducer |

Thresholds are configurable but validated: open loop must be below under-range,
under-range cannot exceed 4 mA, over-range must lie between 20 mA and 24 mA,
and window lengths are at least 2. `reset()` clears history; installing a new
calibration via `CurrentLoopSensor::recalibrate` also resets it.

```rust
use tirbase_driver_api::current_loop::{
    CalibrationPoint, CurrentLoopCalibration, CurrentLoopSensor, FaultThresholds,
};
use tirbase_types::UNIT_PERCENT;

let calibration = CurrentLoopCalibration::new(
    vec![
        CalibrationPoint::new(683, 4_000),
        CalibrationPoint::new(1_366, 8_000),
        CalibrationPoint::new(2_048, 12_000),
        CalibrationPoint::new(2_730, 16_000),
        CalibrationPoint::new(3_413, 20_000),
    ],
    0,
    1_000,
    -1,
    UNIT_PERCENT,
    FaultThresholds::default(),
)?;
let mut sensor = CurrentLoopSensor::new(calibration)?;

let reading = sensor.read(adc_counts);
// reading.current_ua, reading.engineering (FixedPointValue), reading.fault
```

## Calibration persistence

The guard owns the file. `CurrentLoopCalibrationStore` writes a versioned JSON
document to a hidden temp file in the same directory, `fsync`s it, and renames
it over the target, so a crash cannot leave a partially written calibration.
`load()` re-validates every invariant and rejects unsupported versions and
unknown fields; a hand-edited or corrupt file never enters the runtime.

```rust
use tirbase_guard::CurrentLoopCalibrationStore;

let store = CurrentLoopCalibrationStore::new("/var/lib/tirbase/loop-01.json");
store.save(&calibration)?;

// Later boot / new process:
let loaded = store.load()?.expect("commissioned calibration");
let mut sensor = CurrentLoopSensor::new(loaded)?;

// Compare a fresh calibration against the stored baseline (60 µA allowed).
if let Some(drift) = store.detect_drift(&fresh, 60)? {
    if drift.drifted {
        report_drift(&drift); // max_abs_delta_ua, per-point deltas
    }
}
```

Drift compares the measured calibration at its own ADC points against the
reference interpolation, so the two tables need not share an identical point
set. A missing file yields `Ok(None)` rather than an error.

## Bounds

| Limit | Value |
|---|---:|
| Calibration points | 2–16 |
| Loop current | 0–24 000 µA |
| Engineering exponent | −9..=9 |
| Noise/stuck window | ≥ 2 samples |
| Persisted schema | version 1 |

## Tests

- `tirbase-driver-api/src/current_loop.rs`: reference vectors, engineering
  clamping, extrapolation, fault priority, noise and stuck windows, invalid
  calibration tables, unit-registry/exponent integration, drift tolerance, and
  a deterministic boundary sweep.
- `tirbase-guard/src/current_loop.rs`: save/load round trip, simulated process
  restart, corrupt/future/unknown-version rejection, and baseline drift.
- `tirbase-guard/tests/current_loop_4_20ma.rs`: simulator-backed reference
  readings, open-loop vs under/over-range distinguishability, noise and stuck
  injection, calibration survival across a store restart, and persisted-baseline
  drift.

Run locally:

```sh
cargo test -p tirbase-driver-api --lib current_loop
cargo test -p tirbase-guard current_loop
```
