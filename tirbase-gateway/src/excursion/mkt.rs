// SPDX-License-Identifier: AGPL-3.0-only

//! Mean kinetic temperature (MKT) for the excursion workflow (CC-11).
//!
//! MKT is the Haynes single-isothermal-equivalent temperature: the constant
//! storage temperature that would produce the same Arrhenius degradation as the
//! recorded temperature series,
//!
//! ```text
//! MKT = (ΔH / R) / ( -ln( (1/n) · Σ exp(-ΔH / (R · T_i)) ) )
//! ```
//!
//! with `T_i` in kelvin, `ΔH` the activation energy, and `R` the gas constant.
//! The parameters come from the pack (`gdp.toml` in the pharma GDP pack), so the
//! same engine covers 2–8 °C, frozen, and controlled-room storage.
//!
//! # Numeric behaviour and tolerance
//!
//! The summation is carried out in `f64` because the Arrhenius factor spans many
//! orders of magnitude; a fixed-point `exp` would need a lookup table whose error
//! we could not bound as tightly. The documented behaviour is:
//!
//! - samples are converted from their integer `FixedPointValue` representation
//!   to milli-degrees Celsius, then to kelvin;
//! - the accumulator is a plain `f64` sum of `exp(-ΔH/(R·T))` in the input order;
//! - the result is rounded once, to `0.001 °C` (`MKT_EXPONENT`), then stored as a
//!   `FixedPointValue` in unit `1` (degC);
//! - `MKT_TOLERANCE_C` (0.02 °C) is the documented agreement bound against the
//!   reference vectors in [`MKT_GOLDEN_VECTORS`]. Every vector is asserted inside
//!   that bound by the crate's tests; the bound absorbs `f64` accumulation order
//!   and libm `exp`/`ln` differences across platforms.
//! - each sample must lie in `MKT_MIN_C ..= MKT_MAX_C`; a series needs at least
//!   one sample and at most `MktParameters::max_samples` samples.
//!
//! # Time weighting
//!
//! [`mean_kinetic_temperature_c`] treats every sample as equally weighted (one
//! reporting interval each). [`time_weighted_mkt_c`] weights each sample by its
//! dwell time, which is what a sampler that reports at an irregular cadence
//! needs: a 300 s sample and a 900 s sample must not count the same.

use serde::{Deserialize, Serialize};
use tirbase_types::FixedPointValue;

/// Documented agreement bound against the reference vectors, in °C.
pub const MKT_TOLERANCE_C: f64 = 0.02;

/// Exponent of the returned `FixedPointValue` (milli-degrees Celsius).
pub const MKT_EXPONENT: i8 = -3;

/// Unit id for degC (`docs/unit-registry.md`).
pub const MKT_UNIT_ID: u16 = 1;

/// Lowest accepted sample temperature, in °C.
pub const MKT_MIN_C: f64 = -90.0;

/// Highest accepted sample temperature, in °C.
pub const MKT_MAX_C: f64 = 90.0;

/// Default maximum number of samples in one MKT calculation.
pub const MKT_DEFAULT_MAX_SAMPLES: usize = 10_000;

/// Arrhenius parameters for an MKT calculation.
///
/// The defaults are the Haynes constants used by the pharma GDP pack:
/// `ΔH = 83 144 J/mol`, `R = 8.314 J/(mol·K)` (stored as milli-joules so the
/// value stays an integer, matching the pack's `gdp.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MktParameters {
    /// Activation energy `ΔH` in joules per mole.
    pub activation_energy_j_per_mol: u32,
    /// Gas constant `R` in millijoules per mole per kelvin (8314 ⇒ 8.314).
    pub gas_constant_milli_j_per_mol_k: u32,
    /// Maximum samples accepted in one calculation (bounds the work done).
    pub max_samples: usize,
}

impl Default for MktParameters {
    fn default() -> Self {
        Self {
            activation_energy_j_per_mol: 83_144,
            gas_constant_milli_j_per_mol_k: 8_314,
            max_samples: MKT_DEFAULT_MAX_SAMPLES,
        }
    }
}

impl MktParameters {
    /// Build parameters from the pack's integer fields.
    pub fn new(activation_energy_j_per_mol: u32, gas_constant_milli_j_per_mol_k: u32) -> Self {
        Self {
            activation_energy_j_per_mol,
            gas_constant_milli_j_per_mol_k,
            max_samples: MKT_DEFAULT_MAX_SAMPLES,
        }
    }

    /// `ΔH / R` expressed in kelvin.
    pub fn characteristic_temperature_k(&self) -> Result<f64, MktError> {
        self.validate()?;
        Ok(self.activation_energy_j_per_mol as f64
            / (self.gas_constant_milli_j_per_mol_k as f64 / 1000.0))
    }

    fn validate(&self) -> Result<(), MktError> {
        if self.activation_energy_j_per_mol == 0 {
            return Err(MktError::InvalidParameters(
                "activation_energy_j_per_mol must be non-zero",
            ));
        }
        if self.gas_constant_milli_j_per_mol_k == 0 {
            return Err(MktError::InvalidParameters(
                "gas_constant_milli_j_per_mol_k must be non-zero",
            ));
        }
        if self.max_samples == 0 {
            return Err(MktError::InvalidParameters("max_samples must be non-zero"));
        }
        Ok(())
    }
}

/// Why an MKT calculation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MktError {
    /// A parameter is unusable (zero activation energy, zero gas constant, …).
    InvalidParameters(&'static str),
    /// The series was empty.
    NoSamples,
    /// The series exceeded `MktParameters::max_samples`.
    TooManySamples { count: usize, max: usize },
    /// A sample fell outside `MKT_MIN_C ..= MKT_MAX_C`.
    TemperatureOutOfRange { milli_c: i64 },
    /// A time-weighted sample had zero dwell time.
    ZeroDuration,
    /// The accumulator produced a non-finite value.
    NonFinite,
}

impl std::fmt::Display for MktError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MktError::InvalidParameters(reason) => write!(f, "invalid MKT parameters: {reason}"),
            MktError::NoSamples => write!(f, "MKT needs at least one sample"),
            MktError::TooManySamples { count, max } => {
                write!(f, "MKT series has {count} samples, limit is {max}")
            }
            MktError::TemperatureOutOfRange { milli_c } => write!(
                f,
                "MKT sample {milli_c} milli-°C is outside {MKT_MIN_C}..={MKT_MAX_C} °C"
            ),
            MktError::ZeroDuration => write!(f, "time-weighted MKT sample has zero duration"),
            MktError::NonFinite => write!(f, "MKT accumulator produced a non-finite value"),
        }
    }
}

impl std::error::Error for MktError {}

/// One time-weighted sample: a temperature held for `duration_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MktSample {
    /// Storage temperature during the interval.
    pub temperature_c: FixedPointValue,
    /// Interval length in seconds.
    pub duration_secs: u64,
}

/// Mean kinetic temperature of equally weighted samples.
///
/// Unit `1` (degC) is required; the result carries exponent [`MKT_EXPONENT`].
pub fn mean_kinetic_temperature_c(
    parameters: &MktParameters,
    samples: &[FixedPointValue],
) -> Result<FixedPointValue, MktError> {
    parameters.validate()?;
    if samples.is_empty() {
        return Err(MktError::NoSamples);
    }
    if samples.len() > parameters.max_samples {
        return Err(MktError::TooManySamples {
            count: samples.len(),
            max: parameters.max_samples,
        });
    }

    let characteristic = parameters.characteristic_temperature_k()?;
    let mut accumulator = 0.0f64;
    for sample in samples {
        let milli_c = scaled_milli_celsius(sample)?;
        let kelvin = milli_c as f64 / 1000.0 + 273.15;
        accumulator += (-characteristic / kelvin).exp();
    }
    finish(characteristic, accumulator, samples.len() as f64)
}

/// Mean kinetic temperature weighted by each sample's dwell time.
pub fn time_weighted_mkt_c(
    parameters: &MktParameters,
    samples: &[MktSample],
) -> Result<FixedPointValue, MktError> {
    parameters.validate()?;
    if samples.is_empty() {
        return Err(MktError::NoSamples);
    }
    if samples.len() > parameters.max_samples {
        return Err(MktError::TooManySamples {
            count: samples.len(),
            max: parameters.max_samples,
        });
    }

    let characteristic = parameters.characteristic_temperature_k()?;
    let mut accumulator = 0.0f64;
    let mut total_secs = 0.0f64;
    for sample in samples {
        if sample.duration_secs == 0 {
            return Err(MktError::ZeroDuration);
        }
        let milli_c = scaled_milli_celsius(&sample.temperature_c)?;
        let kelvin = milli_c as f64 / 1000.0 + 273.15;
        let weight = sample.duration_secs as f64;
        accumulator += weight * (-characteristic / kelvin).exp();
        total_secs += weight;
    }
    finish(characteristic, accumulator, total_secs)
}

/// Convert a temperature to milli-degrees Celsius, rejecting out-of-range values.
fn scaled_milli_celsius(value: &FixedPointValue) -> Result<i64, MktError> {
    if value.unit_id != MKT_UNIT_ID {
        return Err(MktError::InvalidParameters(
            "MKT samples must be in degC (unit 1)",
        ));
    }
    let scale = value.exponent as i16 - MKT_EXPONENT as i16;
    let milli: i128 = if scale >= 0 {
        i128::from(value.mantissa) * pow10(scale as u32)
    } else {
        i128::from(value.mantissa) / pow10((-scale) as u32)
    };
    let milli = i64::try_from(milli).map_err(|_| MktError::NonFinite)?;
    let celsius = milli as f64 / 1000.0;
    if !(MKT_MIN_C..=MKT_MAX_C).contains(&celsius) {
        return Err(MktError::TemperatureOutOfRange { milli_c: milli });
    }
    Ok(milli)
}

fn pow10(exponent: u32) -> i128 {
    let mut value = 1i128;
    for _ in 0..exponent {
        value = value.saturating_mul(10);
    }
    value
}

fn finish(
    characteristic_temperature_k: f64,
    accumulator: f64,
    weight: f64,
) -> Result<FixedPointValue, MktError> {
    if weight <= 0.0 || !accumulator.is_finite() || accumulator <= 0.0 {
        return Err(MktError::NonFinite);
    }
    let mean_factor = accumulator / weight;
    let kelvin = characteristic_temperature_k / -mean_factor.ln();
    let celsius = kelvin - 273.15;
    if !celsius.is_finite() {
        return Err(MktError::NonFinite);
    }
    let milli = (celsius * 1000.0).round();
    if milli > i64::MAX as f64 || milli < i64::MIN as f64 {
        return Err(MktError::NonFinite);
    }
    Ok(FixedPointValue::new(
        milli as i64,
        MKT_EXPONENT,
        MKT_UNIT_ID,
    ))
}

/// A published MKT reference vector.
#[derive(Debug, Clone, Copy)]
pub struct MktGoldenVector {
    /// Stable vector name (also used in test failure messages).
    pub name: &'static str,
    /// Sample temperatures in tenths of a degree Celsius.
    pub temperatures_deci_c: &'static [i64],
    /// Reference MKT in °C, computed independently of this crate.
    pub expected_c: f64,
}

/// Reference vectors for the Haynes constants (`ΔH = 83 144 J/mol`).
///
/// The expected values were produced by an independent `f64` implementation of
/// the same formula (see `tirbase-gateway/tests/excursion_mkt.rs`). Tests assert
/// agreement within [`MKT_TOLERANCE_C`].
pub const MKT_GOLDEN_VECTORS: &[MktGoldenVector] = &[
    MktGoldenVector {
        name: "constant_5c",
        temperatures_deci_c: &[50, 50, 50, 50, 50, 50],
        expected_c: 5.0,
    },
    MktGoldenVector {
        name: "two_point_2_8c",
        temperatures_deci_c: &[20, 80],
        expected_c: 5.536451,
    },
    MktGoldenVector {
        name: "daily_cycle_2_8c",
        temperatures_deci_c: &[20, 30, 40, 50, 60, 70, 80, 80, 70, 60, 50, 40],
        expected_c: 5.619738,
    },
    MktGoldenVector {
        name: "excursion_12c",
        temperatures_deci_c: &[50, 50, 50, 120, 120, 50, 50, 50],
        expected_c: 7.366267,
    },
    MktGoldenVector {
        name: "boundary_8c",
        temperatures_deci_c: &[80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80],
        expected_c: 8.0,
    },
    MktGoldenVector {
        name: "frozen_constant_minus20c",
        temperatures_deci_c: &[
            -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200,
            -200, -200, -200, -200, -200, -200, -200, -200, -200, -200,
        ],
        expected_c: -20.0,
    },
    MktGoldenVector {
        name: "frozen_excursion",
        temperatures_deci_c: &[
            -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200, -200,
            -200, -200, -200, -200, -200, -200, -120, -120, -120, -120,
        ],
        expected_c: -17.861075,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_agree_within_tolerance() {
        let parameters = MktParameters::default();
        for vector in MKT_GOLDEN_VECTORS {
            let samples: Vec<FixedPointValue> = vector
                .temperatures_deci_c
                .iter()
                .map(|deci| FixedPointValue::new(*deci, -1, MKT_UNIT_ID))
                .collect();
            let mkt = mean_kinetic_temperature_c(&parameters, &samples)
                .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
            let observed = mkt.mantissa as f64 / 1000.0;
            assert!(
                (observed - vector.expected_c).abs() <= MKT_TOLERANCE_C,
                "{}: observed {observed} vs expected {} (tolerance {MKT_TOLERANCE_C})",
                vector.name,
                vector.expected_c
            );
        }
    }

    #[test]
    fn a_constant_series_returns_the_constant() {
        let parameters = MktParameters::default();
        let samples: Vec<FixedPointValue> = (0..12)
            .map(|_| FixedPointValue::new(50, -1, MKT_UNIT_ID))
            .collect();
        assert_eq!(
            mean_kinetic_temperature_c(&parameters, &samples).expect("mkt"),
            FixedPointValue::new(5_000, -3, MKT_UNIT_ID)
        );
    }

    #[test]
    fn time_weighting_changes_the_result() {
        let parameters = MktParameters::default();
        let samples = [
            MktSample {
                temperature_c: FixedPointValue::new(5_000, -3, MKT_UNIT_ID),
                duration_secs: 8 * 3600,
            },
            MktSample {
                temperature_c: FixedPointValue::new(15_000, -3, MKT_UNIT_ID),
                duration_secs: 4 * 3600,
            },
        ];
        let weighted = time_weighted_mkt_c(&parameters, &samples).expect("weighted mkt");
        let observed = weighted.mantissa as f64 / 1000.0;
        assert!(
            (observed - 9.744131).abs() <= MKT_TOLERANCE_C,
            "time-weighted MKT {observed} is not the 8h/4h reference value"
        );

        // Equal weights would give more weight to the warm interval.
        let equally_weighted = mean_kinetic_temperature_c(
            &parameters,
            &[
                FixedPointValue::new(5_000, -3, MKT_UNIT_ID),
                FixedPointValue::new(15_000, -3, MKT_UNIT_ID),
            ],
        )
        .expect("mkt");
        assert!(equally_weighted.mantissa > weighted.mantissa);
    }

    #[test]
    fn invalid_parameters_and_samples_are_rejected() {
        let samples = [FixedPointValue::new(50, -1, MKT_UNIT_ID)];
        assert_eq!(
            mean_kinetic_temperature_c(&MktParameters::new(0, 8_314), &samples),
            Err(MktError::InvalidParameters(
                "activation_energy_j_per_mol must be non-zero"
            ))
        );
        assert_eq!(
            mean_kinetic_temperature_c(&MktParameters::default(), &[]),
            Err(MktError::NoSamples)
        );
        assert!(matches!(
            mean_kinetic_temperature_c(
                &MktParameters::default(),
                &[FixedPointValue::new(50, -1, 6)]
            ),
            Err(MktError::InvalidParameters(_))
        ));
        assert_eq!(
            mean_kinetic_temperature_c(
                &MktParameters::default(),
                &[FixedPointValue::new(50_000, -1, MKT_UNIT_ID)]
            ),
            Err(MktError::TemperatureOutOfRange { milli_c: 5_000_000 })
        );
        let mut limited = MktParameters::default();
        limited.max_samples = 1;
        assert_eq!(
            mean_kinetic_temperature_c(
                &limited,
                &[
                    FixedPointValue::new(50, -1, MKT_UNIT_ID),
                    FixedPointValue::new(50, -1, MKT_UNIT_ID)
                ]
            ),
            Err(MktError::TooManySamples { count: 2, max: 1 })
        );
        assert_eq!(
            time_weighted_mkt_c(
                &MktParameters::default(),
                &[MktSample {
                    temperature_c: FixedPointValue::new(5_000, -3, MKT_UNIT_ID),
                    duration_secs: 0,
                }]
            ),
            Err(MktError::ZeroDuration)
        );
    }

    #[test]
    fn millidegree_inputs_are_accepted() {
        let parameters = MktParameters::default();
        let samples: Vec<FixedPointValue> = (0..6)
            .map(|_| FixedPointValue::new(5_250, -3, MKT_UNIT_ID))
            .collect();
        assert_eq!(
            mean_kinetic_temperature_c(&parameters, &samples).expect("mkt"),
            FixedPointValue::new(5_250, -3, MKT_UNIT_ID)
        );
    }
}
