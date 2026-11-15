// SPDX-License-Identifier: Apache-2.0

//! 4–20 mA transducer conversion and fault classification (CC-05).
//!
//! The pipeline is integer-only and deterministic:
//!
//! ```text
//! ADC counts --calibration points--> loop current (µA) --engineering span--> FixedPointValue
//! ```
//!
//! Calibration points map raw ADC counts to loop current. The engineering span
//! maps the nominal 4 mA and 20 mA points onto a unit-registry unit at a fixed
//! exponent, and the result is clamped to the span. Faults are classified from
//! the converted current with a bounded sliding window:
//! open loop, under-range, over-range, noise, and stuck value.
//!
//! This module performs no I/O and reads no clock. Calibration persistence and
//! drift comparison against stored calibration live in `tirbase_guard`.

use std::collections::VecDeque;
use std::fmt;

use tirbase_types::{unit_descriptor, FixedPointValue, UnitId, UNIT_UNKNOWN};

/// Loop current in microamperes.
pub type MicroAmps = i32;
/// Raw ADC counts.
pub type AdcCounts = u32;

/// Nominal 4 mA endpoint.
pub const NOMINAL_4MA_UA: MicroAmps = 4_000;
/// Nominal 20 mA endpoint.
pub const NOMINAL_20MA_UA: MicroAmps = 20_000;
/// Highest accepted loop current (above the 20 mA nominal range).
pub const MAX_LOOP_UA: MicroAmps = 24_000;
/// Minimum calibration points.
pub const MIN_CALIBRATION_POINTS: usize = 2;
/// Maximum calibration points.
pub const MAX_CALIBRATION_POINTS: usize = 16;
/// Default open-loop threshold: below 3.6 mA the loop is considered open.
pub const DEFAULT_OPEN_LOOP_UA: MicroAmps = 3_600;
/// Default under-range threshold: below 3.8 mA (but above open loop).
pub const DEFAULT_UNDER_RANGE_UA: MicroAmps = 3_800;
/// Default over-range threshold: above 20.5 mA.
pub const DEFAULT_OVER_RANGE_UA: MicroAmps = 20_500;
/// Default peak-to-peak noise limit.
pub const DEFAULT_MAX_NOISE_UA: MicroAmps = 500;
/// Default noise window length.
pub const DEFAULT_NOISE_WINDOW: usize = 8;
/// Default stuck window length.
pub const DEFAULT_STUCK_WINDOW: usize = 8;
/// Default stuck-value tolerance in µA.
pub const DEFAULT_STUCK_EPSILON_UA: MicroAmps = 2;

/// One calibration point: ADC counts and the loop current they represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationPoint {
    pub adc_counts: AdcCounts,
    pub loop_ua: MicroAmps,
}

impl CalibrationPoint {
    pub const fn new(adc_counts: AdcCounts, loop_ua: MicroAmps) -> Self {
        Self {
            adc_counts,
            loop_ua,
        }
    }
}

/// Thresholds for fault classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultThresholds {
    pub open_loop_ua: MicroAmps,
    pub under_range_ua: MicroAmps,
    pub over_range_ua: MicroAmps,
    pub max_noise_ua: MicroAmps,
    pub noise_window: usize,
    pub stuck_window: usize,
    pub stuck_epsilon_ua: MicroAmps,
}

impl Default for FaultThresholds {
    fn default() -> Self {
        Self {
            open_loop_ua: DEFAULT_OPEN_LOOP_UA,
            under_range_ua: DEFAULT_UNDER_RANGE_UA,
            over_range_ua: DEFAULT_OVER_RANGE_UA,
            max_noise_ua: DEFAULT_MAX_NOISE_UA,
            noise_window: DEFAULT_NOISE_WINDOW,
            stuck_window: DEFAULT_STUCK_WINDOW,
            stuck_epsilon_ua: DEFAULT_STUCK_EPSILON_UA,
        }
    }
}

impl FaultThresholds {
    /// Validates ordering and window bounds.
    pub fn validate(&self) -> Result<(), CurrentLoopError> {
        if self.open_loop_ua < 0 {
            return Err(CurrentLoopError::InvalidThresholds(
                "open_loop_ua must be non-negative".into(),
            ));
        }
        if self.open_loop_ua >= self.under_range_ua {
            return Err(CurrentLoopError::InvalidThresholds(
                "open_loop_ua must be below under_range_ua".into(),
            ));
        }
        if self.under_range_ua > NOMINAL_4MA_UA {
            return Err(CurrentLoopError::InvalidThresholds(
                "under_range_ua must not exceed the 4 mA nominal".into(),
            ));
        }
        if self.over_range_ua < NOMINAL_20MA_UA || self.over_range_ua > MAX_LOOP_UA {
            return Err(CurrentLoopError::InvalidThresholds(
                "over_range_ua must lie between 20 mA and MAX_LOOP_UA".into(),
            ));
        }
        if self.max_noise_ua < 0 {
            return Err(CurrentLoopError::InvalidThresholds(
                "max_noise_ua must be non-negative".into(),
            ));
        }
        if self.noise_window < 2 {
            return Err(CurrentLoopError::InvalidThresholds(
                "noise_window must be at least 2".into(),
            ));
        }
        if self.stuck_window < 2 {
            return Err(CurrentLoopError::InvalidThresholds(
                "stuck_window must be at least 2".into(),
            ));
        }
        if self.stuck_epsilon_ua < 0 {
            return Err(CurrentLoopError::InvalidThresholds(
                "stuck_epsilon_ua must be non-negative".into(),
            ));
        }
        Ok(())
    }
}

/// Fault classification for one reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopFault {
    /// Loop current below the open-loop threshold (disconnected/open circuit).
    OpenLoop,
    /// Current is above open loop but below the under-range threshold.
    UnderRange,
    /// Current is above the over-range threshold.
    OverRange,
    /// Peak-to-peak variation in the recent window exceeds the noise limit.
    Noisy,
    /// Recent values are effectively unchanged for the stuck window.
    StuckValue,
}

impl fmt::Display for LoopFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenLoop => "open_loop",
            Self::UnderRange => "under_range",
            Self::OverRange => "over_range",
            Self::Noisy => "noisy",
            Self::StuckValue => "stuck_value",
        })
    }
}

/// Conversion and configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentLoopError {
    TooFewPoints {
        min: usize,
    },
    TooManyPoints {
        max: usize,
    },
    UnsortedAdcCounts {
        previous: AdcCounts,
        current: AdcCounts,
    },
    DuplicateAdcCounts(AdcCounts),
    NonMonotonicCurrent {
        previous: MicroAmps,
        current: MicroAmps,
    },
    CurrentOutOfBounds {
        loop_ua: MicroAmps,
        max: MicroAmps,
    },
    UnitNotRegistered(UnitId),
    InvalidExponent(i8),
    EmptyEngineeringSpan,
    InvalidThresholds(String),
    InvalidDriftTolerance(MicroAmps),
}

impl fmt::Display for CurrentLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewPoints { min } => write!(f, "calibration needs at least {min} points"),
            Self::TooManyPoints { max } => write!(f, "calibration allows at most {max} points"),
            Self::UnsortedAdcCounts { previous, current } => write!(
                f,
                "calibration points must be sorted by ADC counts: {previous} then {current}"
            ),
            Self::DuplicateAdcCounts(counts) => {
                write!(f, "duplicate calibration ADC count {counts}")
            }
            Self::NonMonotonicCurrent { previous, current } => write!(
                f,
                "calibration current must increase with ADC counts: {previous} µA then {current} µA"
            ),
            Self::CurrentOutOfBounds { loop_ua, max } => {
                write!(f, "calibration current {loop_ua} µA outside 0..={max}")
            }
            Self::UnitNotRegistered(unit) => {
                write!(f, "unit id {unit} is not registered")
            }
            Self::InvalidExponent(exponent) => {
                write!(f, "fixed-point exponent {exponent} outside -9..=9")
            }
            Self::EmptyEngineeringSpan => {
                f.write_str("engineering span must have distinct endpoints")
            }
            Self::InvalidThresholds(reason) => write!(f, "invalid loop thresholds: {reason}"),
            Self::InvalidDriftTolerance(tolerance) => {
                write!(f, "drift tolerance {tolerance} µA must be non-negative")
            }
        }
    }
}

impl std::error::Error for CurrentLoopError {}

/// Validated ADC→current and current→engineering calibration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentLoopCalibration {
    points: Vec<CalibrationPoint>,
    eng_min: i64,
    eng_max: i64,
    exponent: i8,
    unit: UnitId,
    thresholds: FaultThresholds,
}

impl CurrentLoopCalibration {
    /// Builds a validated calibration.
    ///
    /// `eng_min`/`eng_max` are mantissas at `exponent` for the 4 mA/20 mA
    /// endpoints. They may be descending (for inverted spans).
    pub fn new(
        points: Vec<CalibrationPoint>,
        eng_min: i64,
        eng_max: i64,
        exponent: i8,
        unit: UnitId,
        thresholds: FaultThresholds,
    ) -> Result<Self, CurrentLoopError> {
        let calibration = Self {
            points,
            eng_min,
            eng_max,
            exponent,
            unit,
            thresholds,
        };
        calibration.validate()?;
        Ok(calibration)
    }

    /// Re-validates all invariants.
    pub fn validate(&self) -> Result<(), CurrentLoopError> {
        let count = self.points.len();
        if count < MIN_CALIBRATION_POINTS {
            return Err(CurrentLoopError::TooFewPoints {
                min: MIN_CALIBRATION_POINTS,
            });
        }
        if count > MAX_CALIBRATION_POINTS {
            return Err(CurrentLoopError::TooManyPoints {
                max: MAX_CALIBRATION_POINTS,
            });
        }
        for pair in self.points.windows(2) {
            let (previous, current) = (pair[0], pair[1]);
            if current.adc_counts < previous.adc_counts {
                return Err(CurrentLoopError::UnsortedAdcCounts {
                    previous: previous.adc_counts,
                    current: current.adc_counts,
                });
            }
            if current.adc_counts == previous.adc_counts {
                return Err(CurrentLoopError::DuplicateAdcCounts(current.adc_counts));
            }
            if current.loop_ua <= previous.loop_ua {
                return Err(CurrentLoopError::NonMonotonicCurrent {
                    previous: previous.loop_ua,
                    current: current.loop_ua,
                });
            }
        }
        for point in &self.points {
            if !(0..=MAX_LOOP_UA).contains(&point.loop_ua) {
                return Err(CurrentLoopError::CurrentOutOfBounds {
                    loop_ua: point.loop_ua,
                    max: MAX_LOOP_UA,
                });
            }
        }
        if self.unit == UNIT_UNKNOWN || unit_descriptor(self.unit).is_none() {
            return Err(CurrentLoopError::UnitNotRegistered(self.unit));
        }
        if !(-9..=9).contains(&self.exponent) {
            return Err(CurrentLoopError::InvalidExponent(self.exponent));
        }
        if self.eng_min == self.eng_max {
            return Err(CurrentLoopError::EmptyEngineeringSpan);
        }
        self.thresholds.validate()
    }

    /// Calibration points in ADC order.
    pub fn points(&self) -> &[CalibrationPoint] {
        &self.points
    }

    /// Engineering mantissa at the 4 mA endpoint.
    pub fn eng_min(&self) -> i64 {
        self.eng_min
    }

    /// Engineering mantissa at the 20 mA endpoint.
    pub fn eng_max(&self) -> i64 {
        self.eng_max
    }

    /// Fixed-point exponent of engineering values.
    pub fn exponent(&self) -> i8 {
        self.exponent
    }

    /// Unit-registry unit of engineering values.
    pub fn unit(&self) -> UnitId {
        self.unit
    }

    /// Fault thresholds.
    pub fn thresholds(&self) -> FaultThresholds {
        self.thresholds
    }

    /// Maps ADC counts to loop current using piecewise-linear interpolation.
    ///
    /// Counts outside the calibration range extrapolate along the nearest
    /// segment, then the result is clamped to `0..=MAX_LOOP_UA`.
    pub fn counts_to_current_ua(&self, adc_counts: AdcCounts) -> MicroAmps {
        let first = self.points[0];
        let last = self.points[self.points.len() - 1];
        let (left, right) = if adc_counts <= first.adc_counts {
            (first, self.points[1])
        } else if adc_counts >= last.adc_counts {
            (self.points[self.points.len() - 2], last)
        } else {
            let index = self
                .points
                .partition_point(|point| point.adc_counts <= adc_counts)
                - 1;
            (self.points[index], self.points[index + 1])
        };
        let dx = i128::from(right.adc_counts - left.adc_counts);
        let x = i128::from(adc_counts) - i128::from(left.adc_counts);
        let dy = i128::from(right.loop_ua) - i128::from(left.loop_ua);
        let numerator = i128::from(left.loop_ua) * dx + x * dy;
        let current = div_round_half_away(numerator, dx);
        current.clamp(0, i128::from(MAX_LOOP_UA)) as MicroAmps
    }

    /// Maps loop current to a clamped fixed-point engineering value.
    ///
    /// 4 mA maps to `eng_min`, 20 mA maps to `eng_max`; values outside that
    /// current span clamp to the engineering endpoints.
    pub fn current_to_engineering(&self, loop_ua: MicroAmps) -> FixedPointValue {
        let current = i128::from(loop_ua.clamp(0, MAX_LOOP_UA));
        let span = i128::from(self.eng_max) - i128::from(self.eng_min);
        let numerator = (current - i128::from(NOMINAL_4MA_UA)) * span
            + i128::from(self.eng_min) * i128::from(NOMINAL_20MA_UA - NOMINAL_4MA_UA);
        let denominator = i128::from(NOMINAL_20MA_UA - NOMINAL_4MA_UA);
        let raw = div_round_half_away(numerator, denominator);
        let low = i128::from(self.eng_min.min(self.eng_max));
        let high = i128::from(self.eng_min.max(self.eng_max));
        FixedPointValue::new(raw.clamp(low, high) as i64, self.exponent, self.unit)
    }

    /// Converts ADC counts through both stages without fault classification.
    pub fn convert(&self, adc_counts: AdcCounts) -> LoopConversion {
        let current_ua = self.counts_to_current_ua(adc_counts);
        LoopConversion {
            adc_counts,
            current_ua,
            engineering: self.current_to_engineering(current_ua),
        }
    }
}

/// Conversion result without a fault classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopConversion {
    pub adc_counts: AdcCounts,
    pub current_ua: MicroAmps,
    pub engineering: FixedPointValue,
}

/// Conversion result with the current fault state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentLoopReading {
    pub adc_counts: AdcCounts,
    pub current_ua: MicroAmps,
    pub engineering: FixedPointValue,
    pub fault: Option<LoopFault>,
}

/// Bounded stateful fault classifier.
#[derive(Debug, Clone)]
pub struct FaultDetector {
    thresholds: FaultThresholds,
    recent: VecDeque<MicroAmps>,
    stuck_run: usize,
    last: Option<MicroAmps>,
    fault: Option<LoopFault>,
}

impl FaultDetector {
    /// Creates a detector and validates its thresholds.
    pub fn new(thresholds: FaultThresholds) -> Result<Self, CurrentLoopError> {
        thresholds.validate()?;
        Ok(Self {
            thresholds,
            recent: VecDeque::with_capacity(thresholds.noise_window),
            stuck_run: 0,
            last: None,
            fault: None,
        })
    }

    /// Thresholds in use.
    pub fn thresholds(&self) -> FaultThresholds {
        self.thresholds
    }

    /// Most recent classification.
    pub fn current_fault(&self) -> Option<LoopFault> {
        self.fault
    }

    /// Clears history (for example after recalibration).
    pub fn reset(&mut self) {
        self.recent.clear();
        self.stuck_run = 0;
        self.last = None;
        self.fault = None;
    }

    /// Adds one converted current sample and returns its classification.
    ///
    /// Priority: open loop, over-range, under-range, noise, stuck. Range and
    /// open-loop faults take precedence because they invalidate the signal
    /// more directly than noise or a flat trace.
    pub fn push(&mut self, current_ua: MicroAmps) -> Option<LoopFault> {
        self.stuck_run = match self.last {
            Some(previous)
                if (i64::from(current_ua) - i64::from(previous)).abs()
                    <= i64::from(self.thresholds.stuck_epsilon_ua) =>
            {
                self.stuck_run.saturating_add(1)
            }
            _ => 1,
        };
        self.last = Some(current_ua);

        self.recent.push_back(current_ua);
        while self.recent.len() > self.thresholds.noise_window {
            self.recent.pop_front();
        }

        let fault = self.classify(current_ua);
        self.fault = fault;
        fault
    }

    fn classify(&self, current_ua: MicroAmps) -> Option<LoopFault> {
        if current_ua < self.thresholds.open_loop_ua {
            return Some(LoopFault::OpenLoop);
        }
        if current_ua > self.thresholds.over_range_ua {
            return Some(LoopFault::OverRange);
        }
        if current_ua < self.thresholds.under_range_ua {
            return Some(LoopFault::UnderRange);
        }
        if self.recent.len() >= self.thresholds.noise_window {
            let min = *self.recent.iter().min().expect("non-empty window");
            let max = *self.recent.iter().max().expect("non-empty window");
            if i64::from(max) - i64::from(min) > i64::from(self.thresholds.max_noise_ua) {
                return Some(LoopFault::Noisy);
            }
        }
        if self.stuck_run >= self.thresholds.stuck_window {
            return Some(LoopFault::StuckValue);
        }
        None
    }
}

/// Calibrated transducer with bounded fault history.
#[derive(Debug, Clone)]
pub struct CurrentLoopSensor {
    calibration: CurrentLoopCalibration,
    detector: FaultDetector,
}

impl CurrentLoopSensor {
    /// Builds a sensor from a validated calibration.
    pub fn new(calibration: CurrentLoopCalibration) -> Result<Self, CurrentLoopError> {
        calibration.validate()?;
        let detector = FaultDetector::new(calibration.thresholds())?;
        Ok(Self {
            calibration,
            detector,
        })
    }

    /// Installs a new calibration and resets fault history.
    pub fn recalibrate(
        &mut self,
        calibration: CurrentLoopCalibration,
    ) -> Result<(), CurrentLoopError> {
        calibration.validate()?;
        self.detector = FaultDetector::new(calibration.thresholds())?;
        self.calibration = calibration;
        Ok(())
    }

    /// Calibration in use.
    pub fn calibration(&self) -> &CurrentLoopCalibration {
        &self.calibration
    }

    /// Classifier state.
    pub fn detector(&self) -> &FaultDetector {
        &self.detector
    }

    /// Clears fault history without changing calibration.
    pub fn reset(&mut self) {
        self.detector.reset();
    }

    /// Reads one raw ADC count and classifies it.
    pub fn read(&mut self, adc_counts: AdcCounts) -> CurrentLoopReading {
        let conversion = self.calibration.convert(adc_counts);
        let fault = self.detector.push(conversion.current_ua);
        CurrentLoopReading {
            adc_counts,
            current_ua: conversion.current_ua,
            engineering: conversion.engineering,
            fault,
        }
    }
}

/// Current measured at one calibration point during drift comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriftPoint {
    pub adc_counts: AdcCounts,
    pub reference_ua: MicroAmps,
    pub measured_ua: MicroAmps,
    pub delta_ua: MicroAmps,
}

/// Drift report comparing a stored calibration with a fresh one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationDrift {
    pub points: Vec<DriftPoint>,
    pub max_abs_delta_ua: MicroAmps,
    pub tolerance_ua: MicroAmps,
    pub drifted: bool,
}

/// Compares `measured` against `reference` at every measured ADC point.
///
/// The reference interpolates at the measured point's ADC count, so the two
/// calibrations need not share exactly the same point set.
pub fn detect_drift(
    reference: &CurrentLoopCalibration,
    measured: &CurrentLoopCalibration,
    tolerance_ua: MicroAmps,
) -> Result<CalibrationDrift, CurrentLoopError> {
    if tolerance_ua < 0 {
        return Err(CurrentLoopError::InvalidDriftTolerance(tolerance_ua));
    }
    reference.validate()?;
    measured.validate()?;

    let mut points = Vec::with_capacity(measured.points().len());
    let mut max_abs_delta = 0;
    for point in measured.points() {
        let reference_ua = reference.counts_to_current_ua(point.adc_counts);
        let delta_ua = point.loop_ua - reference_ua;
        max_abs_delta = max_abs_delta.max(delta_ua.abs());
        points.push(DriftPoint {
            adc_counts: point.adc_counts,
            reference_ua,
            measured_ua: point.loop_ua,
            delta_ua,
        });
    }
    Ok(CalibrationDrift {
        points,
        max_abs_delta_ua: max_abs_delta,
        tolerance_ua,
        drifted: max_abs_delta > tolerance_ua,
    })
}

/// Rounds `numerator / denominator` half away from zero.
fn div_round_half_away(numerator: i128, denominator: i128) -> i128 {
    debug_assert!(denominator > 0);
    if numerator >= 0 {
        (numerator + denominator / 2) / denominator
    } else {
        (numerator - denominator / 2) / denominator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_types::{UNIT_DEG_C, UNIT_PERCENT};

    /// Reference 12-bit calibration: 0–24 mA maps to 0–4095 counts, with
    /// points at each 4 mA step. These are the committed reference vectors.
    fn reference_calibration() -> CurrentLoopCalibration {
        CurrentLoopCalibration::new(
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
        )
        .expect("reference calibration")
    }

    fn sensor() -> CurrentLoopSensor {
        CurrentLoopSensor::new(reference_calibration()).expect("sensor")
    }

    #[test]
    fn calibrated_readings_match_reference_vectors() {
        let cases = [
            (683u32, 4_000, 0i64),
            (1_366, 8_000, 250),
            (2_048, 12_000, 500),
            (2_730, 16_000, 750),
            (3_413, 20_000, 1_000),
        ];
        let calibration = reference_calibration();
        for (counts, current_ua, engineering_mantissa) in cases {
            let conversion = calibration.convert(counts);
            assert_eq!(conversion.current_ua, current_ua, "counts {counts}");
            assert_eq!(
                conversion.engineering,
                FixedPointValue::new(engineering_mantissa, -1, UNIT_PERCENT),
                "counts {counts}"
            );
        }
    }

    #[test]
    fn conversion_clamps_engineering_to_the_span() {
        let calibration = reference_calibration();
        // 3 mA -> below the 4 mA span endpoint.
        let below = calibration.current_to_engineering(3_000);
        assert_eq!(below, FixedPointValue::new(0, -1, UNIT_PERCENT));
        // 22 mA -> above the 20 mA span endpoint.
        let above = calibration.current_to_engineering(22_000);
        assert_eq!(above, FixedPointValue::new(1_000, -1, UNIT_PERCENT));
    }

    #[test]
    fn counts_outside_calibration_extrapolate_then_clamp() {
        let calibration = reference_calibration();
        assert_eq!(calibration.counts_to_current_ua(0), 0);
        assert_eq!(calibration.counts_to_current_ua(5_000), MAX_LOOP_UA);
        assert!(calibration.counts_to_current_ua(4_095) > DEFAULT_OVER_RANGE_UA);
    }

    #[test]
    fn open_loop_and_range_faults_are_distinguishable() {
        let calibration = reference_calibration();
        // 0 counts extrapolates to 0 µA: open loop.
        let open = calibration.convert(0);
        assert!(open.current_ua < DEFAULT_OPEN_LOOP_UA);
        let mut detector = FaultDetector::new(FaultThresholds::default()).unwrap();
        assert_eq!(detector.push(open.current_ua), Some(LoopFault::OpenLoop));

        // 3.7 mA is below under-range but above open loop.
        assert_eq!(detector.push(3_700), Some(LoopFault::UnderRange));

        // 21 mA is above the over-range threshold.
        assert_eq!(detector.push(21_000), Some(LoopFault::OverRange));

        // Nominal signal has no fault.
        assert_eq!(detector.push(12_000), None);
    }

    #[test]
    fn sensor_classifies_open_loop_from_adc_counts() {
        let mut sensor = sensor();
        let reading = sensor.read(0);
        assert_eq!(reading.fault, Some(LoopFault::OpenLoop));
        assert_eq!(
            reading.engineering,
            FixedPointValue::new(0, -1, UNIT_PERCENT)
        );
        assert!(reading.current_ua < NOMINAL_4MA_UA);
    }

    #[test]
    fn over_range_from_adc_counts_is_distinct() {
        let mut sensor = sensor();
        let reading = sensor.read(4_095);
        assert_eq!(reading.fault, Some(LoopFault::OverRange));
        assert!(reading.current_ua > DEFAULT_OVER_RANGE_UA);
        assert_eq!(
            reading.engineering,
            FixedPointValue::new(1_000, -1, UNIT_PERCENT)
        );
    }

    #[test]
    fn noise_is_detected_over_a_bounded_window() {
        let thresholds = FaultThresholds {
            noise_window: 4,
            max_noise_ua: 300,
            ..FaultThresholds::default()
        };
        let mut detector = FaultDetector::new(thresholds).unwrap();
        assert_eq!(detector.push(12_000), None);
        assert_eq!(detector.push(12_100), None);
        assert_eq!(detector.push(11_900), None);
        assert_eq!(detector.push(12_300), Some(LoopFault::Noisy));
    }

    #[test]
    fn stuck_value_is_detected_after_the_window() {
        let thresholds = FaultThresholds {
            stuck_window: 4,
            stuck_epsilon_ua: 1,
            ..FaultThresholds::default()
        };
        let mut detector = FaultDetector::new(thresholds).unwrap();
        assert_eq!(detector.push(12_000), None);
        assert_eq!(detector.push(12_000), None);
        assert_eq!(detector.push(12_001), None);
        assert_eq!(detector.push(12_000), Some(LoopFault::StuckValue));
        // A real change clears the stuck state.
        assert_eq!(detector.push(12_500), None);
        assert_eq!(detector.current_fault(), None);
    }

    #[test]
    fn calibration_validation_rejects_bad_tables() {
        let thresholds = FaultThresholds::default();
        let two = vec![
            CalibrationPoint::new(0, 4_000),
            CalibrationPoint::new(4_095, 20_000),
        ];

        assert!(matches!(
            CurrentLoopCalibration::new(vec![two[0]], 0, 100, -1, UNIT_PERCENT, thresholds),
            Err(CurrentLoopError::TooFewPoints { .. })
        ));
        assert!(matches!(
            CurrentLoopCalibration::new(
                vec![
                    CalibrationPoint::new(10, 4_000),
                    CalibrationPoint::new(5, 20_000)
                ],
                0,
                100,
                -1,
                UNIT_PERCENT,
                thresholds
            ),
            Err(CurrentLoopError::UnsortedAdcCounts { .. })
        ));
        assert!(matches!(
            CurrentLoopCalibration::new(
                vec![
                    CalibrationPoint::new(10, 4_000),
                    CalibrationPoint::new(10, 20_000)
                ],
                0,
                100,
                -1,
                UNIT_PERCENT,
                thresholds
            ),
            Err(CurrentLoopError::DuplicateAdcCounts(10))
        ));
        assert!(matches!(
            CurrentLoopCalibration::new(
                vec![
                    CalibrationPoint::new(0, 20_000),
                    CalibrationPoint::new(4_095, 4_000)
                ],
                0,
                100,
                -1,
                UNIT_PERCENT,
                thresholds
            ),
            Err(CurrentLoopError::NonMonotonicCurrent { .. })
        ));
        assert!(matches!(
            CurrentLoopCalibration::new(two.clone(), 0, 100, -1, 99, thresholds),
            Err(CurrentLoopError::UnitNotRegistered(99))
        ));
        assert!(matches!(
            CurrentLoopCalibration::new(two.clone(), 50, 50, -1, UNIT_PERCENT, thresholds),
            Err(CurrentLoopError::EmptyEngineeringSpan)
        ));
        assert!(matches!(
            CurrentLoopCalibration::new(
                two,
                0,
                100,
                -1,
                UNIT_PERCENT,
                FaultThresholds {
                    open_loop_ua: 4_000,
                    ..thresholds
                }
            ),
            Err(CurrentLoopError::InvalidThresholds(_))
        ));
    }

    #[test]
    fn engineering_unit_uses_the_registry_and_exponent() {
        let calibration = CurrentLoopCalibration::new(
            vec![
                CalibrationPoint::new(0, 4_000),
                CalibrationPoint::new(1_000, 20_000),
            ],
            -500,
            1_500,
            -2,
            UNIT_DEG_C,
            FaultThresholds::default(),
        )
        .unwrap();
        assert_eq!(calibration.unit(), UNIT_DEG_C);
        assert_eq!(calibration.exponent(), -2);
        assert_eq!(
            calibration.current_to_engineering(12_000),
            FixedPointValue::new(500, -2, UNIT_DEG_C)
        );
    }

    #[test]
    fn drift_detection_flags_shifted_points() {
        let reference = reference_calibration();
        let measured = CurrentLoopCalibration::new(
            vec![
                CalibrationPoint::new(683, 4_050),
                CalibrationPoint::new(1_366, 8_010),
                CalibrationPoint::new(2_048, 12_000),
                CalibrationPoint::new(2_730, 16_000),
                CalibrationPoint::new(3_413, 20_000),
            ],
            0,
            1_000,
            -1,
            UNIT_PERCENT,
            FaultThresholds::default(),
        )
        .unwrap();

        let tight = detect_drift(&reference, &measured, 20).unwrap();
        assert!(tight.drifted);
        assert_eq!(tight.max_abs_delta_ua, 50);
        assert_eq!(tight.points[0].delta_ua, 50);

        let loose = detect_drift(&reference, &measured, 50).unwrap();
        assert!(!loose.drifted);
        assert_eq!(loose.max_abs_delta_ua, 50);
        assert!(detect_drift(&reference, &measured, -1).is_err());
    }

    #[test]
    fn deterministic_boundary_sweep_stays_in_span() {
        let calibration = reference_calibration();
        for counts in (0..=u16::MAX).step_by(17) {
            let conversion = calibration.convert(u32::from(counts));
            assert!((0..=MAX_LOOP_UA).contains(&conversion.current_ua));
            assert!(conversion.engineering.mantissa >= 0);
            assert!(conversion.engineering.mantissa <= 1_000);
            assert_eq!(conversion.engineering.exponent, -1);
            assert_eq!(conversion.engineering.unit_id, UNIT_PERCENT);
        }
    }
}
