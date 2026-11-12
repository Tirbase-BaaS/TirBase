// SPDX-License-Identifier: Apache-2.0
//! `FixedPointValue` — integer-mantissa physical value with canonical-exponent enforcement.
//!
//! All guard-facing parameter values use this type; IEEE 754 floats are rejected at ingress.
//! Float −0 is normalised to integer 0 at the conversion boundary.
//!
//! **PV-21.1** — `canonical_exponent` must match the profile's `ParameterSpec.canonical_exponent`
//! for a command to be accepted at Stage 10.
//!
//! **INV-1** — no out-of-envelope actuation may occur; `compare_with_bounds` uses i128 arithmetic
//! to prevent overflow in envelope-bound comparisons (CLAIM-4.4).

use crate::UnitId;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can arise when constructing or converting a [`FixedPointValue`].
///
/// These error variants are distinct so callers can distinguish rejection causes:
/// - `NonFiniteInput` → float-to-fixed ingress path (CLAIM-4.3)
/// - `OverflowOnConversion` → canonical-exponent rescaling overflowed i64
/// - `LossyConversion` → canonical-exponent rescaling would be lossy (non-zero remainder)
/// - `UnitMismatch` → caller tried to compare values with different `unit_id`s (CLAIM-4.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FixedPointError {
 /// The input was NaN, +∞, or −∞ (IEEE 754 non-finite).
    NonFiniteInput,
 /// Rescaling to the canonical exponent would overflow an `i64` mantissa.
    OverflowOnConversion,
 /// Rescaling to the canonical exponent would be lossy (remainder is non-zero).
    LossyConversion,
 /// The two values have different `unit_id`s; comparison is undefined.
    UnitMismatch,
}

// ── BoundsCheck ───────────────────────────────────────────────────────────────

/// Result of an envelope bounds check (INV-1, CLAIM-4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundsCheck {
 /// `min ≤ self ≤ max` in the same unit.
    WithinBounds,
 /// `self < min`.
    BelowMin,
 /// `self > max`.
    AboveMax,
}

// ── FixedPointValue ───────────────────────────────────────────────────────────

/// Fixed-point physical value (PV-21.1, CLAIM-4.2).
///
/// Represents the quantity `mantissa × 10^exponent` in the unit identified by `unit_id`.
///
/// # Canonical-exponent invariant (Stage 10)
/// The guard checks that `self.exponent == profile.canonical_exponent` for the
/// addressed parameter before accepting a command. Use [`FixedPointValue::with_canonical_exponent`]
/// to rescale an incoming value, or reject it with [`FixedPointError::LossyConversion`] /
/// [`FixedPointError::OverflowOnConversion`] if exact rescaling is impossible.
///
/// # Integer representation of negative zero
/// Integer types have no negative zero; float −0.0 is normalised to 0 at the ingress
/// conversion boundary. There is no negative-zero issue in this type itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FixedPointValue {
 /// Signed integer mantissa.
    pub mantissa: i64,
 /// Power-of-ten exponent: value = `mantissa × 10^exponent`.
    pub exponent: i8,
 /// Unit identifier (from `docs/unit-registry.md`).
    pub unit_id: UnitId,
}

impl FixedPointValue {
 // ── Constructors ─────────────────────────────────────────────────────────

 /// Construct a new `FixedPointValue` directly from its components.
 ///
 /// No canonicalisation is performed here; use
 /// [`with_canonical_exponent`][Self::with_canonical_exponent] to enforce a profile
 /// canonical exponent before passing to the guard.
    #[inline]
    pub const fn new(mantissa: i64, exponent: i8, unit_id: UnitId) -> Self {
        Self {
            mantissa,
            exponent,
            unit_id,
        }
    }

 // ── Float-to-fixed conversion (CLAIM-4.3, PV-21.1, PV-21.3) ─────────────

 /// Convert a finite `f64` to a `FixedPointValue` at the given
 /// `target_exponent` and `unit_id`.
 ///
 /// This is the **ingress boundary** for any floating-point value entering the
 /// guard pipeline. It enforces the following invariants required by CLAIM-4.3:
 ///
 /// | Input | Result |
 /// |---------|--------|
 /// | NaN | `Err(FixedPointError::NonFiniteInput)` |
 /// | +∞ | `Err(FixedPointError::NonFiniteInput)` |
 /// | −∞ | `Err(FixedPointError::NonFiniteInput)` |
 /// | −0.0 | `Ok(…)` with `mantissa == 0` (normalised) |
 /// | overflow i64 | `Err(FixedPointError::OverflowOnConversion)` |
 ///
 /// # Scaling
 ///
 /// `mantissa = round(value × 10^(−target_exponent))`
 ///
 /// Example: `value = 25.5`, `target_exponent = -1` → `mantissa = 255`.
 ///
 /// # Wiring note (CLAIM-4.3 mutation check)
 /// The three non-finite checks are tagged with `// CLAIM-4.3` comments.
 /// Removing **any** of those three `return Err(…)` branches will cause the
 /// corresponding unit test (`from_f64_nan_rejected`, `from_f64_pos_inf_rejected`,
 /// `from_f64_neg_inf_rejected`) and the ingress-boundary integration test in
 /// `tirbase-guard` to fail.
    pub fn from_f64(
        value: f64,
        target_exponent: i8,
        unit_id: UnitId,
    ) -> Result<Self, FixedPointError> {
 // ── CLAIM-4.3: non-finite rejection ──────────────────────────────────
 // NaN must be checked first because NaN comparisons always return false.
        if value.is_nan() {
            return Err(FixedPointError::NonFiniteInput); // CLAIM-4.3 NaN check
        }
        if value == f64::INFINITY {
            return Err(FixedPointError::NonFiniteInput); // CLAIM-4.3 +∞ check
        }
        if value == f64::NEG_INFINITY {
            return Err(FixedPointError::NonFiniteInput); // CLAIM-4.3 −∞ check
        }
 // ─────────────────────────────────────────────────────────────────────

 // Normalise IEEE 754 −0 to +0. Integer types have no negative zero;
 // this is the only place in the codebase where float −0 can appear.
        let value = if value == 0.0_f64 { 0.0_f64 } else { value };

 // Scale: mantissa = round(value × 10^(−target_exponent)).
 // `libm` is used so this compiles under `no_std` (core `f64` has no inherent `powi`/`round`).
        let scale = libm::pow(10.0_f64, -(target_exponent as f64));
        let scaled = value * scale;

 // Reject values that cannot be represented as i64 before casting.
 // `i64::MAX as f64` is the largest representable f64 that fits in i64.
        if scaled > i64::MAX as f64 || scaled < i64::MIN as f64 {
            return Err(FixedPointError::OverflowOnConversion);
        }

        let mantissa = libm::round(scaled) as i64;
        Ok(FixedPointValue {
            mantissa,
            exponent: target_exponent,
            unit_id,
        })
    }

 // ── Canonical-exponent enforcement (CLAIM-4.2, PV-21.1) ─────────────────

 /// Rescale this value to `canonical` exponent.
 ///
 /// Returns `Ok(rescaled)` only when the rescaling is *exact* and does not overflow
 /// an `i64` mantissa. Errors otherwise:
 ///
 /// - If `self.exponent == canonical`: returns `Ok(*self)` (identity).
 /// - If `canonical < self.exponent` (multiply): computes `scale = 10^(self.exponent −
 /// canonical)` and uses [`i64::checked_mul`] to detect overflow.
 /// - If `canonical > self.exponent` (divide): only succeeds if `mantissa % scale == 0`.
 ///
 /// The `unit_id` is preserved unchanged.
 ///
 /// # Errors
 /// - [`FixedPointError::OverflowOnConversion`] — scale factor overflows `i64`.
 /// - [`FixedPointError::LossyConversion`] — divide path has a non-zero remainder.
    pub fn with_canonical_exponent(&self, canonical: i8) -> Result<Self, FixedPointError> {
        if self.exponent == canonical {
            return Ok(*self);
        }

 // exp_delta > 0 means we need to multiply (canonical is more negative).
 // exp_delta < 0 means we need to divide (canonical is less negative / larger).
        let exp_delta = self.exponent as i16 - canonical as i16;

        if exp_delta > 0 {
 // self.exponent > canonical → multiply mantissa by 10^exp_delta
            let scale =
                checked_pow10(exp_delta as u32).ok_or(FixedPointError::OverflowOnConversion)?;
            let new_mantissa = self
                .mantissa
                .checked_mul(scale)
                .ok_or(FixedPointError::OverflowOnConversion)?;
            Ok(Self {
                mantissa: new_mantissa,
                exponent: canonical,
                unit_id: self.unit_id,
            })
        } else {
 // self.exponent < canonical → divide mantissa by 10^(exp_delta)
            let neg_delta = (-exp_delta) as u32;
            let scale = checked_pow10(neg_delta).ok_or(FixedPointError::OverflowOnConversion)?;
            if self.mantissa % scale != 0 {
                return Err(FixedPointError::LossyConversion);
            }
            Ok(Self {
                mantissa: self.mantissa / scale,
                exponent: canonical,
                unit_id: self.unit_id,
            })
        }
    }

 // ── Envelope bounds comparison (CLAIM-4.4, INV-1) ────────────────────────

 /// Compare `self` against envelope bounds `[min, max]` using **i128 arithmetic**
 /// to prevent overflow (CLAIM-4.4).
 ///
 /// All three values (`self`, `min`, `max`) must carry the same `unit_id`; otherwise
 /// [`FixedPointError::UnitMismatch`] is returned.
 ///
 /// The comparison normalises all three to the most-negative common exponent so no
 /// precision is lost, then compares the resulting i128 mantissas.
 ///
 /// # Errors
 /// - [`FixedPointError::UnitMismatch`] — unit IDs differ.
 /// - [`FixedPointError::OverflowOnConversion`] — scale factor does not fit i128
 /// (can only occur with exponent spans > 38; practically impossible for PV-21
 /// values which use `i8` exponents spanning at most 255 steps, but safely handled).
    pub fn compare_with_bounds(
        &self,
        min: &FixedPointValue,
        max: &FixedPointValue,
    ) -> Result<BoundsCheck, FixedPointError> {
        if self.unit_id != min.unit_id || self.unit_id != max.unit_id {
            return Err(FixedPointError::UnitMismatch);
        }

 // Choose the most-negative (finest-resolution) exponent as the common base.
        let common_exp = self.exponent.min(min.exponent).min(max.exponent);

        let self_m = scale_to_i128(self.mantissa, self.exponent, common_exp)?;
        let min_m = scale_to_i128(min.mantissa, min.exponent, common_exp)?;
        let max_m = scale_to_i128(max.mantissa, max.exponent, common_exp)?;

        if self_m < min_m {
            Ok(BoundsCheck::BelowMin)
        } else if self_m > max_m {
            Ok(BoundsCheck::AboveMax)
        } else {
            Ok(BoundsCheck::WithinBounds)
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Compute `10^exp` as `i64`, returning `None` on overflow.
/// Only called with exponents derived from `i8` differences, so max is 255.
fn checked_pow10(exp: u32) -> Option<i64> {
 // i64::MAX ≈ 9.2 × 10^18; 10^19 overflows.
    if exp > 18 {
        return None;
    }
    let mut result: i64 = 1;
    for _ in 0..exp {
        result = result.checked_mul(10)?;
    }
    Some(result)
}

/// Scale `mantissa` (which is at `src_exp`) to `dst_exp` using i128 arithmetic.
///
/// The arithmetic itself lives in [`fixed_point_core`] so that the Kani proof
/// (CLAIM-51.6) verifies the exact code this function compiles.
/// Returns an error if the required scale factor overflows i128.
fn scale_to_i128(mantissa: i64, src_exp: i8, dst_exp: i8) -> Result<i128, FixedPointError> {
    let exp_delta = src_exp as i16 - dst_exp as i16;
    debug_assert!(
        exp_delta >= 0,
        "dst_exp must be ≤ src_exp (we chose the minimum)"
    );
    crate::fixed_point_core::scale_mantissa(mantissa, exp_delta)
        .ok_or(FixedPointError::OverflowOnConversion)
}

// ── Unit ID constants (docs/unit-registry.md) ────────────────────────────────

/// Reserved — unknown / dimensionless. MUST NOT be used for physical quantities.
/// Any command with `unit_id == UNIT_UNKNOWN` for a typed parameter is rejected at Stage 10.
pub const UNIT_UNKNOWN: UnitId = 0;

/// Degrees Celsius (temperature).
pub const UNIT_DEG_C: UnitId = 1;

/// Pascal (pressure).
pub const UNIT_PA: UnitId = 2;

/// Revolutions per minute (angular velocity).
pub const UNIT_RPM: UnitId = 3;

/// Bar (pressure; 1 bar = 100 000 Pa).
pub const UNIT_BAR: UnitId = 4;

/// Kilowatt (power).
pub const UNIT_KW: UnitId = 5;

/// Percent (dimensionless ratio; range typically [0, 100]).
pub const UNIT_PERCENT: UnitId = 6;

/// Boolean (0 = false, 1 = true; mantissa MUST be 0 or 1).
pub const UNIT_BOOLEAN: UnitId = 7;

/// Kilopascal (pressure; 1 kPa = 1 000 Pa).
pub const UNIT_KPA: UnitId = 8;

/// Cubic metres per hour (volumetric flow rate).
pub const UNIT_M3H: UnitId = 9;

/// Volt (electric potential).
pub const UNIT_V: UnitId = 10;

/// Ampere (electric current — SI base unit).
pub const UNIT_A: UnitId = 11;

/// Hertz (frequency).
pub const UNIT_HZ: UnitId = 12;

// ── UnitDescriptor ────────────────────────────────────────────────────────────

/// Human-readable descriptor for a `UnitId`.
/// Used for logging and diagnostics only — never at the guard boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitDescriptor {
    pub id: UnitId,
 /// Short symbol, e.g. `"degC"`.
    pub label: &'static str,
 /// Physical dimension, e.g. `"temperature"`.
    pub dimension: &'static str,
}

/// Static table of all registered unit descriptors (mirrors `docs/unit-registry.md`).
pub const UNIT_DESCRIPTORS: &[UnitDescriptor] = &[
    UnitDescriptor {
        id: UNIT_UNKNOWN,
        label: "unknown",
        dimension: "dimensionless",
    },
    UnitDescriptor {
        id: UNIT_DEG_C,
        label: "degC",
        dimension: "temperature",
    },
    UnitDescriptor {
        id: UNIT_PA,
        label: "Pa",
        dimension: "pressure",
    },
    UnitDescriptor {
        id: UNIT_RPM,
        label: "rpm",
        dimension: "angular_velocity",
    },
    UnitDescriptor {
        id: UNIT_BAR,
        label: "bar",
        dimension: "pressure",
    },
    UnitDescriptor {
        id: UNIT_KW,
        label: "kW",
        dimension: "power",
    },
    UnitDescriptor {
        id: UNIT_PERCENT,
        label: "percent",
        dimension: "dimensionless_ratio",
    },
    UnitDescriptor {
        id: UNIT_BOOLEAN,
        label: "boolean",
        dimension: "dimensionless",
    },
    UnitDescriptor {
        id: UNIT_KPA,
        label: "kPa",
        dimension: "pressure",
    },
    UnitDescriptor {
        id: UNIT_M3H,
        label: "m3h",
        dimension: "volumetric_flow",
    },
    UnitDescriptor {
        id: UNIT_V,
        label: "V",
        dimension: "electric_potential",
    },
    UnitDescriptor {
        id: UNIT_A,
        label: "A",
        dimension: "electric_current",
    },
    UnitDescriptor {
        id: UNIT_HZ,
        label: "Hz",
        dimension: "frequency",
    },
];

/// Look up a [`UnitDescriptor`] by its integer ID.
pub fn unit_descriptor(id: UnitId) -> Option<&'static UnitDescriptor> {
    UNIT_DESCRIPTORS.iter().find(|d| d.id == id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

 // ── Helpers ──────────────────────────────────────────────────────────────

    fn fpv(mantissa: i64, exponent: i8) -> FixedPointValue {
        FixedPointValue::new(mantissa, exponent, UNIT_DEG_C)
    }

 // ── from_f64 (CLAIM-4.3, PV-21.1, PV-21.3) ──────────────────────────────

 /// NaN must be rejected (CLAIM-4.3 wiring check — removing the NaN branch fails this test).
    #[test]
    fn from_f64_nan_rejected() {
        let result = FixedPointValue::from_f64(f64::NAN, -1, UNIT_DEG_C);
        assert_eq!(result, Err(FixedPointError::NonFiniteInput));
    }

 /// +∞ must be rejected (CLAIM-4.3 wiring check — removing the +∞ branch fails this test).
    #[test]
    fn from_f64_pos_inf_rejected() {
        let result = FixedPointValue::from_f64(f64::INFINITY, -1, UNIT_DEG_C);
        assert_eq!(result, Err(FixedPointError::NonFiniteInput));
    }

 /// −∞ must be rejected (CLAIM-4.3 wiring check — removing the −∞ branch fails this test).
    #[test]
    fn from_f64_neg_inf_rejected() {
        let result = FixedPointValue::from_f64(f64::NEG_INFINITY, -1, UNIT_DEG_C);
        assert_eq!(result, Err(FixedPointError::NonFiniteInput));
    }

 /// IEEE 754 −0.0 normalises to integer 0; the mantissa must be 0 (PV-21.3).
    #[test]
    fn from_f64_negative_zero_normalises_to_zero() {
        let fpv = FixedPointValue::from_f64(-0.0_f64, -1, UNIT_DEG_C).unwrap();
        assert_eq!(fpv.mantissa, 0, "−0.0 must normalise to integer 0");
        assert_eq!(fpv.exponent, -1);
        assert_eq!(fpv.unit_id, UNIT_DEG_C);
    }

 /// +0.0 also converts to mantissa 0.
    #[test]
    fn from_f64_positive_zero() {
        let fpv = FixedPointValue::from_f64(0.0_f64, -1, UNIT_DEG_C).unwrap();
        assert_eq!(fpv.mantissa, 0);
    }

 /// 25.5 °C with exponent -1 → mantissa 255 (canonical example from PV-21.1).
    #[test]
    fn from_f64_25_5_celsius_exp_neg1() {
        let fpv = FixedPointValue::from_f64(25.5_f64, -1, UNIT_DEG_C).unwrap();
        assert_eq!(fpv.mantissa, 255);
        assert_eq!(fpv.exponent, -1);
        assert_eq!(fpv.unit_id, UNIT_DEG_C);
    }

 /// Negative temperature: −3.7 °C with exponent -1 → mantissa −37.
    #[test]
    fn from_f64_neg_3_7_celsius() {
        let fpv = FixedPointValue::from_f64(-3.7_f64, -1, UNIT_DEG_C).unwrap();
        assert_eq!(fpv.mantissa, -37);
        assert_eq!(fpv.exponent, -1);
    }

 /// Integer value with exponent 0: 100.0 → mantissa 100.
    #[test]
    fn from_f64_integer_exponent_zero() {
        let fpv = FixedPointValue::from_f64(100.0_f64, 0, UNIT_DEG_C).unwrap();
        assert_eq!(fpv.mantissa, 100);
        assert_eq!(fpv.exponent, 0);
    }

 /// Positive exponent: 25000.0 with exponent 3 → mantissa 25.
    #[test]
    fn from_f64_positive_exponent() {
        let fpv = FixedPointValue::from_f64(25000.0_f64, 3, UNIT_DEG_C).unwrap();
        assert_eq!(fpv.mantissa, 25);
        assert_eq!(fpv.exponent, 3);
    }

 /// Value too large to fit in i64 → OverflowOnConversion.
    #[test]
    fn from_f64_overflow_positive() {
 // 1e30 scaled by 10^18 (exponent -18) overflows i64
        let result = FixedPointValue::from_f64(1e30_f64, -18, UNIT_DEG_C);
        assert_eq!(result, Err(FixedPointError::OverflowOnConversion));
    }

 /// Negative value too large to fit in i64 → OverflowOnConversion.
    #[test]
    fn from_f64_overflow_negative() {
        let result = FixedPointValue::from_f64(-1e30_f64, -18, UNIT_DEG_C);
        assert_eq!(result, Err(FixedPointError::OverflowOnConversion));
    }

 /// Different unit IDs are stored correctly.
    #[test]
    fn from_f64_unit_id_preserved() {
        let fpv = FixedPointValue::from_f64(101.325_f64, -3, UNIT_KPA).unwrap();
        assert_eq!(fpv.unit_id, UNIT_KPA);
    }

 // ── with_canonical_exponent ─────────────────────────────────────────────── /// Identity: exponent already canonical → Ok, unchanged.
    #[test]
    fn canonical_identity() {
        let v = fpv(123, -2);
        assert_eq!(v.with_canonical_exponent(-2), Ok(fpv(123, -2)));
    }

 /// Multiply path (canonical more negative): 123 × 10^-2 → 12300 × 10^-4.
    #[test]
    fn canonical_multiply_exact() {
        let v = fpv(123, -2);
        let r = v.with_canonical_exponent(-4).unwrap();
        assert_eq!(r.mantissa, 12300);
        assert_eq!(r.exponent, -4);
    }

 /// Multiply overflow: huge mantissa that would overflow i64.
    #[test]
    fn canonical_multiply_overflow() {
        let v = fpv(i64::MAX, 0);
        assert_eq!(
            v.with_canonical_exponent(-1),
            Err(FixedPointError::OverflowOnConversion)
        );
    }

 /// Divide path (canonical less negative / larger): 12300 × 10^-4 → 123 × 10^-2.
    #[test]
    fn canonical_divide_exact() {
        let v = fpv(12300, -4);
        let r = v.with_canonical_exponent(-2).unwrap();
        assert_eq!(r.mantissa, 123);
        assert_eq!(r.exponent, -2);
    }

 /// Divide path lossy: 12301 × 10^-4 cannot be exactly represented at 10^-2.
    #[test]
    fn canonical_divide_lossy() {
        let v = fpv(12301, -4);
        assert_eq!(
            v.with_canonical_exponent(-2),
            Err(FixedPointError::LossyConversion)
        );
    }

 /// Large exponent difference still works correctly (e.g. 1 × 10^0 → 1000000 × 10^-6).
    #[test]
    fn canonical_large_delta_exact() {
        let v = fpv(1, 0);
        let r = v.with_canonical_exponent(-6).unwrap();
        assert_eq!(r.mantissa, 1_000_000);
        assert_eq!(r.exponent, -6);
    }

 /// Exponent delta > 18 overflows.
    #[test]
    fn canonical_delta_too_large_overflows() {
        let v = fpv(1, 0);
 // canonical = -19 → delta = 19 → 10^19 > i64::MAX
        assert_eq!(
            v.with_canonical_exponent(-19),
            Err(FixedPointError::OverflowOnConversion)
        );
    }

 /// unit_id is preserved across rescaling.
    #[test]
    fn canonical_preserves_unit_id() {
        let v = FixedPointValue::new(42, -1, UNIT_PA);
        let r = v.with_canonical_exponent(-2).unwrap();
        assert_eq!(r.unit_id, UNIT_PA);
    }

 // ── compare_with_bounds ───────────────────────────────────────────────────

    fn bounds_check(
        v: i64,
        v_exp: i8,
        lo: i64,
        lo_exp: i8,
        hi: i64,
        hi_exp: i8,
    ) -> Result<BoundsCheck, FixedPointError> {
        let val = FixedPointValue::new(v, v_exp, UNIT_DEG_C);
        let min = FixedPointValue::new(lo, lo_exp, UNIT_DEG_C);
        let max = FixedPointValue::new(hi, hi_exp, UNIT_DEG_C);
        val.compare_with_bounds(&min, &max)
    }

 /// 5.0 in [0.0, 10.0] → WithinBounds.
    #[test]
    fn bounds_within() {
        assert_eq!(
            bounds_check(50, -1, 0, 0, 100, -1),
            Ok(BoundsCheck::WithinBounds)
        );
    }

 /// −1 < 0 → BelowMin.
    #[test]
    fn bounds_below_min() {
        assert_eq!(bounds_check(-1, 0, 0, 0, 100, 0), Ok(BoundsCheck::BelowMin));
    }

 /// 101 > 100 → AboveMax.
    #[test]
    fn bounds_above_max() {
        assert_eq!(
            bounds_check(101, 0, 0, 0, 100, 0),
            Ok(BoundsCheck::AboveMax)
        );
    }

 /// Exact boundary values are WithinBounds (inclusive).
    #[test]
    fn bounds_at_min_exact() {
        assert_eq!(
            bounds_check(0, 0, 0, 0, 100, 0),
            Ok(BoundsCheck::WithinBounds)
        );
    }

    #[test]
    fn bounds_at_max_exact() {
        assert_eq!(
            bounds_check(100, 0, 0, 0, 100, 0),
            Ok(BoundsCheck::WithinBounds)
        );
    }

 /// Mixed exponents: 5.0 (as 50 × 10^-1) against bounds in different exponents.
    #[test]
    fn bounds_mixed_exponents() {
 // val = 500 × 10^-2 = 5.0
 // min = 0 × 10^0 = 0.0
 // max = 100 × 10^-1 = 10.0
        assert_eq!(
            bounds_check(500, -2, 0, 0, 100, -1),
            Ok(BoundsCheck::WithinBounds)
        );
    }

 /// Unit mismatch returns an error.
    #[test]
    fn bounds_unit_mismatch_self_vs_min() {
        let val = FixedPointValue::new(50, -1, UNIT_DEG_C);
        let min = FixedPointValue::new(0, 0, UNIT_PA);
        let max = FixedPointValue::new(100, -1, UNIT_DEG_C);
        assert_eq!(
            val.compare_with_bounds(&min, &max),
            Err(FixedPointError::UnitMismatch)
        );
    }

    #[test]
    fn bounds_unit_mismatch_self_vs_max() {
        let val = FixedPointValue::new(50, -1, UNIT_DEG_C);
        let min = FixedPointValue::new(0, 0, UNIT_DEG_C);
        let max = FixedPointValue::new(100, -1, UNIT_PA);
        assert_eq!(
            val.compare_with_bounds(&min, &max),
            Err(FixedPointError::UnitMismatch)
        );
    }

 /// Large i64 values use i128 intermediates without overflow.
    #[test]
    fn bounds_large_values_no_overflow() {
 // mantissa near i64::MAX in the same exponent — must compare without overflow
        let val = FixedPointValue::new(i64::MAX - 1, 0, UNIT_DEG_C);
        let min = FixedPointValue::new(0, 0, UNIT_DEG_C);
        let max = FixedPointValue::new(i64::MAX, 0, UNIT_DEG_C);
        assert_eq!(
            val.compare_with_bounds(&min, &max),
            Ok(BoundsCheck::WithinBounds)
        );
    }

 // ── UnitId constants ─────────────────────────────────────────────────────

    #[test]
    fn unit_ids_match_registry() {
        assert_eq!(UNIT_DEG_C, 1);
        assert_eq!(UNIT_PA, 2);
        assert_eq!(UNIT_RPM, 3);
        assert_eq!(UNIT_BAR, 4);
        assert_eq!(UNIT_KW, 5);
        assert_eq!(UNIT_PERCENT, 6);
        assert_eq!(UNIT_BOOLEAN, 7);
        assert_eq!(UNIT_KPA, 8);
        assert_eq!(UNIT_M3H, 9);
        assert_eq!(UNIT_V, 10);
        assert_eq!(UNIT_A, 11);
        assert_eq!(UNIT_HZ, 12);
 // 0 is reserved
        assert_eq!(UNIT_UNKNOWN, 0);
    }

    #[test]
    fn unit_descriptor_lookup() {
        let d = unit_descriptor(UNIT_DEG_C).unwrap();
        assert_eq!(d.label, "degC");
        assert_eq!(d.dimension, "temperature");

        assert!(unit_descriptor(99).is_none());
    }

 // ── serde round-trip ─────────────────────────────────────────────────────

    #[cfg(test)]
    #[test]
    fn fixed_point_serde_roundtrip() {
        let v = FixedPointValue::new(-123456, -4, UNIT_KPA);
        let json = serde_json::to_string(&v).unwrap();
        let back: FixedPointValue = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn fixed_point_error_serde_roundtrip() {
        let e = FixedPointError::LossyConversion;
        let json = serde_json::to_string(&e).unwrap();
        let back: FixedPointError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

 // ── checked_pow10 ────────────────────────────────────────────────────────

    #[test]
    fn checked_pow10_edge_cases() {
        assert_eq!(super::checked_pow10(0), Some(1));
        assert_eq!(super::checked_pow10(1), Some(10));
        assert_eq!(
            super::checked_pow10(18),
            Some(1_000_000_000_000_000_000_i64)
        );
        assert_eq!(super::checked_pow10(19), None);
        assert_eq!(super::checked_pow10(100), None);
    }
}

// ── Property-based tests (CLAIM-4.4, PV-21.1) ────────────────────────────────
//
// **Validates: Requirements PV-21.1 (CLAIM-4.4)**
//
// These properties verify that `compare_with_bounds` behaves correctly across
// arbitrary mantissa/exponent inputs using i128 arithmetic.
//
// # Wiring mutation check
// The property `p_boundary_i64_overflow` is specifically designed to catch the
// regression described in CLAIM-4.4: reverting `scale_to_i128` from i128 to i64
// arithmetic causes this property to fail for mantissa values near i64::MAX where
// `mantissa * 10` overflows i64 but is well-defined in i128.
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

 // ── Strategies ────────────────────────────────────────────────────────────

 /// Safe exponent range: [-18, 18].
 /// Exponents outside this range risk i128 overflow in scale_to_i128 when the
 /// span between two exponents exceeds 38; that error path is tested separately
 /// in the unit tests above.
    fn safe_exp() -> impl Strategy<Value = i8> {
        -18_i8..=18_i8
    }

    fn fpv_with_exp(unit_id: UnitId, exp: i8) -> impl Strategy<Value = FixedPointValue> {
        any::<i64>().prop_map(move |m| FixedPointValue {
            mantissa: m,
            exponent: exp,
            unit_id,
        })
    }

    fn fpv_any(unit_id: UnitId) -> impl Strategy<Value = FixedPointValue> {
        safe_exp().prop_flat_map(move |e| fpv_with_exp(unit_id, e))
    }

 // ── Properties ────────────────────────────────────────────────────────────

    proptest! {
 // ── P1: compare_with_bounds is self-consistent at min boundary ────────
 //
 // For any value V and any max ≥ V (same exponent), V.compare_with_bounds(V, max)
 // must be WithinBounds.
 //
 // This property catches an off-by-one in the < vs ≤ boundary; it also
 // detects sign errors that would arise from a naive i64 cast.
        #[test]
        fn p1_at_min_boundary_is_within_bounds(
            base in (-10_000_i64..=10_000_i64),
            offset in (0_i64..=10_000_i64),
            exp in safe_exp(),
        ) {
            let min = FixedPointValue::new(base, exp, UNIT_DEG_C);
            let max = FixedPointValue::new(base.saturating_add(offset), exp, UNIT_DEG_C);
            let result = min.compare_with_bounds(&min, &max);
            match result {
                Ok(r) => prop_assert_eq!(r, BoundsCheck::WithinBounds,
                    "at-min must be WithinBounds (base={}, offset={}, exp={})", base, offset, exp),
                Err(FixedPointError::OverflowOnConversion) => {}
                Err(e) => prop_assert!(false, "unexpected error {:?}", e),
            }
        }

 // ── P2: compare_with_bounds is self-consistent at max boundary ────────
        #[test]
        fn p2_at_max_boundary_is_within_bounds(
            base in (-10_000_i64..=10_000_i64),
            offset in (0_i64..=10_000_i64),
            exp in safe_exp(),
        ) {
            let min = FixedPointValue::new(base.saturating_sub(offset), exp, UNIT_DEG_C);
            let max = FixedPointValue::new(base, exp, UNIT_DEG_C);
            let result = max.compare_with_bounds(&min, &max);
            match result {
                Ok(r) => prop_assert_eq!(r, BoundsCheck::WithinBounds,
                    "at-max must be WithinBounds (base={}, offset={}, exp={})", base, offset, exp),
                Err(FixedPointError::OverflowOnConversion) => {}
                Err(e) => prop_assert!(false, "unexpected error {:?}", e),
            }
        }

 // ── P3: unit mismatch always returns UnitMismatch ─────────────────────
        #[test]
        fn p3_unit_mismatch_always_errors(
            v  in fpv_any(UNIT_DEG_C),
            lo in fpv_any(UNIT_PA),      // different unit from v and hi
            hi in fpv_any(UNIT_DEG_C),
        ) {
            prop_assert_eq!(
                v.compare_with_bounds(&lo, &hi),
                Err(FixedPointError::UnitMismatch)
            );
        }

 // ── P4: value one mantissa unit below min → BelowMin ─────────────────
 //
 // When all three values share the same exponent and val = min − 1,
 // the result must be BelowMin (no overflow possible for small values).
        #[test]
        fn p4_one_below_min_is_below_min(
            min_m in (i64::MIN + 2..=10_000_i64),
        ) {
            let val = FixedPointValue::new(min_m - 1, 0, UNIT_DEG_C);
            let min = FixedPointValue::new(min_m,     0, UNIT_DEG_C);
            let max = FixedPointValue::new(min_m.saturating_add(100), 0, UNIT_DEG_C);
            prop_assert_eq!(
                val.compare_with_bounds(&min, &max),
                Ok(BoundsCheck::BelowMin)
            );
        }

 // ── P5: value one mantissa unit above max → AboveMax ─────────────────
        #[test]
        fn p5_one_above_max_is_above_max(
            max_m in (-10_000_i64..=i64::MAX - 2),
        ) {
            let val = FixedPointValue::new(max_m + 1, 0, UNIT_DEG_C);
            let min = FixedPointValue::new(max_m.saturating_sub(100), 0, UNIT_DEG_C);
            let max = FixedPointValue::new(max_m, 0, UNIT_DEG_C);
            prop_assert_eq!(
                val.compare_with_bounds(&min, &max),
                Ok(BoundsCheck::AboveMax)
            );
        }

 // ── P6 (CLAIM-4.4 wiring mutation check) ─────────────────────────────
 //
 // For any large_m in [i64::MAX/10 + 1, i64::MAX], compare:
 // val = large_m × 10^0 against bounds [0 × 10^0, large_m × 10^1].
 //
 // Correct result: WithinBounds (val equals the min, and max = 10 × val ≥ val).
 //
 // With i64 arithmetic:
 // common_exp = min(0, 0, 1) = 0.
 // max_scaled = large_m * 10 → OVERFLOWS i64 for large_m ≥ i64::MAX/10.
 // The overflow either panics (debug) or wraps to a negative value (release),
 // causing the comparison to return AboveMax instead of WithinBounds.
 //
 // With i128 arithmetic (CLAIM-4.4):
 // max_scaled = large_m as i128 * 10 — always fits in i128.
 // Correct result: WithinBounds.
 //
 // Removing the i128 cast in `scale_to_i128` will make this property fail.
        #[test]
        fn p6_boundary_i64_overflow_caught_by_i128(
            large_m in ((i64::MAX / 10 + 1)..=i64::MAX),
        ) {
            let val = FixedPointValue::new(large_m, 0, UNIT_DEG_C);
            let min = FixedPointValue::new(0,        0, UNIT_DEG_C);
 // max = large_m × 10^1 > val × 10^0, so val is WithinBounds.
            let max = FixedPointValue::new(large_m,  1, UNIT_DEG_C);

            match val.compare_with_bounds(&min, &max) {
                Ok(BoundsCheck::WithinBounds) => {} // correct
                Ok(BoundsCheck::AboveMax) => prop_assert!(
                    false,
                    "got AboveMax for large_m={}: i64 overflow in comparison? \
                     CLAIM-4.4 i128 arithmetic may have been reverted",
                    large_m
                ),
                Ok(BoundsCheck::BelowMin) => prop_assert!(
                    false,
                    "got BelowMin for large_m={}: unexpected result",
                    large_m
                ),
                Err(FixedPointError::OverflowOnConversion) => {} // acceptable if scale overflows i128
                Err(e) => prop_assert!(false, "unexpected error {:?} for large_m={}", e, large_m),
            }
        }

 // ── P7: symmetric i64::MIN boundary (negative overflow) ───────────────
 //
 // Mirrors P6 for negative mantissa values. With i64 arithmetic:
 // min_scaled = i64::MIN as i64 * 10 → OVERFLOWS (undefined behaviour or wraps).
 // With i128: correct.
        #[test]
        fn p7_neg_boundary_i64_overflow_caught_by_i128(
            large_neg in (i64::MIN..=(i64::MIN / 10 - 1)),
        ) {
 // min = large_neg × 10^1 (very negative)
 // max = 0 × 10^0
 // val = large_neg × 10^0 → should be WithinBounds (min ≤ val ≤ max).
            let val = FixedPointValue::new(large_neg, 0, UNIT_DEG_C);
            let min = FixedPointValue::new(large_neg, 1, UNIT_DEG_C);  // 10× more negative
            let max = FixedPointValue::new(0,          0, UNIT_DEG_C);

            match val.compare_with_bounds(&min, &max) {
                Ok(BoundsCheck::WithinBounds) => {} // correct
                Ok(BoundsCheck::BelowMin) => prop_assert!(
                    false,
                    "got BelowMin for large_neg={}: i64 overflow in comparison? \
                     CLAIM-4.4 i128 arithmetic may have been reverted",
                    large_neg
                ),
                Ok(BoundsCheck::AboveMax) => prop_assert!(
                    false,
                    "got AboveMax for large_neg={}: unexpected result",
                    large_neg
                ),
                Err(FixedPointError::OverflowOnConversion) => {}
                Err(e) => prop_assert!(false, "unexpected error {:?} for large_neg={}", e, large_neg),
            }
        }

 // ── P8: compare_with_bounds result is internally consistent ───────────
 //
 // If a value is WithinBounds it must be ≥ min and ≤ max when evaluated
 // with same-exponent comparison. This catches subtle boundary errors
 // that affect all arithmetic widths equally.
        #[test]
        fn p8_within_bounds_agrees_with_direct_compare(
            v_m in (-1_000_i64..=1_000_i64),
            lo_m in (-1_000_i64..=1_000_i64),
            hi_m in (-1_000_i64..=1_000_i64),
        ) {
            let val = FixedPointValue::new(v_m,  0, UNIT_DEG_C);
            let min = FixedPointValue::new(lo_m, 0, UNIT_DEG_C);
            let max = FixedPointValue::new(hi_m, 0, UNIT_DEG_C);

            match val.compare_with_bounds(&min, &max) {
                Ok(BoundsCheck::WithinBounds) => {
                    prop_assert!(v_m >= lo_m && v_m <= hi_m,
                        "WithinBounds but v_m={} not in [{}, {}]", v_m, lo_m, hi_m);
                }
                Ok(BoundsCheck::BelowMin) => {
                    prop_assert!(v_m < lo_m,
                        "BelowMin but v_m={} >= lo_m={}", v_m, lo_m);
                }
                Ok(BoundsCheck::AboveMax) => {
                    prop_assert!(v_m > hi_m,
                        "AboveMax but v_m={} <= hi_m={}", v_m, hi_m);
                }
                Err(_) => {} // overflow handled elsewhere
            }
        }
    }
}
