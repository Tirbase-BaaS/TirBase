//! Scenario S30 — exponent-overflow value (PV-21, INV-1).
//!
//! A command carrying `mantissa = i64::MAX` and an extreme exponent must be
//! rejected during canonical rescaling or bounds comparison, never wrapped into
//! an accepted in-envelope value.

use tirbase_types::fixed_point::{BoundsCheck, FixedPointError};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

/// S30 — non-canonical/overflowing exponents fail closed in the production
/// `FixedPointValue` arithmetic used by Stage 10/11.
pub fn run_s30(seed: u64) -> Result<(), String> {
    let canonical = -1 + (seed % 3) as i8;

    // Stage 10: canonical-exponent enforcement.  Rescaling i64::MAX at
    // exponent 100 down to a canonical fractional exponent requires 10^101,
    // which cannot be represented; the production conversion must error.
    let overflow_value = FixedPointValue::new(i64::MAX, 100, UNIT_DEG_C);
    match overflow_value.with_canonical_exponent(canonical) {
        Err(FixedPointError::OverflowOnConversion) => {}
        other => {
            return Err(format!(
                "S30 FAIL: exponent-100 i64::MAX was not rejected as overflow: {other:?}"
            ))
        }
    }

    // Stage 11: a bounds comparison whose exponent span exceeds i128 scale
    // must error rather than wrap.
    let huge = FixedPointValue::new(i64::MAX, 127, UNIT_DEG_C);
    let min = FixedPointValue::new(i64::MIN, -128, UNIT_DEG_C);
    let max = FixedPointValue::new(i64::MAX, -128, UNIT_DEG_C);
    match huge.compare_with_bounds(&min, &max) {
        Err(FixedPointError::OverflowOnConversion) => {}
        other => {
            return Err(format!(
                "S30 FAIL: bounds comparison overflow was not detected: {other:?}"
            ))
        }
    }

    // Control: the same i64::MAX mantissa at a canonical exponent still
    // compares correctly (no artificial rejection).
    let in_range = FixedPointValue::new(i64::MAX, -1, UNIT_DEG_C);
    let normal_min = FixedPointValue::new(0, -1, UNIT_DEG_C);
    let normal_max = FixedPointValue::new(1_000, -1, UNIT_DEG_C);
    match in_range.compare_with_bounds(&normal_min, &normal_max) {
        Ok(BoundsCheck::AboveMax) => Ok(()),
        other => Err(format!(
            "S30 FAIL: canonical i64::MAX comparison behaved unexpectedly: {other:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s30_exponent_overflow_rejected() {
        run_s30(1).expect("S30");
    }
}
