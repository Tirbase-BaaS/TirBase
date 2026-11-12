// Dependency-free fixed-point arithmetic core (INV-1, CLAIM-4.4, CLAIM-51.6).
//
// This module deliberately has **no dependencies and no error types** so that
// the Kani proof harness (`formal/kani_envelope_arith.rs`) can `include!` it
// verbatim (inner `//!` docs would be invalid in an included module body). The
// proof therefore covers the same source text the production
// `FixedPointValue::compare_with_bounds` compiles — not a hand-written copy.
//
// Semantics:
// - `scale_mantissa` widens to `i128`, multiplies by `10^exp_delta` using
//   checked arithmetic, and returns `None` when the scaling cannot be
//   represented. Callers map `None` to `OverflowOnConversion`.
// - `compare_scaled` is the ordering decision used by
//   `compare_with_bounds`: `-1` below min, `0` within bounds, `1` above max.

/// Scale `mantissa` by `10^exp_delta` in `i128`.
///
/// `exp_delta` is `src_exp - dst_exp` from [`super::fixed_point`]; the
/// production caller only passes a non-negative delta (the common exponent is
/// the minimum of the three exponents). Values above 38 cannot be represented
/// even in `i128`, and a negative delta is not a valid scaling direction.
pub(crate) fn scale_mantissa(mantissa: i64, exp_delta: i16) -> Option<i128> {
    if exp_delta < 0 || exp_delta > 38 {
        return None;
    }
    let mut scale: i128 = 1;
    let mut i: i16 = 0;
    while i < exp_delta {
        scale = scale.checked_mul(10)?;
        i += 1;
    }
    (mantissa as i128).checked_mul(scale)
}

/// Ordering decision for the three scaled mantissas: `-1` below minimum,
/// `0` within bounds, `1` above maximum.
pub(crate) fn compare_scaled(value: i128, min: i128, max: i128) -> i8 {
    if value < min {
        -1
    } else if value > max {
        1
    } else {
        0
    }
}
