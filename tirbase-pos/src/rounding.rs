// SPDX-License-Identifier: AGPL-3.0-only

//! Integer-only rounding for money arithmetic.
//!
//! The POS model never stores or computes money with an IEEE 754 float. The
//! only lossy operation is a division whose exact quotient is not an integer
//! (fractional quantity × unit price, percentage discounts and tax rates). That
//! division is performed on `i128` integers with one explicit
//! [`RoundingMode`]. The chosen mode is recorded on the check, so a replayed
//! command stream recomputes byte-identical totals.

use crate::error::PosError;

/// How a non-integral minor-unit quotient is rounded.
///
/// The names are explicit about sign behaviour. `HalfAwayFromZero` is the
/// retail default; the other modes exist so a deployment can match a local
/// accounting rule without changing the arithmetic model.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub enum RoundingMode {
    /// Round halves away from zero (2.5 → 3, −2.5 → −3).
    #[default]
    HalfAwayFromZero,
    /// Round halves toward zero (2.5 → 2, −2.5 → −2).
    HalfTowardZero,
    /// Round halves to the nearest even integer, also known as banker's rounding.
    HalfEven,
    /// Always round to the next integer away from zero.
    AwayFromZero,
    /// Truncate toward zero.
    TowardZero,
    /// Round toward positive infinity.
    Ceiling,
    /// Round toward negative infinity.
    Floor,
}

impl RoundingMode {
    /// Every supported mode, in a stable order.
    pub const ALL: [RoundingMode; 7] = [
        RoundingMode::HalfAwayFromZero,
        RoundingMode::HalfTowardZero,
        RoundingMode::HalfEven,
        RoundingMode::AwayFromZero,
        RoundingMode::TowardZero,
        RoundingMode::Ceiling,
        RoundingMode::Floor,
    ];
}

/// Divide `numerator` by `denominator` and round to an `i64`.
///
/// `denominator` must be positive. `numerator` may be negative; the rounding
/// mode is applied to the signed result, not to the magnitude.
///
/// # Errors
///
/// - [`PosError::InvalidDivisor`] when `denominator <= 0`.
/// - [`PosError::ArithmeticOverflow`] when the rounded quotient does not fit in
///   an `i64`.
pub fn div_round(numerator: i128, denominator: i128, mode: RoundingMode) -> Result<i64, PosError> {
    if denominator <= 0 {
        return Err(PosError::InvalidDivisor);
    }

    let negative = numerator < 0;
    let magnitude = numerator.unsigned_abs();
    let divisor = denominator as u128;
    let quotient = magnitude / divisor;
    let remainder = magnitude % divisor;

    let bump = match mode {
        RoundingMode::TowardZero => false,
        RoundingMode::AwayFromZero => remainder > 0,
        // Floor moves a negative quotient one step further from zero.
        RoundingMode::Floor => negative && remainder > 0,
        // Ceiling moves a positive quotient one step from zero.
        RoundingMode::Ceiling => !negative && remainder > 0,
        RoundingMode::HalfAwayFromZero => remainder * 2 >= divisor,
        RoundingMode::HalfTowardZero => remainder * 2 > divisor,
        RoundingMode::HalfEven => {
            let twice = remainder * 2;
            if twice > divisor {
                true
            } else if twice < divisor {
                false
            } else {
                // Exactly half: leave the magnitude even.
                quotient % 2 == 1
            }
        }
    };

    let rounded = quotient + u128::from(bump);
    // `rounded` is at most 2^127 + 1, which does not always fit in `i128`.
    if rounded > i128::MAX as u128 {
        return Err(PosError::ArithmeticOverflow);
    }
    let signed = rounded as i128;
    let signed = if negative { -signed } else { signed };
    if signed < i64::MIN as i128 || signed > i64::MAX as i128 {
        return Err(PosError::ArithmeticOverflow);
    }
    Ok(signed as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(n: i128, d: i128, mode: RoundingMode) -> i64 {
        div_round(n, d, mode).unwrap()
    }

    #[test]
    fn positive_half_behaviour_per_mode() {
        assert_eq!(r(5, 2, RoundingMode::HalfAwayFromZero), 3);
        assert_eq!(r(5, 2, RoundingMode::HalfTowardZero), 2);
        assert_eq!(r(5, 2, RoundingMode::HalfEven), 2);
        assert_eq!(r(7, 2, RoundingMode::HalfEven), 4);
    }

    #[test]
    fn negative_half_behaviour_per_mode() {
        assert_eq!(r(-5, 2, RoundingMode::HalfAwayFromZero), -3);
        assert_eq!(r(-5, 2, RoundingMode::HalfTowardZero), -2);
        assert_eq!(r(-5, 2, RoundingMode::HalfEven), -2);
        assert_eq!(r(-7, 2, RoundingMode::HalfEven), -4);
    }

    #[test]
    fn directional_modes_handle_signs() {
        assert_eq!(r(7, 2, RoundingMode::TowardZero), 3);
        assert_eq!(r(-7, 2, RoundingMode::TowardZero), -3);
        assert_eq!(r(7, 2, RoundingMode::AwayFromZero), 4);
        assert_eq!(r(-7, 2, RoundingMode::AwayFromZero), -4);
        assert_eq!(r(7, 2, RoundingMode::Ceiling), 4);
        assert_eq!(r(-7, 2, RoundingMode::Ceiling), -3);
        assert_eq!(r(7, 2, RoundingMode::Floor), 3);
        assert_eq!(r(-7, 2, RoundingMode::Floor), -4);
    }

    #[test]
    fn exact_quotients_are_unchanged_in_every_mode() {
        for mode in RoundingMode::ALL {
            assert_eq!(r(10, 5, mode), 2);
            assert_eq!(r(-10, 5, mode), -2);
            assert_eq!(r(0, 5, mode), 0);
        }
    }

    #[test]
    fn zero_and_negative_divisors_are_rejected() {
        assert_eq!(
            div_round(1, 0, RoundingMode::HalfEven),
            Err(PosError::InvalidDivisor)
        );
        assert_eq!(
            div_round(1, -2, RoundingMode::HalfEven),
            Err(PosError::InvalidDivisor)
        );
    }

    #[test]
    fn overflow_is_reported_not_wrapped() {
        assert_eq!(
            div_round(i128::MAX, 1, RoundingMode::HalfEven),
            Err(PosError::ArithmeticOverflow)
        );
        assert_eq!(
            div_round(i128::MIN, 1, RoundingMode::HalfEven),
            Err(PosError::ArithmeticOverflow)
        );
    }

    #[test]
    fn i64_min_is_representable() {
        assert_eq!(r(i64::MIN as i128, 1, RoundingMode::TowardZero), i64::MIN);
    }
}
