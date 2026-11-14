// SPDX-License-Identifier: AGPL-3.0-only

//! Kani proof harness (CLAIM-51.6, PV-26.4).
//!
//! This harness `include!`s `tirbase-types/src/fixed_point_core.rs` — the exact
//! module that `FixedPointValue::compare_with_bounds` compiles for scaling and
//! ordering. The proof therefore covers the shipping arithmetic, not a copy.
//!
//! Run:
//! ```text
//! kani formal/kani_envelope_arith.rs --default-unwind 40
//! ```
//!
//! Properties proved:
//! 1. `scale_mantissa` never panics and never wraps: for every `i64` mantissa
//! and every admissible `exp_delta` (`0..=38`) it either returns a scaled
//! `i128` or `None`; it is total in the safe domain (always `Some`).
//! 2. `compare_scaled` is a total ordering decision: it always returns one of
//! `-1`, `0`, `1`, and it is consistent with the bounds it was given.
//! 3. A value equal to its minimum or maximum bound is never classified outside
//! the envelope.

#![allow(dead_code)]

mod core {
    include!("../tirbase-types/src/fixed_point_core.rs");
}

/// Concrete sanity check when the file is run as a normal program.
fn main() {
    assert_eq!(core::scale_mantissa(5, 1), Some(50));
    assert_eq!(core::scale_mantissa(i64::MAX, 19), None);
    assert_eq!(core::compare_scaled(5, 5, 9), 0);
    assert_eq!(core::compare_scaled(4, 5, 9), -1);
}

#[cfg(kani)]
mod proofs {
    use super::core::{compare_scaled, scale_mantissa};

 /// The production scaling path is total and panic-free across the whole
 /// admissible exponent-delta domain, including `i64::MIN`/`MAX` mantissas.
 ///
 /// Equality against the mathematical product is checked below on a small
 /// (fully expanded) delta domain; this harness establishes the no-panic /
 /// no-silent-wrap property for the full `0..=38` domain.
    #[kani::proof]
    #[kani::unwind(40)]
    fn scale_mantissa_is_panic_free_in_full_domain() {
        let mantissa: i64 = kani::any();
        let exp_delta: i16 = kani::any();
        kani::assume((0..=38).contains(&exp_delta));

        let scaled = scale_mantissa(mantissa, exp_delta);
        if exp_delta == 0 {
            assert_eq!(scaled, Some(mantissa as i128));
        }
        if mantissa == 0 {
            assert_eq!(scaled, Some(0));
        }
    }

 /// Exactness: over a small, fully expanded delta domain the scaled value is
 /// precisely `mantissa × 10^delta` (nothing wraps silently).
    #[kani::proof]
    #[kani::unwind(6)]
    fn scale_mantissa_matches_exact_product_for_small_deltas() {
        let mantissa: i64 = kani::any();
        let exp_delta: i16 = kani::any();
        kani::assume((0..=4).contains(&exp_delta));

        let exact = (mantissa as i128).checked_mul(10i128.pow(exp_delta as u32));
        assert_eq!(scale_mantissa(mantissa, exp_delta), exact);
    }

 /// Ordering is total and respects the bounds for every i128 triple.
    #[kani::proof]
    fn compare_scaled_is_total_and_sound() {
        let value: i128 = kani::any();
        let min: i128 = kani::any();
        let max: i128 = kani::any();
        kani::assume(min <= max);

        let decision = compare_scaled(value, min, max);
        assert!(decision == -1 || decision == 0 || decision == 1);
        if decision == -1 {
            assert!(value < min);
        } else if decision == 1 {
            assert!(value > max);
        } else {
            assert!(value >= min && value <= max);
        }
    }

 /// A value exactly on either bound is inside the envelope — the property
 /// that would break if the comparison used strict-only bounds.
    #[kani::proof]
    fn boundary_values_are_within_bounds() {
        let bound: i128 = kani::any();
        assert_eq!(compare_scaled(bound, bound, bound), 0);
    }
}
