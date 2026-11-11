//! Kani proof spike (CLAIM-51.6, PV-26.4).
//!
//! Proves that envelope bound comparison on `FixedPointValue`-like scaled values
//! is overflow-free for all `i64` mantissa inputs when comparison is performed
//! via i128 scaling to a common exponent, as implemented by the guard
//! (`compare_with_bounds` scales mantissas with i128 intermediates).
//!
//! Run (requires Kani): `cargo kani --standalone formal/kani_envelope_arith.rs`
//! or integrate as a harness in a crate configured for Kani.

#![allow(dead_code)]

#[derive(Clone, Copy)]
struct Fpv {
    mantissa: i64,
    exponent: i8,
    unit_id: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cmp {
    Below,
    Within,
    Above,
}

fn scale_to_i128(mantissa: i64, src_exp: i8, dst_exp: i8) -> Option<i128> {
    let exp_delta = src_exp as i16 - dst_exp as i16;
    if exp_delta < 0 {
        return None;
    }
    let mut m: i128 = mantissa as i128;
    if exp_delta == 0 {
        return Some(m);
    }
    // Bound comparison normalizes to the most-negative exponent; exponent span
    // for i8 is <= 255, but i128 can represent 10^38. The production path
    // rejects/guards impossible spans; for the proof we model the safe domain
    // (all practical envelope exponents) and prove no overflow inside it.
    if exp_delta > 38 {
        return None;
    }
    let mut i: i16 = 0;
    while i < exp_delta {
        m = m.checked_mul(10)?;
        i += 1;
    }
    Some(m)
}

fn compare_bounds(val: Fpv, min: Fpv, max: Fpv) -> Option<Cmp> {
    if val.unit_id != min.unit_id || val.unit_id != max.unit_id {
        return None;
    }
    let common = if val.exponent <= min.exponent { val.exponent } else { min.exponent };
    let common = if common <= max.exponent { common } else { max.exponent };
    let v = scale_to_i128(val.mantissa, val.exponent, common)?;
    let lo = scale_to_i128(min.mantissa, min.exponent, common)?;
    let hi = scale_to_i128(max.mantissa, max.exponent, common)?;
    if v < lo {
        Some(Cmp::Below)
    } else if v > hi {
        Some(Cmp::Above)
    } else {
        Some(Cmp::Within)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn envelope_min_max_compare_overflow_free_for_i64_mantissas() {
        let v_m: i64 = kani::any();
        let lo_m: i64 = kani::any();
        let hi_m: i64 = kani::any();
        let v_e: i8 = kani::any();
        let lo_e: i8 = kani::any();
        let hi_e: i8 = kani::any();
        let u: u16 = kani::any();

        // Constrain to the representable scaling domain for i128 normalization.
        // Production comparison rejects spans it cannot scale exactly/safely.
        let common = if v_e <= lo_e { v_e } else { lo_e };
        let common = if common <= hi_e { common } else { hi_e };
        let dv = v_e as i16 - common as i16;
        let dl = lo_e as i16 - common as i16;
        let dh = hi_e as i16 - common as i16;
        kani::assume(dv >= 0 && dv <= 18);
        kani::assume(dl >= 0 && dl <= 18);
        kani::assume(dh >= 0 && dh <= 18);

        let val = Fpv { mantissa: v_m, exponent: v_e, unit_id: u };
        let min = Fpv { mantissa: lo_m, exponent: lo_e, unit_id: u };
        let max = Fpv { mantissa: hi_m, exponent: hi_e, unit_id: u };

        // Must not panic/overflow and must return a comparable result in-domain.
        let r = compare_bounds(val, min, max);
        assert!(r.is_some());

        // Consistency: if min <= val <= max under same scaling, result is Within.
        let sv = scale_to_i128(v_m, v_e, common).unwrap();
        let slo = scale_to_i128(lo_m, lo_e, common).unwrap();
        let shi = scale_to_i128(hi_m, hi_e, common).unwrap();
        if sv >= slo && sv <= shi {
            assert!(matches!(r, Some(Cmp::Within)));
        }
    }

    #[kani::proof]
    fn scaling_i128_has_no_overflow_in_bounded_delta() {
        let m: i64 = kani::any();
        let src: i8 = kani::any();
        let delta: i16 = kani::any();
        kani::assume(delta >= 0 && delta <= 18);
        // choose dst so src-dst == delta and dst valid
        let dst16 = src as i16 - delta;
        kani::assume(dst16 >= i8::MIN as i16 && dst16 <= i8::MAX as i16);
        let dst = dst16 as i8;
        let r = scale_to_i128(m, src, dst);
        assert!(r.is_some());
    }
}

fn main() {
    // Standalone sanity check when run without Kani.
    let v = Fpv { mantissa: 50, exponent: -1, unit_id: 1 };
    let lo = Fpv { mantissa: 0, exponent: 0, unit_id: 1 };
    let hi = Fpv { mantissa: 10, exponent: 0, unit_id: 1 };
    assert_eq!(compare_bounds(v, lo, hi), Some(Cmp::Within));
}
