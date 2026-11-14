// SPDX-License-Identifier: AGPL-3.0-only

//! Proptest offline soundness proof for classify_bundle (//! CLAIM-12.9, PV-4.11, INV-3).

use std::collections::BTreeMap;

use proptest::prelude::*;
use tirbase_guard::policy::classify_bundle;
use tirbase_guard::trust_root::{ParamFloor, TrustRootRecord};
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::policy::PolicyBundleKind;
use tirbase_types::{DeviceSignature, FixedPointValue, ProfileId, UNIT_DEG_C};

fn fp(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, -1, UNIT_DEG_C)
}
fn param(
    min: i64,
    max: i64,
    rate: i64,
    dwell: u32,
    min_off: u32,
    critical: bool,
    safe: i64,
) -> ParameterSpec {
    ParameterSpec {
        name: "temp".to_string(),
        unit_id: UNIT_DEG_C,
        canonical_exponent: -1,
        kind: ParameterKind::Range {
            min: fp(min),
            max: fp(max),
        },
        max_rate_per_sec: fp(rate),
        dwell_secs: dwell,
        min_off_secs: min_off,
        drift_window_secs: 60,
        max_delta_in_window: fp(50),
        safe_default: fp(safe),
        tightening_floor: fp(-500),
        critical,
    }
}
fn profile(p: ParameterSpec, m: u8, n: u8, tl: u32, cancel: u32) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [1u8; 16] as ProfileId,
        version: 1,
        device_class: "cold_room".to_string(),
        parameters: vec![p],
        cross_constraints: vec![],
        policy_loosen_m: m,
        policy_loosen_n: n,
        policy_timelock_secs: tl,
        policy_cancel_window_secs: cancel,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}
fn trust_root(min_floor: i64, max_ceiling: i64) -> TrustRootRecord {
    let mut floors = BTreeMap::new();
    floors.insert(
        "cold_room".to_string(),
        vec![ParamFloor {
            param_name: "temp".to_string(),
            min_floor: fp(min_floor),
            max_ceiling: fp(max_ceiling),
        }],
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![],
        threshold_k: 1,
        role_thresholds: BTreeMap::new(),
        device_class_floors: floors,
        expiry_est: i64::MAX,
        revoked_root_ca_keys: vec![],
        signatures: vec![],
    }
}

fn fp_leq(a: &FixedPointValue, b: &FixedPointValue) -> bool {
    let scale = |x: &FixedPointValue, common: i8| -> Option<i128> {
        let d = (x.exponent as i16 - common as i16) as u32;
        let mut s: i128 = 1;
        for _ in 0..d {
            s = s.checked_mul(10)?;
        }
        (x.mantissa as i128).checked_mul(s)
    };
    let c = a.exponent.min(b.exponent);
    scale(a, c)
        .zip(scale(b, c))
        .map(|(x, y)| x <= y)
        .unwrap_or(false)
}
fn fp_geq(a: &FixedPointValue, b: &FixedPointValue) -> bool {
    fp_leq(b, a)
}

fn accepts_range(profile: &EnvelopeProfile, value: &FixedPointValue) -> bool {
    let Some(p) = profile.parameters.first() else {
        return false;
    };
    match &p.kind {
        ParameterKind::Range { min, max } => fp_geq(value, min) && fp_leq(value, max),
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn tightening_is_always_a_strict_envelope_subset(
        omin in -400i64..400,
        ospan in 10i64..400,
        nmin_delta in 0i64..50,
        nmax_delta in 0i64..50,
        orate in 5i64..50,
        nrate_delta in 0i64..5,
        odwell in 0u32..30,
        ndwell_add in 0u32..30,
        ooff in 0u32..30,
        noff_add in 0u32..30,
        om in 1u8..4,
        nm_add in 0u8..2,
        tl in 10u32..500,
        tl_add in 0u32..100,
        cancel in 10u32..200,
        cancel_add in 0u32..50,
        safe in -100i64..100,
    ) {
        let omax = omin + ospan;
        let nmin = (omin + nmin_delta).min(omax - 1);
        let nmax = (omax - nmax_delta).max(nmin + 1);
        let tr = trust_root(-1000, 2000);
        let old = profile(param(omin, omax, orate, odwell, ooff, false, safe), om, om, tl, cancel);
        let new = profile(
            param(nmin, nmax, (orate - nrate_delta).max(1), odwell + ndwell_add, ooff + noff_add, false, safe),
            om + nm_add, om + nm_add, tl + tl_add, cancel + cancel_add,
        );
        let kind = classify_bundle(&old, &new, &tr);
        if kind == PolicyBundleKind::Tightening {
 // For a sample of values accepted by new, old must also accept.
            let step = ((nmax - nmin) / 10).max(1);
            let mut v = nmin;
            while v <= nmax {
                let fv = fp(v);
                prop_assert!(accepts_range(&new, &fv));
                prop_assert!(accepts_range(&old, &fv), "tightening broke subset at {v}");
                v += step;
            }
 // Explicit boundary containment.
            if let (ParameterKind::Range { min: nmi, max: nma }, ParameterKind::Range { min: omi, max: oma }) =
                (&new.parameters[0].kind, &old.parameters[0].kind)
            {
                prop_assert!(fp_geq(nmi, omi) && fp_leq(nma, oma));
            }
        }
    }

    #[test]
    fn loosening_a_constraint_never_classifies_as_tightening(
        omin in -300i64..100,
        ospan in 50i64..300,
        widen_min in 1i64..50,
        orate in 5i64..50,
    ) {
        let omax = omin + ospan;
        let tr = trust_root(-1000, 2000);
        let old = profile(param(omin, omax, orate, 5, 2, false, 0), 2, 2, 100, 30);
 // widen min downward = loosening
        let new = profile(param(omin - widen_min, omax, orate, 5, 2, false, 0), 2, 2, 100, 30);
        prop_assert_ne!(classify_bundle(&old, &new, &tr), PolicyBundleKind::Tightening);
    }
}
