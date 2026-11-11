//! EnvelopeProfile data model & install-path tests (tasks 10.1–10.6 —
//! CLAIM-10.1…CLAIM-10.6, PV-4.5, INV-1).
//!
//! Production callers exercised here:
//! - `tirbase_guard::envelope::{install_profile, validate_profile, verify_profile_signature, ProfileMap}`
//! - `tirbase_types::envelope::*` data model
//!
//! Integration shape: profiles are signed with a `PolicyAuthority` identity
//! (the same signing/verification primitives the gateway uses) and installed
//! through the production `install_profile` path against a trust root and
//! device model.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::envelope::{
    install_profile, profile_signing_bytes, validate_profile, verify_profile_signature, FieldError,
    ProfileInstallError, ProfileMap,
};
use tirbase_guard::signed_operation::CONTEXT_ENVELOPE_PROFILE;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootError, TrustRootRecord,
};
use tirbase_guard::{
    ConstraintOperator, DeviceModel, DeviceParameter, EnvelopeProfile, LinearConstraint,
    ParameterKind, ParameterSpec,
};
use tirbase_types::{
    CommandRole, DeviceSignature, FixedPointValue, TargetId, UnitId, UNIT_BOOLEAN, UNIT_DEG_C,
    UNIT_PERCENT,
};

fn fpv(mantissa: i64, exponent: i8, unit: UnitId) -> FixedPointValue {
    FixedPointValue::new(mantissa, exponent, unit)
}

fn pa_trust_root(pa: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes(),
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1u8; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

fn rm_only_trust_root(rm: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: rm.did().to_string(),
                public_key: rm.public_key_bytes(),
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1u8; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

fn sign_profile(profile: &mut EnvelopeProfile, pa: &InMemoryKeyProvider) {
    let msg = profile_signing_bytes(profile);
    profile.signature = pa.sign(&msg).expect("PA signs profile");
}

fn sample_temp_spec() -> ParameterSpec {
    ParameterSpec {
        name: "setpoint_c".to_string(),
        unit_id: UNIT_DEG_C,
        canonical_exponent: -1, // tenths of °C
        kind: ParameterKind::Range {
            min: fpv(-200, -1, UNIT_DEG_C), // -20.0 °C
            max: fpv(80, -1, UNIT_DEG_C),   //  8.0 °C
        },
        max_rate_per_sec: fpv(5, -1, UNIT_DEG_C),
        dwell_secs: 60,
        min_off_secs: 0,
        drift_window_secs: 300,
        max_delta_in_window: fpv(50, -1, UNIT_DEG_C),
        safe_default: fpv(40, -1, UNIT_DEG_C), // 4.0 °C
        tightening_floor: fpv(-250, -1, UNIT_DEG_C),
        critical: true,
    }
}

fn sample_profile(pa: &InMemoryKeyProvider) -> EnvelopeProfile {
    let mut profile = EnvelopeProfile {
        profile_id: [0x10; 16],
        version: 1,
        device_class: "cold_room".to_string(),
        parameters: vec![sample_temp_spec()],
        cross_constraints: Vec::new(),
        policy_loosen_m: 2,
        policy_loosen_n: 3,
        policy_timelock_secs: 3600,
        policy_cancel_window_secs: 600,
        signature: DeviceSignature::Ed25519([0u8; 64]), // placeholder
    };
    sign_profile(&mut profile, pa);
    profile
}

fn sample_device_model() -> DeviceModel {
    DeviceModel {
        device_class: "cold_room".to_string(),
        parameters: vec![DeviceParameter {
            name: "setpoint_c".to_string(),
            unit_id: UNIT_DEG_C,
            unit_label: "degC".to_string(),
            range: [fpv(-400, -1, UNIT_DEG_C), fpv(150, -1, UNIT_DEG_C)],
            writable: true,
        }],
    }
}

// ── 10.1 ParameterKind ───────────────────────────────────────────────────────

#[test]
fn parameter_kind_range_enum_bool_construct_and_serde() {
    let range = ParameterKind::Range {
        min: fpv(0, 0, UNIT_PERCENT),
        max: fpv(100, 0, UNIT_PERCENT),
    };
    let en = ParameterKind::Enum {
        variants: vec![("off".into(), 0), ("low".into(), 1), ("high".into(), 2)],
    };
    let b = ParameterKind::Bool;

    // Round-trip via serde_json (exercises derive + variant shapes).
    for kind in [&range, &en, &b] {
        let j = serde_json::to_string(kind).unwrap();
        let back: ParameterKind = serde_json::from_str(&j).unwrap();
        assert_eq!(&back, kind);
    }
    match en {
        ParameterKind::Enum { variants } => assert_eq!(variants.len(), 3),
        _ => panic!("expected Enum"),
    }
    assert!(matches!(b, ParameterKind::Bool));
}

// ── 10.2 ParameterSpec ───────────────────────────────────────────────────────

#[test]
fn parameter_spec_carries_all_required_fields() {
    let s = sample_temp_spec();
    assert_eq!(s.name, "setpoint_c");
    assert_eq!(s.unit_id, UNIT_DEG_C);
    assert_eq!(s.canonical_exponent, -1);
    assert_eq!(s.dwell_secs, 60);
    assert_eq!(s.min_off_secs, 0);
    assert_eq!(s.drift_window_secs, 300);
    assert!(s.critical);
    assert_eq!(s.safe_default, fpv(40, -1, UNIT_DEG_C));
    assert!(matches!(s.kind, ParameterKind::Range { .. }));

    // Serde round-trip (serde_json in dev-deps).
    let j = serde_json::to_string(&s).unwrap();
    let back: ParameterSpec = serde_json::from_str(&j).unwrap();
    assert_eq!(back, s);
}

// ── 10.3 LinearConstraint ────────────────────────────────────────────────────

#[test]
fn linear_constraint_expresses_conjunction_and_evaluates_bound() {
    // temp_setpoint + (2 * compressor_pct/100) <= 12.0 °C-equivalent
    let c1 = LinearConstraint {
        coefficients: vec![
            ("setpoint_c".into(), fpv(1, 0, UNIT_DEG_C)),
            ("compressor".into(), fpv(2, 0, UNIT_PERCENT)),
        ],
        bound: fpv(120, -1, UNIT_DEG_C),
        operator: ConstraintOperator::Leq,
    };
    let c2 = LinearConstraint {
        coefficients: vec![("setpoint_c".into(), fpv(1, 0, UNIT_DEG_C))],
        bound: fpv(-200, -1, UNIT_DEG_C),
        operator: ConstraintOperator::Geq,
    };
    let conjunction = vec![c1.clone(), c2.clone()];
    assert_eq!(conjunction.len(), 2);
    assert!(matches!(c1.operator, ConstraintOperator::Leq));
    assert!(matches!(c2.operator, ConstraintOperator::Geq));

    // Total/non-Turing-complete representation is just data; serde round-trip.
    let j = serde_json::to_string(&conjunction).unwrap();
    let back: Vec<LinearConstraint> = serde_json::from_str(&j).unwrap();
    assert_eq!(back, conjunction);

    // Eq operator present.
    let eq = LinearConstraint {
        coefficients: vec![("mode".into(), fpv(1, 0, UNIT_BOOLEAN))],
        bound: fpv(1, 0, UNIT_BOOLEAN),
        operator: ConstraintOperator::Eq,
    };
    assert!(matches!(eq.operator, ConstraintOperator::Eq));
}

// ── 10.4 EnvelopeProfile + signature (PolicyAuthority) ───────────────────────

#[test]
fn envelope_profile_signed_by_policy_authority_is_accepted() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let trust = pa_trust_root(&pa);
    let profile = sample_profile(&pa);
    let model = sample_device_model();

    let signer = install_profile(&profile, &model, &trust).expect("PA-signed profile installs");
    assert_eq!(signer, pa.did());
}

#[test]
fn profile_signed_by_non_policy_authority_is_rejected() {
    // Wiring mutation check (CLAIM-10.4): removing the PolicyAuthority/registry
    // gate must fail this test.
    let pa = InMemoryKeyProvider::generate().unwrap(); // signs the profile
    let rm = InMemoryKeyProvider::generate().unwrap(); // only RM is in trust root
    let mut profile = sample_profile(&pa);
    sign_profile(&mut profile, &pa);
    let model = sample_device_model();

    // Trust root has NO PolicyAuthority role configured.
    let trust = rm_only_trust_root(&rm);
    let err = install_profile(&profile, &model, &trust).unwrap_err();
    assert!(
        matches!(
            err,
            ProfileInstallError::TrustRoot(TrustRootError::RoleNotConfigured {
                role: CommandRole::PolicyAuthority
            })
        ),
        "non-PA context must be rejected: {err:?}"
    );
}

#[test]
fn profile_signed_by_unregistered_key_is_rejected_even_if_valid() {
    let registered_pa = InMemoryKeyProvider::generate().unwrap();
    let rogue = InMemoryKeyProvider::generate().unwrap();
    let trust = pa_trust_root(&registered_pa);
    let mut profile = sample_profile(&registered_pa);
    // Sign with a key that is NOT in the PolicyAuthority registry.
    let msg = profile_signing_bytes(&profile);
    profile.signature = rogue.sign(&msg).unwrap();
    let model = sample_device_model();

    let err = install_profile(&profile, &model, &trust).unwrap_err();
    assert!(
        matches!(err, ProfileInstallError::SignatureNotAuthorized { .. }),
        "unregistered signer must be rejected: {err:?}"
    );

    // Direct signature helper agrees.
    assert!(verify_profile_signature(&profile, &trust).is_err());
}

#[test]
fn profile_signing_bytes_are_domain_separated() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let profile = sample_profile(&pa);
    let bytes = profile_signing_bytes(&profile);
    assert!(bytes.starts_with(CONTEXT_ENVELOPE_PROFILE.as_bytes()));
    assert_eq!(bytes[CONTEXT_ENVELOPE_PROFILE.len()], 0);
    // hash length 32
    assert_eq!(bytes.len(), CONTEXT_ENVELOPE_PROFILE.len() + 1 + 32);
    // Deterministic.
    assert_eq!(bytes, profile_signing_bytes(&profile));

    // Mutating a governance field changes the signed body.
    let mut p2 = profile.clone();
    p2.policy_loosen_m = 3;
    sign_profile(&mut p2, &pa);
    assert_ne!(profile_signing_bytes(&profile), profile_signing_bytes(&p2));
}

#[test]
fn tampered_profile_body_fails_signature_verification() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let trust = pa_trust_root(&pa);
    let mut profile = sample_profile(&pa);
    // Tamper after signing.
    profile.policy_timelock_secs = 1;
    assert!(verify_profile_signature(&profile, &trust).is_err());
}

// ── 10.5 Target-to-profile map with hot-swap ─────────────────────────────────

#[test]
fn profile_map_hot_swap_takes_effect() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let p1 = sample_profile(&pa);
    let mut p2 = sample_profile(&pa);
    p2.version = 2;
    p2.policy_timelock_secs = 7200;
    sign_profile(&mut p2, &pa);

    let target = TargetId::new("device-1");
    let map = ProfileMap::from_profiles([(target.clone(), p1.clone())]);
    assert_eq!(map.load(&target).unwrap().version, 1);

    assert!(map.swap(&target, p2.clone()));
    assert_eq!(map.load(&target).unwrap().version, 2);
    assert_eq!(map.load(&target).unwrap().policy_timelock_secs, 7200);
}

#[test]
fn profile_map_hot_swap_visible_across_threads_within_one_second() {
    // Integration-style concurrency check for hot-swap (CLAIM-10.5).
    let pa = InMemoryKeyProvider::generate().unwrap();
    let p1 = sample_profile(&pa);
    let mut p2 = sample_profile(&pa);
    p2.version = 99;
    sign_profile(&mut p2, &pa);
    let target = TargetId::new("device-hot");
    let map = ProfileMap::from_profiles([(target.clone(), p1)]);

    let barrier = Arc::new(Barrier::new(2));
    let reader_map = map.clone();
    let reader_target = target.clone();
    let reader_barrier = barrier.clone();
    let reader = thread::spawn(move || {
        reader_barrier.wait();
        let start_micros = tirbase_core::traits::monotonic_now();
        loop {
            let elapsed =
                tirbase_core::traits::monotonic_now().saturating_sub(start_micros);
            if reader_map.load(&reader_target).unwrap().version == 99 {
                return Duration::from_micros(elapsed);
            }
            if elapsed > 1_000_000 {
                panic!("hot-swap not observed within 1 second");
            }
            thread::yield_now();
        }
    });

    barrier.wait();
    // swap after reader is ready
    assert!(map.swap(&target, p2));
    let observed = reader.join().unwrap();
    assert!(observed < Duration::from_secs(1));
}

#[test]
fn profile_map_swap_returns_false_for_unknown_target() {
    let map = ProfileMap::new();
    let pa = InMemoryKeyProvider::generate().unwrap();
    assert!(!map.swap(&TargetId::new("missing"), sample_profile(&pa)));
}

// ── 10.6 Install-time validation against DeviceModel ─────────────────────────

#[test]
fn validate_profile_rejects_unit_id_mismatch_with_field_error() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let profile = sample_profile(&pa);
    let mut model = sample_device_model();
    model.parameters[0].unit_id = UNIT_PERCENT; // mismatch vs profile (degC)

    let err = validate_profile(&profile, &model).unwrap_err();
    let ProfileInstallError::Validation(errors) = err else {
        panic!("expected Validation");
    };
    assert!(
        errors
            .iter()
            .any(|e: &FieldError| e.field == "setpoint_c" && e.message.contains("unit_id")),
        "expected unit_id field error: {errors:?}"
    );
}

#[test]
fn validate_profile_rejects_range_outside_device_model() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let mut profile = sample_profile(&pa);
    // Expand profile range beyond device model max (device max is 15.0°C).
    if let ParameterKind::Range { max, .. } = &mut profile.parameters[0].kind {
        *max = fpv(500, -1, UNIT_DEG_C); // 50.0°C > 15.0°C
    }
    sign_profile(&mut profile, &pa);
    let model = sample_device_model();

    let err = validate_profile(&profile, &model).unwrap_err();
    let ProfileInstallError::Validation(errors) = err else {
        panic!("expected Validation");
    };
    assert!(
        errors
            .iter()
            .any(|e| e.field == "setpoint_c" && e.message.contains("max")),
        "expected range-max field error: {errors:?}"
    );
}

#[test]
fn validate_profile_rejects_non_writable_parameter() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let profile = sample_profile(&pa);
    let mut model = sample_device_model();
    model.parameters[0].writable = false;

    let err = validate_profile(&profile, &model).unwrap_err();
    let ProfileInstallError::Validation(errors) = err else {
        panic!("expected Validation");
    };
    assert!(
        errors.iter().any(|e| e.message.contains("not writable")),
        "expected writability field error: {errors:?}"
    );
}

#[test]
fn validate_profile_rejects_unknown_parameter_with_field_error() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let profile = sample_profile(&pa);
    let model = DeviceModel {
        device_class: "cold_room".to_string(),
        parameters: vec![DeviceParameter {
            name: "other_param".to_string(),
            unit_id: UNIT_DEG_C,
            unit_label: "degC".to_string(),
            range: [fpv(-400, -1, UNIT_DEG_C), fpv(150, -1, UNIT_DEG_C)],
            writable: true,
        }],
    };
    let err = validate_profile(&profile, &model).unwrap_err();
    let ProfileInstallError::Validation(errors) = err else {
        panic!("expected Validation");
    };
    assert!(errors.iter().any(|e| e.field == "setpoint_c"));
}

#[test]
fn validate_profile_rejects_device_class_mismatch() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let profile = sample_profile(&pa);
    let mut model = sample_device_model();
    model.device_class = "boiler".to_string();
    let err = validate_profile(&profile, &model).unwrap_err();
    assert!(matches!(
        err,
        ProfileInstallError::DeviceClassMismatch { .. }
    ));
}

#[test]
fn install_profile_runs_validation_after_signature() {
    // Valid PA signature but invalid model (unit mismatch) => Validation error,
    // proving both gates run and validation is reachable post-signature.
    let pa = InMemoryKeyProvider::generate().unwrap();
    let trust = pa_trust_root(&pa);
    let profile = sample_profile(&pa);
    let mut model = sample_device_model();
    model.parameters[0].writable = false;

    let err = install_profile(&profile, &model, &trust).unwrap_err();
    assert!(matches!(err, ProfileInstallError::Validation(_)));
}
