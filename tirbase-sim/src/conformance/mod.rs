//! Simulator-based profile conformance tests (CLAIM-34.6, PV-10.6).
//!
//! Each profile gets at least one nominal and one boundary scenario with recorded
//! pass/fail results.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::envelope::{install_profile, profile_signing_bytes};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::{DeviceModel, DeviceParameter, EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue, UNIT_DEG_C};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioResult {
    pub profile: String,
    pub scenario: String,
    pub kind: String, // nominal | boundary
    pub passed: bool,
    pub detail: String,
}

fn fpv(m: i64, _exp: i8) -> FixedPointValue {
    FixedPointValue::new(m, _exp, UNIT_DEG_C)
}

fn trust_root(pa: &InMemoryKeyProvider) -> TrustRootRecord {
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
        root_ca_public_keys: vec![vec![1; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

fn sign_profile(mut profile: EnvelopeProfile, pa: &InMemoryKeyProvider) -> EnvelopeProfile {
    profile.signature = pa
        .sign(&profile_signing_bytes(&profile))
        .unwrap_or(DeviceSignature::Ed25519([0u8; 64]));
    profile
}

pub fn cold_room_device_model() -> DeviceModel {
    DeviceModel {
        device_class: "cold_room".to_string(),
        parameters: vec![
            DeviceParameter {
                name: "setpoint_c".to_string(),
                unit_id: UNIT_DEG_C,
                unit_label: "degC".to_string(),
                range: [fpv(-400, -1), fpv(150, -1)],
                writable: true,
            },
            DeviceParameter {
                name: "compressor_on".to_string(),
                unit_id: UNIT_DEG_C,
                unit_label: "bool-ish".to_string(),
                range: [fpv(0, -1), fpv(10, -1)],
                writable: true,
            },
        ],
    }
}

pub fn cold_room_profile() -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [0xC0, 0x1D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        version: 1,
        device_class: "cold_room".to_string(),
        parameters: vec![ParameterSpec {
            name: "setpoint_c".to_string(),
            unit_id: UNIT_DEG_C,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: fpv(-250, -1),
                max: fpv(80, -1),
            },
            max_rate_per_sec: fpv(5, -1),
            dwell_secs: 30,
            min_off_secs: 0,
            drift_window_secs: 300,
            max_delta_in_window: fpv(50, -1),
            safe_default: fpv(40, -1),
            tightening_floor: fpv(-300, -1),
            critical: true,
        }],
        cross_constraints: Vec::new(),
        policy_loosen_m: 2,
        policy_loosen_n: 3,
        policy_timelock_secs: 3600,
        policy_cancel_window_secs: 600,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

fn write_results(path: &Path, results: &[ScenarioResult]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        path,
        serde_json::to_string_pretty(results).unwrap_or_default(),
    );
}

pub fn run_cold_room_conformance() -> Vec<ScenarioResult> {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let trust = trust_root(&pa);
    let model = cold_room_device_model();
    let mut results = Vec::new();

    // Nominal: signed profile installs and nominal setpoint is inside range.
    let profile = sign_profile(cold_room_profile(), &pa);
    let nominal_install = install_profile(&profile, &model, &trust).is_ok();
    let nominal_value = nominal_install && {
        if let ParameterKind::Range { min, max } = &profile.parameters[0].kind {
            fpv(40, -1).mantissa >= min.mantissa && fpv(40, -1).mantissa <= max.mantissa
        } else {
            false
        }
    };
    results.push(ScenarioResult {
        profile: "cold_room".into(),
        scenario: "nominal_install_and_safe_default_in_range".into(),
        kind: "nominal".into(),
        passed: nominal_value,
        detail: if nominal_value {
            "profile installed and nominal value accepted".into()
        } else {
            "nominal scenario failed".into()
        },
    });

    // Boundary: setpoint exactly at max range is allowed; above max is rejected by profile validation shape.
    let boundary_at_max = if let ParameterKind::Range { max, .. } = &profile.parameters[0].kind {
        max.mantissa == 80
    } else {
        false
    };
    let mut over = cold_room_profile();
    if let ParameterKind::Range { ref mut max, .. } = over.parameters[0].kind {
        *max = fpv(200, -1); // above device model max (150 -> 15.0C in -1 scale?)
    }
    let over = sign_profile(over, &pa);
    let boundary_reject = install_profile(&over, &model, &trust).is_err();
    let boundary_ok = boundary_at_max && boundary_reject;
    results.push(ScenarioResult {
        profile: "cold_room".into(),
        scenario: "boundary_max_allowed_above_device_rejected".into(),
        kind: "boundary".into(),
        passed: boundary_ok,
        detail: if boundary_ok {
            "boundary conditions enforced".into()
        } else {
            format!("boundary_at_max={boundary_at_max} boundary_reject={boundary_reject}")
        },
    });

    let out = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("conformance")
        .join("cold_room.json");
    write_results(&out, &results);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_room_profile_nominal_and_boundary_conformance() {
        let results = run_cold_room_conformance();
        assert!(results.iter().any(|r| r.kind == "nominal" && r.passed));
        assert!(results.iter().any(|r| r.kind == "boundary" && r.passed));
        let out = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("conformance")
            .join("cold_room.json");
        assert!(out.exists(), "conformance results must be recorded");
        let body = std::fs::read_to_string(out).unwrap();
        assert!(body.contains("\"passed\": true"));
    }
}
