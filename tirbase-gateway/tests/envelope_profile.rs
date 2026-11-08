//! Gateway-adjacent integration test for EnvelopeProfile install (tasks 10.4,
//! 10.6 — CLAIM-10.4, CLAIM-10.6, PV-4.5).
//!
//! Exercises the production install path (`tirbase_guard::envelope::install_profile`)
//! that the gateway/guard use to admit a PolicyAuthority-signed profile after
//! device-model validation. Uses real Ed25519 signing and the trust-root role
//! registry.

use std::collections::BTreeMap;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::envelope::{install_profile, profile_signing_bytes, ProfileInstallError};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootError, TrustRootRecord};
use tirbase_guard::{DeviceModel, DeviceParameter, EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue, UNIT_DEG_C};

fn fpv(mantissa: i64, exponent: i8) -> FixedPointValue {
    FixedPointValue::new(mantissa, exponent, UNIT_DEG_C)
}

#[test]
fn gateway_profile_install_accepts_policy_authority_and_rejects_non_pa() {
    let pa = InMemoryKeyProvider::generate().unwrap();
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
    let trust = TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1u8; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };

    let mut profile = EnvelopeProfile {
        profile_id: [9; 16],
        version: 1,
        device_class: "cold_room".to_string(),
        parameters: vec![ParameterSpec {
            name: "setpoint_c".to_string(),
            unit_id: UNIT_DEG_C,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: fpv(-200, -1),
                max: fpv(80, -1),
            },
            max_rate_per_sec: fpv(5, -1),
            dwell_secs: 60,
            min_off_secs: 0,
            drift_window_secs: 300,
            max_delta_in_window: fpv(50, -1),
            safe_default: fpv(40, -1),
            tightening_floor: fpv(-250, -1),
            critical: true,
        }],
        cross_constraints: Vec::new(),
        policy_loosen_m: 2,
        policy_loosen_n: 3,
        policy_timelock_secs: 3600,
        policy_cancel_window_secs: 600,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };
    profile.signature = pa.sign(&profile_signing_bytes(&profile)).unwrap();

    let model = DeviceModel {
        device_class: "cold_room".to_string(),
        parameters: vec![DeviceParameter {
            name: "setpoint_c".to_string(),
            unit_id: UNIT_DEG_C,
            unit_label: "degC".to_string(),
            range: [fpv(-400, -1), fpv(150, -1)],
            writable: true,
        }],
    };

    assert_eq!(install_profile(&profile, &model, &trust).unwrap(), pa.did());

    // Non-PolicyAuthority trust context rejects install (CLAIM-10.4 wiring check).
    let rm = InMemoryKeyProvider::generate().unwrap();
    let mut rm_roles = BTreeMap::new();
    rm_roles.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: rm.did().to_string(),
                public_key: rm.public_key_bytes(),
            }],
        ),
    );
    let rm_trust = TrustRootRecord {
        role_thresholds: rm_roles,
        ..trust
    };
    assert!(matches!(
        install_profile(&profile, &model, &rm_trust),
        Err(ProfileInstallError::TrustRoot(
            TrustRootError::RoleNotConfigured {
                role: CommandRole::PolicyAuthority
            }
        ))
    ));
}
