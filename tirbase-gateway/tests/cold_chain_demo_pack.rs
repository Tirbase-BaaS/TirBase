//! Cold-chain flagship demo pack profile/install integration (CLAIM-47.1, PV-16.1).
//!
//! Loads the cold-chain `EnvelopeProfile` TOML and Modbus register map from the
//! demo pack, verifies PolicyAuthority-signed install against the cold_chain
//! device model via the gateway profile install path.

use std::collections::BTreeMap;
use std::path::PathBuf;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::profiles::{load_profile_from_path, sign_parsed_profile};
use tirbase_guard::envelope::install_profile;
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::{DeviceModel, DeviceParameter};
use tirbase_types::envelope::ParameterKind;
use tirbase_types::{CommandRole, FixedPointValue};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn cold_chain_device_model() -> DeviceModel {
    DeviceModel {
        device_class: "cold_chain".to_string(),
        parameters: vec![
            DeviceParameter {
                name: "temperature_setpoint_c".to_string(),
                unit_id: 1, // degC
                unit_label: "degC".to_string(),
                range: [
                    FixedPointValue::new(-400, -1, 1),
                    FixedPointValue::new(150, -1, 1),
                ],
                writable: true,
            },
            DeviceParameter {
                name: "compressor_on".to_string(),
                unit_id: 7, // boolean
                unit_label: "boolean".to_string(),
                range: [
                    FixedPointValue::new(0, 0, 7),
                    FixedPointValue::new(1, 0, 7),
                ],
                writable: true,
            },
        ],
    }
}

fn pa_trust_root(pa_did: &str, pa_pk: Vec<u8>) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa_did.to_string(),
                public_key: pa_pk,
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

#[test]
fn cold_chain_profile_has_temperature_setpoint_compressor_and_rate_limit() {
    let profile_path = workspace_root().join("tirbase-demo/cold-chain/profiles/cold_chain.toml");
    let profile = load_profile_from_path(&profile_path).expect("parse cold-chain profile");
    assert_eq!(profile.device_class, "cold_chain");

    let setpoint = profile
        .parameters
        .iter()
        .find(|p| p.name == "temperature_setpoint_c")
        .expect("temperature setpoint parameter");
    assert!(matches!(setpoint.kind, ParameterKind::Range { .. }));
 // Rate-of-change limit: 0.5 °C/s encoded as mantissa 5, exponent -1 (unit degC).
    assert_eq!(setpoint.max_rate_per_sec.mantissa, 5);
    assert_eq!(setpoint.max_rate_per_sec.exponent, -1);

    let compressor = profile
        .parameters
        .iter()
        .find(|p| p.name == "compressor_on")
        .expect("compressor on/off parameter");
    assert!(matches!(compressor.kind, ParameterKind::Bool));
}

#[test]
fn cold_chain_profile_installs_and_validates() {
    let profile_path = workspace_root().join("tirbase-demo/cold-chain/profiles/cold_chain.toml");
    let parsed = load_profile_from_path(&profile_path).expect("parse cold-chain profile");

 // Re-sign with a generated PA for the install-path validation (the committed
 // fixture signature is for the [0x47;32] PA seed; install validates signature
 // against the trust root's authorized PA key).
    let pa = InMemoryKeyProvider::generate().expect("generate PA key");
    let signed = sign_parsed_profile(parsed, &pa);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let model = cold_chain_device_model();

    let signer = install_profile(&signed, &model, &trust)
        .expect("cold-chain profile must install and validate via gateway path");
    assert_eq!(signer, pa.did());

 // Modbus register map exists alongside the profile.
    let regmap = workspace_root().join("tirbase-demo/cold-chain/docs/modbus-register-map.md");
    let reg_text = std::fs::read_to_string(&regmap).expect("read register map");
    assert!(reg_text.contains("temperature_setpoint_c"));
    assert!(reg_text.contains("compressor_on"));
}
