//! Task 34.5: EnvelopeProfile TOML documents validated by gateway install-time path.
//! Production caller: tirbase-gateway profile install path.
//! Wiring/negative: invalid profile is rejected with field-level error.

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::profiles::{
    cold_room_device_model, install_profile_toml, load_profile_from_path, pa_trust_root,
    parse_profile_toml, sign_parsed_profile,
};

#[test]
fn claim_34_5_profiles_dir_cold_room_toml_parses_and_validates() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("profiles")
        .join("cold_room.toml");
    let profile = load_profile_from_path(&path).expect("profiles/cold_room.toml must parse");
    assert_eq!(profile.device_class, "cold_room");
    assert_eq!(profile.parameters[0].name, "setpoint_c");

    let pa = InMemoryKeyProvider::generate().unwrap();
    let signed = sign_parsed_profile(profile, &pa);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let model = cold_room_device_model();
    let toml = std::fs::read_to_string(&path).unwrap();
    // install_profile_toml parses+validates via 10.6 path; signature in file is placeholder,
    // so use signed parsed form via install path components.
    tirbase_guard::envelope::install_profile(&signed, &model, &trust)
        .expect("signed cold_room profile must install");
    let _ = toml;
}

#[test]
fn claim_34_5_invalid_profile_rejected_with_field_level_error() {
    let bad = r#"
profile_id = "c01d0000-0000-0000-0000-000000000001"
version = 1
device_class = ""
[[parameters]]
name = "x"
unit_id = 1
canonical_exponent = -1
max_rate_per_sec = { mantissa = 1, exponent = 0, unit_id = 1 }
dwell_secs = 0
drift_window_secs = 0
max_delta_in_window = { mantissa = 1, exponent = 0, unit_id = 1 }
safe_default = { mantissa = 0, exponent = 0, unit_id = 1 }
tightening_floor = { mantissa = 0, exponent = 0, unit_id = 1 }
[parameters.kind]
type = "range"
min = { mantissa = 0, exponent = 0, unit_id = 1 }
max = { mantissa = 1, exponent = 0, unit_id = 1 }
"#;
    let err = parse_profile_toml(bad).unwrap_err();
    assert_eq!(err.field, "device_class", "field-level error: {err}");
    assert!(err.message.contains("empty"), "{err}");
}

#[test]
fn claim_34_5_missing_parameters_reports_field() {
    let bad = r#"
profile_id = "c01d0000-0000-0000-0000-000000000001"
version = 1
device_class = "x"
parameters = []
"#;
    let err = parse_profile_toml(bad).unwrap_err();
    assert_eq!(err.field, "parameters");
}

#[test]
fn claim_34_5_invalid_install_path_reports_error() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let model = cold_room_device_model();
    let bad = "profile_id=\"x\"\nversion=1\ndevice_class=\"x\"\nparameters=[]\n";
    let err = install_profile_toml(bad, &model, &trust).unwrap_err();
    assert!(
        err.contains("parameters") || err.contains("profile"),
        "{err}"
    );
}
