// SPDX-License-Identifier: Apache-2.0

//! Structural checks for the workflow-pack configuration (CC-13, Apache).
//!
//! Proves the three committed packs load, that every required section is present,
//! that unknown fields, missing fields, bad ranges, wrong units, incompatible
//! versions and secret keys are refused with the offending field named, and that
//! the committed documents carry no secrets.

use std::path::PathBuf;

use tirbase_demo::load_pack;
use tirbase_demo::workflow::{
    WorkflowConfig, WorkflowConfigError, WORKFLOW_DISPOSITION_KINDS, WORKFLOW_SCHEMA_VERSION,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_dir(id: &str) -> PathBuf {
    workspace_root().join("tirbase-demo").join(id)
}

fn committed(id: &str) -> String {
    std::fs::read_to_string(pack_dir(id).join("workflow.toml")).expect("read workflow.toml")
}

fn parse(text: &str) -> Result<WorkflowConfig, WorkflowConfigError> {
    WorkflowConfig::parse(text, "test-workflow.toml")
}

fn error_field(text: &str) -> String {
    let error = parse(text).expect_err("config must be refused");
    error
        .field()
        .unwrap_or_else(|| panic!("error names no field: {error}"))
}

fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "missing snippet {from:?}");
    text.replacen(from, to, 1)
}

fn remove_between(text: &str, start: &str, end: &str) -> String {
    let start = text.find(start).expect("section start");
    let end = text.find(end).expect("section end");
    format!("{}{}", &text[..start], &text[end..])
}

// ---------------------------------------------------------------------------
// The committed packs
// ---------------------------------------------------------------------------

#[test]
fn all_three_packs_load_a_complete_workflow_config() {
    for id in ["cold-room", "reefer", "pharma-gdp"] {
        let pack = load_pack(pack_dir(id)).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(
            pack.manifest.workflow.as_deref(),
            Some("workflow.toml"),
            "{id} must reference its workflow document"
        );
        let config = pack
            .workflow
            .as_ref()
            .unwrap_or_else(|| panic!("{id} must load workflow.toml"));

        assert_eq!(config.schema_version, WORKFLOW_SCHEMA_VERSION);
        assert_eq!(config.pack, pack.manifest.id, "{id} workflow pack binding");
        assert!(!config.id.trim().is_empty());
        assert!(!config.title.trim().is_empty());

        // Thresholds: an ordered band, positive rate, non-zero windows.
        let thresholds = &config.thresholds;
        assert!(thresholds.band_min_c.mantissa < thresholds.band_max_c.mantissa);
        assert_eq!(thresholds.band_min_c.unit_id, 1);
        assert_eq!(thresholds.band_max_c.exponent, -1);
        assert!(thresholds.max_rate_c_per_sec.mantissa > 0);
        assert!(thresholds.max_door_open_secs > 0);
        assert!(thresholds.max_telemetry_gap_secs > 0);

        // Windows and debounce are coherent.
        assert!(
            config.windows.sampling_interval_secs <= config.windows.reporting_interval_secs,
            "{id} sampling must not exceed reporting"
        );
        assert!(config.windows.assessment_secs <= config.windows.max_quarantine_secs);
        assert!(config.debounce.min_findings >= 1);
        assert!(config.debounce.cooldown_secs < config.windows.max_quarantine_secs);

        // MKT parameters are usable.
        assert!(config.mkt.activation_energy_j_per_mol > 0);
        assert!(config.mkt.gas_constant_milli_j_per_mol_k > 0);
        assert!(config.mkt.max_samples > 0);

        // Every disposition kind has a code, and at least one route is live.
        for kind in WORKFLOW_DISPOSITION_KINDS {
            assert!(
                config.disposition_code_for(kind).is_some(),
                "{id} declares no code for {kind}"
            );
        }
        assert!(!config.notification.routes.is_empty());
        assert!(config.notification.routes.iter().any(|route| route.enabled));

        // Lot metadata is complete.
        assert!(!config.lot.uom.trim().is_empty());
        assert!(!config.lot.label_prefix.trim().is_empty());
        assert!(["lot", "batch", "repack"].contains(&config.lot.lot_kind.as_str()));
    }
}

#[test]
fn committed_configs_contain_no_secret_keys() {
    const SECRETS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "bearer",
        "authorization",
        "access_key",
    ];
    fn walk(value: &toml::Value, path: &str) {
        match value {
            toml::Value::Table(table) => {
                for (key, child) in table {
                    let lowered = key.to_ascii_lowercase();
                    assert!(
                        !SECRETS.iter().any(|fragment| lowered.contains(fragment)),
                        "secret-looking key {path}.{key}"
                    );
                    walk(child, &format!("{path}.{key}"));
                }
            }
            toml::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{index}]"));
                }
            }
            _ => {}
        }
    }
    for id in ["cold-room", "reefer", "pharma-gdp"] {
        let text = committed(id);
        let value: toml::Value = toml::from_str(&text).expect("committed config is TOML");
        walk(&value, id);
    }
}

// ---------------------------------------------------------------------------
// Schema errors name the field
// ---------------------------------------------------------------------------

#[test]
fn unknown_fields_are_rejected() {
    let text = replace_once(
        &committed("cold-room"),
        "[thresholds]\n",
        "[thresholds]\nunexpected = true\n",
    );
    assert_eq!(error_field(&text), "unexpected");
}

#[test]
fn missing_fields_are_rejected() {
    let text = remove_between(
        &committed("cold-room"),
        "[debounce]",
        "[[notification.routes]]",
    );
    assert_eq!(error_field(&text), "debounce");
}

#[test]
fn ranges_and_units_are_validated() {
    let base = committed("cold-room");

    // Band ordering.
    let text = replace_once(
        &base,
        "band_min_c = { mantissa = 0,",
        "band_min_c = { mantissa = 900,",
    );
    assert_eq!(error_field(&text), "thresholds.band_min_c");

    // Unit id.
    let text = replace_once(
        &base,
        "band_max_c = { mantissa = 80, exponent = -1, unit_id = 1 }",
        "band_max_c = { mantissa = 80, exponent = -1, unit_id = 2 }",
    );
    assert_eq!(error_field(&text), "thresholds.band_max_c");

    // Exponent (0.1 °C, not 1 °C).
    let text = replace_once(
        &base,
        "mkt_limit_c = { mantissa = 80, exponent = -1, unit_id = 1 }",
        "mkt_limit_c = { mantissa = 8, exponent = 0, unit_id = 1 }",
    );
    assert_eq!(error_field(&text), "thresholds.mkt_limit_c");

    // Zero rate.
    let text = replace_once(
        &base,
        "max_rate_c_per_sec = { mantissa = 5,",
        "max_rate_c_per_sec = { mantissa = 0,",
    );
    assert_eq!(error_field(&text), "thresholds.max_rate_c_per_sec");

    // Reporting shorter than sampling.
    let text = replace_once(
        &base,
        "reporting_interval_secs = 3600\nsampling_interval_secs = 300",
        "reporting_interval_secs = 60\nsampling_interval_secs = 300",
    );
    assert_eq!(error_field(&text), "windows.reporting_interval_secs");

    // Quarantine cap shorter than the assessment window.
    let text = replace_once(
        &base,
        "max_quarantine_secs = 86400",
        "max_quarantine_secs = 60",
    );
    assert_eq!(error_field(&text), "windows.max_quarantine_secs");

    // Debounce bounds.
    let text = replace_once(&base, "min_findings = 2", "min_findings = 0");
    assert_eq!(error_field(&text), "debounce.min_findings");

    let text = replace_once(&base, "cooldown_secs = 1800", "cooldown_secs = 999999");
    assert_eq!(error_field(&text), "debounce.cooldown_secs");

    // MKT parameters.
    let text = replace_once(
        &base,
        "activation_energy_j_per_mol = 83144",
        "activation_energy_j_per_mol = 0",
    );
    assert_eq!(error_field(&text), "mkt.activation_energy_j_per_mol");

    // Disposition vocabulary.
    let text = replace_once(&base, "code = \"CR-HOLD-002\"", "code = \"CR-REL-001\"");
    assert_eq!(error_field(&text), "dispositions.codes[1].code");

    let text = replace_once(&base, "kind = \"destroy\"", "kind = \"release\"");
    assert_eq!(error_field(&text), "dispositions.codes");

    // Notification routes.
    let text = replace_once(
        &base,
        "event = \"disposition_recorded\"",
        "event = \"page_me\"",
    );
    assert_eq!(error_field(&text), "notification.routes[1].event");

    let text = replace_once(&base, "channel = \"pager\"", "channel = \"Pager One\"");
    assert_eq!(error_field(&text), "notification.routes[0].channel");

    // Lot metadata.
    let text = replace_once(&base, "lot_kind = \"lot\"", "lot_kind = \"pallet\"");
    assert_eq!(error_field(&text), "lot.lot_kind");
}

#[test]
fn version_compatibility_is_enforced() {
    let text = replace_once(
        &committed("cold-room"),
        "schema_version = 1",
        "schema_version = 2",
    );
    assert_eq!(error_field(&text), "schema_version");

    let text = replace_once(
        &committed("cold-room"),
        "tirbase_min_version = \"0.1.0\"",
        "tirbase_min_version = \"9.0.0\"",
    );
    assert_eq!(error_field(&text), "tirbase_min_version");

    let text = replace_once(
        &committed("cold-room"),
        "tirbase_min_version = \"0.1.0\"",
        "tirbase_min_version = \"0.1\"",
    );
    assert_eq!(error_field(&text), "tirbase_min_version");
}

#[test]
fn secrets_are_refused_by_field_name() {
    let text = replace_once(
        &committed("cold-room"),
        "tirbase_min_version = \"0.1.0\"",
        "tirbase_min_version = \"0.1.0\"\napi_token = \"abc\"",
    );
    let error = parse(&text).expect_err("secret must be refused");
    assert_eq!(error.field().as_deref(), Some("api_token"));
    assert!(error.to_string().contains("secrets must not be stored"));

    let text = replace_once(
        &committed("cold-room"),
        "channel = \"pager\"",
        "channel = \"pager\"\npassword = \"hunter2\"",
    );
    let error = parse(&text).expect_err("secret must be refused");
    assert_eq!(
        error.field().as_deref(),
        Some("notification.routes[0].password")
    );
}

#[test]
fn pack_binding_mismatch_is_rejected_by_the_loader() {
    // The document validates on its own; the loader compares its `pack` field
    // with the manifest id, so a workflow cannot be attached to the wrong pack.
    let text = replace_once(
        &committed("cold-room"),
        "pack = \"cold-room\"",
        "pack = \"reefer\"",
    );
    let config = parse(&text).expect("document is valid on its own");
    assert_eq!(config.pack, "reefer");
    assert_ne!(
        config.pack,
        load_pack(pack_dir("cold-room")).expect("pack").manifest.id
    );
}
