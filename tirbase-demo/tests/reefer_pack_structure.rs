// SPDX-License-Identifier: Apache-2.0

//! Structural checks for the reefer/container pack (pack format v1, CC-09).
//!
//! Apache-licensed: these tests read the pack as data and never touch the
//! gateway. They prove the manifest, profile, trip metadata, register maps,
//! scenarios, expected outputs, simulator config, and docs are consistent, that
//! the trip disposition follows from the defended door timeline, and that the
//! pack is data-only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tirbase_demo::{
    load_pack, AdversaryClass, Pack, PackError, ScenarioDisposition, StepDisposition,
    TripDisposition, PACK_MANIFEST_SCHEMA_VERSION,
};
use tirbase_driver_api::ModbusRegisterMap;

/// Additional pack-specific layout entries beyond the framework's manifest.
const PACK_FILES: &[&str] = &[
    "pack.toml",
    "profiles/reefer.toml",
    "trip.toml",
    "register-maps/reefer_reference.register-map.toml",
    "register-maps/reefer_legacy.register-map.toml",
    "expected/outcomes.toml",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/register-maps.md",
];

const SCENARIO_IDS: &[&str] = &[
    "S1_ambient_spike",
    "S1_setpoint_tampering",
    "S2_door_open_in_transit",
    "S2_power_loss",
    "S2_sensor_dropout",
];

const PARAMETERS: &[&str] = &[
    "ambient_c",
    "temperature_setpoint_c",
    "door_open",
    "power_state",
    "defrost_mode",
    "compressor_on",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_root() -> PathBuf {
    workspace_root().join("tirbase-demo/reefer")
}

fn reefer_pack() -> Pack {
    load_pack(pack_root()).expect("reefer pack must load and validate")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(pack_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn document(relative: &str) -> toml::Value {
    toml::from_str(&read(relative)).unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

// ---------------------------------------------------------------------------
// Manifest and layout
// ---------------------------------------------------------------------------

#[test]
fn pack_manifest_is_versioned_and_identifies_the_directory() {
    let pack = reefer_pack();
    assert_eq!(pack.manifest.schema_version, PACK_MANIFEST_SCHEMA_VERSION);
    assert_eq!(pack.manifest.id, "reefer");
    assert_eq!(pack.manifest.version, "1.0.0");
    assert_eq!(pack.manifest.licence, "Apache-2.0");
    assert_eq!(pack.manifest.device_class, "reefer");
    assert_eq!(pack.manifest.run, "run.sh");
    assert_eq!(pack.manifest.trip.as_deref(), Some("trip.toml"));
    assert_eq!(pack.manifest.profiles, vec!["profiles/reefer.toml"]);
    assert_eq!(pack.profiles.len(), 1);
    assert_eq!(pack.profiles[0].device_class, "reefer");
}

#[test]
fn pack_declares_every_layout_file() {
    let pack = reefer_pack();
    for relative in PACK_FILES {
        assert!(
            pack_root().join(relative).is_file(),
            "reefer pack missing {relative}"
        );
    }
    for relative in pack
        .manifest
        .profiles
        .iter()
        .chain(pack.manifest.register_maps.iter())
        .chain(pack.manifest.docs.iter())
        .chain(pack.manifest.scenarios.iter())
        .chain(std::iter::once(&pack.manifest.expected))
        .chain(std::iter::once(&pack.manifest.sim))
        .chain(pack.manifest.trip.iter())
    {
        assert!(
            tirbase_demo::safe_pack_path(&pack_root(), relative).is_ok(),
            "manifest reference {relative} must resolve inside the pack"
        );
    }
}

// ---------------------------------------------------------------------------
// Data-only purity
// ---------------------------------------------------------------------------

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read pack directory") {
        let entry = entry.expect("pack directory entry");
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).expect("pack file metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "pack must not contain symlinks: {}",
            path.display()
        );
        if metadata.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn pack_contains_no_executable_code() {
    let mut files = Vec::new();
    collect_files(&pack_root(), &mut files);
    assert!(!files.is_empty());

    let allowed: BTreeSet<&str> = ["toml", "md"].into_iter().collect();
    for path in &files {
        let relative = path
            .strip_prefix(pack_root())
            .expect("pack-relative path")
            .to_string_lossy()
            .replace('\\', "/");

        if relative == "run.sh" {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .expect("launcher metadata")
                    .permissions();
                assert!(
                    mode.mode() & 0o111 != 0,
                    "run.sh must be executable so the pack can be launched"
                );
            }
            continue;
        }

        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        assert!(
            allowed.contains(extension),
            "pack file '{relative}' is not data (allowed: .toml, .md, run.sh)"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .expect("pack file metadata")
                .permissions();
            assert_eq!(
                mode.mode() & 0o111,
                0,
                "pack file '{relative}' must not be executable"
            );
        }

        let text = std::fs::read_to_string(path).expect("pack file is UTF-8 text");
        assert!(
            !text.starts_with("#!"),
            "pack file '{relative}' must not be a script"
        );
    }
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

#[test]
fn profile_declares_the_six_transport_parameters() {
    let document = document("profiles/reefer.toml");
    let parameters = document["parameters"]
        .as_array()
        .expect("profile parameters array");
    let by_name: BTreeMap<&str, &toml::Value> = parameters
        .iter()
        .map(|parameter| {
            (
                parameter["name"].as_str().expect("parameter name"),
                parameter,
            )
        })
        .collect();
    let expected: BTreeSet<&str> = PARAMETERS.iter().copied().collect();
    assert_eq!(
        by_name.keys().copied().collect::<BTreeSet<_>>(),
        expected,
        "profile parameter set changed; update the pack docs and register maps"
    );

    let ambient = by_name["ambient_c"];
    assert_eq!(ambient["unit_id"].as_integer(), Some(1));
    assert_eq!(ambient["kind"]["type"].as_str(), Some("range"));
    assert_eq!(ambient["kind"]["min"]["mantissa"].as_integer(), Some(-450));
    assert_eq!(ambient["kind"]["max"]["mantissa"].as_integer(), Some(500));
    // 5.0 degC/s with a 10.0 degC / 300 s drift budget.
    assert_eq!(
        ambient["max_rate_per_sec"]["mantissa"].as_integer(),
        Some(50)
    );
    assert_eq!(ambient["drift_window_secs"].as_integer(), Some(300));
    assert_eq!(
        ambient["max_delta_in_window"]["mantissa"].as_integer(),
        Some(100)
    );

    let setpoint = by_name["temperature_setpoint_c"];
    assert_eq!(setpoint["critical"].as_bool(), Some(true));
    assert_eq!(setpoint["kind"]["min"]["mantissa"].as_integer(), Some(-300));
    assert_eq!(setpoint["kind"]["max"]["mantissa"].as_integer(), Some(-180));
    assert_eq!(setpoint["dwell_secs"].as_integer(), Some(30));
    assert_eq!(setpoint["drift_window_secs"].as_integer(), Some(300));

    let door = by_name["door_open"];
    assert_eq!(door["unit_id"].as_integer(), Some(7));
    assert_eq!(door["dwell_secs"].as_integer(), Some(45));
    assert_eq!(door["min_off_secs"].as_integer(), Some(600));

    let power = by_name["power_state"];
    assert_eq!(power["kind"]["type"].as_str(), Some("bool"));
    assert_eq!(power["dwell_secs"].as_integer(), Some(300));
    assert_eq!(power["min_off_secs"].as_integer(), Some(600));

    let defrost = by_name["defrost_mode"];
    assert_eq!(defrost["dwell_secs"].as_integer(), Some(120));
    assert_eq!(defrost["min_off_secs"].as_integer(), Some(900));

    let compressor = by_name["compressor_on"];
    assert_eq!(compressor["min_off_secs"].as_integer(), Some(300));
}

#[test]
fn profile_document_carries_the_fields_install_needs() {
    let document = document("profiles/reefer.toml");
    let profile_id = document["profile_id"].as_str().expect("profile_id string");
    assert_eq!(profile_id.len(), 36, "profile_id must be a hyphenated UUID");
    assert_eq!(profile_id.matches('-').count(), 4);
    assert_eq!(document["version"].as_integer(), Some(1));
    assert_eq!(document["signature_alg"].as_str(), Some("ed25519"));
    let signature = document["signature_hex"]
        .as_str()
        .expect("signature_hex string");
    assert_eq!(signature.len(), 128, "signature must be 64 bytes of hex");
    assert!(
        signature.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "signature_hex must be hexadecimal"
    );
    assert!(
        signature.bytes().any(|byte| byte != b'0'),
        "the pack must ship a real test-fixture signature, not a placeholder"
    );
    assert_eq!(document["policy_loosen_m"].as_integer(), Some(2));
    assert_eq!(document["policy_loosen_n"].as_integer(), Some(3));

    for parameter in document["parameters"].as_array().expect("parameters") {
        assert!(
            parameter["safe_default"].is_table(),
            "safe_default required"
        );
        assert!(
            parameter["tightening_floor"].is_table(),
            "tightening_floor required"
        );
        assert!(
            parameter["canonical_exponent"].is_integer(),
            "canonical_exponent required"
        );
    }
}

// ---------------------------------------------------------------------------
// Trip metadata
// ---------------------------------------------------------------------------

#[test]
fn trip_document_carries_container_location_and_trip_metadata() {
    let document = document("trip.toml");
    assert_eq!(document["schema_version"].as_integer(), Some(1));

    let container_id = document["container_id"].as_str().expect("container_id");
    assert_eq!(
        container_id.chars().filter(char::is_ascii_digit).count(),
        7,
        "container_id must carry a 7-digit serial"
    );
    assert_eq!(
        container_id
            .chars()
            .filter(char::is_ascii_uppercase)
            .count(),
        4,
        "container_id must carry a 4-letter owner code"
    );
    assert_eq!(document["container_class"].as_str(), Some("reefer_40ft"));
    assert!(!document["trailer_id"]
        .as_str()
        .unwrap_or_default()
        .is_empty());
    assert_eq!(document["trip_id"].as_str(), Some("TRIP-2026-1115-0042"));
    assert!(!document["origin"].as_str().unwrap_or_default().is_empty());
    assert!(!document["destination"]
        .as_str()
        .unwrap_or_default()
        .is_empty());
    assert!(!document["cargo"].as_str().unwrap_or_default().is_empty());

    let cargo_min = document["cargo_min_c"]["mantissa"].as_integer().unwrap();
    let cargo_max = document["cargo_max_c"]["mantissa"].as_integer().unwrap();
    assert!(cargo_min < cargo_max, "cargo band must have min < max");
    assert_eq!(document["cargo_min_c"]["unit_id"].as_integer(), Some(1));

    let location = &document["location"];
    assert!(!location["site"].as_str().unwrap_or_default().is_empty());
    let lat = location["lat_e6"].as_integer().expect("lat_e6");
    let lon = location["lon_e6"].as_integer().expect("lon_e6");
    assert!((-90_000_000..=90_000_000).contains(&lat));
    assert!((-180_000_000..=180_000_000).contains(&lon));

    let pack = reefer_pack();
    let trip = pack.trip.as_ref().expect("trip document is loaded");
    assert_eq!(trip.trip_id, "TRIP-2026-1115-0042");
    assert_eq!(trip.max_door_open_secs, 120);
    assert_eq!(trip.door_param, "door_open");
    assert!(pack.parameters().contains_key(trip.door_param.as_str()));
}

#[test]
fn trip_disposition_follows_from_the_defended_door_timeline() {
    let pack = reefer_pack();
    assert_eq!(
        pack.door_open_secs("S2_door_open_in_transit"),
        Some(300),
        "the accepted door timeline stays open for 300 s"
    );
    assert_eq!(
        pack.derived_trip_disposition("S2_door_open_in_transit"),
        Some(TripDisposition::Quarantined),
        "300 s open against a 120 s rule must quarantine the trip"
    );

    let expected = pack
        .expected
        .trip
        .as_ref()
        .expect("expected output declares a trip disposition");
    assert_eq!(expected.scenario, "S2_door_open_in_transit");
    assert_eq!(expected.disposition, TripDisposition::Quarantined);
    assert_eq!(expected.door_open_secs, 300);
    assert_eq!(expected.mechanism, "door_open_in_transit");

    // Scenarios without an accepted open door cannot quarantine the trip.
    assert_eq!(pack.door_open_secs("S2_power_loss"), None);
    assert_eq!(pack.derived_trip_disposition("S2_power_loss"), None);
}

#[test]
fn framework_rejects_an_expected_trip_that_contradicts_the_scenario() {
    let directory = temp_pack_copy("trip-mismatch");
    let path = directory.join("expected/outcomes.toml");
    let text = std::fs::read_to_string(&path).expect("read expected output");
    std::fs::write(
        &path,
        text.replace("door_open_secs = 300", "door_open_secs = 90"),
    )
    .expect("write expected output");

    match load_pack(&directory) {
        Err(PackError::Validation(message)) => assert!(
            message.contains("leaves it open 300s"),
            "unexpected validation error: {message}"
        ),
        other => panic!("expected a trip-disposition rejection, got {other:?}"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn framework_rejects_a_pack_with_a_trip_but_no_trip_disposition() {
    let directory = temp_pack_copy("trip-missing-disposition");
    let path = directory.join("expected/outcomes.toml");
    let text = std::fs::read_to_string(&path).expect("read expected output");
    let without_trip = text
        .split("\n[trip]\n")
        .next()
        .expect("expected output before the trip table")
        .to_string();
    std::fs::write(&path, without_trip).expect("write expected output");

    match load_pack(&directory) {
        Err(PackError::Validation(message)) => assert!(
            message.contains("[trip]"),
            "unexpected validation error: {message}"
        ),
        other => panic!("expected a missing trip-disposition rejection, got {other:?}"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

// ---------------------------------------------------------------------------
// Register maps and units
// ---------------------------------------------------------------------------

fn register_maps() -> Vec<(&'static str, ModbusRegisterMap)> {
    [
        "register-maps/reefer_reference.register-map.toml",
        "register-maps/reefer_legacy.register-map.toml",
    ]
    .into_iter()
    .map(|relative| {
        let text = read(relative);
        let map = ModbusRegisterMap::parse(&text)
            .unwrap_or_else(|error| panic!("parse {relative}: {error}"));
        (relative, map)
    })
    .collect()
}

#[test]
fn register_maps_pin_names_and_units_to_the_profile() {
    let pack = reefer_pack();
    let profile_units = pack.parameters();
    assert_eq!(profile_units.len(), PARAMETERS.len());
    for parameter in PARAMETERS {
        assert!(
            profile_units.contains_key(parameter),
            "profile is missing {parameter}"
        );
    }

    for (relative, map) in register_maps() {
        assert_eq!(map.device_class, "reefer", "{relative} device_class");
        assert!(!map.registers.is_empty(), "{relative} has no registers");

        let mut writable = BTreeSet::new();
        for register in &map.registers {
            assert_eq!(
                map.registers
                    .iter()
                    .filter(|other| other.name == register.name)
                    .count(),
                1,
                "{relative} declares register '{}' more than once",
                register.name
            );
            assert!(
                register.unit_id == 1 || register.unit_id == 7,
                "{relative} register '{}' uses unsupported unit {}",
                register.name,
                register.unit_id
            );
            if register.writable {
                writable.insert(register.name.as_str());
            }
        }

        for name in &writable {
            let unit = profile_units.get(name).copied().unwrap_or_else(|| {
                panic!("{relative} writes '{name}', which the profile does not declare")
            });
            let register = map
                .registers
                .iter()
                .find(|register| register.name == *name)
                .expect("writable register");
            assert_eq!(
                register.unit_id, unit,
                "{relative} register '{name}' unit does not match the profile"
            );
        }

        let profile_params: BTreeSet<&str> = profile_units.keys().copied().collect();
        assert_eq!(
            writable, profile_params,
            "{relative} must expose exactly the profile's commandable parameters"
        );

        let temperature = map
            .registers
            .iter()
            .find(|register| register.name == "container_temp_c")
            .unwrap_or_else(|| panic!("{relative} has no container_temp_c reading"));
        assert!(
            !temperature.writable,
            "{relative} temperature must be read-only"
        );
        assert_eq!(temperature.unit_id, 1);
        assert_eq!(temperature.scale_exponent, -1);
    }
}

#[test]
fn register_maps_use_documented_units() {
    let units = read("docs/register-maps.md");
    for name in PARAMETERS.iter().copied().chain(["container_temp_c"]) {
        assert!(
            units.contains(name),
            "docs/register-maps.md must document register '{name}'"
        );
    }
    assert!(units.contains("1 = degC"));
    assert!(units.contains("7 = boolean"));
}

// ---------------------------------------------------------------------------
// Scenarios and expected output
// ---------------------------------------------------------------------------

#[test]
fn pack_ships_the_five_container_scenarios() {
    let pack = reefer_pack();
    let ids: Vec<&str> = pack
        .scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    assert_eq!(ids, SCENARIO_IDS);

    let classes = pack.covered_classes();
    assert!(classes.contains(&AdversaryClass::S1));
    assert!(classes.contains(&AdversaryClass::S2));

    for scenario in &pack.scenarios {
        assert_eq!(
            scenario.target, "reefer-1",
            "scenario '{}' targets an unexpected device",
            scenario.id
        );
        assert!(
            scenario
                .steps
                .windows(2)
                .all(|pair| pair[0].at_secs <= pair[1].at_secs),
            "scenario '{}' steps must be time-ordered",
            scenario.id
        );
        assert!(
            scenario
                .steps
                .iter()
                .any(|step| step.expect != StepDisposition::Accepted),
            "scenario '{}' demonstrates no defense",
            scenario.id
        );
    }
}

#[test]
fn expected_outcomes_are_defended_and_machine_readable() {
    let pack = reefer_pack();
    assert_eq!(pack.expected.schema_version, PACK_MANIFEST_SCHEMA_VERSION);

    let mut actuations = 0;
    for scenario in &pack.scenarios {
        let outcome = pack
            .expected_outcome(&scenario.id)
            .expect("expected output for every scenario");
        assert_eq!(outcome.class, scenario.class);
        assert!(!outcome.mechanism.is_empty());
        actuations += outcome.actuations;

        let steps: Vec<StepDisposition> = scenario.steps.iter().map(|step| step.expect).collect();
        assert_eq!(outcome.steps, steps);
        assert_eq!(outcome.disposition, ScenarioDisposition::from_steps(&steps));
        assert_eq!(
            outcome.actuations,
            steps
                .iter()
                .filter(|step| **step == StepDisposition::Accepted)
                .count()
        );
    }

    let total_steps: usize = pack.scenarios.iter().map(|s| s.steps.len()).sum();
    assert!(
        actuations < total_steps,
        "expected output must show attacks being blocked"
    );
}

#[test]
fn scenario_mechanisms_match_the_rejections_they_expect() {
    let pack = reefer_pack();
    let expected_mechanisms: BTreeMap<&str, &str> = BTreeMap::from([
        ("S1_ambient_spike", "envelope+drift"),
        ("S1_setpoint_tampering", "envelope"),
        ("S2_door_open_in_transit", "dwell+min_off"),
        ("S2_power_loss", "min_off+dwell"),
        ("S2_sensor_dropout", "drift+min_off"),
    ]);
    for scenario in &pack.scenarios {
        let outcome = pack
            .expected_outcome(&scenario.id)
            .expect("expected output");
        assert_eq!(
            outcome.mechanism,
            expected_mechanisms[scenario.id.as_str()],
            "scenario '{}' defense changed; update docs/README.md",
            scenario.id
        );
        for step in &scenario.steps {
            if step.expect == StepDisposition::Rejected {
                assert!(
                    step.mechanism.is_some(),
                    "scenario '{}' rejects '{}' without naming a mechanism",
                    scenario.id,
                    step.param
                );
            }
        }
    }
}

#[test]
fn door_scenario_opens_the_door_and_hides_it_with_interlocks() {
    let pack = reefer_pack();
    let scenario = pack
        .scenario("S2_door_open_in_transit")
        .expect("door scenario");
    let door_steps: Vec<&tirbase_demo::ScenarioStep> = scenario
        .steps
        .iter()
        .filter(|step| step.param == "door_open")
        .collect();
    assert_eq!(door_steps.len(), 4, "every step drives the door");
    assert_eq!(door_steps[0].value.mantissa, 1);
    assert_eq!(door_steps[0].expect, StepDisposition::Accepted);
    assert_eq!(door_steps[1].mechanism.as_deref(), Some("dwell"));
    assert_eq!(door_steps[2].value.mantissa, 0);
    assert_eq!(door_steps[2].expect, StepDisposition::Accepted);
    assert_eq!(door_steps[3].mechanism.as_deref(), Some("min_off"));
}

// ---------------------------------------------------------------------------
// Simulator config
// ---------------------------------------------------------------------------

#[test]
fn sim_config_models_thermal_mass_and_ambient_variation() {
    let config = document("sim/config.toml");

    assert_eq!(config["device"]["class"].as_str(), Some("reefer"));
    assert_eq!(config["device"]["target"].as_str(), Some("reefer-1"));
    assert_eq!(
        config["device"]["profile"].as_str(),
        Some("profiles/reefer.toml")
    );

    let thermal = &config["thermal"];
    let mass = thermal["container_mass_kg"]
        .as_float()
        .expect("container mass");
    let cargo = thermal["cargo_mass_kg"].as_float().expect("cargo mass");
    let heat = thermal["specific_heat_j_per_kgk"]
        .as_float()
        .expect("specific heat");
    assert!(mass > 0.0 && cargo > 0.0 && heat > 0.0);
    // The lumped heat capacity must be large enough to be a container, not a box.
    assert!(
        (mass + cargo) * heat > 10_000_000.0,
        "thermal mass is too small to model a loaded container"
    );
    let closed_ua = thermal["ua_w_per_k"].as_float().expect("closed-door UA");
    let open_ua = thermal["door_open_ua_w_per_k"]
        .as_float()
        .expect("open-door UA");
    assert!(
        open_ua > closed_ua,
        "an open door must conduct more ambient heat than a closed one"
    );
    assert!(thermal["max_cooling_w"].as_float().expect("cooling") > 0.0);

    let ambient = &config["ambient"];
    assert!(
        ambient["amplitude_c"].as_float().expect("amplitude") > 0.0,
        "ambient variation must be non-zero"
    );
    assert!(
        ambient["period_secs"].as_integer().expect("period") > 0,
        "ambient variation needs a period"
    );
    assert!(ambient["noise_c"].as_float().expect("noise") >= 0.0);

    let includes: Vec<&str> = config["scenarios"]["include"]
        .as_array()
        .expect("scenario classes")
        .iter()
        .map(|value| value.as_str().expect("class string"))
        .collect();
    assert_eq!(includes, vec!["S1", "S2"]);
}

// ---------------------------------------------------------------------------
// Documentation and negative cases
// ---------------------------------------------------------------------------

#[test]
fn readme_documents_intended_use_assumptions_and_non_goals() {
    let readme = read("docs/README.md");
    for section in [
        "## Intended use",
        "## Assumptions",
        "## Non-goals",
        "## Expected defended output",
    ] {
        assert!(
            readme.contains(section),
            "pack README must contain the '{section}' section"
        );
    }
    assert!(
        readme.contains("What TirBase does not protect against in this scenario"),
        "pack README must contain the required non-goals statement"
    );
    assert!(
        readme.contains("Trip disposition") && readme.contains("quarantined"),
        "pack README must document the trip quarantine disposition"
    );
    for scenario in reefer_pack().scenarios {
        assert!(
            readme.contains(&scenario.id),
            "README omits {}",
            scenario.id
        );
    }
}

#[test]
fn framework_rejects_a_pack_that_declares_a_missing_file() {
    let directory = temp_pack_copy("missing-trip");
    std::fs::remove_file(directory.join("trip.toml")).expect("remove trip document");

    match load_pack(&directory) {
        Err(error) => {
            let message = error.to_string();
            assert!(message.contains("trip.toml"), "unexpected error: {message}");
        }
        Ok(_) => panic!("expected a missing-file rejection"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

/// Copy the pack into a uniquely named temporary directory so negative tests can
/// mutate it without touching the committed pack. The manifest identity check
/// compares the id against the directory name, so the copy keeps `reefer`.
fn temp_pack_copy(label: &str) -> PathBuf {
    let directory = std::env::temp_dir()
        .join(format!(
            "tirbase-reefer-pack-{label}-{}",
            std::process::id()
        ))
        .join("reefer");
    std::fs::remove_dir_all(&directory).ok();
    copy_tree(&pack_root(), &directory);
    directory
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create temp pack directory");
    for entry in std::fs::read_dir(from).expect("read source directory") {
        let entry = entry.expect("source directory entry");
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy pack file");
        }
    }
}
