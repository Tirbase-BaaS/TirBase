// SPDX-License-Identifier: Apache-2.0

//! Structural checks for the cold-room pack (pack format v1, CC-08).
//!
//! Apache-licensed: these tests read the pack as data and never touch the
//! gateway. They prove the manifest, profiles, register maps, scenarios,
//! expected outputs, and docs are consistent, and that the pack is data-only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tirbase_demo::{
    load_pack, AdversaryClass, Pack, PackError, ScenarioDisposition, StepDisposition,
    PACK_MANIFEST_SCHEMA_VERSION,
};
use tirbase_driver_api::ModbusRegisterMap;

/// Additional pack-specific layout entries beyond the framework's manifest.
const PACK_FILES: &[&str] = &[
    "pack.toml",
    "profiles/cold_room.toml",
    "register-maps/cold_room_reference.register-map.toml",
    "register-maps/cold_room_legacy.register-map.toml",
    "expected/outcomes.toml",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/register-maps.md",
];

const SCENARIO_IDS: &[&str] = &[
    "S1_out_of_envelope_setpoint",
    "S1_defrost_manipulation",
    "S2_slow_ramp",
    "S2_door_abuse",
    "S2_compressor_short_cycling",
    "S3_replay",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_root() -> PathBuf {
    workspace_root().join("tirbase-demo/cold-room")
}

fn cold_room_pack() -> Pack {
    load_pack(pack_root()).expect("cold-room pack must load and validate")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(pack_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

// ---------------------------------------------------------------------------
// Manifest and layout
// ---------------------------------------------------------------------------

#[test]
fn pack_manifest_is_versioned_and_identifies_the_directory() {
    let pack = cold_room_pack();
    assert_eq!(pack.manifest.schema_version, PACK_MANIFEST_SCHEMA_VERSION);
    assert_eq!(pack.manifest.id, "cold-room");
    assert_eq!(pack.manifest.version, "1.0.0");
    assert_eq!(pack.manifest.licence, "Apache-2.0");
    assert_eq!(pack.manifest.device_class, "cold_room");
    assert_eq!(pack.manifest.run, "run.sh");
    assert_eq!(pack.manifest.profiles, vec!["profiles/cold_room.toml"]);
    assert_eq!(pack.profiles.len(), 1);
    assert_eq!(pack.profiles[0].device_class, "cold_room");
}

#[test]
fn pack_declares_every_layout_file() {
    let pack = cold_room_pack();
    for relative in PACK_FILES {
        assert!(
            pack_root().join(relative).is_file(),
            "cold-room pack missing {relative}"
        );
    }
    // Every manifest reference resolves inside the pack.
    for relative in pack
        .manifest
        .profiles
        .iter()
        .chain(pack.manifest.register_maps.iter())
        .chain(pack.manifest.docs.iter())
        .chain(pack.manifest.scenarios.iter())
        .chain(std::iter::once(&pack.manifest.expected))
        .chain(std::iter::once(&pack.manifest.sim))
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
            // The launcher is the single permitted executable.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path).expect("launcher metadata").permissions();
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
            let mode = std::fs::metadata(path).expect("pack file metadata").permissions();
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
fn profile_declares_the_six_protective_parameters() {
    let path = pack_root().join("profiles/cold_room.toml");
    let text = std::fs::read_to_string(&path).expect("read cold-room profile");
    let document: toml::Value = toml::from_str(&text).expect("profile is TOML");
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
    let expected: BTreeSet<&str> = [
        "temperature_setpoint_c",
        "door_open",
        "defrost_mode",
        "defrost_termination_c",
        "compressor_on",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        by_name.keys().copied().collect::<BTreeSet<_>>(),
        expected,
        "profile parameter set changed; update the pack docs and register maps"
    );

    let setpoint = by_name["temperature_setpoint_c"];
    assert_eq!(setpoint["unit_id"].as_integer(), Some(1));
    // Rate-of-change: 0.5 degC/s.
    assert_eq!(setpoint["max_rate_per_sec"]["mantissa"].as_integer(), Some(5));
    assert_eq!(setpoint["max_rate_per_sec"]["exponent"].as_integer(), Some(-1));
    // Cumulative drift: 2.0 degC per 300 s.
    assert_eq!(setpoint["drift_window_secs"].as_integer(), Some(300));
    assert_eq!(
        setpoint["max_delta_in_window"]["mantissa"].as_integer(),
        Some(20)
    );

    let door = by_name["door_open"];
    assert_eq!(door["dwell_secs"].as_integer(), Some(60));
    assert_eq!(door["min_off_secs"].as_integer(), Some(300));

    let defrost = by_name["defrost_mode"];
    assert_eq!(defrost["min_off_secs"].as_integer(), Some(600));

    let termination = by_name["defrost_termination_c"];
    assert_eq!(termination["kind"]["type"].as_str(), Some("range"));
    assert_eq!(
        termination["kind"]["max"]["mantissa"].as_integer(),
        Some(80),
        "defrost termination ceiling is +8.0 degC"
    );

    let compressor = by_name["compressor_on"];
    assert_eq!(compressor["min_off_secs"].as_integer(), Some(300));
}

#[test]
fn profile_document_carries_the_fields_install_needs() {
    let text = read("profiles/cold_room.toml");
    let document: toml::Value = toml::from_str(&text).expect("profile is TOML");

    // install-time validation parses the profile_id as a 16-byte UUID and the
    // signature as 64 ed25519 bytes.
    let profile_id = document["profile_id"]
        .as_str()
        .expect("profile_id string");
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
    // Policy geometry must be present, otherwise the guard rejects the install.
    assert_eq!(document["policy_loosen_m"].as_integer(), Some(2));
    assert_eq!(document["policy_loosen_n"].as_integer(), Some(3));

    for parameter in document["parameters"].as_array().expect("parameters") {
        assert!(parameter["safe_default"].is_table(), "safe_default required");
        assert!(
            parameter["tightening_floor"].is_table(),
            "tightening_floor required"
        );
        assert!(
            parameter["canonical_exponent"].is_integer(),
            "canonical_exponent required"
        );
        let kind = parameter["kind"]["type"]
            .as_str()
            .expect("parameter kind type");
        assert!(
            kind == "range" || kind == "bool",
            "unsupported parameter kind '{kind}'"
        );
    }
}

// ---------------------------------------------------------------------------
// Register maps and units
// ---------------------------------------------------------------------------

fn register_maps() -> Vec<(&'static str, ModbusRegisterMap)> {
    [
        "register-maps/cold_room_reference.register-map.toml",
        "register-maps/cold_room_legacy.register-map.toml",
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
    let pack = cold_room_pack();
    let profile_units = pack.parameters();
    assert_eq!(profile_units.len(), 5);
    assert_eq!(profile_units["temperature_setpoint_c"], 1);
    assert_eq!(profile_units["door_open"], 7);
    assert_eq!(profile_units["compressor_on"], 7);

    for (relative, map) in register_maps() {
        assert_eq!(map.device_class, "cold_room", "{relative} device_class");
        assert!(!map.registers.is_empty(), "{relative} has no registers");

        let mut writable = BTreeSet::new();
        for register in &map.registers {
            assert!(
                map.registers
                    .iter()
                    .filter(|other| other.name == register.name)
                    .count()
                    == 1,
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

        // Every writable register is a profile parameter with the same unit.
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

        // Every commandable profile parameter is addressable on every controller.
        let profile_params: BTreeSet<&str> = profile_units.keys().copied().collect();
        assert_eq!(
            writable,
            profile_params,
            "{relative} must expose exactly the profile's commandable parameters"
        );

        // The read-only temperature input exists so operators can observe the room.
        let temperature = map
            .registers
            .iter()
            .find(|register| register.name == "temperature_c")
            .unwrap_or_else(|| panic!("{relative} has no temperature_c reading"));
        assert!(!temperature.writable, "{relative} temperature must be read-only");
        assert_eq!(temperature.unit_id, 1);
        assert_eq!(temperature.scale_exponent, -1);
    }
}

#[test]
fn register_maps_use_documented_units() {
    let units = read("docs/register-maps.md");
    for name in [
        "temperature_setpoint_c",
        "door_open",
        "defrost_mode",
        "defrost_termination_c",
        "compressor_on",
        "temperature_c",
    ] {
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
fn pack_ships_all_six_scenarios_across_s1_s2_s3() {
    let pack = cold_room_pack();
    let ids: Vec<&str> = pack
        .scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    assert_eq!(ids, SCENARIO_IDS);

    let classes = pack.covered_classes();
    assert!(classes.contains(&AdversaryClass::S1));
    assert!(classes.contains(&AdversaryClass::S2));
    assert!(classes.contains(&AdversaryClass::S3));

    for scenario in &pack.scenarios {
        assert_eq!(
            scenario.target, "cold-room-1",
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
        // Every scenario must end defended: at least one rejection or one
        // deduplicated replay, otherwise it is not an adversary scenario.
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
    let pack = cold_room_pack();
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
        assert_eq!(
            outcome.disposition,
            ScenarioDisposition::from_steps(&steps)
        );
        assert_eq!(
            outcome.actuations,
            steps
                .iter()
                .filter(|step| **step == StepDisposition::Accepted)
                .count()
        );
    }

    // The defended pack rejects more commands than it dispatches.
    let total_steps: usize = pack.scenarios.iter().map(|s| s.steps.len()).sum();
    assert!(
        actuations < total_steps,
        "expected output must show attacks being blocked"
    );
}

#[test]
fn scenario_mechanisms_match_the_rejections_they_expect() {
    let pack = cold_room_pack();
    let expected_mechanisms: BTreeMap<&str, &str> = BTreeMap::from([
        ("S1_out_of_envelope_setpoint", "envelope"),
        ("S1_defrost_manipulation", "envelope+min_off"),
        ("S2_slow_ramp", "drift"),
        ("S2_door_abuse", "dwell+min_off"),
        ("S2_compressor_short_cycling", "min_off"),
        ("S3_replay", "idempotency"),
    ]);
    for scenario in &pack.scenarios {
        let outcome = pack.expected_outcome(&scenario.id).expect("expected output");
        assert_eq!(
            outcome.mechanism,
            expected_mechanisms[scenario.id.as_str()],
            "scenario '{}' defense changed; update docs/README.md",
            scenario.id
        );
        // A rejected step must name the guard stage that rejects it.
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
fn replay_scenario_replays_a_previously_accepted_sequence() {
    let pack = cold_room_pack();
    let scenario = pack.scenario("S3_replay").expect("replay scenario");
    let original = scenario
        .steps
        .iter()
        .find(|step| step.sequence == 1)
        .expect("original command");
    assert_eq!(original.expect, StepDisposition::Accepted);
    let replay = scenario
        .steps
        .iter()
        .find(|step| step.replay_of == Some(1))
        .expect("replay step");
    assert_eq!(replay.expect, StepDisposition::Deduplicated);
    assert_eq!(replay.param, original.param);
    assert_eq!(replay.value, original.value);
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
    // Every scenario id and its mechanism appear in the defended-output table.
    for scenario in cold_room_pack().scenarios {
        assert!(readme.contains(&scenario.id), "README omits {}", scenario.id);
    }
}

#[test]
fn framework_rejects_a_pack_whose_manifest_is_inconsistent() {
    let directory = temp_pack_copy("bad-schema");
    let manifest_path = directory.join("pack.toml");
    let mut manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
    manifest = manifest.replace("schema_version = 1", "schema_version = 2");
    std::fs::write(&manifest_path, manifest).expect("write manifest");

    match load_pack(&directory) {
        Err(PackError::Validation(message)) => {
            assert!(
                message.contains("schema_version"),
                "unexpected validation error: {message}"
            );
        }
        other => panic!("expected a schema_version rejection, got {other:?}"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn framework_rejects_a_pack_that_declares_a_missing_file() {
    let directory = temp_pack_copy("missing-profile");
    std::fs::remove_file(directory.join("profiles/cold_room.toml")).expect("remove profile");

    match load_pack(&directory) {
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains("profiles/cold_room.toml"),
                "unexpected error: {message}"
            );
        }
        Ok(_) => panic!("expected a missing-file rejection"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

/// Copy the pack into a uniquely named temporary directory so negative tests can
/// mutate it without touching the committed pack.
fn temp_pack_copy(label: &str) -> PathBuf {
    // The pack directory name is part of the manifest identity check, so the
    // copy keeps the name `cold-room` and varies only its parent.
    let directory = std::env::temp_dir()
        .join(format!("tirbase-pack-{label}-{}", std::process::id()))
        .join("cold-room");
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
