// SPDX-License-Identifier: Apache-2.0

//! Structural checks for the pharma GDP pack (pack format v1, CC-10).
//!
//! Apache-licensed: these tests read the pack as data and never touch the
//! gateway. They prove the manifest, three storage profiles, GDP policy,
//! calibration records, qualification checklist, scenarios, release checks,
//! simulator config, and docs are consistent; that the pack distinguishes a
//! transient excursion from cumulative drift; that an expired calibration blocks
//! release; and that the pack is data-only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tirbase_demo::{
    load_pack, AdversaryClass, ExcursionClass, Pack, PackError, ReleaseDisposition,
    ScenarioDisposition, StepDisposition, PACK_MANIFEST_SCHEMA_VERSION,
    RELEASE_CODE_CALIBRATION_EXPIRED, RELEASE_CODE_CLEAR, RELEASE_CODE_CUMULATIVE_DRIFT,
    RELEASE_CODE_TRANSIENT_EXCURSION,
};
use tirbase_driver_api::ModbusRegisterMap;

const PACK_FILES: &[&str] = &[
    "pack.toml",
    "gdp.toml",
    "calibration.toml",
    "qualification.toml",
    "profiles/gdp_2_8c.toml",
    "profiles/gdp_frozen.toml",
    "profiles/gdp_controlled_room.toml",
    "register-maps/gdp_reference.register-map.toml",
    "register-maps/gdp_legacy.register-map.toml",
    "expected/outcomes.toml",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/register-maps.md",
];

const PROFILES: &[&str] = &[
    "profiles/gdp_2_8c.toml",
    "profiles/gdp_frozen.toml",
    "profiles/gdp_controlled_room.toml",
];

const PARAMETERS: &[&str] = &[
    "temperature_setpoint_c",
    "humidity_setpoint_rh",
    "door_open",
    "defrost_mode",
    "compressor_on",
];

const SCENARIO_IDS: &[&str] = &[
    "S2_transient_excursion",
    "S2_cumulative_drift",
    "S2_sensor_failure",
];

const RELEASE_IDS: &[&str] = &[
    "release_clear",
    "transient_excursion",
    "cumulative_drift",
    "calibration_expiry",
    "lane_risk_event",
    "sensor_failure",
    "mkt_exceeded",
    "frozen_clear",
    "controlled_room_mkt_limit",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_root() -> PathBuf {
    workspace_root().join("tirbase-demo/pharma-gdp")
}

fn gdp_pack() -> Pack {
    load_pack(pack_root()).expect("pharma-gdp pack must load and validate")
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
fn pack_manifest_is_versioned_and_covers_three_storage_classes() {
    let pack = gdp_pack();
    assert_eq!(pack.manifest.schema_version, PACK_MANIFEST_SCHEMA_VERSION);
    assert_eq!(pack.manifest.id, "pharma-gdp");
    assert_eq!(pack.manifest.version, "1.0.0");
    assert_eq!(pack.manifest.licence, "Apache-2.0");
    assert_eq!(pack.manifest.device_class, "gdp_room");
    assert_eq!(pack.manifest.run, "run.sh");
    assert_eq!(pack.manifest.gdp.as_deref(), Some("gdp.toml"));
    assert_eq!(
        pack.manifest.calibration.as_deref(),
        Some("calibration.toml")
    );
    assert_eq!(
        pack.manifest.qualification.as_deref(),
        Some("qualification.toml")
    );
    assert_eq!(pack.manifest.profiles, PROFILES);
    assert_eq!(pack.profiles.len(), 3);
    for profile in &pack.profiles {
        assert_eq!(profile.device_class, "gdp_room");
    }
}

#[test]
fn pack_declares_every_layout_file() {
    let pack = gdp_pack();
    for relative in PACK_FILES {
        assert!(
            pack_root().join(relative).is_file(),
            "pharma-gdp pack missing {relative}"
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
        .chain(pack.manifest.gdp.iter())
        .chain(pack.manifest.calibration.iter())
        .chain(pack.manifest.qualification.iter())
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
// Profiles and units
// ---------------------------------------------------------------------------

#[test]
fn every_profile_declares_the_same_five_parameters() {
    let pack = gdp_pack();
    assert_eq!(pack.parameters().len(), PARAMETERS.len());
    for profile in PROFILES {
        let document = document(profile);
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
        assert_eq!(
            by_name.keys().copied().collect::<BTreeSet<_>>(),
            PARAMETERS.iter().copied().collect::<BTreeSet<_>>(),
            "{profile} must declare the pack's shared parameter set"
        );
        assert_eq!(
            by_name["temperature_setpoint_c"]["critical"].as_bool(),
            Some(true)
        );
        assert_eq!(
            by_name["humidity_setpoint_rh"]["unit_id"].as_integer(),
            Some(6)
        );
        assert_eq!(by_name["door_open"]["unit_id"].as_integer(), Some(7));
        // Every profile keeps a one-hour drift window so excursion and drift
        // classification are comparable across storage classes.
        assert_eq!(
            by_name["temperature_setpoint_c"]["drift_window_secs"].as_integer(),
            Some(3600)
        );
    }
}

#[test]
fn profiles_keep_the_command_envelope_wider_than_the_storage_band() {
    let pack = gdp_pack();
    for storage in &pack.gdp.as_ref().expect("GDP policy").storage {
        let document = document(&storage.profile);
        let setpoint = document["parameters"]
            .as_array()
            .expect("parameters")
            .iter()
            .find(|parameter| parameter["name"].as_str() == Some("temperature_setpoint_c"))
            .expect("setpoint parameter");
        let envelope_min = setpoint["kind"]["min"]["mantissa"].as_integer().unwrap();
        let envelope_max = setpoint["kind"]["max"]["mantissa"].as_integer().unwrap();
        assert!(
            envelope_min <= storage.band_min_c.mantissa,
            "{} envelope min must reach below the labelled band",
            storage.label
        );
        assert!(
            envelope_max >= storage.band_max_c.mantissa,
            "{} envelope max must reach above the labelled band",
            storage.label
        );
    }
}

#[test]
fn profile_document_carries_the_fields_install_needs() {
    for profile in PROFILES {
        let document = document(profile);
        let profile_id = document["profile_id"].as_str().expect("profile_id");
        assert_eq!(profile_id.len(), 36, "{profile} profile_id must be a UUID");
        assert_eq!(document["signature_alg"].as_str(), Some("ed25519"));
        let signature = document["signature_hex"].as_str().expect("signature_hex");
        assert_eq!(signature.len(), 128, "{profile} signature must be 64 bytes");
        assert!(
            signature.bytes().any(|byte| byte != b'0'),
            "{profile} must ship a real test-fixture signature, not a placeholder"
        );
        for parameter in document["parameters"].as_array().expect("parameters") {
            for field in ["safe_default", "tightening_floor"] {
                assert!(
                    parameter[field].is_table(),
                    "{profile} parameter '{}' needs {field}",
                    parameter["name"]
                );
            }
        }
    }
}

#[test]
fn register_maps_pin_names_and_units_to_the_profiles() {
    let pack = gdp_pack();
    let profile_units = pack.parameters();
    for relative in [
        "register-maps/gdp_reference.register-map.toml",
        "register-maps/gdp_legacy.register-map.toml",
    ] {
        let map = ModbusRegisterMap::parse(&read(relative))
            .unwrap_or_else(|error| panic!("parse {relative}: {error}"));
        assert_eq!(map.device_class, "gdp_room", "{relative} device_class");
        let mut writable = BTreeSet::new();
        for register in &map.registers {
            if register.writable {
                writable.insert(register.name.as_str());
            }
            let expected_unit = match register.name.as_str() {
                "storage_temp_c" | "temperature_setpoint_c" => 1,
                "relative_humidity_rh" | "humidity_setpoint_rh" => 6,
                _ => 7,
            };
            assert_eq!(
                register.unit_id, expected_unit,
                "{relative} register '{}' unit",
                register.name
            );
        }
        let profile_params: BTreeSet<&str> = profile_units.keys().copied().collect();
        assert_eq!(
            writable, profile_params,
            "{relative} must expose exactly the profiles' commandable parameters"
        );
        let temp = map
            .registers
            .iter()
            .find(|register| register.name == "storage_temp_c")
            .unwrap_or_else(|| panic!("{relative} has no storage_temp_c reading"));
        assert!(!temp.writable);
        assert_eq!(temp.scale_exponent, -1);
        let humidity = map
            .registers
            .iter()
            .find(|register| register.name == "relative_humidity_rh")
            .unwrap_or_else(|| panic!("{relative} has no relative_humidity_rh reading"));
        assert!(!humidity.writable);
        assert_eq!(humidity.unit_id, 6);
    }
}

#[test]
fn register_maps_use_documented_units() {
    let units = read("docs/register-maps.md");
    for name in PARAMETERS
        .iter()
        .copied()
        .chain(["storage_temp_c", "relative_humidity_rh"])
    {
        assert!(
            units.contains(name),
            "docs/register-maps.md must document register '{name}'"
        );
    }
    assert!(units.contains("1 = degC"));
    assert!(units.contains("6 = percent"));
    assert!(units.contains("7 = boolean"));
}

// ---------------------------------------------------------------------------
// GDP policy, MKT, calibration, qualification
// ---------------------------------------------------------------------------

#[test]
fn gdp_policy_declares_storage_classes_and_mkt_parameters() {
    let pack = gdp_pack();
    let gdp = pack.gdp.as_ref().expect("GDP policy");

    assert_eq!(gdp.lot.id, "LOT-2026-1115-0042");
    assert!(!gdp.lot.product.is_empty());
    assert!(gdp.lot.batch_size_units > 0);

    // Haynes constants: 83.144 kJ/mol over 8.314 J/(mol·K).
    assert_eq!(gdp.mkt.activation_energy_j_per_mol, 83_144);
    assert_eq!(gdp.mkt.gas_constant_milli_j_per_mol_k, 8_314);
    assert_eq!(gdp.mkt.reference_c.mantissa, 50);
    assert_eq!(gdp.mkt.reporting_interval_secs, 3_600);
    assert_eq!(gdp.mkt.sampling_interval_secs, 300);
    assert!(gdp.mkt.sampling_interval_secs <= gdp.mkt.reporting_interval_secs);
    // Six samples per reported MKT.
    assert_eq!(
        gdp.mkt.reporting_interval_secs / gdp.mkt.sampling_interval_secs,
        12
    );

    assert_eq!(gdp.storage.len(), 3);
    let labels: BTreeSet<&str> = gdp.storage.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels.len(), 3, "storage labels must be distinct");
    let profiles: BTreeSet<&str> = gdp.storage.iter().map(|s| s.profile.as_str()).collect();
    assert_eq!(profiles, PROFILES.iter().copied().collect::<BTreeSet<_>>());

    let cold = pack
        .storage_for_profile("profiles/gdp_2_8c.toml")
        .expect("2–8 °C storage class");
    assert_eq!(cold.band_min_c.mantissa, 20);
    assert_eq!(cold.band_max_c.mantissa, 80);
    assert_eq!(cold.transient_max_secs, 900);
    assert_eq!(cold.cumulative_budget_degree_secs, 600);
    assert_eq!(cold.mkt_limit_c.mantissa, 80);

    let frozen = pack
        .storage_for_profile("profiles/gdp_frozen.toml")
        .expect("frozen storage class");
    assert_eq!(frozen.band_min_c.mantissa, -250);
    assert_eq!(frozen.band_max_c.mantissa, -150);

    let room = pack
        .storage_for_profile("profiles/gdp_controlled_room.toml")
        .expect("controlled-room storage class");
    assert_eq!(room.band_min_c.mantissa, 150);
    assert_eq!(room.band_max_c.mantissa, 250);
    assert!(room.cumulative_budget_degree_secs > cold.cumulative_budget_degree_secs);
}

#[test]
fn calibration_records_are_traceable_and_inside_policy() {
    let pack = gdp_pack();
    let gdp = pack.gdp.as_ref().expect("GDP policy");
    let calibration = pack.calibration.as_ref().expect("calibration records");
    assert_eq!(calibration.sensor.len(), 4);

    let ids: BTreeSet<&str> = calibration
        .sensor
        .iter()
        .map(|sensor| sensor.sensor_id.as_str())
        .collect();
    assert_eq!(ids.len(), calibration.sensor.len(), "sensor ids are unique");
    for sensor in &calibration.sensor {
        assert!(
            sensor.interval_days <= gdp.calibration.max_interval_days,
            "{} claims a longer interval than the policy allows",
            sensor.sensor_id
        );
        assert!(sensor.expires_at_est > sensor.calibrated_at_est);
        assert!(
            sensor.certificate.starts_with("CAL-"),
            "{} must cite a calibration certificate",
            sensor.sensor_id
        );
        // The fixture interval really is 180 days.
        assert_eq!(
            sensor.expires_at_est - sensor.calibrated_at_est,
            i64::from(sensor.interval_days) * 86_400
        );
    }
}

#[test]
fn qualification_checklist_states_that_it_is_not_a_certification() {
    let pack = gdp_pack();
    let qualification = pack.qualification.as_ref().expect("checklist");
    assert_eq!(qualification.certification, "none");
    assert!(!qualification.statement.is_empty());
    assert!(!qualification.evidence_boundary.is_empty());
    assert!(
        qualification.item.len() >= 8,
        "checklist must cover DQ/IQ/OQ/PQ"
    );

    let prefixes: BTreeSet<&str> = qualification
        .item
        .iter()
        .map(|item| item.id.split('-').next().unwrap_or_default())
        .collect();
    for prefix in ["DQ", "IQ", "OQ", "PQ"] {
        assert!(
            prefixes.contains(prefix),
            "checklist must contain {prefix} items"
        );
    }
    for item in &qualification.item {
        assert!(!item.requirement.is_empty() && !item.evidence.is_empty());
    }
    // Performance qualification with the real product cannot ship with a pack.
    let pq = qualification
        .item
        .iter()
        .find(|item| item.id == "PQ-01")
        .expect("PQ-01");
    assert_eq!(pq.status, tirbase_demo::QualificationStatus::NotApplicable);
}

// ---------------------------------------------------------------------------
// Scenarios, expected output, and the excursion/drift distinction
// ---------------------------------------------------------------------------

#[test]
fn pack_ships_the_three_command_scenarios() {
    let pack = gdp_pack();
    let ids: Vec<&str> = pack
        .scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    assert_eq!(ids, SCENARIO_IDS);
    for scenario in &pack.scenarios {
        assert_eq!(scenario.class, AdversaryClass::S2);
        assert_eq!(scenario.target, "pharma-2-8-1");
        assert!(
            scenario
                .steps
                .windows(2)
                .all(|pair| pair[0].at_secs <= pair[1].at_secs),
            "scenario '{}' steps must be time-ordered",
            scenario.id
        );
    }
    // Two of three scenarios end in a refusal; the excursion scenario is
    // accepted by design and handled through the release disposition instead.
    let defended: Vec<&str> = pack
        .scenarios
        .iter()
        .filter(|scenario| {
            scenario
                .steps
                .iter()
                .any(|step| step.expect != StepDisposition::Accepted)
        })
        .map(|scenario| scenario.id.as_str())
        .collect();
    assert_eq!(defended, vec!["S2_cumulative_drift", "S2_sensor_failure"]);
}

#[test]
fn expected_outcomes_are_defended_and_machine_readable() {
    let pack = gdp_pack();
    assert_eq!(pack.expected.schema_version, PACK_MANIFEST_SCHEMA_VERSION);
    for scenario in &pack.scenarios {
        let outcome = pack
            .expected_outcome(&scenario.id)
            .expect("expected output for every scenario");
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
    let mechanisms: BTreeMap<&str, &str> = BTreeMap::from([
        ("S2_transient_excursion", "recorded"),
        ("S2_cumulative_drift", "drift"),
        ("S2_sensor_failure", "envelope+drift"),
    ]);
    for scenario in &pack.scenarios {
        assert_eq!(
            pack.expected_outcome(&scenario.id)
                .expect("outcome")
                .mechanism,
            mechanisms[scenario.id.as_str()]
        );
    }
}

#[test]
fn pack_distinguishes_a_transient_excursion_from_cumulative_drift() {
    let pack = gdp_pack();
    let profile = "profiles/gdp_2_8c.toml";

    let transient = pack
        .excursion("S2_transient_excursion", profile)
        .expect("transient excursion summary");
    assert_eq!(transient.class, ExcursionClass::Transient);
    assert_eq!(transient.out_of_band_secs, 300);
    assert_eq!(transient.out_of_band_degree_secs, 300);
    assert_eq!(transient.rejections, 0);

    let cumulative = pack
        .excursion("S2_cumulative_drift", profile)
        .expect("cumulative drift summary");
    assert_eq!(cumulative.class, ExcursionClass::Cumulative);
    assert_eq!(cumulative.rejections, 1, "the fifth step is refused");

    // The distinction drives the release disposition.
    let hold = pack
        .evaluate_release(
            profile,
            &tirbase_demo::ReleaseInputs {
                at_est: 1_770_000_000,
                excursion: Some("S2_transient_excursion"),
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(hold.disposition, ReleaseDisposition::Hold);
    assert_eq!(hold.code, RELEASE_CODE_TRANSIENT_EXCURSION);
    assert!(
        !hold.blocked,
        "a transient excursion does not block release"
    );

    let reject = pack
        .evaluate_release(
            profile,
            &tirbase_demo::ReleaseInputs {
                at_est: 1_770_000_000,
                excursion: Some("S2_cumulative_drift"),
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(reject.disposition, ReleaseDisposition::Reject);
    assert_eq!(reject.code, RELEASE_CODE_CUMULATIVE_DRIFT);
    assert!(reject.blocked);
}

#[test]
fn transient_scenario_stays_inside_the_drift_budget() {
    let pack = gdp_pack();
    let cumulative_budget = pack
        .storage_for_profile("profiles/gdp_2_8c.toml")
        .expect("storage class")
        .cumulative_budget_degree_secs;
    let transient = pack
        .excursion("S2_transient_excursion", "profiles/gdp_2_8c.toml")
        .expect("summary");
    assert!(
        transient.out_of_band_degree_secs <= cumulative_budget,
        "the transient scenario must stay inside the cumulative budget"
    );

    // The drift scenario accumulates more area than the excursion scenario,
    // which is exactly what "cumulative" is meant to capture.
    let cumulative = pack
        .excursion("S2_cumulative_drift", "profiles/gdp_2_8c.toml")
        .expect("summary");
    assert!(cumulative.out_of_band_degree_secs > transient.out_of_band_degree_secs);
}

#[test]
fn release_checks_cover_every_disposition_and_re_derive() {
    let pack = gdp_pack();
    let ids: Vec<&str> = pack
        .expected
        .release
        .iter()
        .map(|release| release.id.as_str())
        .collect();
    assert_eq!(ids, RELEASE_IDS);

    for release in &pack.expected.release {
        let decision = pack
            .evaluate_release(
                &release.profile,
                &tirbase_demo::ReleaseInputs {
                    at_est: release.at_est,
                    excursion: release.excursion.as_deref(),
                    mkt_c: release.mkt_c,
                    lane_risk_level: release.lane_risk_level,
                    sensor_failures: release.sensor_failures,
                },
            )
            .expect("release decision");
        assert_eq!(decision.code, release.code, "release '{}'", release.id);
        assert_eq!(decision.disposition, release.disposition);
        assert_eq!(decision.blocked, release.blocked);
        assert_eq!(decision.code, release.code);
    }

    let by_id: BTreeMap<&str, &tirbase_demo::ExpectedReleaseOutcome> = pack
        .expected
        .release
        .iter()
        .map(|release| (release.id.as_str(), release))
        .collect();

    // Calibration expiry blocks release even on a clean temperature record.
    let expired = by_id["calibration_expiry"];
    assert_eq!(expired.code, RELEASE_CODE_CALIBRATION_EXPIRED);
    assert_eq!(expired.disposition, ReleaseDisposition::Hold);
    assert!(expired.blocked);
    assert!(expired.mkt_c.is_some());
    assert!(expired.excursion.is_none());

    // A clean record releases without blocking.
    let clear = by_id["release_clear"];
    assert_eq!(clear.code, RELEASE_CODE_CLEAR);
    assert_eq!(clear.disposition, ReleaseDisposition::Release);
    assert!(!clear.blocked);

    let dispositions: BTreeSet<ReleaseDisposition> = pack
        .expected
        .release
        .iter()
        .map(|release| release.disposition)
        .collect();
    assert_eq!(
        dispositions,
        BTreeSet::from([
            ReleaseDisposition::Release,
            ReleaseDisposition::Hold,
            ReleaseDisposition::Reject,
        ])
    );
}

#[test]
fn expired_calibration_blocks_release_before_excursion_assessment() {
    let pack = gdp_pack();
    let profile = "profiles/gdp_2_8c.toml";
    let expiry = pack
        .calibration
        .as_ref()
        .expect("calibration")
        .sensor
        .iter()
        .map(|sensor| sensor.expires_at_est)
        .min()
        .expect("at least one sensor");

    // One second before expiry the same clean record releases.
    let before = pack
        .evaluate_release(
            profile,
            &tirbase_demo::ReleaseInputs {
                at_est: expiry - 1,
                ..Default::default()
            },
        )
        .expect("decision");
    assert_eq!(before.code, RELEASE_CODE_CLEAR);

    // One second after expiry it is blocked, even with no excursion and a good
    // MKT: the evidence itself has lapsed.
    let after = pack
        .evaluate_release(
            profile,
            &tirbase_demo::ReleaseInputs {
                at_est: expiry,
                mkt_c: Some(tirbase_types::FixedPointValue::new(50, -1, 1)),
                ..Default::default()
            },
        )
        .expect("decision");
    assert_eq!(after.code, RELEASE_CODE_CALIBRATION_EXPIRED);
    assert_eq!(after.disposition, ReleaseDisposition::Hold);
    assert!(after.blocked);
    assert!(
        after
            .reasons
            .iter()
            .any(|reason| reason.contains("calibration")),
        "the decision must explain the lapsed calibration: {:?}",
        after.reasons
    );

    // Calibration outranks the excursion assessment.
    let with_excursion = pack
        .evaluate_release(
            profile,
            &tirbase_demo::ReleaseInputs {
                at_est: expiry,
                excursion: Some("S2_cumulative_drift"),
                ..Default::default()
            },
        )
        .expect("decision");
    assert_eq!(with_excursion.code, RELEASE_CODE_CALIBRATION_EXPIRED);
}

// ---------------------------------------------------------------------------
// Simulator config, docs, and negative cases
// ---------------------------------------------------------------------------

#[test]
fn sim_config_models_thermal_humidity_and_mkt_reporting() {
    let config = document("sim/config.toml");
    assert_eq!(config["device"]["class"].as_str(), Some("gdp_room"));
    assert_eq!(
        config["device"]["profile"].as_str(),
        Some("profiles/gdp_2_8c.toml")
    );
    let thermal = &config["thermal"];
    let capacity = thermal["product_mass_kg"].as_float().expect("product mass")
        * thermal["specific_heat_j_per_kgk"]
            .as_float()
            .expect("specific heat");
    assert!(
        capacity > 10_000_000.0,
        "thermal mass is too small for a room"
    );
    assert!(
        thermal["door_open_ua_w_per_k"].as_float().expect("door UA")
            > thermal["ua_w_per_k"].as_float().expect("closed UA")
    );
    assert!(thermal["max_heating_w"].as_float().expect("heating") > 0.0);

    let humidity = &config["humidity"];
    assert!(humidity["baseline_rh"].as_integer().expect("baseline") > 0);
    assert!(
        humidity["door_open_inflow_rh"]
            .as_integer()
            .expect("inflow")
            > 0
    );

    let mkt = &config["mkt"];
    assert_eq!(
        mkt["reporting_interval_secs"].as_integer(),
        Some(3_600),
        "sim MKT reporting interval must match gdp.toml"
    );
    assert_eq!(
        mkt["sampling_interval_secs"].as_integer(),
        Some(300),
        "sim MKT sampling interval must match gdp.toml"
    );

    let includes: Vec<&str> = config["scenarios"]["include"]
        .as_array()
        .expect("scenario classes")
        .iter()
        .map(|value| value.as_str().expect("class string"))
        .collect();
    assert_eq!(includes, vec!["S2"]);
}

#[test]
fn readme_documents_intended_use_non_goals_and_evidence_boundary() {
    let readme = read("docs/README.md");
    for section in [
        "## Intended use",
        "## Assumptions",
        "## Non-goals",
        "## Expected defended output",
        "## Evidence boundary",
        "### Release dispositions (aligned with CC-11)",
        "### Transient excursion vs cumulative drift",
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
    for code in [
        "GDP-REL-001",
        "GDP-BLK-002",
        "GDP-BLK-003",
        "GDP-HLD-004",
        "GDP-BLK-005",
        "GDP-REJ-006",
        "GDP-REJ-007",
    ] {
        assert!(readme.contains(code), "README must document code {code}");
    }
    for scenario in gdp_pack().scenarios {
        assert!(
            readme.contains(&scenario.id),
            "README omits {}",
            scenario.id
        );
    }
}

#[test]
fn framework_rejects_a_pack_that_claims_certification() {
    let directory = temp_pack_copy("claims-certification");
    let path = directory.join("qualification.toml");
    let text = std::fs::read_to_string(&path).expect("read checklist");
    std::fs::write(
        &path,
        text.replace(
            "certification = \"none\"",
            "certification = \"GMP certified\"",
        ),
    )
    .expect("write checklist");

    match load_pack(&directory) {
        Err(PackError::Validation(message)) => assert!(
            message.contains("may not claim certification"),
            "unexpected validation error: {message}"
        ),
        other => panic!("expected a certification rejection, got {other:?}"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn framework_rejects_a_release_row_that_contradicts_the_policy() {
    let directory = temp_pack_copy("wrong-release");
    let path = directory.join("expected/outcomes.toml");
    let text = std::fs::read_to_string(&path).expect("read expected output");
    let patched = text.replace(
        "id = \"calibration_expiry\"\nprofile = \"profiles/gdp_2_8c.toml\"\nat_est = 1780000000",
        "id = \"calibration_expiry\"\nprofile = \"profiles/gdp_2_8c.toml\"\nat_est = 1770000000",
    );
    assert_ne!(patched, text, "the calibration row must be patched");
    std::fs::write(&path, patched).expect("write expected output");

    match load_pack(&directory) {
        Err(PackError::Validation(message)) => assert!(
            message.contains("calibration_expiry"),
            "unexpected validation error: {message}"
        ),
        other => panic!("expected a release-check rejection, got {other:?}"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn framework_rejects_a_calibration_interval_above_policy() {
    let directory = temp_pack_copy("long-calibration");
    let path = directory.join("calibration.toml");
    let text = std::fs::read_to_string(&path).expect("read calibration");
    let patched = text.replace(
        "sensor_id = \"PHARMA-2-8-A\"\nmethod = \"comparison, ice-point, ASTM E74\"\ncalibrated_at_est = 1760000000\ninterval_days = 180",
        "sensor_id = \"PHARMA-2-8-A\"\nmethod = \"comparison, ice-point, ASTM E74\"\ncalibrated_at_est = 1760000000\ninterval_days = 365",
    );
    assert_ne!(patched, text, "the sensor row must be patched");
    std::fs::write(&path, patched).expect("write calibration");

    match load_pack(&directory) {
        Err(PackError::Validation(message)) => assert!(
            message.contains("PHARMA-2-8-A"),
            "unexpected validation error: {message}"
        ),
        other => panic!("expected a calibration-policy rejection, got {other:?}"),
    }
    std::fs::remove_dir_all(&directory).ok();
}

/// Copy the pack into a uniquely named temporary directory so negative tests can
/// mutate it without touching the committed pack. The manifest identity check
/// compares the id against the directory name, so the copy keeps `pharma-gdp`.
fn temp_pack_copy(label: &str) -> PathBuf {
    let directory = std::env::temp_dir()
        .join(format!("tirbase-gdp-pack-{label}-{}", std::process::id()))
        .join("pharma-gdp");
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
