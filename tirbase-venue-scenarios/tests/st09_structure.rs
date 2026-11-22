// SPDX-License-Identifier: Apache-2.0

//! ST-09 structural tests for the data-only scenario pack.
//!
//! These tests validate the pack itself: every scenario parses strictly,
//! declares its initial state, timeline, approvals, expectations and invariant,
//! stays deterministic, and the pack contains no runtime dependency.

use std::collections::BTreeSet;

use tirbase_venue_scenarios::{
    load_all, validated, ExpectedFinal, Scenario, TimelineStep, INVARIANTS, SCENARIOS,
};

const EXPECTED_IDS: &[&str] = &[
    "capacity-breach",
    "gate-replay",
    "power-loss-gate",
    "revocation-expiry",
    "sensor-spoof",
    "venue-lockdown",
];

#[test]
fn the_pack_holds_the_six_declared_scenarios() {
    let scenarios = validated().expect("pack validates");
    let ids: Vec<&str> = scenarios.iter().map(|scenario| scenario.id.as_str()).collect();
    assert_eq!(ids, EXPECTED_IDS);
    assert_eq!(SCENARIOS.len(), EXPECTED_IDS.len());

    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "scenario ids are unique");
}

#[test]
fn every_scenario_declares_state_timeline_commands_and_expectations() {
    for scenario in load_all().expect("pack parses") {
        assert!(!scenario.timeline.is_empty(), "{} has steps", scenario.id);
        assert!(
            !scenario.expected_steps.is_empty(),
            "{} declares expected steps",
            scenario.id
        );
        assert!(
            !scenario.safety_invariant.statement.trim().is_empty(),
            "{} declares an invariant statement",
            scenario.id
        );
        assert!(
            INVARIANTS.contains(&scenario.safety_invariant.id.as_str()),
            "{} uses a known invariant id",
            scenario.id
        );
        assert!(
            !scenario.initial.venue_id.is_empty(),
            "{} declares a venue",
            scenario.id
        );

        let uses_commands = scenario.timeline.iter().any(|step| {
            matches!(
                step,
                TimelineStep::Lockdown { .. }
                    | TimelineStep::ReleaseLockdown { .. }
                    | TimelineStep::CapacityOverride { .. }
                    | TimelineStep::EmergencyGateOpen { .. }
                    | TimelineStep::ApplyRevocationDelta { .. }
            )
        });
        if integer_actions(&scenario).contains("capacity_override")
            || scenario.id == "venue-lockdown"
        {
            assert!(
                uses_commands,
                "{} declares its signed commands and approvals",
                scenario.id
            );
        }

        // Every timeline step is covered by an expected outcome or the final
        // expectations; the runner asserts both.
        for expected in &scenario.expected_steps {
            assert!(expected.index < scenario.timeline.len());
            assert!(!expected.result.trim().is_empty());
        }
        assert!(
            scenario_final_asserts_something(&scenario.expected_final),
            "{} asserts a final state",
            scenario.id
        );
    }
}

fn integer_actions(scenario: &Scenario) -> BTreeSet<&'static str> {
    scenario
        .timeline
        .iter()
        .map(TimelineStep::action)
        .collect()
}

fn scenario_final_asserts_something(expected: &ExpectedFinal) -> bool {
    expected.venue_occupancy.is_some()
        || expected.revocation_version.is_some()
        || expected.revocation_alarm.is_some()
        || !expected.zone_occupancy.is_empty()
        || !expected.revoked_tickets.is_empty()
        || !expected.lockdowns.is_empty()
        || !expected.gate_postures.is_empty()
        || !expected.security_events.is_empty()
        || !expected.capacity_audit_events.is_empty()
        || !expected.gate_positions.is_empty()
}

#[test]
fn scenarios_are_deterministic_documents() {
    let first = load_all().expect("parse");
    let second = load_all().expect("parse");
    assert_eq!(first, second, "loading twice yields equal documents");

    for scenario in &first {
        let json = serde_json::to_string(scenario).expect("serialize");
        let restored: Scenario = serde_json::from_str(&json).expect("parse");
        assert_eq!(&restored, scenario, "{} round-trips", scenario.id);
        let again = serde_json::to_string(&restored).expect("serialize");
        assert_eq!(json, again, "{} serializes deterministically", scenario.id);
    }
}

#[test]
fn the_pack_is_strict_data() {
    // Unknown fields are rejected on the document and on individual steps.
    let json = SCENARIOS[0].1;
    let mut value: serde_json::Value = serde_json::from_str(json).expect("value");
    value["unexpected"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<Scenario>(value).is_err(),
        "unknown document fields are refused"
    );

    let mut value: serde_json::Value = serde_json::from_str(SCENARIOS[1].1).expect("value");
    value["timeline"][0]["extra"] = serde_json::json!("ignored?");
    assert!(
        serde_json::from_value::<Scenario>(value).is_err(),
        "unknown step fields are refused"
    );

    // The pack is JSON only, one document per declared scenario.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("scenarios directory")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    let expected: Vec<String> = SCENARIOS
        .iter()
        .map(|(id, _)| format!("{id}.json"))
        .collect();
    assert_eq!(names, expected, "only the declared JSON documents exist");
    for name in &names {
        assert!(name.ends_with(".json"));
    }
}

#[test]
fn the_pack_is_apache_and_links_no_runtime() {
    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("license = \"Apache-2.0\""));
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("tirbase-")),
        "the Apache pack depends on no TirBase runtime crate"
    );

    let docs = include_str!("../../docs/venues/st09-scenario-pack.md");
    for phrase in [
        "not safety certification",
        "biometric",
        "fire-system",
        "data-only",
    ] {
        assert!(
            docs.to_lowercase().contains(phrase),
            "docs state the non-goal: {phrase}"
        );
    }
}

#[test]
fn every_invariant_is_used_by_a_scenario() {
    let scenarios = load_all().expect("parse");
    for invariant in INVARIANTS {
        assert!(
            scenarios
                .iter()
                .any(|scenario| scenario.safety_invariant.id == *invariant),
            "invariant {invariant} is exercised by a scenario"
        );
    }
}
