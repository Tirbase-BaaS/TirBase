// SPDX-License-Identifier: AGPL-3.0-only

//! ST-09 gateway integration tests: the real engines must defend every
//! scenario, deterministically, with expectations and invariants asserted.

use tirbase_venue_scenario_runner::{run_scenario, RunError};
use tirbase_venue_scenarios::{load_all, validated, Scenario};

fn scenario(id: &str) -> Scenario {
    load_all()
        .expect("pack parses")
        .into_iter()
        .find(|scenario| scenario.id == id)
        .unwrap_or_else(|| panic!("scenario {id} exists"))
}

#[test]
fn every_scenario_defends_its_invariant() {
    for scenario in validated().expect("pack validates") {
        let observation =
            run_scenario(&scenario).unwrap_or_else(|error| panic!("{}: {error}", scenario.id));
        assert!(observation.invariant.passed, "{}", scenario.id);
        assert_eq!(observation.steps.len(), scenario.timeline.len());
        assert_eq!(observation.invariant.id, scenario.safety_invariant.id);
    }
}

#[test]
fn runs_are_deterministic() {
    for scenario in load_all().expect("parse") {
        let first = run_scenario(&scenario).expect("first run");
        let second = run_scenario(&scenario).expect("second run");
        assert_eq!(first, second, "{} is deterministic", scenario.id);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap(),
            "{} serializes deterministically",
            scenario.id
        );
    }
}

#[test]
fn a_wrong_step_expectation_is_caught() {
    let mut scenario = scenario("gate-replay");
    scenario.expected_steps[1].result = "admitted".to_string();
    match run_scenario(&scenario) {
        Err(RunError::StepMismatch { index, .. }) => assert_eq!(index, 1),
        other => panic!("expected StepMismatch, got {other:?}"),
    }
}

#[test]
fn a_wrong_final_expectation_is_caught() {
    let mut scenario = scenario("capacity-breach");
    scenario.expected_final.venue_occupancy = Some(99);
    match run_scenario(&scenario) {
        Err(RunError::FinalMismatch { field, .. }) => assert_eq!(field, "venue_occupancy"),
        other => panic!("expected FinalMismatch, got {other:?}"),
    }
}

#[test]
fn a_missing_observation_fails_its_invariant() {
    // The sensor scenario is run with the stale-list invariant: no stale
    // revocation list is ever observed, so the invariant cannot hold.
    let mut scenario = scenario("sensor-spoof");
    scenario.safety_invariant.id = "stale_revocation_list_never_admits".to_string();
    match run_scenario(&scenario) {
        Err(RunError::InvariantFailed { id, detail }) => {
            assert_eq!(id, "stale_revocation_list_never_admits");
            assert!(detail.contains("no stale revocation list"), "{detail}");
        }
        other => panic!("expected InvariantFailed, got {other:?}"),
    }
}

#[test]
fn an_unknown_invariant_is_refused() {
    let mut scenario = scenario("power-loss-gate");
    scenario.safety_invariant.id = "vibes_based_safety".to_string();
    match run_scenario(&scenario) {
        Err(RunError::Invalid(detail)) => assert!(detail.contains("unknown invariant")),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn an_unknown_ticket_or_gate_is_refused() {
    let mut scenario = scenario("gate-replay");
    scenario.timeline[0] = tirbase_venue_scenarios::TimelineStep::PresentTicket {
        at_offset_us: 3_600_000_000,
        ticket_id: "ticket-missing".to_string(),
        gate_id: "gate-n1".to_string(),
    };
    match run_scenario(&scenario) {
        Err(RunError::Invalid(detail)) => assert!(detail.contains("not declared")),
        other => panic!("expected Invalid, got {other:?}"),
    }
}
