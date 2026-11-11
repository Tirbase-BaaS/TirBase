//! Task 39 integration test — TOML scenario catalog + ≥1,000 seeded runs.
//!
//! CI executes every declared seed of the S1–S35 catalog.  The runner prints a
//! failing scenario's seed before returning (PV-12.2); the test below asserts
//! both the catalog shape and the failure-report contract.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tirbase_sim::runner::{
    load_scenario_dir, RunnerError, ScenarioRunner, ScenarioSpec, MIN_SEEDS_PER_RUN,
};

fn catalog_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios")
}

#[test]
fn catalog_declares_s1_through_s35_and_at_least_1000_seeds() {
    let specs = load_scenario_dir(catalog_dir()).expect("load scenario catalog");
    assert_eq!(specs.len(), 35, "catalog must contain S1..S35");
    let ids: std::collections::BTreeSet<&str> = specs.iter().map(|s| s.id.as_str()).collect();
    for index in 1..=35 {
        let id = format!("S{index}");
        assert!(ids.contains(id.as_str()), "{id} missing from TOML catalog");
    }
    let total: u64 = specs.iter().map(|spec| spec.seeds).sum();
    assert!(
        total >= MIN_SEEDS_PER_RUN,
        "catalog declares only {total} seeds; CI requires {MIN_SEEDS_PER_RUN}"
    );
    for spec in &specs {
        assert!(!spec.guards.is_empty(), "{} has no guard target", spec.id);
        assert!(
            !spec.requirements.is_empty(),
            "{} has no PV requirement",
            spec.id
        );
        assert!(spec.ticks > 0, "{} has zero ticks", spec.id);
    }
}

#[test]
fn ci_executes_every_seeded_scenario() {
    let runner = ScenarioRunner::builtin().expect("builtin scenario runner");
    let summary = runner.run_to(&mut std::io::sink()).unwrap_or_else(|error| {
        panic!("scenario catalog failed: {error}");
    });
    assert_eq!(summary.scenarios, 35);
    assert!(
        summary.seeds_executed >= MIN_SEEDS_PER_RUN,
        "executed only {} seeded scenarios",
        summary.seeds_executed
    );
    assert_eq!(summary.per_scenario.len(), 35);
}

fn failing(_seed: u64) -> Result<(), String> {
    Err("guard/control removed".to_string())
}

#[test]
fn failing_scenario_prints_its_seed_before_exit() {
    type ScenarioFn = fn(u64) -> Result<(), String>;
    let mut registry: BTreeMap<String, ScenarioFn> = BTreeMap::new();
    registry.insert("S1".to_string(), failing);
    let spec = ScenarioSpec {
        id: "S1".to_string(),
        title: "mutation probe".to_string(),
        seeds: MIN_SEEDS_PER_RUN,
        ticks: 1,
        requirements: vec!["PV-12.4".to_string()],
        guards: vec!["mutation-probe".to_string()],
        source: PathBuf::from("S01.toml"),
    };
    let runner = ScenarioRunner::new(vec![spec], registry);
    let mut output = Vec::new();
    let error = runner.run_to(&mut output).expect_err("must fail");
    let text = String::from_utf8(output).expect("utf-8 output");
    assert!(
        text.contains("scenario S1 FAILED seed=1 :: guard/control removed"),
        "failure report must print the seed before exit: {text}"
    );
    match error {
        RunnerError::Failures(failures) => {
            assert_eq!(failures.len() as u64, MIN_SEEDS_PER_RUN);
            assert_eq!(failures[0].seed, 1);
        }
        other => panic!("unexpected error: {other}"),
    }
}
