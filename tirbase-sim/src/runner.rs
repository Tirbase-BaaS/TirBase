// SPDX-License-Identifier: AGPL-3.0-only

//! TOML adversary-scenario loader and seeded scenario runner (//! CLAIM-39.1, PV-12.1, PV-12.2).
//!
//! Each scenario in `tirbase-sim/scenarios/S*.toml` declares its catalog ID,
//! title, requirement references, the guard/control it exercises, and how many
//! seeds to execute. [`ScenarioRunner`] resolves the ID through
//! [`crate::scenarios::registry`] and runs the scenario once per seed.
//!
//! * A CI run executes every declared seed; [`MIN_SEEDS_PER_RUN`] is enforced
//! so the adversarial catalog can never silently shrink below 1,000 seeded
//! executions (PV-12.1).
//! * On the first failing seed the runner writes
//! `scenario <ID> FAILED seed=<seed> :: <detail>` to the output stream
//! *before* returning, so re-running with that seed reproduces the failure
//! exactly (PV-12.2).
//!
//! The runner is production code (not `#[cfg(test)]`) so it can be driven by
//! the simulator binary, CI, or an operator reproducing a failure locally.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// CI must execute at least this many seeded scenarios per run (PV-12.1).
pub const MIN_SEEDS_PER_RUN: u64 = 1_000;

const DEFAULT_SEEDS: u64 = 32;
const DEFAULT_TICKS: u64 = 16;
const MAX_SEEDS_PER_SPEC: u64 = 4_096;

/// A single TOML scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioSpec {
 /// Catalog identifier, `S1`..`S35`.
    pub id: String,
 /// Human-readable title (matches `docs/adversary-scenarios.md`).
    pub title: String,
 /// Number of seeds to execute for this scenario in one full run.
    pub seeds: u64,
 /// Virtual ticks used by scenarios that drive [`crate::TirBaseSim`].
    pub ticks: u64,
 /// PV requirement identifiers this scenario covers.
    pub requirements: Vec<String>,
 /// Guard/control names the scenario exercises (used by the wiring audit).
    pub guards: Vec<String>,
 /// Path the scenario was loaded from.
    pub source: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ScenarioFile {
    id: String,
    title: String,
    #[serde(default = "default_seeds")]
    seeds: u64,
    #[serde(default = "default_ticks")]
    ticks: u64,
    #[serde(default)]
    requirements: Vec<String>,
    #[serde(default)]
    guards: Vec<String>,
}

fn default_seeds() -> u64 {
    DEFAULT_SEEDS
}

fn default_ticks() -> u64 {
    DEFAULT_TICKS
}

/// Errors produced while loading or running the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerError {
 /// The scenario directory or file could not be read.
    Io(String),
 /// The TOML document is malformed.
    Toml(String),
 /// A declared field is invalid or a catalog invariant is violated.
    InvalidSpec(String),
 /// A scenario ID has no registered implementation.
    UnknownScenario(String),
 /// One or more seeded executions failed. Every failure already had its
 /// seed written to the output stream before this error was returned.
    Failures(Vec<ScenarioFailure>),
 /// The catalog would execute fewer than [`MIN_SEEDS_PER_RUN`] seeds.
    InsufficientSeeds { declared: u64, required: u64 },
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunnerError::Io(detail) => write!(f, "scenario loader I/O error: {detail}"),
            RunnerError::Toml(detail) => write!(f, "scenario TOML parse error: {detail}"),
            RunnerError::InvalidSpec(detail) => write!(f, "invalid scenario declaration: {detail}"),
            RunnerError::UnknownScenario(id) => {
                write!(f, "no implementation registered for scenario {id}")
            }
            RunnerError::Failures(failures) => {
                let first = failures
                    .first()
                    .map(|failure| {
                        format!(
                            "{} failed (seed={}); {} failure(s) in this run",
                            failure.id,
                            failure.seed,
                            failures.len()
                        )
                    })
                    .unwrap_or_else(|| "scenario run failed".to_string());
                write!(f, "{first}")
            }
            RunnerError::InsufficientSeeds { declared, required } => write!(
                f,
                "scenario catalog declares {declared} seeded runs, CI requires at least {required}"
            ),
        }
    }
}

impl std::error::Error for RunnerError {}

/// One failing seeded execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioFailure {
    pub id: String,
    pub seed: u64,
    pub detail: String,
}

/// Summary of a complete catalog run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioRunSummary {
 /// Number of scenario specs executed.
    pub scenarios: usize,
 /// Total seeded executions (sum of each spec's `seeds`).
    pub seeds_executed: u64,
 /// Per-scenario seed counts, in catalog order.
    pub per_scenario: Vec<(String, u64)>,
}

impl ScenarioRunSummary {
 /// Total seeds executed in this run.
    pub fn total_seeds(&self) -> u64 {
        self.seeds_executed
    }
}

type ScenarioFn = fn(u64) -> Result<(), String>;

/// Loads and executes the S1–S35 scenario catalog.
pub struct ScenarioRunner {
    specs: Vec<ScenarioSpec>,
    registry: BTreeMap<String, ScenarioFn>,
    base_seed: u64,
}

impl fmt::Debug for ScenarioRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScenarioRunner")
            .field("specs", &self.specs.len())
            .field("registered", &self.registry.len())
            .field("base_seed", &self.base_seed)
            .finish()
    }
}

impl ScenarioRunner {
 /// Build a runner from explicit specs and a scenario registry.
    pub fn new(specs: Vec<ScenarioSpec>, registry: BTreeMap<String, ScenarioFn>) -> Self {
        Self {
            specs,
            registry,
            base_seed: 1,
        }
    }

 /// Load the catalog shipped with this crate and the built-in registry.
    pub fn builtin() -> Result<Self, RunnerError> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios");
        let specs = load_scenario_dir(&dir)?;
        Ok(Self::new(specs, crate::scenarios::registry()))
    }

 /// Override the first seed in the run. Each spec's seeds are offset so
 /// different scenarios do not replay the same RNG streams.
    pub fn with_base_seed(mut self, base_seed: u64) -> Self {
        self.base_seed = base_seed;
        self
    }

 /// Loaded scenario declarations.
    pub fn specs(&self) -> &[ScenarioSpec] {
        &self.specs
    }

 /// Number of registered implementations.
    pub fn registered(&self) -> usize {
        self.registry.len()
    }

 /// Total seeds this catalog will execute.
    pub fn declared_seeds(&self) -> u64 {
        self.specs.iter().map(|spec| spec.seeds).sum()
    }

 /// Execute one scenario for one explicit seed.
    pub fn run_scenario(&self, id: &str, seed: u64) -> Result<(), RunnerError> {
        let Some(scenario) = self.registry.get(id) else {
            return Err(RunnerError::UnknownScenario(id.to_string()));
        };
        execute(id, *scenario, seed).map_err(|detail| {
            RunnerError::Failures(vec![ScenarioFailure {
                id: id.to_string(),
                seed,
                detail,
            }])
        })
    }

 /// Execute every spec for every configured seed, writing a reproducible
 /// failure line (including the seed) before returning.
    pub fn run(&self) -> Result<ScenarioRunSummary, RunnerError> {
        let mut out = io::stdout().lock();
        self.run_to(&mut out)
    }

 /// Like [`ScenarioRunner::run`], but writes failure reports to `out`.
    pub fn run_to(&self, out: &mut dyn Write) -> Result<ScenarioRunSummary, RunnerError> {
        let declared = self.declared_seeds();
        if declared < MIN_SEEDS_PER_RUN {
            return Err(RunnerError::InsufficientSeeds {
                declared,
                required: MIN_SEEDS_PER_RUN,
            });
        }

        let mut failures = Vec::new();
        let mut per_scenario = Vec::with_capacity(self.specs.len());
        let mut seeds_executed = 0u64;

        for (index, spec) in self.specs.iter().enumerate() {
            let Some(scenario) = self.registry.get(&spec.id) else {
                return Err(RunnerError::UnknownScenario(spec.id.clone()));
            };
            per_scenario.push((spec.id.clone(), spec.seeds));
            for offset in 0..spec.seeds {
                let seed = self
                    .base_seed
                    .wrapping_add((index as u64).wrapping_mul(10_000))
                    .wrapping_add(offset);
                seeds_executed = seeds_executed.saturating_add(1);
                if let Err(detail) = execute(&spec.id, *scenario, seed) {
 // PV-12.2: write the seed before returning to the caller.
                    let _ = writeln!(
                        out,
                        "scenario {} FAILED seed={} :: {}",
                        spec.id, seed, detail
                    );
                    let _ = out.flush();
                    failures.push(ScenarioFailure {
                        id: spec.id.clone(),
                        seed,
                        detail,
                    });
                }
            }
        }

        if failures.is_empty() {
            Ok(ScenarioRunSummary {
                scenarios: self.specs.len(),
                seeds_executed,
                per_scenario,
            })
        } else {
            Err(RunnerError::Failures(failures))
        }
    }
}

fn execute(id: &str, scenario: ScenarioFn, seed: u64) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(|| scenario(seed))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(detail)) => Err(detail),
        Err(payload) => Err(format!(
            "scenario {id} panicked: {}",
            panic_message(payload)
        )),
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Load and validate a single scenario TOML file.
pub fn load_scenario_file(path: impl AsRef<Path>) -> Result<ScenarioSpec, RunnerError> {
    let path = path.as_ref();
    let source = std::fs::read_to_string(path)
        .map_err(|error| RunnerError::Io(format!("{}: {error}", path.display())))?;
    let file: ScenarioFile = toml::from_str(&source)
        .map_err(|error| RunnerError::Toml(format!("{}: {error}", path.display())))?;
    validate_spec(file, path)
}

/// Load every `*.toml` file in `dir` in deterministic filename order.
pub fn load_scenario_dir(dir: impl AsRef<Path>) -> Result<Vec<ScenarioSpec>, RunnerError> {
    let dir = dir.as_ref();
    let entries = std::fs::read_dir(dir)
        .map_err(|error| RunnerError::Io(format!("{}: {error}", dir.display())))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| RunnerError::Io(format!("{}: {error}", dir.display())))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(RunnerError::InvalidSpec(format!(
            "no scenario TOML files found in {}",
            dir.display()
        )));
    }

    let mut specs = Vec::with_capacity(paths.len());
    let mut seen = BTreeSet::new();
    for path in paths {
        let spec = load_scenario_file(&path)?;
        if !seen.insert(spec.id.clone()) {
            return Err(RunnerError::InvalidSpec(format!(
                "duplicate scenario id {} in catalog",
                spec.id
            )));
        }
        specs.push(spec);
    }
    Ok(specs)
}

fn validate_spec(file: ScenarioFile, path: &Path) -> Result<ScenarioSpec, RunnerError> {
    let id = file.id.trim().to_string();
    if id.len() < 2
        || !id.starts_with('S')
        || !id[1..].chars().all(|character| character.is_ascii_digit())
    {
        return Err(RunnerError::InvalidSpec(format!(
            "{}: scenario id {id:?} must look like S1..S35",
            path.display()
        )));
    }
    if file.title.trim().is_empty() {
        return Err(RunnerError::InvalidSpec(format!(
            "{}: scenario {id} has an empty title",
            path.display()
        )));
    }
    if file.seeds == 0 || file.seeds > MAX_SEEDS_PER_SPEC {
        return Err(RunnerError::InvalidSpec(format!(
            "{}: scenario {id} seeds={} must be 1..={MAX_SEEDS_PER_SPEC}",
            path.display(),
            file.seeds
        )));
    }
    if file.ticks == 0 {
        return Err(RunnerError::InvalidSpec(format!(
            "{}: scenario {id} ticks must be greater than zero",
            path.display()
        )));
    }
    Ok(ScenarioSpec {
        id,
        title: file.title,
        seeds: file.seeds,
        ticks: file.ticks,
        requirements: file.requirements,
        guards: file.guards,
        source: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: &str, seeds: u64) -> ScenarioSpec {
        ScenarioSpec {
            id: id.to_string(),
            title: format!("scenario {id}"),
            seeds,
            ticks: 4,
            requirements: vec!["PV-12.4".to_string()],
            guards: vec!["test".to_string()],
            source: PathBuf::from(format!("{id}.toml")),
        }
    }

    fn ok(_seed: u64) -> Result<(), String> {
        Ok(())
    }

    fn always_fails(_seed: u64) -> Result<(), String> {
        Err("guard missing".to_string())
    }

    #[test]
    fn loads_the_shipped_catalog_and_meets_the_seed_floor() {
        let runner = ScenarioRunner::builtin().expect("builtin catalog");
        assert_eq!(runner.specs().len(), 35, "catalog must contain S1..S35");
        assert!(
            runner.declared_seeds() >= MIN_SEEDS_PER_RUN,
            "declared {} seeds",
            runner.declared_seeds()
        );
        assert_eq!(runner.registered(), 35);
        for index in 1..=35 {
            assert!(runner
                .specs()
                .iter()
                .any(|spec| spec.id == format!("S{index}")));
        }
    }

    #[test]
    fn failing_scenario_prints_the_seed_before_exit() {
        let mut registry = BTreeMap::new();
        registry.insert("S1".to_string(), always_fails as ScenarioFn);
        let runner = ScenarioRunner::new(vec![spec("S1", MIN_SEEDS_PER_RUN)], registry);
        let mut out = Vec::new();
        let error = runner.run_to(&mut out).expect_err("must fail");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("scenario S1 FAILED seed=1"), "{text}");
        match error {
            RunnerError::Failures(failures) => {
                assert_eq!(failures.len(), MIN_SEEDS_PER_RUN as usize);
                assert_eq!(failures[0].seed, 1);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn insufficient_catalog_is_rejected() {
        let mut registry = BTreeMap::new();
        registry.insert("S1".to_string(), ok as ScenarioFn);
        let runner = ScenarioRunner::new(vec![spec("S1", 10)], registry);
        assert_eq!(
            runner.run_to(&mut Vec::new()),
            Err(RunnerError::InsufficientSeeds {
                declared: 10,
                required: MIN_SEEDS_PER_RUN
            })
        );
    }

    #[test]
    fn unknown_scenario_is_rejected() {
        let runner = ScenarioRunner::new(vec![spec("S99", MIN_SEEDS_PER_RUN)], BTreeMap::new());
        assert_eq!(
            runner.run_to(&mut Vec::new()),
            Err(RunnerError::UnknownScenario("S99".to_string()))
        );
    }

    #[test]
    fn panic_is_reported_as_a_failure_with_the_seed() {
        fn panics(_seed: u64) -> Result<(), String> {
            panic!("boom");
        }
        let mut registry = BTreeMap::new();
        registry.insert("S1".to_string(), panics as ScenarioFn);
        let runner = ScenarioRunner::new(vec![spec("S1", MIN_SEEDS_PER_RUN)], registry);
        let mut out = Vec::new();
        let error = runner.run_to(&mut out).expect_err("must fail");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("seed=1"), "{text}");
        assert!(text.contains("boom"), "{text}");
        assert!(matches!(error, RunnerError::Failures(_)));
    }
}
