// SPDX-License-Identifier: AGPL-3.0-only

//! `venue-scenarios` — run the ST-09 defensive scenario pack.
//!
//! Every scenario is interpreted against the real ST-02..ST-08 engines. A run
//! prints each observed step, the final state summary and the scenario's
//! safety invariant. Exit code 0 means every selected scenario defended its
//! invariant; 1 means at least one did not; 2 means the pack itself failed to
//! load.

use std::process::ExitCode;

use tirbase_venue_scenario_runner::run_scenario;
use tirbase_venue_scenarios::{load_all, Scenario};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => run(None),
        [flag] if flag == "--list" => list(),
        [flag, id] if flag == "--scenario" => run(Some(id.as_str())),
        [flag] if flag == "--help" || flag == "-h" => {
            usage();
            ExitCode::SUCCESS
        }
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("usage: venue-scenarios [--list | --scenario <id>]");
}

fn scenarios() -> Result<Vec<Scenario>, ExitCode> {
    match load_all() {
        Ok(scenarios) => Ok(scenarios),
        Err(error) => {
            eprintln!("scenario pack failed to load: {error}");
            Err(ExitCode::from(2))
        }
    }
}

fn list() -> ExitCode {
    let scenarios = match scenarios() {
        Ok(scenarios) => scenarios,
        Err(code) => return code,
    };
    for scenario in scenarios {
        println!("{:<20} {}", scenario.id, scenario.title);
    }
    ExitCode::SUCCESS
}

fn run(only: Option<&str>) -> ExitCode {
    let scenarios = match scenarios() {
        Ok(scenarios) => scenarios,
        Err(code) => return code,
    };
    let selected: Vec<Scenario> = match only {
        Some(id) => match scenarios.into_iter().find(|scenario| scenario.id == id) {
            Some(scenario) => vec![scenario],
            None => {
                eprintln!("unknown scenario: {id}");
                return ExitCode::from(2);
            }
        },
        None => scenarios,
    };

    println!("TirBase venue scenario pack — defended run");
    println!("runners: ST-02..ST-08 engines; pack is Apache-2.0 data\n");

    let mut defended = 0usize;
    for scenario in &selected {
        println!(
            "scenario {} — {}\n  invariant: {}\n  {}",
            scenario.id,
            scenario.title,
            scenario.safety_invariant.id,
            scenario.safety_invariant.statement
        );
        match run_scenario(scenario) {
            Ok(observation) => {
                for step in &observation.steps {
                    match &step.reason {
                        Some(reason) => println!(
                            "  step {:>2} {:>+14}us {:<22} {:<10} {}",
                            step.index, step.at_offset_us, step.action, step.result, reason
                        ),
                        None => println!(
                            "  step {:>2} {:>+14}us {:<22} {:<10}",
                            step.index, step.at_offset_us, step.action, step.result
                        ),
                    }
                }
                println!(
                    "  final: occupancy={} revocation=v{} lockdowns={:?} alarms={:?}",
                    observation.final_state.venue_occupancy,
                    observation.final_state.revocation_version,
                    observation.final_state.lockdowns,
                    observation.final_state.revocation_alarm
                );
                println!(
                    "  invariant {} — {}\n  DEFENDED\n",
                    observation.invariant.id,
                    if observation.invariant.passed {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                );
                defended += 1;
            }
            Err(error) => println!("  NOT DEFENDED: {error}\n"),
        }
    }

    println!(
        "summary: {defended}/{} scenarios defended",
        selected.len()
    );
    if defended == selected.len() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
