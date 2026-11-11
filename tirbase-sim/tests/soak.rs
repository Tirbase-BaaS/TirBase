//! Virtual-time soak integration test (CLAIM-45.1, PV-15.5).
//!
//! Runs 72h of simulated operation via the tirbase-sim accelerated clock with
//! deterministic fault injection and must complete within the 2-hour CI
//! wall-clock budget.

use std::time::Instant;

use tirbase_sim::soak::{
    run_ci_72h_soak, run_soak, SoakConfig, SOAK_DURATION_SECS,
};

#[test]
fn soak_api_covers_required_duration() {
    let cfg = SoakConfig {
        seed: 0x45A1,
        duration_secs: 600,
        tick_ms: 1_000,
        nodes: 3,
        fault_injection: true,
    };
    let report = run_soak(&cfg).expect("short virtual soak must pass");
    assert!(report.simulated_secs >= 600);
    assert!(report.faults_injected > 0);
}

#[test]
fn virtual_time_soak_runs_72h_with_fault_injection_within_budget() {
    let start = Instant::now();
    let report = run_ci_72h_soak(0x5072_45A1).expect("72h virtual-time soak must pass");
    let elapsed = start.elapsed();

    assert_eq!(
        report.simulated_secs, SOAK_DURATION_SECS,
        "soak must simulate the full 72h duration"
    );
    assert!(
        report.faults_injected > 0,
        "soak must exercise deterministic fault injection"
    );
    assert!(
        elapsed.as_secs() < 2 * 60 * 60,
        "72h virtual-time soak exceeded 2h CI wall-clock limit: {elapsed:?}"
    );

    println!(
        "soak OK: seed={} simulated={}s ticks={} faults={} elapsed={:?}",
        report.seed, report.simulated_secs, report.ticks, report.faults_injected, elapsed
    );
}
