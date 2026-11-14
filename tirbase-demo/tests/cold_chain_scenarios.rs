// SPDX-License-Identifier: Apache-2.0

//! Cold-chain flagship demo pack — S1/S2/S3 wiring and run.sh (CLAIM-47.2, 47.4).
//!
//! Each adversary scenario is exercised via the production `tirbase-sim`
//! scenario implementations (guard/envelope, drift window, anti-replay/idempotency)
//! with observable ACCEPT/REJECT output demonstrating the defended attack.

use std::process::Command;
use std::time::Duration;

use tirbase_sim::scenarios::s1_s2_s3::{
    scenario_s1_envelope_violation_rejected, scenario_s2_slow_ramp_drift_rejected,
    scenario_s3_replay_duplicate_idempotency_no_second_actuation,
};

#[test]
fn cold_chain_s1_out_of_envelope_command_defended() {
    scenario_s1_envelope_violation_rejected();
    println!("S1 (out-of-envelope command): REJECTED - envelope bounds defended (no actuation)");
}

#[test]
fn cold_chain_s2_slow_ramp_defended() {
    scenario_s2_slow_ramp_drift_rejected();
    println!("S2 (slow ramp / cumulative drift): REJECTED - drift/rate window defended");
}

#[test]
fn cold_chain_s3_replay_defended() {
    scenario_s3_replay_duplicate_idempotency_no_second_actuation();
    println!("S3 (replay): DEDUPLICATED - cached original result, no second actuation");
}

#[test]
fn cold_chain_run_sh_produces_observable_output_within_120s() {
    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("cold-chain")
        .join("run.sh");
    assert!(script.exists(), "run.sh must exist at {}", script.display());

    let start = tirbase_core::traits::monotonic_now();
    let output = Command::new("bash")
        .arg(&script)
        .env("TIRBASE_DEMO_INNER", "0")
        .output()
        .expect("run cold-chain run.sh");
    let elapsed =
        Duration::from_micros(tirbase_core::traits::monotonic_now().saturating_sub(start));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "run.sh failed (exit {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        elapsed <= Duration::from_secs(120),
        "run.sh must complete within 120s, took {elapsed:?}"
    );
    assert!(
        stdout.contains("S1") && stdout.contains("S2") && stdout.contains("S3"),
        "observable output must demonstrate defended S1/S2/S3 scenarios:\n{stdout}"
    );
    assert!(
        stdout.contains("defended"),
        "output must demonstrate defended attack scenario:\n{stdout}"
    );
}
