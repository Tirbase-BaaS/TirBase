//! Vertical demo pack integration tests (CLAIM-48.1–48.6, PV-16.2).
//!
//! Exercises the required scenarios for each pack via production `tirbase-sim`
//! implementations and verifies each pack's `run.sh` produces observable
//! defended output within 120 seconds.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use tirbase_sim::scenarios::s1_s2_s3::{
    scenario_s1_envelope_violation_rejected, scenario_s2_slow_ramp_drift_rejected,
    scenario_s3_replay_duplicate_idempotency_no_second_actuation,
};
use tirbase_sim::scenarios::{s10_revoked_delta, s12_partition_rejoin};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn assert_pack_layout(pack: &str, required: &[&str]) {
    let root = workspace_root().join(format!("tirbase-demo/{pack}"));
    assert!(
        tirbase_demo::pack_has_required_layout(&root, required),
        "pack {pack} missing required layout entries: {required:?}"
    );
    for rel in required {
        assert!(
            root.join(rel).exists(),
            "pack {pack} missing required entry: {rel}"
        );
    }
}

fn assert_pack_readme_non_goals(pack: &str) {
    let readme = workspace_root().join(format!("docs/demo/{pack}/README.md"));
    let text = std::fs::read_to_string(&readme)
        .unwrap_or_else(|e| panic!("read docs/demo/{pack}/README.md: {e}"));
    assert!(
        text.contains("What TirBase does not protect against in this scenario"),
        "docs/demo/{pack}/README.md must contain the required non-goals section"
    );
    let pack_readme = workspace_root().join(format!("tirbase-demo/{pack}/docs/README.md"));
    let pack_text = std::fs::read_to_string(&pack_readme)
        .unwrap_or_else(|e| panic!("read tirbase-demo/{pack}/docs/README.md: {e}"));
    assert!(
        pack_text.contains("What TirBase does not protect against in this scenario"),
        "tirbase-demo/{pack}/docs/README.md must contain the required non-goals section"
    );
}

fn run_pack_script(pack: &str, expected_scenarios: &[&str]) {
    let script = workspace_root()
        .join(format!("tirbase-demo/{pack}/run.sh"));
    assert!(script.exists(), "run.sh must exist for pack {pack}");
    let start = tirbase_core::traits::monotonic_now();
    let output = Command::new("bash")
        .arg(&script)
        .env("TIRBASE_DEMO_INNER", "0")
        .output()
        .unwrap_or_else(|e| panic!("run {pack} run.sh: {e}"));
    let elapsed =
        Duration::from_micros(tirbase_core::traits::monotonic_now().saturating_sub(start));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{pack} run.sh failed (exit {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        elapsed <= Duration::from_secs(120),
        "{pack} run.sh must complete within 120s, took {elapsed:?}"
    );
    for s in expected_scenarios {
        assert!(
            stdout.contains(s),
            "{pack} output must mention scenario {s}:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("defended"),
        "{pack} output must demonstrate defended scenarios:\n{stdout}"
    );
}

// --- 48.1 Energy edge (S1, S2) ---

#[test]
fn energy_edge_pack_layout() {
    assert_pack_layout(
        "energy-edge",
        &[
            "profiles/energy_edge.toml",
            "scenarios/S1.toml",
            "scenarios/S2.toml",
            "sim/config.toml",
            "run.sh",
            "docs/README.md",
            "docs/modbus-register-map.md",
        ],
    );
}

#[test]
fn energy_edge_readme_documents_non_goals() {
    assert_pack_readme_non_goals("energy-edge");
}

#[test]
fn energy_edge_s1_out_of_envelope_defended() {
    scenario_s1_envelope_violation_rejected();
    println!("S1 (energy-edge out-of-envelope): REJECTED - envelope bounds defended");
}

#[test]
fn energy_edge_s2_slow_ramp_defended() {
    scenario_s2_slow_ramp_drift_rejected();
    println!("S2 (energy-edge slow ramp/drift): REJECTED - drift window defended");
}

#[test]
fn energy_edge_run_sh_produces_observable_output_within_120s() {
    run_pack_script("energy-edge", &["S1", "S2"]);
}

// --- 48.2 Water/pumping (S1, S3) ---

#[test]
fn water_pumping_pack_layout() {
    assert_pack_layout(
        "water-pumping",
        &[
            "profiles/water_pumping.toml",
            "scenarios/S1.toml",
            "scenarios/S3.toml",
            "sim/config.toml",
            "run.sh",
            "docs/README.md",
            "docs/modbus-register-map.md",
        ],
    );
}

#[test]
fn water_pumping_readme_documents_non_goals() {
    assert_pack_readme_non_goals("water-pumping");
}

#[test]
fn water_pumping_s1_out_of_envelope_defended() {
    scenario_s1_envelope_violation_rejected();
    println!("S1 (water-pumping out-of-envelope): REJECTED - envelope bounds defended");
}

#[test]
fn water_pumping_s3_replay_defended() {
    scenario_s3_replay_duplicate_idempotency_no_second_actuation();
    println!("S3 (water-pumping replay): DEDUPLICATED - no second actuation");
}

#[test]
fn water_pumping_run_sh_produces_observable_output_within_120s() {
    run_pack_script("water-pumping", &["S1", "S3"]);
}

// --- 48.3 Logistics node (S10, S12) ---

#[test]
fn logistics_node_pack_layout() {
    assert_pack_layout(
        "logistics-node",
        &[
            "scenarios/S10.toml",
            "scenarios/S12.toml",
            "sim/config.toml",
            "run.sh",
            "docs/README.md",
            "docs/modbus-register-map.md",
        ],
    );
}

#[test]
fn logistics_node_readme_documents_non_goals() {
    assert_pack_readme_non_goals("logistics-node");
}

#[test]
fn logistics_node_s10_revoked_delta_defended() {
    s10_revoked_delta::run_s10(48_301).expect("S10 revoked delta defended");
    println!("S10 (logistics-node revoked delta): REJECTED - revoked author blocked");
}

#[test]
fn logistics_node_s12_partition_rejoin_converges() {
    s12_partition_rejoin::run_s12(48_302).expect("S12 partition/rejoin converged");
    println!("S12 (logistics-node partition+rejoin): CONVERGED - state consistent after heal");
}

#[test]
fn logistics_node_run_sh_produces_observable_output_within_120s() {
    run_pack_script("logistics-node", &["S10", "S12"]);
}

// --- 48.4 Buildings/BMS (S1, S2, BACnet placeholder) ---

#[test]
fn buildings_bms_pack_layout() {
    assert_pack_layout(
        "buildings-bms",
        &[
            "profiles/buildings_bms.toml",
            "scenarios/S1.toml",
            "scenarios/S2.toml",
            "sim/config.toml",
            "run.sh",
            "docs/README.md",
            "docs/modbus-register-map.md",
        ],
    );
}

#[test]
fn buildings_bms_readme_documents_non_goals() {
    assert_pack_readme_non_goals("buildings-bms");
}

#[test]
fn buildings_bms_s1_out_of_envelope_defended() {
    scenario_s1_envelope_violation_rejected();
    println!("S1 (buildings-bms out-of-envelope): REJECTED - envelope bounds defended");
}

#[test]
fn buildings_bms_s2_slow_ramp_defended() {
    scenario_s2_slow_ramp_drift_rejected();
    println!("S2 (buildings-bms slow ramp/drift): REJECTED - drift window defended");
}

#[test]
fn buildings_bms_run_sh_produces_observable_output_within_120s() {
    run_pack_script("buildings-bms", &["S1", "S2"]);
}

// --- 48.5 Remote-ops mesh (S12) ---

#[test]
fn remote_ops_mesh_pack_layout() {
    assert_pack_layout(
        "remote-ops-mesh",
        &[
            "scenarios/S12.toml",
            "sim/config.toml",
            "run.sh",
            "docs/README.md",
            "docs/modbus-register-map.md",
        ],
    );
}

#[test]
fn remote_ops_mesh_readme_documents_non_goals() {
    assert_pack_readme_non_goals("remote-ops-mesh");
}

#[test]
fn remote_ops_mesh_s12_partition_rejoin_converges() {
    s12_partition_rejoin::run_s12(48_501).expect("S12 partition/rejoin converged");
    println!("S12 (remote-ops-mesh partition+rejoin): CONVERGED - state consistent after heal");
}

#[test]
fn remote_ops_mesh_run_sh_produces_observable_output_within_120s() {
    run_pack_script("remote-ops-mesh", &["S12"]);
}

// --- 48.6 Defense-logistics (S3, M-of-N movement orders sim) ---

#[test]
fn defense_logistics_pack_layout() {
    assert_pack_layout(
        "defense-logistics",
        &[
            "scenarios/S3.toml",
            "sim/config.toml",
            "run.sh",
            "docs/README.md",
            "docs/modbus-register-map.md",
        ],
    );
}

#[test]
fn defense_logistics_readme_documents_non_goals() {
    assert_pack_readme_non_goals("defense-logistics");
}

#[test]
fn defense_logistics_s3_replay_defended() {
    scenario_s3_replay_duplicate_idempotency_no_second_actuation();
    println!("S3 (defense-logistics M-of-N movement orders replay): DEDUPLICATED - no second actuation");
}

#[test]
fn defense_logistics_run_sh_produces_observable_output_within_120s() {
    run_pack_script("defense-logistics", &["S3"]);
}
