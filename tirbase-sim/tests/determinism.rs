// SPDX-License-Identifier: AGPL-3.0-only

//! Determinism and seeded-scenario integration tests (38.4/38.5 —
//! CLAIM-38.1, CLAIM-38.4, CLAIM-38.5, PV-12.1, PV-12.3).
//!
//! CI executes 1,000 seeded scenarios in `thousand_seeded_scenarios_per_run`.
//!
//! Wiring mutation check: replacing the seeded `ChaCha8Rng` with an
//! entropy-seeded RNG (or using `std` float math in the models) makes these
//! tests fail — repeated runs would no longer match, and the golden
//! trajectories would drift.

use tirbase_sim::models::{BatteryModel, ThermalModel};
use tirbase_sim::{seeded_rng, ScenarioReport, TirBaseSim};

/// Number of seeded scenarios required per CI run (PV-12.1).
const SEEDED_SCENARIOS: u64 = 1_000;

#[test]
fn thousand_seeded_scenarios_per_run() {
    let mut digests = std::collections::BTreeSet::new();
    for seed in 0..SEEDED_SCENARIOS {
        let report = TirBaseSim::run_seeded_scenario(seed, 16)
            .unwrap_or_else(|err| panic!("seeded scenario failed: {err}"));
        assert_eq!(report.seed, seed);
        assert_eq!(report.ticks, 16);
        digests.insert(report.digest);
    }
 // Seeds must actually vary the trajectory; identical digests for 1,000
 // seeds would mean the RNG is not feeding the scenario.
    assert!(
        digests.len() > 900,
        "expected distinct trajectories, got {} unique digests",
        digests.len()
    );
}

#[test]
fn same_seed_is_bit_identical_across_independent_runs() {
    for seed in [0u64, 1, 42, 0x5EED, u64::MAX - 1] {
        let first = TirBaseSim::run_seeded_scenario(seed, 32).expect("first run");
        let second = TirBaseSim::run_seeded_scenario(seed, 32).expect("second run");
        assert_eq!(
            first, second,
            "seed {seed} must produce a bit-identical scenario report"
        );

        let mut a = TirBaseSim::new(seed);
        let mut b = TirBaseSim::new(seed);
        a.run(32).unwrap();
        b.run(32).unwrap();
        assert_eq!(a.report(), b.report());
    }
}

#[test]
fn different_seeds_diverge() {
    let a = TirBaseSim::run_seeded_scenario(7, 24).unwrap();
    let b = TirBaseSim::run_seeded_scenario(8, 24).unwrap();
    assert_ne!(a.digest, b.digest);
}

#[test]
fn seeded_rng_is_reproducible_and_seed_sensitive() {
    let mut a = seeded_rng(1234);
    let mut b = seeded_rng(1234);
    let mut c = seeded_rng(1235);
    let a: Vec<u64> = (0..16).map(|_| rand::Rng::gen(&mut a)).collect();
    let b: Vec<u64> = (0..16).map(|_| rand::Rng::gen(&mut b)).collect();
    let c: Vec<u64> = (0..16).map(|_| rand::Rng::gen(&mut c)).collect();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn scenario_reports_serialize_their_seed_for_ci_logs() {
    let report = TirBaseSim::run_seeded_scenario(0xF00D, 8).unwrap();
    let ScenarioReport {
        seed,
        ticks,
        digest,
        ..
    } = report;
    assert_eq!(seed, 0xF00D);
    assert_eq!(ticks, 8);
    assert_ne!(digest, 0);
}

#[test]
fn thermal_model_is_bit_identical_from_the_same_seed() {
    let mut a = ThermalModel::new(0xABCD);
    let mut b = ThermalModel::new(0xABCD);
    a.set_setpoint_c(2.0);
    b.set_setpoint_c(2.0);
    assert_eq!(a.run_steps_bits(1_000), b.run_steps_bits(1_000));
}

#[test]
fn battery_model_is_bit_identical_from_the_same_seed() {
    let mut a = BatteryModel::new(0xABCD);
    let mut b = BatteryModel::new(0xABCD);
    a.set_power_w(2_400.0);
    b.set_power_w(2_400.0);
    assert_eq!(a.run_steps_bits(1_000), b.run_steps_bits(1_000));
    assert_eq!(a.state_bits(), b.state_bits());
}

#[test]
fn emit_cross_arch_digest() {
 // CI runs this test natively on x86_64 and aarch64 and compares the two
 // digest artifacts (CLAIM-38.4/38.5, PV-12.3). The digest covers the
 // thermal trajectory, the battery trajectory, and a seeded scenario.
    fn fnv(mut hash: u64, values: impl IntoIterator<Item = u64>) -> u64 {
        for value in values {
            hash ^= value;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    let mut thermal = ThermalModel::new(0xC01D);
    let thermal_digest = fnv(0xcbf2_9ce4_8422_2325, thermal.run_steps_bits(4_096));

    let mut battery = BatteryModel::new(0xBA77_0000);
    battery.set_power_w(2_000.0);
    let battery_digest = fnv(0xcbf2_9ce4_8422_2325, battery.run_steps_bits(4_096));

    let scenario = TirBaseSim::run_seeded_scenario(0x5EED, 64).expect("seeded scenario");

    let digest = format!(
        "thermal={thermal_digest:016x}\nbattery={battery_digest:016x}\nscenario={:016x}\n",
        scenario.digest
    );

    if let Ok(path) = std::env::var("TIRBASE_SIM_DIGEST_OUT") {
        std::fs::write(&path, &digest)
            .unwrap_or_else(|err| panic!("write digest to {path}: {err}"));
    }

 // Golden values are architecture independent because the models use libm
 // and every random draw comes from the seeded ChaCha8 stream.
    assert_eq!(thermal_digest, 0x6685_5de9_5161_dfb7);
    assert_eq!(battery_digest, 0xf728_c2c0_3ab8_5f19);
    assert_eq!(scenario.digest, 0x3fd0_e16b_b8e7_a941);
}

#[test]
fn thermal_and_battery_golden_bits_are_platform_independent() {
 // The thermal/battery modules pin golden bit patterns in their unit tests.
 // This integration test re-checks that reconstruction from the same seed
 // reproduces them exactly from outside the crate: the same seed on x86_64
 // and ARM must yield the same bits because `libm` is pure Rust.
    let mut model = ThermalModel::new(0xC01D);
    let bits = model.run_steps_bits(8);
    assert_eq!(bits[0], 0x401f_f886_b00a_52d7);
    assert_eq!(bits[7], 0x401f_c5a2_5646_60dd);

    let mut pack = BatteryModel::new(0xBA77_0000);
    pack.set_power_w(2_000.0);
    let soc = pack.run_steps_bits(6);
    assert_eq!(soc[0], 0x3fe9_9a54_0375_76d5);
    assert_eq!(soc[5], 0x3fe9_94f5_36bf_f746);
}
