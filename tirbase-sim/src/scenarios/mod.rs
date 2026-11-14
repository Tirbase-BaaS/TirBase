// SPDX-License-Identifier: AGPL-3.0-only

//! Adversarial scenario implementations (39.4, PV-12.4, PV-12.8).
//!
//! Every scenario in `docs/adversary-scenarios.md` (S1–S35) is registered here
//! and executed by [`crate::runner::ScenarioRunner`] from
//! `tirbase-sim/scenarios/S*.toml`.
//!
//! Each scenario is a function `fn(u64) -> Result<(), String>`. The seed
//! parameterises the attack so a failing seed reproduces the exact run; the
//! runner also catches panics and prints the seed before exiting.
//!
//! Wiring mutations: each scenario asserts the *rejection* or *bounded
//! behaviour* of the production control it targets, so removing that control
//! turns the scenario red.

use std::collections::BTreeMap;

pub mod common;
pub mod guard_harness;

pub mod s10_revoked_delta;
pub mod s11_s18_controls;
pub mod s12_partition_rejoin;
pub mod s13_crash_every_step;
pub mod s14_log_flooding;
pub mod s16_s17_admission;
pub mod s19_s23_s31_time;
pub mod s1_s2_s3;
pub mod s20_sequence_poisoning;
pub mod s21_lease_starvation;
pub mod s22_snapshot_restore;
pub mod s24_crash_loop;
pub mod s25_quarantine_flush;
pub mod s26_s29_idempotency;
pub mod s30_exponent_overflow;
pub mod s32_challenge_nonce_flood;
pub mod s33_pending_queue_bomb;
pub mod s34_partial_sig;
pub mod s35_fd_leakage;
pub mod s36_postcondition_failure;
pub mod s4_clock_poisoning;
pub mod s5_s15_crdt_caps;
pub mod s6_policy_history;
pub mod s7_policy_loosening;
pub mod s8_malicious_migration;
pub mod s9_engine_profile_mismatch;

fn s1(_seed: u64) -> Result<(), String> {
    s1_s2_s3::scenario_s1_envelope_violation_rejected();
    Ok(())
}

fn s2(_seed: u64) -> Result<(), String> {
    s1_s2_s3::scenario_s2_slow_ramp_drift_rejected();
    Ok(())
}

fn s3(_seed: u64) -> Result<(), String> {
    s1_s2_s3::scenario_s3_replay_returns_cached_no_second_actuation();
    Ok(())
}

fn s4(seed: u64) -> Result<(), String> {
    s4_clock_poisoning::run_s4(seed)
}

fn s5(seed: u64) -> Result<(), String> {
    s5_s15_crdt_caps::run_s5(seed)
}

fn s6(seed: u64) -> Result<(), String> {
    s6_policy_history::run_s6(seed)
}

fn s7(_seed: u64) -> Result<(), String> {
    s7_policy_loosening::run_s7();
    Ok(())
}

fn s8(_seed: u64) -> Result<(), String> {
    s8_malicious_migration::scenario_s8_malicious_migration_float_rejected();
    s8_malicious_migration::scenario_s8_malicious_migration_simd_forbidden();
    Ok(())
}

fn s9(_seed: u64) -> Result<(), String> {
    s9_engine_profile_mismatch::scenario_s9_engine_version_mismatch_quarantined();
    s9_engine_profile_mismatch::scenario_s9_profile_id_mismatch_quarantined();
    Ok(())
}

fn s10(seed: u64) -> Result<(), String> {
    s10_revoked_delta::run_s10(seed)
}

fn s11(seed: u64) -> Result<(), String> {
    s11_s18_controls::run_s11(seed)
}

fn s12(seed: u64) -> Result<(), String> {
    s12_partition_rejoin::run_s12(seed)
}

fn s13(seed: u64) -> Result<(), String> {
    s13_crash_every_step::run_s13(seed)
}

fn s14(seed: u64) -> Result<(), String> {
    s14_log_flooding::run_s14(seed)
}

fn s15(seed: u64) -> Result<(), String> {
    s5_s15_crdt_caps::run_s15(seed)
}

fn s16(seed: u64) -> Result<(), String> {
    s16_s17_admission::run_s16(seed)
}

fn s17(seed: u64) -> Result<(), String> {
    s16_s17_admission::run_s17(seed)
}

fn s18(seed: u64) -> Result<(), String> {
    s11_s18_controls::run_s18(seed)
}

fn s19(seed: u64) -> Result<(), String> {
    s19_s23_s31_time::run_s19(seed)
}

fn s20(_seed: u64) -> Result<(), String> {
    s20_sequence_poisoning::scenario_s20_sequence_poisoning_rejected_cmd_does_not_advance_window();
    Ok(())
}

fn s21(seed: u64) -> Result<(), String> {
    s21_lease_starvation::run_s21(seed)
}

fn s22(seed: u64) -> Result<(), String> {
    s22_snapshot_restore::run_s22(seed)
}

fn s23(seed: u64) -> Result<(), String> {
    s19_s23_s31_time::run_s23(seed)
}

fn s24(_seed: u64) -> Result<(), String> {
    s24_crash_loop::s24_crash_loop_escalates_to_lockdown_within_window();
    Ok(())
}

fn s25(seed: u64) -> Result<(), String> {
    s25_quarantine_flush::run_s25(seed)
}

fn s26(seed: u64) -> Result<(), String> {
    s26_s29_idempotency::run_s26(seed)
}

fn s27(seed: u64) -> Result<(), String> {
    s6_policy_history::run_s27(seed)
}

fn s28(seed: u64) -> Result<(), String> {
    s6_policy_history::run_s28(seed)
}

fn s29(seed: u64) -> Result<(), String> {
    s26_s29_idempotency::run_s29(seed)
}

fn s30(seed: u64) -> Result<(), String> {
    s30_exponent_overflow::run_s30(seed)
}

fn s31(seed: u64) -> Result<(), String> {
    s19_s23_s31_time::run_s31(seed)
}

fn s32(_seed: u64) -> Result<(), String> {
    s32_challenge_nonce_flood::s32_challenge_nonce_flood_is_rate_limited();
    Ok(())
}

fn s33(seed: u64) -> Result<(), String> {
    s33_pending_queue_bomb::run_s33(seed)
}

fn s34(seed: u64) -> Result<(), String> {
    s34_partial_sig::run_s34(seed)
}

fn s35(seed: u64) -> Result<(), String> {
    s35_fd_leakage::run_s35(seed)
}

/// The scenario registry consumed by [`crate::runner::ScenarioRunner`].
///
/// Every ID in the `S1`..`S35` catalog has exactly one implementation. The
/// `S*.toml` loader verifies the ID set; the runner verifies each spec resolves
/// here, so a deleted or unregistered scenario fails CI rather than silently
/// shrinking coverage.
/// A scenario entry point keyed by `S<n>` in the registry.
type ScenarioFn = fn(u64) -> Result<(), String>;

pub fn registry() -> BTreeMap<String, ScenarioFn> {
    let mut registry: BTreeMap<String, ScenarioFn> = BTreeMap::new();
    for (id, scenario) in [
        ("S1", s1 as ScenarioFn),
        ("S2", s2),
        ("S3", s3),
        ("S4", s4),
        ("S5", s5),
        ("S6", s6),
        ("S7", s7),
        ("S8", s8),
        ("S9", s9),
        ("S10", s10),
        ("S11", s11),
        ("S12", s12),
        ("S13", s13),
        ("S14", s14),
        ("S15", s15),
        ("S16", s16),
        ("S17", s17),
        ("S18", s18),
        ("S19", s19),
        ("S20", s20),
        ("S21", s21),
        ("S22", s22),
        ("S23", s23),
        ("S24", s24),
        ("S25", s25),
        ("S26", s26),
        ("S27", s27),
        ("S28", s28),
        ("S29", s29),
        ("S30", s30),
        ("S31", s31),
        ("S32", s32),
        ("S33", s33),
        ("S34", s34),
        ("S35", s35),
    ] {
        registry.insert(id.to_string(), scenario);
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_every_catalog_scenario() {
        let registry = registry();
        assert_eq!(registry.len(), 35, "S1..S35 must all be registered");
        for index in 1..=35 {
            assert!(
                registry.contains_key(&format!("S{index}")),
                "S{index} is missing from the registry"
            );
        }
    }
}
