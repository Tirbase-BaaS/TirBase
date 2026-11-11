//! Per-tick system invariant checks for `tirbase-sim` (tasks 17.1–17.8, 38.6;
//! CLAIM-17.1..CLAIM-17.8, CLAIM-38.6, PV-12.1, PV-23.2).
//!
//! `InvariantChecker::check_all()` is called on every simulation tick and by
//! scenario code that needs an explicit invariant boundary. Any violation
//! halts the scenario immediately by returning [`InvariantViolation`], which
//! carries the seed, invariant ID, and triggering state.
//!
//! This module is the production caller registered in
//! `docs/system-invariants.md` for INV-1..INV-16.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tirbase_guard::admit::AdmitRejection;
use tirbase_guard::node_mode::NodeMode;
use tirbase_types::{Did, FixedPointValue, TargetId};

/// Stable invariant identifiers (INV-1..INV-16, PV-23.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvariantId {
    Inv1,
    Inv2,
    Inv3,
    Inv4,
    Inv5,
    Inv6,
    Inv7,
    Inv8,
    Inv9,
    Inv10,
    Inv11,
    Inv12,
    Inv13,
    Inv14,
    Inv15,
    Inv16,
}

impl InvariantId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inv1 => "INV-1",
            Self::Inv2 => "INV-2",
            Self::Inv3 => "INV-3",
            Self::Inv4 => "INV-4",
            Self::Inv5 => "INV-5",
            Self::Inv6 => "INV-6",
            Self::Inv7 => "INV-7",
            Self::Inv8 => "INV-8",
            Self::Inv9 => "INV-9",
            Self::Inv10 => "INV-10",
            Self::Inv11 => "INV-11",
            Self::Inv12 => "INV-12",
            Self::Inv13 => "INV-13",
            Self::Inv14 => "INV-14",
            Self::Inv15 => "INV-15",
            Self::Inv16 => "INV-16",
        }
    }
}

impl fmt::Display for InvariantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single observed/attempted actuator write visible to the simulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActuationObservation {
    pub target_id: TargetId,
    pub param: String,
    pub value: FixedPointValue,
    pub safe_default: FixedPointValue,
    pub envelope_min: FixedPointValue,
    pub envelope_max: FixedPointValue,
    pub node_mode: NodeMode,
    /// True only when the write passed through the guard admission/dispatch path.
    pub passed_through_guard: bool,
    /// INV-12: durable `Actuating` record committed before dispatch.
    pub durable_actuating_record: bool,
}

/// Idempotency key tuple `(issuer, target, key)` actuated in the retention window.
pub type IdempotencyTuple = (Did, TargetId, [u8; 16]);
/// Anti-replay/decided-outcome tuple `(issuer, target, sequence, enrollment_epoch)`.
pub type ReplayTuple = (Did, TargetId, u64, u64);

/// Governance fields relevant to INV-14.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GovernanceFields {
    pub policy_loosen_m: u16,
    pub policy_loosen_n: u16,
    pub timelock_secs: u64,
    pub cancel_window_secs: u64,
}

/// A loosening application observation for INV-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseningApplication {
    pub now_est: i64,
    pub timelock_until_est: i64,
}

/// Token/admission observation for INV-7/INV-9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionObservation {
    pub token_attempted_relaxation: bool,
    pub accepted: bool,
    pub rejection: Option<AdmitRejection>,
    pub freshness_verified: bool,
    pub now_est: Option<i64>,
    pub expiry_est: Option<i64>,
    /// Guard/envelope acceptance of the commanded value.
    pub envelope_accepted: bool,
}

/// Decided-outcome cache observation for INV-16.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheObservation {
    pub key: ReplayTuple,
    pub outcome_fingerprint: u64,
    /// True when this observation is a mutation/rewrite of an existing key.
    pub mutated_existing: bool,
    /// True when cache write and `Actuating` commit were observed as atomic.
    pub atomic_with_actuating: bool,
}

/// Deterministic simulation state snapshot checked on every tick.
///
/// Fields default to safe/pass values so checks can be wired incrementally as
/// the simulator runtime (tasks 38.1–38.5) matures.
#[derive(Debug, Clone, Default)]
pub struct SimState {
    pub seed: u64,
    pub tick: u64,
    /// Human-readable triggering context (scenario step, node, command, etc.).
    pub triggering_state: String,

    // INV-1, INV-5, INV-6, INV-12
    pub actuations: Vec<ActuationObservation>,

    // INV-2
    pub idempotency_actuations: Vec<IdempotencyTuple>,

    // INV-3
    pub policy_versions_by_device: BTreeMap<String, Vec<u64>>,

    // INV-4
    pub hash_chain_intact: bool,

    // INV-7, INV-9
    pub admissions: Vec<AdmissionObservation>,

    // INV-8
    pub loosening_applications: Vec<LooseningApplication>,

    // INV-10
    pub accepted_replay_tuples: Vec<ReplayTuple>,

    // INV-11
    pub targets_with_unknown: BTreeSet<TargetId>,
    pub commands_to_unknown_targets: Vec<TargetId>,

    // INV-13
    pub now_est_observations: Vec<i64>,

    // INV-14
    pub previous_governance: Option<GovernanceFields>,
    pub current_governance: Option<GovernanceFields>,
    pub governance_weakening_approved: bool,

    // INV-15
    pub inflight_actuating_per_target: BTreeMap<TargetId, usize>,

    // INV-16
    pub cache_observations: Vec<CacheObservation>,
}

/// Invariant violation returned by [`InvariantChecker::check_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantViolation {
    pub invariant: InvariantId,
    pub seed: u64,
    pub triggering_state: String,
    pub detail: String,
}

impl fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invariant {} violated (seed={}): {} :: {}",
            self.invariant, self.seed, self.triggering_state, self.detail
        )
    }
}

impl std::error::Error for InvariantViolation {}

fn violation(
    state: &SimState,
    invariant: InvariantId,
    detail: impl Into<String>,
) -> InvariantViolation {
    let v = InvariantViolation {
        invariant,
        seed: state.seed,
        triggering_state: if state.triggering_state.is_empty() {
            format!("tick={}", state.tick)
        } else {
            state.triggering_state.clone()
        },
        detail: detail.into(),
    };
    eprintln!("{v}");
    v
}

fn fpv_le(a: &FixedPointValue, b: &FixedPointValue) -> bool {
    // Compare using i128 after exponent alignment where possible; fall back to
    // mantissa comparison for same exponent (the common case in checks).
    if a.unit_id != b.unit_id {
        return false;
    }
    if a.exponent == b.exponent {
        return a.mantissa <= b.mantissa;
    }
    let scale = |v: &FixedPointValue| -> i128 {
        let base = v.mantissa as i128;
        let diff = (v.exponent as i32).unsigned_abs();
        let pow10 = 10_i128.pow(diff.min(38));
        if v.exponent >= 0 {
            base.saturating_mul(pow10)
        } else {
            base / pow10.max(1)
        }
    };
    scale(a) <= scale(b)
}

/// Per-tick invariant checker (PV-23.2, CLAIM-38.6).
#[derive(Debug, Clone, Copy, Default)]
pub struct InvariantChecker;

impl InvariantChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check every invariant (INV-1..INV-16) against the current tick state.
    ///
    /// Fails immediately on the first violation and prints seed, invariant ID,
    /// and triggering state.
    pub fn check_all(&self, state: &SimState) -> Result<(), InvariantViolation> {
        self.check_inv_1(state)?;
        self.check_inv_2(state)?;
        self.check_inv_3(state)?;
        self.check_inv_4(state)?;
        self.check_inv_5(state)?;
        self.check_inv_6(state)?;
        self.check_inv_7(state)?;
        self.check_inv_8(state)?;
        self.check_inv_9(state)?;
        self.check_inv_10(state)?;
        self.check_inv_11(state)?;
        self.check_inv_12(state)?;
        self.check_inv_13(state)?;
        self.check_inv_14(state)?;
        self.check_inv_15(state)?;
        self.check_inv_16(state)?;
        Ok(())
    }

    pub fn check_inv_1(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for a in &state.actuations {
            if !fpv_le(&a.envelope_min, &a.value) || !fpv_le(&a.value, &a.envelope_max) {
                return Err(violation(state, InvariantId::Inv1, format!(
                    "actuator write outside envelope for target={} param={} value={:?} bounds=[{:?},{:?}]",
                    a.target_id.as_str(), a.param, a.value, a.envelope_min, a.envelope_max
                )));
            }
        }
        Ok(())
    }

    pub fn check_inv_2(&self, state: &SimState) -> Result<(), InvariantViolation> {
        let mut seen: BTreeSet<IdempotencyTuple> = BTreeSet::new();
        for t in &state.idempotency_actuations {
            if !seen.insert(t.clone()) {
                return Err(violation(
                    state,
                    InvariantId::Inv2,
                    format!(
                        "duplicate idempotency actuation for (issuer={}, target={}, key={:?})",
                        t.0.as_str(),
                        t.1.as_str(),
                        t.2
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn check_inv_3(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for (device, versions) in &state.policy_versions_by_device {
            let mut prev: Option<u64> = None;
            for &v in versions {
                if let Some(p) = prev {
                    if v <= p {
                        return Err(violation(state, InvariantId::Inv3, format!(
                            "policy version regression/non-monotonic for device={device}: prev={p} next={v}"
                        )));
                    }
                }
                prev = Some(v);
            }
        }
        Ok(())
    }

    pub fn check_inv_4(&self, state: &SimState) -> Result<(), InvariantViolation> {
        if !state.hash_chain_intact {
            return Err(violation(
                state,
                InvariantId::Inv4,
                "security event log hash chain is broken",
            ));
        }
        Ok(())
    }

    pub fn check_inv_5(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for a in &state.actuations {
            if a.node_mode == NodeMode::Lockdown && a.value != a.safe_default {
                return Err(violation(state, InvariantId::Inv5, format!(
                    "LOCKDOWN actuated commanded value {:?} instead of safe_default {:?} for target={} param={}",
                    a.value, a.safe_default, a.target_id.as_str(), a.param
                )));
            }
        }
        Ok(())
    }

    pub fn check_inv_6(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for a in &state.actuations {
            if !a.passed_through_guard {
                return Err(violation(
                    state,
                    InvariantId::Inv6,
                    format!(
                        "actuator write bypassed guard for target={} param={}",
                        a.target_id.as_str(),
                        a.param
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn check_inv_7(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for obs in &state.admissions {
            if obs.token_attempted_relaxation && obs.accepted && !obs.envelope_accepted {
                // accepted despite being outside envelope due to token relaxation
                return Err(violation(state, InvariantId::Inv7,
                    "token caused acceptance of a value outside the authorizer-side EnvelopeProfile".to_string()));
            }
            // Conservative: token relaxation must never produce acceptance without envelope acceptance.
            if obs.token_attempted_relaxation
                && obs.accepted
                && obs.rejection.is_none()
                && !obs.envelope_accepted
            {
                return Err(violation(
                    state,
                    InvariantId::Inv7,
                    "token-relax acceptance observed".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn check_inv_8(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for l in &state.loosening_applications {
            if l.now_est < l.timelock_until_est {
                return Err(violation(state, InvariantId::Inv8, format!(
                    "policy loosening applied before timelock expired: now_est={} < timelock_until_est={}",
                    l.now_est, l.timelock_until_est
                )));
            }
        }
        Ok(())
    }

    pub fn check_inv_9(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for obs in &state.admissions {
            if let (true, Some(now), Some(exp)) =
                (obs.freshness_verified, obs.now_est, obs.expiry_est)
            {
                if now > exp && obs.accepted {
                    return Err(violation(state, InvariantId::Inv9, format!(
                        "expired credential/command accepted in VERIFIED freshness: now_est={now} > expiry_est={exp}"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn check_inv_10(&self, state: &SimState) -> Result<(), InvariantViolation> {
        let mut seen: BTreeSet<ReplayTuple> = BTreeSet::new();
        for t in &state.accepted_replay_tuples {
            if !seen.insert(t.clone()) {
                return Err(violation(
                    state,
                    InvariantId::Inv10,
                    format!(
                        "duplicate accepted tuple (issuer={}, target={}, seq={}, epoch={})",
                        t.0.as_str(),
                        t.1.as_str(),
                        t.2,
                        t.3
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn check_inv_11(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for t in &state.commands_to_unknown_targets {
            if state.targets_with_unknown.contains(t) {
                return Err(violation(state, InvariantId::Inv11, format!(
                    "command accepted for target with unresolved Unknown ledger entry: target={}", t.as_str()
                )));
            }
        }
        Ok(())
    }

    pub fn check_inv_12(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for a in &state.actuations {
            if !a.durable_actuating_record {
                return Err(violation(
                    state,
                    InvariantId::Inv12,
                    format!(
                        "dispatch occurred without durable Actuating record for target={} param={}",
                        a.target_id.as_str(),
                        a.param
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn check_inv_13(&self, state: &SimState) -> Result<(), InvariantViolation> {
        let mut prev: Option<i64> = None;
        for &now in &state.now_est_observations {
            if let Some(p) = prev {
                if now < p {
                    return Err(violation(
                        state,
                        InvariantId::Inv13,
                        format!("now_est decreased across beacons/reboots: prev={p} next={now}"),
                    ));
                }
            }
            prev = Some(now);
        }
        Ok(())
    }

    pub fn check_inv_14(&self, state: &SimState) -> Result<(), InvariantViolation> {
        if let (Some(prev), Some(cur)) = (state.previous_governance, state.current_governance) {
            let weakened = cur.policy_loosen_m < prev.policy_loosen_m
                || cur.policy_loosen_n < prev.policy_loosen_n
                || cur.timelock_secs < prev.timelock_secs
                || cur.cancel_window_secs < prev.cancel_window_secs;
            if weakened && !state.governance_weakening_approved {
                return Err(violation(state, InvariantId::Inv14, format!(
                    "governance weakened without completed loosening approval: prev={prev:?} cur={cur:?}"
                )));
            }
        }
        Ok(())
    }

    pub fn check_inv_15(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for (target, count) in &state.inflight_actuating_per_target {
            if *count > 1 {
                return Err(violation(
                    state,
                    InvariantId::Inv15,
                    format!(
                        "more than one in-flight Actuating entry for target={}: count={count}",
                        target.as_str()
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn check_inv_16(&self, state: &SimState) -> Result<(), InvariantViolation> {
        for obs in &state.cache_observations {
            if obs.mutated_existing {
                return Err(violation(state, InvariantId::Inv16, format!(
                    "decided-outcome cache mutated existing tuple (issuer={}, target={}, seq={}, epoch={})",
                    obs.key.0.as_str(), obs.key.1.as_str(), obs.key.2, obs.key.3
                )));
            }
            if !obs.atomic_with_actuating {
                return Err(violation(state, InvariantId::Inv16, format!(
                    "decided-outcome cache write not atomic with Actuating record for tuple (issuer={}, target={}, seq={}, epoch={})",
                    obs.key.0.as_str(), obs.key.1.as_str(), obs.key.2, obs.key.3
                )));
            }
        }
        Ok(())
    }
}

/// Helper for simulators: check invariants and panic with the canonical halt
/// format (seed, invariant ID, triggering state) on violation.
pub fn assert_invariants_hold(checker: &InvariantChecker, state: &SimState) {
    if let Err(v) = checker.check_all(state) {
        panic!("{v}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_types::{TargetId, UNIT_PERCENT};

    fn fpv(m: i64) -> FixedPointValue {
        FixedPointValue::new(m, -1, UNIT_PERCENT)
    }
    fn did(s: &str) -> Did {
        Did::new(s)
    }
    fn target(s: &str) -> TargetId {
        TargetId::new(s)
    }
    fn actuation(
        value: i64,
        min: i64,
        max: i64,
        mode: NodeMode,
        safe: i64,
    ) -> ActuationObservation {
        ActuationObservation {
            target_id: target("pump-1"),
            param: "speed".into(),
            value: fpv(value),
            safe_default: fpv(safe),
            envelope_min: fpv(min),
            envelope_max: fpv(max),
            node_mode: mode,
            passed_through_guard: true,
            durable_actuating_record: true,
        }
    }
    fn base_state(test: &str) -> SimState {
        SimState {
            seed: 0x5eed_0017,
            tick: 7,
            triggering_state: format!("{test} (tick=7)"),
            hash_chain_intact: true,
            ..Default::default()
        }
    }
    fn check_err(state: &SimState, id: InvariantId) -> InvariantViolation {
        let e = InvariantChecker::new()
            .check_all(state)
            .expect_err("expected invariant violation");
        assert_eq!(e.invariant, id, "wrong invariant: {e}");
        assert_eq!(e.seed, state.seed);
        assert!(
            e.triggering_state.contains("tick=7") || e.triggering_state.contains("INV"),
            "{e}"
        );
        e
    }

    #[test]
    fn inv_1_out_of_envelope_actuation_fails_immediately() {
        let mut s = base_state("INV-1");
        s.actuations
            .push(actuation(5000, 0, 1000, NodeMode::Normal, 0));
        check_err(&s, InvariantId::Inv1);
    }

    #[test]
    fn inv_2_duplicate_actuation_fails_immediately() {
        let mut s = base_state("INV-2");
        let t = (did("did:k:issuer"), target("pump-1"), [9u8; 16]);
        s.idempotency_actuations.push(t.clone());
        s.idempotency_actuations.push(t);
        check_err(&s, InvariantId::Inv2);
    }

    #[test]
    fn inv_3_version_regression_fails_immediately() {
        let mut s = base_state("INV-3");
        s.policy_versions_by_device
            .insert("dev1".into(), vec![1, 3, 2]);
        check_err(&s, InvariantId::Inv3);
    }

    #[test]
    fn inv_4_chain_break_fails_immediately() {
        let mut s = base_state("INV-4");
        s.hash_chain_intact = false;
        check_err(&s, InvariantId::Inv4);
    }

    #[test]
    fn inv_5_non_safe_default_in_lockdown_fails_immediately() {
        let mut s = base_state("INV-5");
        s.actuations
            .push(actuation(500, 0, 1000, NodeMode::Lockdown, 0));
        check_err(&s, InvariantId::Inv5);
    }

    #[test]
    fn inv_6_bypass_attempt_fails_immediately() {
        let mut s = base_state("INV-6");
        let mut a = actuation(500, 0, 1000, NodeMode::Normal, 0);
        a.passed_through_guard = false;
        s.actuations.push(a);
        check_err(&s, InvariantId::Inv6);
    }

    #[test]
    fn inv_7_token_relax_attempt_fails_immediately() {
        let mut s = base_state("INV-7");
        s.admissions.push(AdmissionObservation {
            token_attempted_relaxation: true,
            accepted: true,
            rejection: None,
            freshness_verified: true,
            now_est: Some(100),
            expiry_est: Some(200),
            envelope_accepted: false,
        });
        check_err(&s, InvariantId::Inv7);
    }

    #[test]
    fn inv_8_early_loosening_fails_immediately() {
        let mut s = base_state("INV-8");
        s.loosening_applications.push(LooseningApplication {
            now_est: 50,
            timelock_until_est: 100,
        });
        check_err(&s, InvariantId::Inv8);
    }

    #[test]
    fn inv_9_expired_acceptance_fails_immediately() {
        let mut s = base_state("INV-9");
        s.admissions.push(AdmissionObservation {
            token_attempted_relaxation: false,
            accepted: true,
            rejection: None,
            freshness_verified: true,
            now_est: Some(300),
            expiry_est: Some(200),
            envelope_accepted: true,
        });
        check_err(&s, InvariantId::Inv9);
    }

    #[test]
    fn inv_10_tuple_reuse_fails_immediately() {
        let mut s = base_state("INV-10");
        let t = (did("did:k:i"), target("pump-1"), 7u64, 1u64);
        s.accepted_replay_tuples.push(t.clone());
        s.accepted_replay_tuples.push(t);
        check_err(&s, InvariantId::Inv10);
    }

    #[test]
    fn inv_11_unknown_blocks_command_fails_immediately() {
        let mut s = base_state("INV-11");
        s.targets_with_unknown.insert(target("pump-1"));
        s.commands_to_unknown_targets.push(target("pump-1"));
        check_err(&s, InvariantId::Inv11);
    }

    #[test]
    fn inv_12_dispatch_without_durable_record_fails_immediately() {
        let mut s = base_state("INV-12");
        let mut a = actuation(500, 0, 1000, NodeMode::Normal, 0);
        a.durable_actuating_record = false;
        s.actuations.push(a);
        check_err(&s, InvariantId::Inv12);
    }

    #[test]
    fn inv_13_now_est_regression_fails_immediately() {
        let mut s = base_state("INV-13");
        s.now_est_observations = vec![100, 120, 110];
        check_err(&s, InvariantId::Inv13);
    }

    #[test]
    fn inv_14_governance_weakening_fails_immediately() {
        let mut s = base_state("INV-14");
        s.previous_governance = Some(GovernanceFields {
            policy_loosen_m: 2,
            policy_loosen_n: 3,
            timelock_secs: 60,
            cancel_window_secs: 30,
        });
        s.current_governance = Some(GovernanceFields {
            policy_loosen_m: 1,
            policy_loosen_n: 3,
            timelock_secs: 60,
            cancel_window_secs: 30,
        });
        s.governance_weakening_approved = false;
        check_err(&s, InvariantId::Inv14);
    }

    #[test]
    fn inv_15_multiple_inflight_actuations_fail_immediately() {
        let mut s = base_state("INV-15");
        s.inflight_actuating_per_target.insert(target("pump-1"), 2);
        check_err(&s, InvariantId::Inv15);
    }

    #[test]
    fn inv_16_cache_mutation_fails_immediately() {
        let mut s = base_state("INV-16");
        s.cache_observations.push(CacheObservation {
            key: (did("did:k:i"), target("pump-1"), 1, 0),
            outcome_fingerprint: 1,
            mutated_existing: true,
            atomic_with_actuating: true,
        });
        check_err(&s, InvariantId::Inv16);
    }

    #[test]
    fn checker_accepts_clean_state() {
        let s = base_state("clean");
        InvariantChecker::new().check_all(&s).expect("clean state");
    }

    #[test]
    fn violation_prints_seed_invariant_and_state() {
        let mut s = base_state("INV-1 triggering");
        s.actuations
            .push(actuation(5000, 0, 1000, NodeMode::Normal, 0));
        let e = check_err(&s, InvariantId::Inv1);
        let msg = e.to_string();
        assert!(msg.contains("INV-1"), "{msg}");
        assert!(msg.contains(&s.seed.to_string()), "{msg}");
        assert!(msg.contains("triggering"), "{msg}");
    }
}
