//! Policy lifecycle integration tests (tasks 12.1–12.7, 12.10 — CLAIM-12.1–7,10,
//! PV-4.8–4.12, INV-3, INV-8).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tirbase_core::errors::TirBaseError;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{AssuranceLevel, KeyProvider, MonotonicCounterTrait};
use tirbase_guard::envelope::ProfileMap;
use tirbase_guard::policy::{
    classify_bundle, make_bundle, policy_bundle_signing_bytes, PolicyError, PolicyIngestOutcome,
    PolicyLifecycle,
};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, ParamFloor, RolePolicy, TrustRootRecord};
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::policy::{PolicyBundle, PolicyBundleKind, PolicyCoSignature};
use tirbase_types::{
    CommandRole, DeviceSignature, FixedPointValue, ProfileId, TargetId, UNIT_DEG_C,
};

#[derive(Debug)]
struct MemCounter(AtomicU64);
impl MemCounter {
    fn new(v: u64) -> Self {
        MemCounter(AtomicU64::new(v))
    }
}
impl MonotonicCounterTrait for MemCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
    fn increment(&self) -> Result<u64, TirBaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
        let mut cur = self.0.load(Ordering::SeqCst);
        loop {
            if value <= cur {
                return Ok(cur);
            }
            match self
                .0
                .compare_exchange(cur, value, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(value),
                Err(o) => cur = o,
            }
        }
    }
    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

fn fp(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, -1, UNIT_DEG_C)
}
fn param(name: &str, min: i64, max: i64) -> ParameterSpec {
    ParameterSpec {
        name: name.to_string(),
        unit_id: UNIT_DEG_C,
        canonical_exponent: -1,
        kind: ParameterKind::Range {
            min: fp(min),
            max: fp(max),
        },
        max_rate_per_sec: fp(10),
        dwell_secs: 5,
        min_off_secs: 2,
        drift_window_secs: 60,
        max_delta_in_window: fp(50),
        safe_default: fp(200),
        tightening_floor: fp(-500),
        critical: false,
    }
}
fn profile(version: u64, min: i64, max: i64, m: u8, n: u8, tl: u32) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [version as u8; 16] as ProfileId,
        version,
        device_class: "cold_room".to_string(),
        parameters: vec![param("temp", min, max)],
        cross_constraints: vec![],
        policy_loosen_m: m,
        policy_loosen_n: n,
        policy_timelock_secs: tl,
        policy_cancel_window_secs: 60,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

fn trust_root(pa: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes(),
            }],
        ),
    );
    let mut floors = BTreeMap::new();
    floors.insert(
        "cold_room".to_string(),
        vec![ParamFloor {
            param_name: "temp".to_string(),
            min_floor: fp(-500),
            max_ceiling: fp(1500),
        }],
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: floors,
        expiry_est: i64::MAX,
        revoked_root_ca_keys: vec![],
        signatures: vec![],
    }
}

fn sign_bundle(bundle: &PolicyBundle, pa: &InMemoryKeyProvider) -> PolicyCoSignature {
    let msg = policy_bundle_signing_bytes(bundle);
    PolicyCoSignature {
        signer_did: pa.did().to_string(),
        signature: pa.sign(&msg).expect("sign"),
    }
}

fn lifecycle(
    pa: &InMemoryKeyProvider,
    active_m: u8,
    tl: u32,
) -> (PolicyLifecycle, Arc<MemCounter>) {
    let tr = Arc::new(ArcSwap::from_pointee(trust_root(pa)));
    let counter = Arc::new(MemCounter::new(0));
    let target = TargetId::new("cr1");
    let p0 = profile(1, 0, 1000, active_m, 3, tl);
    let b0 = make_bundle(1, [0; 32], p0.clone(), vec![]);
    let map = Arc::new(ProfileMap::from_profiles([(target.clone(), p0)]));
    let lc = PolicyLifecycle::new(target, b0, counter.clone(), map, tr).expect("init");
    (lc, counter)
}

#[test]
fn tightening_applies_and_commits_rollback_counter() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let (mut lc, counter) = lifecycle(&pa, 2, 300);
    let prev_hash = lc.active().body_hash;
    let mut b = make_bundle(2, prev_hash, profile(2, 10, 900, 2, 3, 300), vec![]);
    b.co_signatures = vec![sign_bundle(&b, &pa)];
    // Claim loosening in wire kind — guard must ignore and recompute as tightening.
    b.kind = PolicyBundleKind::Loosening;
    let out = lc.ingest_bundle(b, 1_000).unwrap();
    assert_eq!(out, PolicyIngestOutcome::TighteningApplied { version: 2 });
    assert_eq!(counter.read().unwrap(), 2);
    assert_eq!(lc.active().bundle.version, 2);
}

#[test]
fn rollback_replay_is_rejected_and_counter_not_regressed() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let (mut lc, counter) = lifecycle(&pa, 2, 300);
    let prev_hash = lc.active().body_hash;
    let mut b2 = make_bundle(2, prev_hash, profile(2, 10, 900, 2, 3, 300), vec![]);
    b2.co_signatures = vec![sign_bundle(&b2, &pa)];
    lc.ingest_bundle(b2, 1_000).unwrap();
    let hash2 = lc.active().body_hash;
    let mut replay = make_bundle(1, [0; 32], profile(1, 0, 1000, 2, 3, 300), vec![]);
    replay.co_signatures = vec![sign_bundle(&replay, &pa)];
    let err = lc.ingest_bundle(replay, 1_100).unwrap_err();
    assert!(matches!(err, PolicyError::Rollback { .. }));
    assert_eq!(counter.read().unwrap(), 2);
    let _ = hash2;
}

#[test]
fn strictly_greater_version_gap_is_accepted() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let (mut lc, counter) = lifecycle(&pa, 2, 300);
    let prev_hash = lc.active().body_hash;
    let mut b = make_bundle(6, prev_hash, profile(6, 10, 900, 2, 3, 300), vec![]);
    b.co_signatures = vec![sign_bundle(&b, &pa)];
    let out = lc.ingest_bundle(b, 1_000).unwrap();
    assert_eq!(out, PolicyIngestOutcome::TighteningApplied { version: 6 });
    assert_eq!(counter.read().unwrap(), 6);
}

#[test]
fn tightening_floor_violation_is_rejected() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    // Floor requires temp min >= 5.0°C (50). Active starts above it so we can
    // attempt to "tighten" the min down below the floor — a subset of old range
    // in the wrong direction is not tightening, but a valid tightening that
    // would push the bound past the safe floor must be rejected (CLAIM-12.3).
    let mut tr = trust_root(&pa);
    tr.device_class_floors.insert(
        "cold_room".to_string(),
        vec![ParamFloor {
            param_name: "temp".to_string(),
            min_floor: fp(50), // 5.0°C floor
            max_ceiling: fp(1500),
        }],
    );
    let tr = Arc::new(ArcSwap::from_pointee(tr));
    let counter = Arc::new(MemCounter::new(0));
    let target = TargetId::new("cr1");
    let p0 = profile(1, 100, 1000, 2, 3, 300); // min 10.0 >= floor 5.0
    let b0 = make_bundle(1, [0; 32], p0.clone(), vec![]);
    let map = Arc::new(ProfileMap::from_profiles([(target.clone(), p0)]));
    let mut lc = PolicyLifecycle::new(target, b0, counter, map, tr).unwrap();
    let prev_hash = lc.active().body_hash;

    // Attempt: set min to 0 (below floor 5.0). Range [0,1000] is NOT a subset of
    // [100,1000] so classifier returns Loosening (conservative) — the guard must
    // never apply it immediately as a tightening.
    let mut b = make_bundle(2, prev_hash, profile(2, 0, 1000, 2, 3, 300), vec![]);
    b.co_signatures = vec![sign_bundle(&b, &pa)];
    b.kind = PolicyBundleKind::Tightening; // lie — guard ignores
    let out = lc.ingest_bundle(b, 1_000).unwrap();
    assert!(
        matches!(out, PolicyIngestOutcome::LooseningPending { .. }),
        "floor-violating/loosening change must not apply as tightening: {out:?}"
    );
    assert_eq!(lc.active().bundle.version, 1, "active version unchanged");

    // Direct floor-check API: a profile that would tighten within the old range
    // but cross the floor is rejected.
    let tr2 = trust_root(&pa);
    let mut floors = std::collections::BTreeMap::new();
    floors.insert(
        "cold_room".to_string(),
        vec![ParamFloor {
            param_name: "temp".to_string(),
            min_floor: fp(200), // 20.0°C
            max_ceiling: fp(1500),
        }],
    );
    let mut tr_floor = tr2;
    tr_floor.device_class_floors = floors;
    let over = profile(2, 100, 900, 2, 3, 300); // min 10.0 < floor 20.0
    assert!(
        tirbase_guard::policy::check_tightening_floors(&over, &tr_floor, "cold_room").is_some(),
        "check_tightening_floors must reject bound below trust-root floor"
    );
}

#[test]
fn loosening_uses_active_m_n_timelock_not_bundle() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    // active has M=2, timelock=500
    let (mut lc, _counter) = lifecycle(&pa, 2, 500);
    let prev_hash = lc.active().body_hash;
    // bundle tries to loosen range AND claims m=1,timelock=0 in envelope (attacker-controlled)
    let mut env = profile(2, -100, 1100, 1, 1, 0);
    env.policy_loosen_m = 1;
    env.policy_loosen_n = 1;
    env.policy_timelock_secs = 0;
    let mut b = make_bundle(2, prev_hash, env, vec![]);
    b.co_signatures = vec![sign_bundle(&b, &pa)];
    b.kind = PolicyBundleKind::Tightening; // lie
    let out = lc.ingest_bundle(b, 1_000).unwrap();
    match out {
        PolicyIngestOutcome::LooseningPending {
            required_m,
            required_n,
            timelock_until_est,
            ..
        } => {
            assert_eq!(required_m, 2, "must read M from active policy");
            assert_eq!(required_n, 3, "must read N from active policy");
            assert_eq!(
                timelock_until_est, 1_500,
                "timelock = now_est + active.timelock_secs"
            );
        }
        other => panic!("expected loosening pending, got {other:?}"),
    }
    // cannot apply before timelock even if cosigs present
    let err = lc.apply_pending_loosening(1_499).unwrap_err();
    assert!(matches!(err, PolicyError::TimelockActive { .. }));
}

#[test]
fn m1_loosening_is_allowed_with_timelock() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let (mut lc, _counter) = lifecycle(&pa, 1, 100);
    let prev_hash = lc.active().body_hash;
    let mut b = make_bundle(2, prev_hash, profile(2, -100, 1100, 1, 1, 100), vec![]);
    b.co_signatures = vec![sign_bundle(&b, &pa)];
    let out = lc.ingest_bundle(b, 1_000).unwrap();
    assert!(matches!(
        out,
        PolicyIngestOutcome::LooseningPending { required_m: 1, .. }
    ));
    assert!(matches!(
        lc.apply_pending_loosening(1_099),
        Err(PolicyError::TimelockActive { .. })
    ));
    let out = lc.apply_pending_loosening(1_100).unwrap();
    assert!(matches!(
        out,
        PolicyIngestOutcome::TighteningApplied { version: 2 }
    ));
}

#[test]
fn version_gap_trick_and_rollback_replay_bypass_attempts_rejected() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let (mut lc, _counter) = lifecycle(&pa, 2, 300);
    let prev_hash = lc.active().body_hash;
    let mut b5 = make_bundle(5, prev_hash, profile(5, 10, 900, 2, 3, 300), vec![]);
    b5.co_signatures = vec![sign_bundle(&b5, &pa)];
    lc.ingest_bundle(b5, 1_000).unwrap();
    // replay v2 after v5 accepted
    let mut old = make_bundle(2, prev_hash, profile(2, 10, 900, 2, 3, 300), vec![]);
    old.co_signatures = vec![sign_bundle(&old, &pa)];
    assert!(matches!(
        lc.ingest_bundle(old, 1_100),
        Err(PolicyError::Rollback { .. })
    ));
    // equal version
    let mut eq = make_bundle(
        5,
        lc.active().body_hash,
        profile(5, 10, 900, 2, 3, 300),
        vec![],
    );
    eq.co_signatures = vec![sign_bundle(&eq, &pa)];
    assert!(matches!(
        lc.ingest_bundle(eq, 1_100),
        Err(PolicyError::Rollback { .. })
    ));
}

#[test]
fn guard_ignores_bundle_kind_by_reclassifying() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let tr = trust_root(&pa);
    let old = profile(1, 0, 1000, 2, 3, 300);
    // actually loosening
    let new = profile(2, -100, 1000, 2, 3, 300);
    let bundle = make_bundle(2, [0; 32], new.clone(), vec![]);
    assert_eq!(bundle.kind, PolicyBundleKind::Loosening); // default conservative
    assert_eq!(
        classify_bundle(&old, &new, &tr),
        PolicyBundleKind::Loosening
    );
    // a forged "Tightening" claim in data is irrelevant to the computed result.
}
