//! Scenario S7 — policy loosening without M-of-N (PV-12.5, CLAIM-12.11).
//!
//! A single PolicyAuthority submits a loosening bundle. The guard MUST NOT
//! apply it: it starts co-signature collection and enforces the time-lock read
//! from the **active** policy (INV-8). Bypassing M-of-N or the time-lock must
//! fail.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tirbase_core::errors::TirBaseError;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{AssuranceLevel, KeyProvider, MonotonicCounterTrait};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, ParamFloor, RolePolicy, TrustRootRecord};
use tirbase_guard::{
    classify_bundle, make_bundle, policy_bundle_signing_bytes, PolicyError, PolicyIngestOutcome,
    PolicyLifecycle, ProfileMap,
};
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::policy::{PolicyBundleKind, PolicyCoSignature};
use tirbase_types::{
    CommandRole, DeviceSignature, FixedPointValue, ProfileId, TargetId, UNIT_DEG_C,
};

#[derive(Debug)]
struct Counter(AtomicU64);
impl Counter {
    fn new(v: u64) -> Self {
        Counter(AtomicU64::new(v))
    }
}
impl MonotonicCounterTrait for Counter {
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
fn profile(version: u64, min: i64, max: i64, m: u8, n: u8, tl: u32) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [version as u8; 16] as ProfileId,
        version,
        device_class: "cold_room".to_string(),
        parameters: vec![ParameterSpec {
            name: "temp".to_string(),
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
        }],
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
fn sign_bundle(
    bundle: &tirbase_guard::PolicyBundle,
    pa: &InMemoryKeyProvider,
) -> PolicyCoSignature {
    PolicyCoSignature {
        signer_did: pa.did().to_string(),
        signature: pa.sign(&policy_bundle_signing_bytes(bundle)).unwrap(),
    }
}

/// Scenario S7: a single PA submits a loosening bundle while active policy
/// requires M=2 and a 600s time-lock. The bundle MUST NOT be applied; only a
/// pending co-signature collection is started.
pub fn run_s7() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let tr = Arc::new(ArcSwap::from_pointee(trust_root(&pa)));
    let counter = Arc::new(Counter::new(0));
    let target = TargetId::new("cr1");
    let p0 = profile(1, 0, 1000, 2, 3, 600);
    let b0 = make_bundle(1, [0; 32], p0.clone(), vec![]);
    let map = Arc::new(ProfileMap::from_profiles([(target.clone(), p0)]));
    let mut lc = PolicyLifecycle::new(target, b0, counter.clone(), map, tr).unwrap();

    let prev = lc.active().body_hash;
 // Loosening: widen range. Attacker also lies about kind and tries to set
 // M=1/timelock=0 in the envelope — guard must ignore both.
    let mut env = profile(2, -200, 1200, 1, 1, 0);
    env.policy_loosen_m = 1;
    env.policy_loosen_n = 1;
    env.policy_timelock_secs = 0;
    let mut b = make_bundle(2, prev, env, vec![]);
    b.co_signatures = vec![sign_bundle(&b, &pa)];
    b.kind = PolicyBundleKind::Tightening; // lie

    let out = lc.ingest_bundle(b, 10_000).expect("ingest");
    match out {
        PolicyIngestOutcome::LooseningPending {
            required_m,
            timelock_until_est,
            ..
        } => {
            assert_eq!(required_m, 2, "M read from active policy, not bundle");
            assert_eq!(timelock_until_est, 10_600, "timelock from active policy");
        }
        other => panic!("S7: single PA loosening must not apply: {other:?}"),
    }
    assert_eq!(lc.active().bundle.version, 1, "S7: active policy unchanged");
    assert_eq!(counter.read().unwrap(), 1, "S7: rollback counter unchanged");
    assert!(
        lc.pending().is_some(),
        "S7: co-signature collection started"
    );
 // Even with a cosig present, timelock blocks application.
    assert!(matches!(
        lc.apply_pending_loosening(10_599),
        Err(PolicyError::TimelockActive { .. })
    ));
 // Classifier itself rejects the attack vector.
    let tr2 = trust_root(&pa);
    let loosening = profile(2, -200, 1200, 2, 3, 600);
    assert_eq!(
        classify_bundle(&profile(1, 0, 1000, 2, 3, 600), &loosening, &tr2),
        PolicyBundleKind::Loosening
    );
}

#[test]
fn s7_policy_loosening_without_m_of_n_is_blocked() {
    run_s7();
}
