// SPDX-License-Identifier: AGPL-3.0-only

//! Scenarios S6, S27 and S28 — policy rollback, governance-weakening
//! "tightening", and `tightening_floor` injection (PV-4.8, PV-4.11).
//!
//! These scenarios drive the production [`PolicyLifecycle`] ingest path, which
//! always recomputes bundle classification and enforces the monotonic policy
//! version counter.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tirbase_core::errors::TirBaseError;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{AssuranceLevel, KeyProvider, MonotonicCounterTrait};
use tirbase_guard::policy::{
    check_tightening_floors, classify_bundle, make_bundle, policy_bundle_signing_bytes,
    PolicyError, PolicyIngestOutcome, PolicyLifecycle,
};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, ParamFloor, RolePolicy, TrustRootRecord};
use tirbase_guard::ProfileMap;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::policy::{PolicyBundle, PolicyBundleKind, PolicyCoSignature};
use tirbase_types::{
    CommandRole, DeviceSignature, FixedPointValue, ProfileId, TargetId, UNIT_DEG_C,
};

#[derive(Debug)]
struct Counter(AtomicU64);

impl Counter {
    fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
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
        let mut current = self.0.load(Ordering::SeqCst);
        loop {
            if value <= current {
                return Ok(current);
            }
            match self
                .0
                .compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(value),
                Err(observed) => current = observed,
            }
        }
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

fn fp(mantissa: i64) -> FixedPointValue {
    FixedPointValue::new(mantissa, -1, UNIT_DEG_C)
}

fn parameter(min: i64, max: i64, tightening_floor: i64) -> ParameterSpec {
    ParameterSpec {
        name: "temp".to_string(),
        unit_id: UNIT_DEG_C,
        canonical_exponent: -1,
        kind: ParameterKind::Range {
            min: fp(min),
            max: fp(max),
        },
        max_rate_per_sec: fp(10),
        dwell_secs: 0,
        min_off_secs: 0,
        drift_window_secs: 60,
        max_delta_in_window: fp(100),
        safe_default: fp(200),
        tightening_floor: fp(tightening_floor),
        critical: false,
    }
}

fn profile(
    version: u64,
    min: i64,
    max: i64,
    loosen_m: u8,
    loosen_n: u8,
    timelock_secs: u32,
    tightening_floor: i64,
) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [version as u8; 16] as ProfileId,
        version,
        device_class: "cold_room".to_string(),
        parameters: vec![parameter(min, max, tightening_floor)],
        cross_constraints: vec![],
        policy_loosen_m: loosen_m,
        policy_loosen_n: loosen_n,
        policy_timelock_secs: timelock_secs,
        policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0; 64]),
    }
}

fn trust_root(
    authority: &InMemoryKeyProvider,
    floor_min: i64,
    ceiling_max: i64,
) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: authority.did().to_string(),
                public_key: authority.public_key_bytes(),
            }],
        ),
    );
    let mut floors = BTreeMap::new();
    floors.insert(
        "cold_room".to_string(),
        vec![ParamFloor {
            param_name: "temp".to_string(),
            min_floor: fp(floor_min),
            max_ceiling: fp(ceiling_max),
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

fn sign_bundle(bundle: &PolicyBundle, authority: &InMemoryKeyProvider) -> PolicyCoSignature {
    let message = policy_bundle_signing_bytes(bundle);
    PolicyCoSignature {
        signer_did: authority.did().to_string(),
        signature: authority.sign(&message).expect("sign policy bundle"),
    }
}

fn make_lifecycle(
    authority: &InMemoryKeyProvider,
    active: EnvelopeProfile,
    floor_min: i64,
) -> (PolicyLifecycle, Arc<Counter>, Arc<ArcSwap<TrustRootRecord>>) {
    let trust_root = Arc::new(ArcSwap::from_pointee(trust_root(
        authority, floor_min, 1500,
    )));
    let counter = Arc::new(Counter::new(0));
    let target = TargetId::new("cold-room-1");
    let initial = make_bundle(1, [0; 32], active.clone(), vec![]);
    let map = Arc::new(ProfileMap::from_profiles([(target.clone(), active)]));
    let lifecycle = PolicyLifecycle::new(target, initial, counter.clone(), map, trust_root.clone())
        .expect("policy lifecycle");
    (lifecycle, counter, trust_root)
}

fn signed(bundle: PolicyBundle, authority: &InMemoryKeyProvider) -> PolicyBundle {
    let mut bundle = bundle;
    bundle.co_signatures = vec![sign_bundle(&bundle, authority)];
    bundle
}

/// S6 — replaying an older, more permissive policy bundle is rejected and the
/// anti-rollback counter never decreases.
pub fn run_s6(seed: u64) -> Result<(), String> {
    let authority =
        InMemoryKeyProvider::generate().map_err(|error| format!("S6 keygen: {error}"))?;
    let (mut lifecycle, counter, _) =
        make_lifecycle(&authority, profile(1, 0, 1000, 2, 3, 300, 0), 0);

    let prev = lifecycle.active().body_hash;
    let tightening = signed(
        make_bundle(
            2,
            prev,
            profile(2, 10 + (seed % 5) as i64, 900, 2, 3, 300, 0),
            vec![],
        ),
        &authority,
    );
    lifecycle
        .ingest_bundle(tightening, 1_000)
        .map_err(|error| format!("S6 tightening v2 rejected: {error}"))?;
    if counter.read().map_err(|e| e.to_string())? != 2 {
        return Err("S6: counter did not advance to 2".to_string());
    }

    let replay = signed(
        make_bundle(1, [0; 32], profile(1, 0, 1000, 2, 3, 300, 0), vec![]),
        &authority,
    );
    match lifecycle.ingest_bundle(replay, 1_100) {
        Err(PolicyError::Rollback {
            incoming,
            committed,
        }) => {
            if incoming != 1 || committed != 2 {
                return Err(format!(
                    "S6: rollback reported wrong versions incoming={incoming} committed={committed}"
                ));
            }
        }
        Ok(outcome) => {
            return Err(format!(
                "S6 FAIL: replayed policy bundle was accepted: {outcome:?}"
            ))
        }
        Err(other) => return Err(format!("S6 FAIL: unexpected error: {other}")),
    }
    if counter.read().map_err(|e| e.to_string())? != 2 {
        return Err("S6 FAIL: rollback decreased the anti-rollback counter".to_string());
    }
    if lifecycle.active().bundle.version != 2 {
        return Err("S6 FAIL: active policy changed on rollback attempt".to_string());
    }
    Ok(())
}

/// S27 — a bundle that narrows bounds but weakens `policy_loosen_m` is
/// classified as Loosening and must go through M-of-N (never applied as a
/// single-signer tightening).
pub fn run_s27(seed: u64) -> Result<(), String> {
    let authority =
        InMemoryKeyProvider::generate().map_err(|error| format!("S27 keygen: {error}"))?;
    let (mut lifecycle, _, trust_root) =
        make_lifecycle(&authority, profile(1, 0, 1000, 2, 3, 300, 0), 0);

    let prev = lifecycle.active().body_hash;
    let candidate = profile(2, 10 + (seed % 5) as i64, 900, 1, 3, 300, 0);
    let classification = classify_bundle(
        &lifecycle.active().bundle.envelope,
        &candidate,
        &trust_root.load(),
    );
    if classification != PolicyBundleKind::Loosening {
        return Err(format!(
            "S27 FAIL: governance-weakening bundle classified as {classification:?}"
        ));
    }

    let bundle = signed(make_bundle(2, prev, candidate, vec![]), &authority);
    match lifecycle
        .ingest_bundle(bundle, 1_000)
        .map_err(|error| format!("S27 ingest failed: {error}"))?
    {
        PolicyIngestOutcome::LooseningPending {
            version,
            required_m,
            required_n,
            ..
        } => {
            if version != 2 || required_m != 2 || required_n != 3 {
                return Err(format!(
                    "S27: pending loosening used wrong governance version={version} m={required_m} n={required_n}"
                ));
            }
        }
        other => {
            return Err(format!(
                "S27 FAIL: governance-weakening bundle applied immediately: {other:?}"
            ))
        }
    }
    if lifecycle.active().bundle.version != 1 {
        return Err("S27 FAIL: active policy changed before M-of-N approval".to_string());
    }
    if lifecycle.active().bundle.envelope.policy_loosen_m != 2 {
        return Err("S27 FAIL: policy_loosen_m was weakened without approval".to_string());
    }
    Ok(())
}

/// S28 — `tightening_floor` values inside a submitted bundle are ignored; the
/// trust-root floor is authoritative and an out-of-floor tightening is
/// rejected.
pub fn run_s28(seed: u64) -> Result<(), String> {
    let authority =
        InMemoryKeyProvider::generate().map_err(|error| format!("S28 keygen: {error}"))?;
    let (mut lifecycle, _, _) = make_lifecycle(&authority, profile(1, 0, 1000, 2, 3, 300, 0), 50);

 // The bundle claims an unusable floor (i64::MAX). If the guard trusted it,
 // even a valid tightening would be rejected. It must be ignored.
    let prev = lifecycle.active().body_hash;
    let valid_tightening = signed(
        make_bundle(
            2,
            prev,
            profile(2, 60 + (seed % 5) as i64, 900, 2, 3, 300, i64::MAX),
            vec![],
        ),
        &authority,
    );
    lifecycle
        .ingest_bundle(valid_tightening, 1_000)
        .map_err(|error| format!("S28 FAIL: bundle-declared floor was trusted: {error}"))?;

 // Trust-root floor is 5.0°C. A tightening to [1.0°C, 900] is a strict
 // subset of the active range but violates the floor, so it must fail.
    let (mut lifecycle, _, trust_root) =
        make_lifecycle(&authority, profile(1, 0, 1000, 2, 3, 300, 0), 50);
    let prev = lifecycle.active().body_hash;
    let below_floor_envelope = profile(2, 10, 900, 2, 3, 300, 0);
    if check_tightening_floors(
        &below_floor_envelope,
        &trust_root.load(),
        &below_floor_envelope.device_class,
    )
    .is_none()
    {
        return Err(
            "S28 FAIL: trust-root floor did not reject the below-floor tightening".to_string(),
        );
    }
    let below_floor = signed(
        make_bundle(2, prev, below_floor_envelope, vec![]),
        &authority,
    );
    match lifecycle.ingest_bundle(below_floor, 1_000) {
        Err(PolicyError::TighteningFloorViolation { .. }) => Ok(()),
        Ok(PolicyIngestOutcome::LooseningPending { .. }) => Ok(()),
        Ok(outcome) => Err(format!(
            "S28 FAIL: tightening below the trust-root floor was applied: {outcome:?}"
        )),
        Err(other) => Err(format!("S28 FAIL: unexpected error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s6_policy_rollback_rejected() {
        run_s6(1).expect("S6");
    }

    #[test]
    fn s27_governance_weakening_is_loosening() {
        run_s27(1).expect("S27");
    }

    #[test]
    fn s28_bundle_floor_ignored_trust_root_enforced() {
        run_s28(1).expect("S28");
    }
}
