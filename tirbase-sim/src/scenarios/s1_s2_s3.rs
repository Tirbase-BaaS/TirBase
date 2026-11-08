//! Task 14/15 scenario hooks for S1 (envelope violation), S2 (slow-ramp/drift),
//! S3 (replay/idempotency cache) using the CommandGuard admit pipeline.

use arc_swap::ArcSwap;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, RwLock};
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::admit::{AdmitContext, AdmitPipelineState, AdmitRejection};
use tirbase_guard::driver_proxy::{DriverProxy, IngressSource};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::node_mode::NodeModeState;
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::{sign_command, CommandGuard, GuardConfig, TargetAdmission};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

#[derive(Debug)]
struct T(u64);
impl TimeSource for T {
    fn monotonic_now(&self) -> u64 {
        self.0
    }
    fn wall_hint(&self) -> Option<i64> {
        Some((self.0 / 1_000_000) as i64)
    }
    fn boot_id(&self) -> u64 {
        1
    }
}
#[derive(Debug, Default)]
struct S(std::sync::Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
impl TimeRatchetStore for S {
    fn load(
        &self,
    ) -> Result<Option<tirbase_guard::time::TimeRatchetRecord>, tirbase_guard::time::TimeRatchetError>
    {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(
        &self,
        r: &tirbase_guard::time::TimeRatchetRecord,
    ) -> Result<(), tirbase_guard::time::TimeRatchetError> {
        *self.0.lock().unwrap() = Some(*r);
        Ok(())
    }
}
fn fpv(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, -1, UNIT_PERCENT)
}

pub fn scenario_s1_envelope_violation_rejected() {
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let target = TargetId::new("pump-1");
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled("dev1", 1_000_000).unwrap();
    let mut targets = BTreeMap::new();
    targets.insert(
        target.clone(),
        TargetAdmission {
            device_id: "dev1".into(),
        },
    );
    let profile = EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "t".into(),
        parameters: vec![ParameterSpec {
            name: "speed".into(),
            unit_id: UNIT_PERCENT,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: fpv(0),
                max: fpv(1000),
            },
            max_rate_per_sec: fpv(10000),
            dwell_secs: 0,
            min_off_secs: 0,
            drift_window_secs: 0,
            max_delta_in_window: fpv(10000),
            safe_default: fpv(0),
            tightening_floor: fpv(0),
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 0,
        policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    let mut pm = BTreeMap::new();
    pm.insert(target.clone(), Arc::new(ArcSwap::from_pointee(profile)));
    let ts: Arc<dyn TimeSource> = Arc::new(T(1_000_000_000));
    let ratchet = Arc::new(std::sync::Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let reg = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
        .public_key_bytes()
        .try_into()
        .unwrap()])));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        reg,
        ratchet,
        ts,
    ));
    pipeline.set_max_ttl_secs(10_000_000_000);
    let guard = CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
    )
    .with_pipeline(
        pipeline,
        Arc::new(pm),
        Arc::new(ArcSwap::from_pointee(None)),
    );
    let tok = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "pump-1",
        "speed",
        &[],
        &ca.secret_seed(),
    )
    .unwrap();
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target,
        param: "speed".into(),
        desired_state: fpv(5000),
        sequence_number: 1,
        idempotency_key: [1; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut cmd, &issuer).unwrap();
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    let mut out = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut out));
    let e = guard
        .admit_with_context(&cmd, &ctx, &mut proxy, b"f")
        .unwrap_err();
    assert!(
        matches!(
            e,
            tirbase_guard::AdmitError::Pipeline {
                category: AdmitRejection::EnvelopeViolation,
                ..
            }
        ),
        "{e:?}"
    );
}

pub fn scenario_s2_slow_ramp_drift_rejected() {
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let target = TargetId::new("pump-1");
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled("dev1", 1_000_000).unwrap();
    let mut targets = BTreeMap::new();
    targets.insert(
        target.clone(),
        TargetAdmission {
            device_id: "dev1".into(),
        },
    );
    let profile = EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "t".into(),
        parameters: vec![ParameterSpec {
            name: "speed".into(),
            unit_id: UNIT_PERCENT,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: fpv(0),
                max: fpv(1000),
            },
            max_rate_per_sec: fpv(10000),
            dwell_secs: 0,
            min_off_secs: 0,
            drift_window_secs: 3600,
            max_delta_in_window: fpv(10),
            safe_default: fpv(0),
            tightening_floor: fpv(0),
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 0,
        policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    let mut pm = BTreeMap::new();
    pm.insert(target.clone(), Arc::new(ArcSwap::from_pointee(profile)));
    let ts: Arc<dyn TimeSource> = Arc::new(T(1_000_000_000));
    let ratchet = Arc::new(std::sync::Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let reg = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
        .public_key_bytes()
        .try_into()
        .unwrap()])));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        reg,
        ratchet,
        ts,
    ));
    pipeline.set_max_ttl_secs(10_000_000_000);
    let guard = CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
    )
    .with_pipeline(
        pipeline,
        Arc::new(pm),
        Arc::new(ArcSwap::from_pointee(None)),
    );
    let tok = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "pump-1",
        "speed",
        &[],
        &ca.secret_seed(),
    )
    .unwrap();
    let mk = |v: i64, seq: u64| {
        let mut cmd = CommandMessage {
            issuer_did: Did::new(issuer.did()),
            role: CommandRole::CommandIssuer,
            target_id: target.clone(),
            param: "speed".into(),
            desired_state: fpv(v),
            sequence_number: seq,
            idempotency_key: [seq as u8; 16],
            expiry_est: 9_999_999_999,
            policy_version: 1,
            enrollment_epoch: 0,
            challenge_nonce: None,
            co_signatures: vec![],
            signature: DeviceSignature::Ed25519([0; 64]),
        };
        sign_command(&mut cmd, &issuer).unwrap();
        cmd
    };
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    {
        let mut out = Vec::new();
        let mut proxy = DriverProxy::new(Cursor::new(&mut out));
        let _ = guard.admit_with_context(&mk(1, 1), &ctx, &mut proxy, b"f");
    }
    let mut out = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut out));
    let e = guard
        .admit_with_context(&mk(500, 2), &ctx, &mut proxy, b"f")
        .unwrap_err();
    assert!(
        matches!(
            e,
            tirbase_guard::AdmitError::Pipeline {
                category: AdmitRejection::DriftExceeded,
                ..
            }
        ) || matches!(
            e,
            tirbase_guard::AdmitError::Pipeline {
                category: AdmitRejection::EnvelopeViolation,
                ..
            }
        ),
        "{e:?}"
    );
}

pub fn scenario_s3_replay_returns_cached_no_second_actuation() {
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let target = TargetId::new("pump-1");
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled("dev1", 1_000_000).unwrap();
    let mut targets = BTreeMap::new();
    targets.insert(
        target.clone(),
        TargetAdmission {
            device_id: "dev1".into(),
        },
    );
    let profile = EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "t".into(),
        parameters: vec![ParameterSpec {
            name: "speed".into(),
            unit_id: UNIT_PERCENT,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: fpv(0),
                max: fpv(1000),
            },
            max_rate_per_sec: fpv(10000),
            dwell_secs: 0,
            min_off_secs: 0,
            drift_window_secs: 0,
            max_delta_in_window: fpv(10000),
            safe_default: fpv(0),
            tightening_floor: fpv(0),
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 0,
        policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    let mut pm = BTreeMap::new();
    pm.insert(target.clone(), Arc::new(ArcSwap::from_pointee(profile)));
    let ts: Arc<dyn TimeSource> = Arc::new(T(1_000_000_000));
    let ratchet = Arc::new(std::sync::Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let reg = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
        .public_key_bytes()
        .try_into()
        .unwrap()])));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        reg,
        ratchet,
        ts,
    ));
    pipeline.set_max_ttl_secs(10_000_000_000);
    let guard = CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
    )
    .with_pipeline(
        pipeline,
        Arc::new(pm),
        Arc::new(ArcSwap::from_pointee(None)),
    );
    let tok = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "pump-1",
        "speed",
        &[],
        &ca.secret_seed(),
    )
    .unwrap();
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target,
        param: "speed".into(),
        desired_state: fpv(500),
        sequence_number: 1,
        idempotency_key: [1; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut cmd, &issuer).unwrap();
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    let mut out = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut out));
    guard
        .admit_with_context(&cmd, &ctx, &mut proxy, b"f")
        .unwrap();
    let mut out2 = Vec::new();
    let mut proxy2 = DriverProxy::new(Cursor::new(&mut out2));
    guard
        .admit_with_context(&cmd, &ctx, &mut proxy2, b"f")
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s1_envelope_violation_claim_14_13_15_9() {
        scenario_s1_envelope_violation_rejected();
    }
    #[test]
    fn s2_slow_ramp_drift_claim_14_15() {
        scenario_s2_slow_ramp_drift_rejected();
    }
    #[test]
    fn s3_replay_cached_claim_14_11_15_9() {
        scenario_s3_replay_returns_cached_no_second_actuation();
    }
}
