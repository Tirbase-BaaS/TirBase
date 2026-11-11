//! Task 21 integration tests (21.10/21.11): Stage 10 Enum/Bool VALUE_INVALID,
//! Stage 13 dwell/min-off interlocks.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::admit::{
    AdmitContext, AdmitDecision, AdmitPipelineState, AdmitRejection, DriftTimingSummary,
};
use tirbase_guard::driver_proxy::IngressSource;
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
        Ok(*self.0.lock().unwrap())
    }
    fn save(
        &self,
        r: &tirbase_guard::time::TimeRatchetRecord,
    ) -> Result<(), tirbase_guard::time::TimeRatchetError> {
        *self.0.lock().unwrap() = Some(*r);
        Ok(())
    }
}
fn fpv0(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, 0, UNIT_PERCENT)
}
#[derive(Debug)]
struct TimingStore(Mutex<BTreeMap<(String, String), DriftTimingSummary>>);
impl tirbase_guard::admit::DriftHistoryStore for TimingStore {
    fn record(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
        _: tirbase_types::FixedPointValue,
    ) -> Result<(), String> {
        Ok(())
    }
    fn recent(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
    ) -> Result<Vec<tirbase_guard::admit::DriftRecord>, String> {
        Ok(vec![])
    }
    fn timing_summary(
        &self,
        target_id: &str,
        param: &str,
    ) -> Result<Option<DriftTimingSummary>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&(target_id.to_string(), param.to_string()))
            .cloned())
    }
}
fn mk_guard(
    ca: &InMemoryKeyProvider,
    profile: EnvelopeProfile,
    ts: Arc<dyn TimeSource>,
    drift_store: Option<Arc<dyn tirbase_guard::admit::DriftHistoryStore>>,
) -> (CommandGuard, Arc<AdmitPipelineState>) {
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
    let mut pm = BTreeMap::new();
    pm.insert(target, Arc::new(ArcSwap::from_pointee(profile)));
    let ratchet = Arc::new(Mutex::new(
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
    pipeline.set_pre_auth_rps(1000);
    pipeline.set_issuer_rps(1000);
    pipeline.set_max_ttl_secs(10_000_000_000);
    if let Some(ds) = drift_store {
        pipeline.set_drift_store(ds);
    }
    let guard = CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
    )
    .with_pipeline(
        pipeline.clone(),
        Arc::new(pm),
        Arc::new(ArcSwap::from_pointee(None)),
    );
    (guard, pipeline)
}
fn mk_cmd(issuer: &InMemoryKeyProvider, param: &str, val: i64, seq: u64) -> CommandMessage {
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("pump-1"),
        param: param.into(),
        desired_state: fpv0(val),
        sequence_number: seq,
        idempotency_key: [seq as u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut cmd, issuer).unwrap();
    cmd
}
fn ctx<'a>(tok: Option<&'a [u8]>) -> AdmitContext<'a> {
    AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "t",
        biscuit_token: tok,
        now_est_secs: Some(1_000),
        simulate: true,
    }
}

#[test]
fn claim_21_11_stage10_enum_and_bool_reject_value_invalid() {
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let profile = EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "x".into(),
        parameters: vec![
            ParameterSpec {
                name: "mode".into(),
                unit_id: UNIT_PERCENT,
                canonical_exponent: 0,
                kind: ParameterKind::Enum {
                    variants: vec![("off".into(), 0), ("on".into(), 1)],
                },
                max_rate_per_sec: fpv0(0),
                dwell_secs: 0,
                min_off_secs: 0,
                drift_window_secs: 0,
                max_delta_in_window: fpv0(0),
                safe_default: fpv0(0),
                tightening_floor: fpv0(0),
                critical: false,
            },
            ParameterSpec {
                name: "enabled".into(),
                unit_id: UNIT_PERCENT,
                canonical_exponent: 0,
                kind: ParameterKind::Bool,
                max_rate_per_sec: fpv0(0),
                dwell_secs: 0,
                min_off_secs: 0,
                drift_window_secs: 0,
                max_delta_in_window: fpv0(0),
                safe_default: fpv0(0),
                tightening_floor: fpv0(0),
                critical: false,
            },
        ],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 1,
        policy_cancel_window_secs: 1,
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    let ts: Arc<dyn TimeSource> = Arc::new(T(10_000_000));
    let (guard, _) = mk_guard(&ca, profile, ts, None);
    let tok_mode = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "pump-1",
        "mode",
        &[],
        &ca.secret_seed(),
    )
    .unwrap();
    let tok_enabled = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "pump-1",
        "enabled",
        &[],
        &ca.secret_seed(),
    )
    .unwrap();
    match guard.simulate(&mk_cmd(&issuer, "mode", 7, 1), &ctx(Some(&tok_mode))) {
        AdmitDecision::Rejected {
            category: AdmitRejection::ValueInvalid,
            ..
        }
        | AdmitDecision::Simulated {
            would_accept: false,
            rejection: Some((AdmitRejection::ValueInvalid, ..)),
            ..
        } => {}
        other => panic!("expected ValueInvalid for enum, got {other:?}"),
    }
    match guard.simulate(&mk_cmd(&issuer, "enabled", 2, 2), &ctx(Some(&tok_enabled))) {
        AdmitDecision::Rejected {
            category: AdmitRejection::ValueInvalid,
            ..
        }
        | AdmitDecision::Simulated {
            would_accept: false,
            rejection: Some((AdmitRejection::ValueInvalid, ..)),
            ..
        } => {}
        other => panic!("expected ValueInvalid for bool, got {other:?}"),
    }
}

#[test]
fn claim_21_10_stage13_dwell_interlock_rejects() {
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let profile = EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "x".into(),
        parameters: vec![ParameterSpec {
            name: "speed".into(),
            unit_id: UNIT_PERCENT,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: FixedPointValue::new(0, -1, UNIT_PERCENT),
                max: FixedPointValue::new(1000, -1, UNIT_PERCENT),
            },
            max_rate_per_sec: FixedPointValue::new(10000, -1, UNIT_PERCENT),
            dwell_secs: 30,
            min_off_secs: 0,
            drift_window_secs: 0,
            max_delta_in_window: FixedPointValue::new(10000, -1, UNIT_PERCENT),
            safe_default: FixedPointValue::new(0, -1, UNIT_PERCENT),
            tightening_floor: FixedPointValue::new(0, -1, UNIT_PERCENT),
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 1,
        policy_cancel_window_secs: 1,
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    let ts: Arc<dyn TimeSource> = Arc::new(T(20_000_000)); // 20s mono
    let timing = Arc::new(TimingStore(Mutex::new(BTreeMap::from([(
        ("pump-1".to_string(), "speed".to_string()),
        DriftTimingSummary {
            last_change_mono: Some(0),
            last_deactivation_mono: None,
        },
    )]))));
    let (guard, _) = mk_guard(&ca, profile, ts, Some(timing));
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
        target_id: TargetId::new("pump-1"),
        param: "speed".into(),
        desired_state: FixedPointValue::new(500, -1, UNIT_PERCENT),
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
    match guard.simulate(&cmd, &ctx(Some(&tok))) {
        AdmitDecision::Rejected {
            category: AdmitRejection::DwellViolation,
            ..
        }
        | AdmitDecision::Simulated {
            would_accept: false,
            rejection: Some((AdmitRejection::DwellViolation, ..)),
            ..
        } => {}
        other => panic!("expected DwellViolation, got {other:?}"),
    }
}
