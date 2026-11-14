// SPDX-License-Identifier: AGPL-3.0-only

//! integration tests: CommandGuard admit pipeline Stages 0–15
//! (CLAIM-14.1–14.17).

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
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

#[derive(Debug, Clone)]
struct TestTime {
    mono: u64,
    boot: u64,
}
impl TimeSource for TestTime {
    fn monotonic_now(&self) -> u64 {
        self.mono
    }
    fn wall_hint(&self) -> Option<i64> {
        Some((self.mono / 1_000_000) as i64)
    }
    fn boot_id(&self) -> u64 {
        self.boot
    }
}
#[derive(Debug, Default)]
struct MemRatchetStore(std::sync::Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
impl TimeRatchetStore for MemRatchetStore {
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
fn fpv(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, -1, UNIT_PERCENT)
}
fn target() -> TargetId {
    TargetId::new("pump-1")
}
fn profile(critical: bool) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "test".into(),
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
            critical,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 0,
        policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0; 64]),
    }
}
struct Harness {
    guard: CommandGuard,
    pipeline: Arc<AdmitPipelineState>,
    issuer: InMemoryKeyProvider,
    root_ca_priv: [u8; 32],
}
impl Harness {
    fn new(critical: bool) -> Self {
        let ca = InMemoryKeyProvider::generate().unwrap();
        let issuer = InMemoryKeyProvider::generate().unwrap();
        let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
        epochs.ensure_enrolled("dev1", 1_000_000).unwrap();
        let mut targets = BTreeMap::new();
        targets.insert(
            target(),
            TargetAdmission {
                device_id: "dev1".into(),
            },
        );
        let mut profiles = BTreeMap::new();
        profiles.insert(target(), Arc::new(ArcSwap::from_pointee(profile(critical))));
        let ts: Arc<dyn TimeSource> = Arc::new(TestTime {
            mono: 1_000_000_000,
            boot: 1,
        });
        let ratchet = Arc::new(std::sync::Mutex::new(
            TimeRatchet::open(
                Arc::new(MemRatchetStore::default()),
                TimeRatchetConfig::default(),
            )
            .unwrap(),
        ));
        let reg = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
            .public_key_bytes()
            .try_into()
            .unwrap()])));
        let pipeline = Arc::new(AdmitPipelineState::new(
            Arc::new(profiles.clone()),
            Arc::new(ArcSwap::from_pointee(None)),
            reg,
            ratchet,
            ts,
        ));
        pipeline.set_pre_auth_rps(1000);
        pipeline.set_issuer_rps(1000);
        pipeline.set_max_ttl_secs(10_000_000_000);
        let guard = CommandGuard::with_mode(
            epochs,
            GuardConfig { targets },
            NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
        )
        .with_pipeline(
            pipeline.clone(),
            Arc::new(profiles),
            Arc::new(ArcSwap::from_pointee(None)),
        );
        let mut root = [0u8; 32];
        root.copy_from_slice(&ca.secret_seed());
        Harness {
            guard,
            pipeline,
            issuer,
            root_ca_priv: root,
        }
    }
    fn token(&self) -> Vec<u8> {
        create_command_token(
            self.issuer.did(),
            "CommandIssuer",
            3600,
            "pump-1",
            "speed",
            &[],
            &self.root_ca_priv,
        )
        .unwrap()
    }
    fn cmd(&self, seq: u64) -> CommandMessage {
        let mut cmd = CommandMessage {
            issuer_did: Did::new(self.issuer.did()),
            role: CommandRole::CommandIssuer,
            target_id: target(),
            param: "speed".into(),
            desired_state: fpv(500),
            sequence_number: seq,
            idempotency_key: [seq as u8; 16],
            expiry_est: 9_999_999_999,
            policy_version: 1,
            enrollment_epoch: 0,
            challenge_nonce: None,
            co_signatures: vec![],
            signature: DeviceSignature::Ed25519([0; 64]),
        };
        sign_command(&mut cmd, &self.issuer).unwrap();
        cmd
    }
    fn admit(&self, cmd: &CommandMessage, ctx: &AdmitContext<'_>) -> Result<(), AdmitRejection> {
        let mut out = Vec::new();
        let mut proxy = DriverProxy::new(Cursor::new(&mut out));
        self.guard
            .admit_with_context(cmd, ctx, &mut proxy, b"f")
            .map(|_| ())
            .map_err(|e| match e {
                tirbase_guard::AdmitError::Pipeline { category, .. } => category,
                other => panic!("unexpected {other:?}"),
            })
    }
}

#[test]
fn claim_14_1_struct_has_arcswap_snapshots() {
    let h = Harness::new(false);
    assert!(h.guard.envelope_profile_for(&target()).is_some());
    let _ = h.guard.policy_snapshot();
}
#[test]
fn claim_14_2_stage0_pre_auth_rate_limit() {
    let h = Harness::new(false);
    h.pipeline.set_pre_auth_rps(1);
    let tok = h.token();
    let cmd = h.cmd(1);
    let ctx = || AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "src:a",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    let _ = h.admit(&cmd, &ctx());
    let e = h.admit(&h.cmd(2), &ctx()).unwrap_err();
    assert_eq!(e, AdmitRejection::PreAuthRateLimit);
}
#[test]
fn claim_14_4_stage2_signature_required() {
    let h = Harness::new(false);
    let tok = h.token();
    let mut cmd = h.cmd(40);
    cmd.signature = DeviceSignature::Ed25519([0; 64]);
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    assert!(matches!(
        h.admit(&cmd, &ctx),
        Err(AdmitRejection::InvalidSignature)
    ));
}
#[test]
fn claim_14_10_challenge_missing_for_unverified_critical() {
    let h = Harness::new(true);
    let tok = h.token();
    let cmd = h.cmd(50);
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    assert_eq!(
        h.admit(&cmd, &ctx).unwrap_err(),
        AdmitRejection::ChallengeMissing
    );
}
#[test]
fn claim_14_12_canonical_exponent_enforced() {
    let h = Harness::new(false);
    let tok = h.token();
    let mut cmd = h.cmd(60);
    cmd.desired_state = FixedPointValue::new(500, 0, UNIT_PERCENT); // wrong exponent
    sign_command(&mut cmd, &h.issuer).unwrap();
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    let e = h.admit(&cmd, &ctx).unwrap_err();
    assert!(
        matches!(
            e,
            AdmitRejection::ValueInvalid | AdmitRejection::EnvelopeViolation
        ),
        "{e:?}"
    );
}
#[test]
fn claim_14_15_drift_exceeded() {
    let h = Harness::new(false);
    h.pipeline.set_issuer_rps(1000);
    let _tok = h.token();
 // make a restrictive drift profile
    let mut p = profile(false);
    p.parameters[0].drift_window_secs = 3600;
    p.parameters[0].max_delta_in_window = fpv(10);
    p.parameters[0].max_rate_per_sec = fpv(10000);
    let profs: Arc<BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>> =
        Arc::new([(target(), Arc::new(ArcSwap::from_pointee(p)))].into());
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled("dev1", 1_000_000).unwrap();
    let mut targets = BTreeMap::new();
    targets.insert(
        target(),
        TargetAdmission {
            device_id: "dev1".into(),
        },
    );
    let ts: Arc<dyn TimeSource> = Arc::new(TestTime {
        mono: 1_000_000_000,
        boot: 1,
    });
    let ratchet = Arc::new(std::sync::Mutex::new(
        TimeRatchet::open(
            Arc::new(MemRatchetStore::default()),
            TimeRatchetConfig::default(),
        )
        .unwrap(),
    ));
    let reg = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
        .public_key_bytes()
        .try_into()
        .unwrap()])));
    let pipeline = Arc::new(AdmitPipelineState::new(
        profs.clone(),
        Arc::new(ArcSwap::from_pointee(None)),
        reg,
        ratchet,
        ts,
    ));
    pipeline.set_pre_auth_rps(1000);
    pipeline.set_issuer_rps(1000);
    pipeline.set_max_ttl_secs(10_000_000_000);
    let guard = CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
    )
    .with_pipeline(pipeline, profs, Arc::new(ArcSwap::from_pointee(None)));
    let mut root = [0u8; 32];
    root.copy_from_slice(&ca.secret_seed());
    let tok = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "pump-1",
        "speed",
        &[],
        &root,
    )
    .unwrap();
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
 // seed history
    let mut cmd1 = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target(),
        param: "speed".into(),
        desired_state: fpv(1),
        sequence_number: 70,
        idempotency_key: [70; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut cmd1, &issuer).unwrap();
    {
        let mut out = Vec::new();
        let mut proxy = DriverProxy::new(Cursor::new(&mut out));
        let _ = guard.admit_with_context(&cmd1, &ctx, &mut proxy, b"f");
    }
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target(),
        param: "speed".into(),
        desired_state: fpv(500),
        sequence_number: 71,
        idempotency_key: [71; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut cmd, &issuer).unwrap();
    let mut out = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut out));
    let e = guard
        .admit_with_context(&cmd, &ctx, &mut proxy, b"f")
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
#[test]
fn claim_14_16_per_issuer_rate_limit() {
    let h = Harness::new(false);
    h.pipeline.set_issuer_rps(1);
    let tok = h.token();
    let ctx = || AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    let _ = h.admit(&h.cmd(80), &ctx());
    let e = h.admit(&h.cmd(81), &ctx()).unwrap_err();
    assert_eq!(e, AdmitRejection::RateLimit);
}
#[test]
fn simulate_skips_issuer_token_consumption_claim_14_10_16() {
    let h = Harness::new(false);
    h.pipeline.set_issuer_rps(1);
    let tok = h.token();
    let cmd = h.cmd(90);
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: true,
    };
    let _ = h.guard.simulate(&cmd, &ctx);
    let ctx2 = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    assert!(h.admit(&cmd, &ctx2).is_ok());
}

/// / CLAIM-56.1: a credential for the wrong role is rejected by the
/// table-driven authorization matrix on the production admission path. Before
/// 56.1 was wired in, Stage 4 used an ad-hoc `!= CommandIssuer` comparison and
/// the matrix had no production caller at all.
#[test]
fn claim_9_6_wrong_role_tokens_rejected_by_authorization_matrix() {
    let h = Harness::new(false);
    let denied_roles = [
        "PolicyAuthority",
        "UpdateSigner",
        "RevocationManager",
        "Auditor",
        "TimeAnchor",
    ];
    for (index, role) in denied_roles.iter().enumerate() {
        let tok = create_command_token(
            h.issuer.did(),
            role,
            3600,
            "pump-1",
            "speed",
            &[],
            &h.root_ca_priv,
        )
        .unwrap_or_else(|e| panic!("mint {role} token: {e}"));
        let cmd = h.cmd(200 + index as u64);
        let ctx = AdmitContext {
            ingress: IngressSource::LocalAdmin,
            source_key: "matrix-test",
            biscuit_token: Some(&tok),
            now_est_secs: Some(1_000),
            simulate: false,
        };
        let rejection = h
            .admit(&cmd, &ctx)
            .expect_err(&format!("role {role} must be denied on the command path"));
        assert_eq!(
            rejection,
            AdmitRejection::ScopeViolation,
            "role {role} must be rejected by the authorization matrix"
        );
    }
}
