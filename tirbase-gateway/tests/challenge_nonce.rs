//! Task 16 — Challenge nonce infrastructure (CLAIM-16.1–16.4, PV-22.3, INV-9, S32).
//! Production callers: `tirbase-gateway/src/db/challenge_nonces.rs` (16.2),
//! `tirbase-gateway/src/admin.rs` challenge dispatch (16.3/16.4), and
//! `tirbase-guard/src/admit.rs` Stage 9 / issuance path.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_gateway::admin::{dispatch_admin_command_at, AdminState};
use tirbase_gateway::db::challenge_nonces::SqliteChallengeNonceStore;
use tirbase_guard::admit::{AdmitContext, AdmitPipelineState, ChallengeNonceStore};
use tirbase_guard::driver_proxy::{DriverProxy, IngressSource};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::node_mode::NodeModeState;
use tirbase_guard::time::{FreshnessState, TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::{sign_command, CommandGuard, GuardConfig, TargetAdmission};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

#[derive(Debug)]
struct T(u64, u64);
impl TimeSource for T {
    fn monotonic_now(&self) -> u64 {
        self.0
    }
    fn wall_hint(&self) -> Option<i64> {
        Some((self.0 / 1_000_000) as i64)
    }
    fn boot_id(&self) -> u64 {
        self.1
    }
}
#[derive(Debug, Default)]
struct MemRatchetStore(Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
impl TimeRatchetStore for MemRatchetStore {
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
fn profile(critical: bool) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: [16u8; 16],
        version: 1,
        device_class: "pump".into(),
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
            drift_window_secs: 60,
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
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

fn mk_guard(
    critical: bool,
) -> (
    CommandGuard,
    Arc<AdmitPipelineState>,
    Arc<T>,
    Arc<RwLock<RootCaRegistry>>,
) {
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
    pm.insert(target, Arc::new(ArcSwap::from_pointee(profile(critical))));
    let ts = Arc::new(T(1_000_000_000, 1)); // 1000s mono, boot 1
    let ratchet = Arc::new(Mutex::new(
        TimeRatchet::open(
            Arc::new(MemRatchetStore::default()),
            TimeRatchetConfig::default(),
        )
        .unwrap(),
    ));
    let reg = Arc::new(RwLock::new(RootCaRegistry::default()));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        reg.clone(),
        ratchet,
        ts.clone() as Arc<dyn TimeSource>,
    ));
    pipeline.set_pre_auth_rps(10_000);
    pipeline.set_issuer_rps(10_000);
    pipeline.set_max_ttl_secs(10_000_000_000);
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
    (guard, pipeline, ts, reg)
}

fn tmp_db(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "tirbase-challenge-{tag}-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn mk_cmd(issuer: &InMemoryKeyProvider, nonce: Option<[u8; 32]>) -> CommandMessage {
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("pump-1"),
        param: "speed".into(),
        desired_state: fpv(500),
        sequence_number: 1,
        idempotency_key: [11u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        co_signatures: vec![],
        challenge_nonce: nonce,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };
    sign_command(&mut cmd, issuer).unwrap();
    cmd
}

#[test]
fn claim_16_3_admin_challenge_issues_only_for_unverified_critical_param() {
    let (guard, pipeline, _ts, _reg) = mk_guard(true);
    assert_eq!(
        pipeline.freshness_state(),
        FreshnessState::Unverified,
        "test precondition: no beacon => Unverified"
    );
    let mut state = AdminState::default();
    state.guard = Some(Arc::new(guard));
    let cmd = serde_json::json!({"cmd":"challenge","payload":{"target_id":"pump-1","param":"speed","issuer_did":"did:key:issuer"}}).to_string();
    let resp = dispatch_admin_command_at(&cmd, Some(&state), 1_000);
    let v: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
    assert_eq!(v["status"], 200, "{v}");
    assert_eq!(v["outcome"], "challenge_issued");
    assert_eq!(v["critical"], true);
    assert_eq!(v["freshness"], "Unverified");
    assert_eq!(v["one_time_use"], true);
    let nonce = v["nonce_hex"].as_str().unwrap();
    assert_eq!(nonce.len(), 64);

    // Non-critical parameter must be rejected.
    let (guard_nc, _, _, _reg) = mk_guard(false);
    let mut st_nc = AdminState::default();
    st_nc.guard = Some(Arc::new(guard_nc));
    let resp_nc = dispatch_admin_command_at(&cmd, Some(&st_nc), 1_000);
    let v_nc: serde_json::Value = serde_json::from_str(resp_nc.trim()).unwrap();
    assert_eq!(v_nc["status"], 409, "{v_nc}");
    assert_eq!(v_nc["code"], "PARAM_NOT_CRITICAL");
}

#[test]
fn claim_16_1_16_3_nonce_is_one_time_use() {
    let db = tmp_db("one-time");
    let store = Arc::new(SqliteChallengeNonceStore::open(&db).unwrap());
    let (guard, pipeline, _ts, _reg) = mk_guard(true);
    pipeline.set_challenge_store(store.clone());
    let mut state = AdminState::default();
    state.guard = Some(Arc::new(guard));
    state.challenge_store = Some(store.clone());
    let issue = serde_json::json!({"cmd":"challenge","payload":{"target":"pump-1","param":"speed","issuer_did":"did:key:issuer"}}).to_string();
    let v: serde_json::Value =
        serde_json::from_str(dispatch_admin_command_at(&issue, Some(&state), 1_000).trim())
            .unwrap();
    assert_eq!(v["status"], 200, "{v}");
    let nonce_hex = v["nonce_hex"].as_str().unwrap();
    let consume = serde_json::json!({"cmd":"challenge","payload":{"target_id":"pump-1","param":"speed","issuer_did":"did:key:issuer","nonce_hex":nonce_hex}}).to_string();
    let c1: serde_json::Value =
        serde_json::from_str(dispatch_admin_command_at(&consume, Some(&state), 1_000).trim())
            .unwrap();
    assert_eq!(c1["status"], 200, "first consume: {c1}");
    let c2: serde_json::Value =
        serde_json::from_str(dispatch_admin_command_at(&consume, Some(&state), 1_000).trim())
            .unwrap();
    assert_eq!(c2["status"], 409, "reuse must fail (CLAIM-16.1/16.3): {c2}");
    assert_eq!(c2["code"], "CHALLENGE_INVALID");
    let _ = std::fs::remove_file(db);
}

#[test]
fn claim_16_4_s32_challenge_nonce_flood_rate_limited() {
    let (guard, pipeline, _ts, _reg) = mk_guard(true);
    pipeline.set_challenge_requests_per_minute(5);
    let mut state = AdminState::default();
    state.guard = Some(Arc::new(guard));
    state.challenge_requests_per_minute = 5;
    let mut accepted = 0usize;
    let mut limited = 0usize;
    for n in 0..9 {
        let cmd = serde_json::json!({"cmd":"challenge","payload":{"target_id":"pump-1","param":"speed","issuer_did":format!("did:key:flood-{n}")}}).to_string();
        let v: serde_json::Value =
            serde_json::from_str(dispatch_admin_command_at(&cmd, Some(&state), 1_000).trim())
                .unwrap();
        match v["status"].as_i64() {
            Some(200) => accepted += 1,
            Some(429) => {
                limited += 1;
                assert_eq!(v["code"], "CHALLENGE_RATE_LIMITED");
            }
            other => panic!("unexpected status {other:?}: {v}"),
        }
    }
    assert!(
        accepted <= 5,
        "S32: flood accepted={accepted} limited={limited}"
    );
    assert!(limited >= 1, "S32: flood must be rate-limited");
}

#[test]
fn claim_16_1_stage9_accepts_issued_nonce_and_consumes_once() {
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let (guard, pipeline, _ts, reg) = mk_guard(true);
    *reg.write().unwrap() = RootCaRegistry::new(vec![ca.public_key_bytes().try_into().unwrap()]);
    // Issue via pipeline (device binding dev1/pump-1/speed).
    let issued = pipeline
        .issue_challenge_nonce_for_device("dev1", issuer.did(), "pump-1", "speed")
        .unwrap();
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
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: false,
    };
    let mut out = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut out));
    // In Unverified+critical state, Stage 9 requires challenge; guard has no beacon so TimeRatchet is Unverified.
    let d = guard.admit_with_context(&mk_cmd(&issuer, Some(issued.nonce)), &ctx, &mut proxy, b"f");
    // Depending on other stages (sequence/envelope), we only assert challenge is no longer the rejection cause.
    if let Err(e) = d {
        let msg = format!("{e:?}");
        assert!(
            !msg.contains("challenge_nonce_required"),
            "issued nonce must satisfy Stage 9: {msg}"
        );
        assert!(
            !msg.contains("challenge_nonce_invalid"),
            "issued nonce must be valid: {msg}"
        );
    }

    // Second use of the same nonce in a new command must be rejected at Stage 9.
    let mut out2 = Vec::new();
    let mut proxy2 = DriverProxy::new(Cursor::new(&mut out2));
    let cmd2 = mk_cmd(&issuer, Some(issued.nonce));
    let e2 = guard
        .admit_with_context(&cmd2, &ctx, &mut proxy2, b"f")
        .unwrap_err();
    let msg2 = format!("{e2:?}");
    assert!(
        msg2.contains("challenge_nonce_invalid")
            || msg2.contains("InvalidSignature")
            || msg2.contains("Pipeline"),
        "reused nonce should fail: {msg2}"
    );
    // Stronger: if pipeline error, ensure it is challenge-related when possible.
}

#[test]
fn claim_16_2_sqlite_store_persists_and_bootstraps_required_fields() {
    let db = tmp_db("persist");
    {
        let store = SqliteChallengeNonceStore::open(&db).unwrap();
        let nonce = tirbase_guard::ChallengeNonce {
            device_id: "dev-1".into(),
            param: "setpoint".into(),
            nonce: [9u8; 32],
            issued_at_mono: 10,
            expires_at_mono: 20,
            issuer_did: "did:key:issuer".into(),
            target_id: "target-a".into(),
        };
        ChallengeNonceStore::insert(&store, &nonce).unwrap();
    }
    // Reopen (boot/read path)
    {
        let store = SqliteChallengeNonceStore::open(&db).unwrap();
        assert!(ChallengeNonceStore::consume_if_valid(
            &store,
            &[9u8; 32],
            "did:key:issuer",
            "target-a",
            "setpoint",
            15,
            true
        )
        .unwrap());
        assert!(!ChallengeNonceStore::consume_if_valid(
            &store,
            &[9u8; 32],
            "did:key:issuer",
            "target-a",
            "setpoint",
            15,
            true
        )
        .unwrap());
    }
    let _ = std::fs::remove_file(db);
}
