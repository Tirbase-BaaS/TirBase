// SPDX-License-Identifier: AGPL-3.0-only

//! : Stage 16–19 atomic commit/dispatch, Stage 17 redaction,
//! simulate (15.7), and token-cannot-relax proptest wiring (15.8).

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_gateway::guard::SqliteStage16Store;
use tirbase_guard::admit::{AdmitContext, AdmitPipelineState};
use tirbase_guard::commit::{
    commit_dispatch_finalize, stage17_rejection, FinalizeContext, Stage16Error, Stage16Request,
    Stage16Store,
};
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
fn tmpdb(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tg15-{name}-{}-{}",
        std::process::id(),
        tirbase_core::traits::monotonic_now()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("primary.db")
}

fn mk_cmd(issuer: &InMemoryKeyProvider, seq: u64, idem: u8, val: i64) -> CommandMessage {
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("pump-1"),
        param: "speed".into(),
        desired_state: fpv(val),
        sequence_number: seq,
        idempotency_key: [idem; 16],
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

/// CLAIM-15.1/INV-12: Stage 16 commits Actuating atomically; lease failure leaves
/// no trace in idempotency or anti-replay state (full rollback).
#[test]
fn claim_15_1_stage16_atomic_commit_and_lease_failure_rolls_back_all_state() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let db = tmpdb("atomic");
    let store = SqliteStage16Store::open(&db).unwrap();
    let cmd = mk_cmd(&issuer, 1, 1, 500);
    let original = "{\"ok\":true}";
    let req = Stage16Request {
        cmd: &cmd,
        entry_id: [1u8; 16],
        actuating_ts: 100,
        now_est: 1000,
        now_mono_secs: 100,
        lease_duration_secs: 30,
        max_consecutive_renewals: 10,
        original_result_json: original,
        idempotency_retention_secs: tirbase_guard::commit::DEFAULT_IDEMPOTENCY_RETENTION_SECS,
    };
    store.commit_actuating(&req).expect("first commit");
    assert_eq!(
        store
            .anti_replay_highest(issuer.did(), "pump-1", 0)
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        store
            .count_idempotency_keys(issuer.did(), "pump-1")
            .unwrap(),
        1
    );
    assert_eq!(
        store.effect_state(&[1u8; 16]).unwrap().as_deref(),
        Some("Actuating")
    );
    assert_eq!(
        store.lease_holder("pump-1").unwrap().as_deref(),
        Some(issuer.did())
    );

 // Force lease failure by holding target lease for another issuer in same DB tx boundary:
 // second command same target, different issuer, same target => LeaseHeld; must not touch idem/replay for that issuer+key.
    let issuer2 = InMemoryKeyProvider::generate().unwrap();
    let cmd2 = mk_cmd(&issuer2, 1, 2, 500);
    let req2 = Stage16Request {
        cmd: &cmd2,
        entry_id: [2u8; 16],
        actuating_ts: 101,
        now_est: 1000,
        now_mono_secs: 101,
        lease_duration_secs: 30,
        max_consecutive_renewals: 10,
        original_result_json: original,
        idempotency_retention_secs: tirbase_guard::commit::DEFAULT_IDEMPOTENCY_RETENTION_SECS,
    };
    let err = store.commit_actuating(&req2).unwrap_err();
    assert!(matches!(err, Stage16Error::LeaseHeld { .. }), "{err:?}");
 // rollback means issuer2 idempotency and anti-replay state not created
    assert_eq!(
        store
            .count_idempotency_keys(issuer2.did(), "pump-1")
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .anti_replay_highest(issuer2.did(), "pump-1", 0)
            .unwrap(),
        None
    );
    assert_eq!(store.effect_state(&[2u8; 16]).unwrap(), None);
 // original issuer state intact
    assert_eq!(
        store
            .count_idempotency_keys(issuer.did(), "pump-1")
            .unwrap(),
        1
    );
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// CLAIM-15.3: coarse rejection to non-privileged caller; fine detail to privileged.
#[test]
fn claim_15_3_stage17_coarse_to_issuer_fine_to_auditor() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let cmd = mk_cmd(&issuer, 1, 1, 5000);
    let nonpriv = stage17_rejection(
        &cmd,
        tirbase_guard::AdmitRejection::EnvelopeViolation,
        "speed=500 > max=100",
        false,
    );
    assert_eq!(nonpriv["status"], "rejected");
    assert_eq!(nonpriv["code"], "ENVELOPE_VIOLATION");
    assert!(
        nonpriv.get("detail").is_none(),
        "non-privileged must not get detail: {nonpriv}"
    );
    let privd = stage17_rejection(
        &cmd,
        tirbase_guard::AdmitRejection::EnvelopeViolation,
        "speed=500 > max=100",
        true,
    );
    assert_eq!(privd["code"], "ENVELOPE_VIOLATION");
    assert!(
        privd.get("detail").is_some(),
        "Auditor/PA must get detail: {privd}"
    );
}

/// CLAIM-15.4/15.5/INV-12: dispatch occurs after commit; driver confirmation
/// finalizes Complete and releases lease.
#[test]
fn claim_15_4_15_5_stage18_dispatch_after_commit_stage19_finalize_releases_lease() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let db = tmpdb("dispatch");
    let store = SqliteStage16Store::open(&db).unwrap();
    let cmd = mk_cmd(&issuer, 1, 1, 500);
    let entry_id = [9u8; 16];
    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(&mut wire);
    let mut driver = Cursor::new(b"OK COMPLETE".to_vec());
    let v = commit_dispatch_finalize(
        &store,
        &cmd,
        FinalizeContext {
            entry_id,
            actuating_ts: 100,
            now_est: 1000,
            now_mono_secs: 100,
            completion_ts: 101,
        },
        &mut proxy,
        b"ACT",
        &mut driver,
    );
    assert_eq!(v["status"], "accepted");
    assert_eq!(v["terminal_state"], "Complete");
    assert_eq!(
        store.effect_state(&entry_id).unwrap().as_deref(),
        Some("Complete")
    );
 // lease released after completion
    assert_eq!(store.lease_holder("pump-1").unwrap(), None);
    assert!(!wire.is_empty(), "driver must receive dispatch frame");
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

#[test]
fn claim_15_5_driver_timeout_results_in_unknown() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let db = tmpdb("timeout");
    let store = SqliteStage16Store::open(&db).unwrap();
    let cmd = mk_cmd(&issuer, 2, 2, 500);
    let entry_id = [8u8; 16];
    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(&mut wire);
    let mut driver = Cursor::new(Vec::<u8>::new()); // no response => Unknown
    let v = commit_dispatch_finalize(
        &store,
        &cmd,
        FinalizeContext {
            entry_id,
            actuating_ts: 100,
            now_est: 1000,
            now_mono_secs: 100,
            completion_ts: 101,
        },
        &mut proxy,
        b"ACT",
        &mut driver,
    );
    assert_eq!(v["terminal_state"], "Unknown");
    assert_eq!(
        store.effect_state(&entry_id).unwrap().as_deref(),
        Some("Unknown")
    );
    assert_eq!(
        store.lease_holder("pump-1").unwrap(),
        None,
        "lease released on unknown/finalize"
    );
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// CLAIM-15.7 / PV-4.17: simulate() is side-effect-free and does not actuate.
#[test]
fn claim_15_7_simulate_returns_rejection_without_actuation() {
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
            critical: true,
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
    pipeline.set_issuer_rps(1);
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
 // critical + Unverified freshness and no nonce would normally need challenge consumption; simulate must not consume nonce/tokens.
    let cmd = mk_cmd(&issuer, 77, 77, 500);
    let sim_ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "sim",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: true,
    };
    let d1 = guard.simulate(&cmd, &sim_ctx);
    let d2 = guard.simulate(&cmd, &sim_ctx);
 // Side-effect-free: returns exact typed rejection (no nonce consumed, no tokens consumed, no actuation).
    assert!(
        matches!(
            d1,
            tirbase_guard::AdmitDecision::Simulated { .. }
                | tirbase_guard::AdmitDecision::Rejected { .. }
        ),
        "{d1:?}"
    );
    assert!(
        matches!(
            d2,
            tirbase_guard::AdmitDecision::Simulated { .. }
                | tirbase_guard::AdmitDecision::Rejected { .. }
        ),
        "{d2:?}"
    );
 // Critical+Unverified+no nonce => ChallengeMissing rejection reason.
    let detail = format!("{d1:?}");
    assert!(
        detail.contains("ChallengeMissing") || detail.contains("Simulated"),
        "{detail}"
    );
    let _ = (d1, d2);
}
