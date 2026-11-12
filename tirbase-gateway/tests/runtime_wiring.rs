//! runtime/admin wiring integration tests (CLAIM-21.1–21.3,21.5,21.9–21.13).
//! Verifies: AEF Unknown-target sync blocks/unblocks via pipeline, operator clear
//! admin path (signed PolicyAuthority), lease-preempt admin path (joint M-of-N),
//! revoke-issuer releases leases, target_state/drift hydration into pipeline.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use rusqlite::Connection;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_gateway::admin::{dispatch_admin_command_at, AdminState};
use tirbase_gateway::db::applied_effects_ledger;
use tirbase_gateway::db::drift_rate_history::{self, DriftSummaryRow};
use tirbase_gateway::db::single_writer_leases::{
    self, acquire_tx, create_table as create_leases, load_tx, DEFAULT_LEASE_DURATION_MONO_SECS,
    DEFAULT_MAX_CONSECUTIVE_RENEWALS,
};
use tirbase_gateway::db::target_state;
use tirbase_gateway::guard::{hydrate_runtime_state, open_drift_timing_store};
use tirbase_guard::admit::{AdmitDecision, AdmitPipelineState, AdmitRejection};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::node_mode::NodeModeState;
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationPayload};
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
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
struct S(Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
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

fn tmpdb(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tg21rt-{name}-{}-{}",
        std::process::id(),
        tirbase_core::traits::monotonic_now()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("primary.db")
}

fn open_primary(path: &std::path::Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.pragma_update(None, "synchronous", "FULL").unwrap();
    applied_effects_ledger::create_table(&c).unwrap();
    create_leases(&c).unwrap();
    target_state::create_table(&c).unwrap();
    drift_rate_history::create_table(&c).unwrap();
    c
}

fn trust_root(pa: &InMemoryKeyProvider, rm: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut role_thresholds = BTreeMap::new();
    role_thresholds.insert(
        CommandRole::PolicyAuthority,
        RolePolicy {
            required_m: 1,
            required_n: 1,
            authorized_signers: vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes().to_vec(),
            }],
        },
    );
    role_thresholds.insert(
        CommandRole::RevocationManager,
        RolePolicy {
            required_m: 1,
            required_n: 1,
            authorized_signers: vec![AuthorizedRoleSigner {
                did: rm.did().to_string(),
                public_key: rm.public_key_bytes().to_vec(),
            }],
        },
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![],
        threshold_k: 1,
        role_thresholds,
        device_class_floors: BTreeMap::new(),
        expiry_est: 9_999_999_999,
        revoked_root_ca_keys: vec![],
        signatures: vec![],
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ClearPayload {
    action: String,
    entry_id_hex: String,
}
impl SignedOperationPayload for ClearPayload {
    const CONTEXT: &'static str = "TirBase/v1/ClearUnknown";
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PreemptPayload {
    action: String,
    target_id: String,
    #[serde(default)]
    new_issuer_did: Option<String>,
    now_est: i64,
}
impl SignedOperationPayload for PreemptPayload {
    const CONTEXT: &'static str = "TirBase/v1/LeasePreempt";
}

fn sign_op<T: SignedOperationPayload + serde::Serialize>(
    payload: &T,
    signer: &InMemoryKeyProvider,
    role: CommandRole,
    created_est: i64,
) -> serde_json::Value {
    let mut op =
        SignedOperation::new(payload, created_est, Some(created_est + 3600)).unwrap();
    op.sign_with(signer, role).unwrap();
    serde_json::to_value(op).unwrap()
}

#[test]
fn claim_21_9_unknown_target_blocks_then_operator_clear_unblocks_runtime() {
    let db = tmpdb("unknown");
    let c = open_primary(&db);
    let entry_id = [0xabu8; 16];
    let tx = c.unchecked_transaction().unwrap();
    applied_effects_ledger::mark_unknown_tx(&tx, entry_id, "did:i", "pump-1", "speed", 100)
        .unwrap();
    tx.commit().unwrap();
    drop(c);

    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled("dev1", 1_000_000).unwrap();
    let mut targets = BTreeMap::new();
    targets.insert(
        TargetId::new("pump-1"),
        TargetAdmission {
            device_id: "dev1".into(),
        },
    );
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
            dwell_secs: 0,
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
    let mut pm = BTreeMap::new();
    pm.insert(
        TargetId::new("pump-1"),
        Arc::new(ArcSwap::from_pointee(profile)),
    );
    let ts: Arc<dyn TimeSource> = Arc::new(T(10_000_000));
    let ratchet = Arc::new(Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        Arc::new(RwLock::new(
            tirbase_core::auth::root_ca::RootCaRegistry::new(vec![]),
        )),
        ratchet,
        ts,
    ));
    let report = hydrate_runtime_state(&db, &pipeline).unwrap();
    assert_eq!(report.unknown_targets, vec!["pump-1".to_string()]);

 // Rebuild pipeline with a registered root CA so token verification reaches Stage 6.5 TargetBusy.
    let ca = InMemoryKeyProvider::generate().unwrap();
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let reg = Arc::new(RwLock::new(
        tirbase_core::auth::root_ca::RootCaRegistry::new(vec![ca
            .public_key_bytes()
            .try_into()
            .unwrap()]),
    ));
    let ratchet2 = Arc::new(Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let ts2: Arc<dyn TimeSource> = Arc::new(T(10_000_000));
    let pipeline2 = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        reg,
        ratchet2,
        ts2,
    ));
    pipeline2.set_max_ttl_secs(10_000_000_000);
    pipeline2.set_pre_auth_rps(1000);
    pipeline2.set_issuer_rps(1000);
    pipeline2.mark_target_unknown("pump-1"); // hydrated/runtime unknown state
    let guard = CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal),
    )
    .with_pipeline(
        pipeline2.clone(),
        Arc::new(pm.clone()),
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
    let ctx = tirbase_guard::admit::AdmitContext {
        ingress: tirbase_guard::driver_proxy::IngressSource::LocalAdmin,
        source_key: "s",
        biscuit_token: Some(&tok),
        now_est_secs: Some(1_000),
        simulate: true,
    };
    match guard.simulate(&cmd, &ctx) {
        AdmitDecision::Rejected {
            category: AdmitRejection::TargetBusy,
            ..
        }
        | AdmitDecision::Simulated {
            would_accept: false,
            rejection: Some((AdmitRejection::TargetBusy, ..)),
            ..
        } => {}
        other => panic!("expected TargetBusy blocked by AEF Unknown, got {other:?}"),
    }
 // Operator clear via admin path (signed PolicyAuthority) + runtime sync.
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let st = AdminState {
        primary_db_path: Some(db.clone()),
        trust_root: Some(Arc::new(trust_root(&pa, &rm))),
        guard: Some(Arc::new(guard)),
        ..Default::default()
    };
    let binding = ClearPayload {
        action: "clear-unknown".into(),
        entry_id_hex: hex::encode(entry_id),
    };
    let op = sign_op(&binding, &pa, CommandRole::PolicyAuthority, 100);
    let req = serde_json::json!({"cmd":"clear-unknown","payload":{"operation":op,"request":{"entry_id_hex":hex::encode(entry_id)}}}).to_string();
    let v: serde_json::Value =
        serde_json::from_str(dispatch_admin_command_at(&req, Some(&st), 100).trim()).unwrap();
    assert_eq!(v["status"], 200, "{v}");
    let d2 = st.guard.as_ref().unwrap().simulate(&cmd, &ctx);
    if let AdmitDecision::Rejected {
            category: AdmitRejection::TargetBusy,
            ..
        } = d2 { panic!("still blocked after clear") }
}

#[test]
fn claim_21_12_13_hydrate_target_state_and_drift_timing_store() {
    let db = tmpdb("hydrate");
    let c = open_primary(&db);
    let tx = c.unchecked_transaction().unwrap();
    target_state::upsert_tx(
        &tx,
        "pump-1",
        "speed",
        FixedPointValue::new(777, -1, UNIT_PERCENT),
    )
    .unwrap();
    drift_rate_history::upsert_summary_tx(
        &tx,
        &DriftSummaryRow {
            target_id: "pump-1".into(),
            param: "speed".into(),
            last_accepted_est: 1,
            last_accepted_mono: 10,
            last_value: FixedPointValue::new(777, -1, UNIT_PERCENT),
            window_start_est: 1,
            cumulative_delta_mantissa: 0,
            last_change_mono: 10,
            last_deactivation_mono: Some(5),
        },
    )
    .unwrap();
    tx.commit().unwrap();
    drop(c);

    let mut pm = BTreeMap::new();
    let profile = EnvelopeProfile {
        profile_id: [1; 16],
        version: 1,
        device_class: "x".into(),
        parameters: vec![],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 1,
        policy_cancel_window_secs: 1,
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    pm.insert(
        TargetId::new("pump-1"),
        Arc::new(ArcSwap::from_pointee(profile)),
    );
    let ts: Arc<dyn TimeSource> = Arc::new(T(10_000_000));
    let ratchet = Arc::new(Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm),
        Arc::new(ArcSwap::from_pointee(None)),
        Arc::new(RwLock::new(
            tirbase_core::auth::root_ca::RootCaRegistry::new(vec![]),
        )),
        ratchet,
        ts,
    ));
    let drift = open_drift_timing_store(&db).unwrap();
    pipeline.set_drift_store(drift.clone());
    let report = hydrate_runtime_state(&db, &pipeline).unwrap();
    assert_eq!(report.desired_state_entries, 1);
 // timing summary available through DriftHistoryStore impl
    let timing =
        tirbase_guard::admit::DriftHistoryStore::timing_summary(drift.as_ref(), "pump-1", "speed")
            .unwrap();
    assert_eq!(timing.unwrap().last_deactivation_mono, Some(5));
}

#[test]
fn claim_21_2_3_admin_lease_preempt_and_revoke_issuer() {
    let db = tmpdb("adminlease");
    let c = open_primary(&db);
    {
        let tx = c.unchecked_transaction().unwrap();
        acquire_tx(
            &tx,
            "pump-1",
            "did:old",
            100,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    drop(c);
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let tr = trust_root(&pa, &rm);
    let st = AdminState {
        primary_db_path: Some(db.clone()),
        trust_root: Some(Arc::new(tr)),
        ..Default::default()
    };
    let binding = PreemptPayload {
        action: "lease-preempt".into(),
        target_id: "pump-1".into(),
        new_issuer_did: Some("did:new".into()),
        now_est: 120,
    };
    let mut op = SignedOperation::new(&binding, 120, Some(4800)).unwrap();
    op.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    op.sign_with(&rm, CommandRole::RevocationManager).unwrap();
    let req = serde_json::json!({"cmd":"lease-preempt","payload":{"operation":serde_json::to_value(op).unwrap(),"request":{"target_id":"pump-1","new_issuer_did":"did:new"}}}).to_string();
    let resp = dispatch_admin_command_at(&req, Some(&st), 120);
    let v: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
    assert_eq!(v["status"], 200, "{v}");
    assert_eq!(v["prior_holder"].as_str(), Some("did:old"));

    let c = open_primary(&db);
    let lease = load_tx(&c.unchecked_transaction().unwrap(), "pump-1")
        .unwrap()
        .unwrap();
    assert_eq!(lease.issuer_did, "did:new");

    let revoke =
        serde_json::json!({"cmd":"revoke-issuer","payload":{"request":{"issuer_did":"did:new"}}})
            .to_string();
    let rv: serde_json::Value =
        serde_json::from_str(dispatch_admin_command_at(&revoke, Some(&st), 130).trim()).unwrap();
    assert_eq!(rv["status"], 200, "{rv}");
    assert_eq!(rv["leases_released"].as_i64(), Some(1));
}

#[test]
fn claim_21_5_release_all_at_boot_blocks_stale_leases() {
    let db = tmpdb("boot");
    let c = open_primary(&db);
    {
        let tx = c.unchecked_transaction().unwrap();
        acquire_tx(
            &tx,
            "t1",
            "did:a",
            100,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert!(single_writer_leases::release_all_at_boot(&c).unwrap() >= 1);
    let tx = c.unchecked_transaction().unwrap();
    assert!(load_tx(&tx, "t1").unwrap().is_none());
}
