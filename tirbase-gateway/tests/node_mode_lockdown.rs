//! Task 13 integration tests — NodeMode, LOCKDOWN persistence/exit, crash-loop,
//! safe defaults, watchdog loop (CLAIM-13.1–13.3, 13.5–13.7, PV-4.13, PV-1.11,
//! PV-4.15, INV-5, S24).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::admin::{dispatch_admin_command_at, AdminState};
use tirbase_gateway::db::lockdown::SqliteLockdownStore;
use tirbase_gateway::health::{run_health_loop, HealthLoopState, WatchdogNotifier};
use tirbase_guard::driver_proxy::{DriverProxy, IngressSource};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::lockdown::{
    apply_crash_decision, apply_lockdown_exit, arm_controller_watchdogs, enter_lockdown,
    CrashLoopEscalation, CrashLoopTracker, LockdownEntryReason, LockdownExitPayload,
    LockdownStore, SafeDefaultBinding,
};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::{sign_command, single_target_guard, AdmitError};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue, TargetId, UNIT_BOOLEAN};

static N: AtomicU64 = AtomicU64::new(0);
fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tirbase-task13-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sample_profile(id: [u8; 16]) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: id, version: 1, device_class: "test".into(),
        parameters: vec![ParameterSpec {
            name: "on".into(), unit_id: UNIT_BOOLEAN, canonical_exponent: 0,
            kind: ParameterKind::Bool, max_rate_per_sec: FixedPointValue::new(1, 0, UNIT_BOOLEAN), dwell_secs: 0, min_off_secs: 0,
            drift_window_secs: 0, max_delta_in_window: FixedPointValue::new(1, 0, UNIT_BOOLEAN),
            safe_default: FixedPointValue::new(0, 0, UNIT_BOOLEAN), tightening_floor: FixedPointValue::new(0, 0, UNIT_BOOLEAN), critical: false,
        }],
        cross_constraints: vec![], policy_loosen_m: 2, policy_loosen_n: 2,
        policy_timelock_secs: 0, policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

fn signed_cmd(target: &TargetId, issuer: &InMemoryKeyProvider) -> CommandMessage {
    let mut cmd = CommandMessage {
        issuer_did: tirbase_types::Did(issuer.did().to_string()), role: CommandRole::CommandIssuer,
        target_id: target.clone(), param: "on".into(),
        desired_state: FixedPointValue::new(1, 0, UNIT_BOOLEAN),
        sequence_number: 1, idempotency_key: [7u8; 16], expiry_est: 9_999_999_999,
        policy_version: 1, enrollment_epoch: 0, co_signatures: vec![],
        challenge_nonce: None,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };
    sign_command(&mut cmd, issuer).unwrap();
    cmd
}

fn make_guard(target: &TargetId, device_id: &str) -> tirbase_guard::CommandGuard {
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled(device_id, 0).unwrap();
    single_target_guard(epochs, target.clone(), device_id.to_string())
}

// ── CLAIM-13.1 ─────────────────────────────────────────────────────────────
#[test]
fn commands_rejected_in_lockdown_and_restricted_mesh_log_export_remain_available_claim_13_1() {
    let target = TargetId::new("valve#1");
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let cmd = signed_cmd(&target, &issuer);
    let guard = make_guard(&target, "dev1");
    let mut proxy = DriverProxy::new(std::io::sink());

    for mode in [NodeMode::Lockdown, NodeMode::Restricted] {
        guard.node_mode().set(mode);
        let err = guard.admit(&cmd, IngressSource::LocalAdmin, &mut proxy, b"f").unwrap_err();
        assert_eq!(err, AdmitError::ModeRejected(mode), "commands must be rejected in {mode}");
        assert!(mode.allows_mesh_sync(), "{mode} must allow mesh sync");
        assert!(mode.allows_log_export(), "{mode} must allow log export");
    }
    guard.node_mode().set(NodeMode::Normal);
    assert!(guard.admit(&cmd, IngressSource::LocalAdmin, &mut proxy, b"f").is_ok());
}

// ── CLAIM-13.2 ─────────────────────────────────────────────────────────────
#[test]
fn lockdown_persists_to_db_and_secondary_file_and_survives_restart_claim_13_2() {
    let dir = tmp_dir("persist");
    let db = dir.join("primary.db");
    let marker = dir.join("var/lib/tirbase/lockdown");
    let mode = NodeModeState::new(NodeMode::Normal);

    {
        let store = SqliteLockdownStore::new(&db, &marker);
        enter_lockdown(&store, &mode, LockdownEntryReason::GuardDecision).unwrap();
        assert_eq!(mode.get(), NodeMode::Lockdown);
        assert!(store.is_lockdown().unwrap());
        assert!(marker.exists(), "secondary /var/lib/tirbase/lockdown indicator must be written");
        let body = std::fs::read_to_string(&marker).unwrap();
        assert!(!marker.to_string_lossy().contains("/run"), "must not use /run");
        assert!(body.contains("lockdown_state=1"));
        let conn = rusqlite::Connection::open(&db).unwrap();
        let v: i64 = conn.query_row(
            "SELECT value FROM monotonic_counters WHERE key=?1",
            [tirbase_guard::LOCKDOWN_DB_KEY], |r| r.get(0),
        ).unwrap();
        assert_eq!(v, 1, "LOCKDOWN must persist in primary.db monotonic_counters");
    }
    // restart
    {
        let store = SqliteLockdownStore::new(&db, &marker);
        assert!(store.is_lockdown().unwrap(), "LOCKDOWN must survive restart (CLAIM-13.2)");
    }
    let _ = std::fs::remove_dir_all(dir);
}

// ── CLAIM-13.3 ─────────────────────────────────────────────────────────────
fn make_trust_root(pa: &InMemoryKeyProvider, rm: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(CommandRole::PolicyAuthority, RolePolicy::new(1, vec![AuthorizedRoleSigner { did: pa.did().to_string(), public_key: pa.public_key_bytes() }]));
    roles.insert(CommandRole::RevocationManager, RolePolicy::new(1, vec![AuthorizedRoleSigner { did: rm.did().to_string(), public_key: rm.public_key_bytes() }]));
    TrustRootRecord { version: 1, root_ca_public_keys: vec![], threshold_k: 1, role_thresholds: roles, device_class_floors: BTreeMap::new(), expiry_est: i64::MAX, revoked_root_ca_keys: vec![], signatures: vec![] }
}

#[test]
fn lockdown_exit_requires_m_of_n_distinct_roles_and_full_profile_claim_13_3() {
    let dir = tmp_dir("exit");
    let store = SqliteLockdownStore::new(dir.join("primary.db"), dir.join("lockdown"));
    let mode = NodeModeState::new(NodeMode::Lockdown);
    store.set_lockdown(LockdownEntryReason::GuardDecision).unwrap();
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let tr = make_trust_root(&pa, &rm);
    let profile = sample_profile([9u8; 16]);
    let payload = LockdownExitPayload { node_id: "node1".into(), issued_at_est: 1_000, reason: "test".into(), envelope_profile_id: profile.profile_id };

    // M=1 (single role) must fail
    let mut op1 = SignedOperation::new(&payload, 1_000, None).unwrap();
    op1.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    let err = apply_lockdown_exit(&op1, &payload, &tr, Some(&profile), &store, &mode).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("distinct roles") || msg.contains(">= 2"), "M<2 must fail: {msg}");
    assert!(store.is_lockdown().unwrap(), "failed exit must not clear lockdown");

    // Missing profile must fail
    let mut op2 = SignedOperation::new(&payload, 1_000, None).unwrap();
    op2.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    op2.sign_with(&rm, CommandRole::RevocationManager).unwrap();
    assert!(apply_lockdown_exit(&op2, &payload, &tr, None, &store, &mode).is_err());

    // Valid 2 distinct roles + profile succeeds
    let mut op3 = SignedOperation::new(&payload, 1_000, None).unwrap();
    op3.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    op3.sign_with(&rm, CommandRole::RevocationManager).unwrap();
    apply_lockdown_exit(&op3, &payload, &tr, Some(&profile), &store, &mode).unwrap();
    assert!(!store.is_lockdown().unwrap());
    assert_eq!(mode.get(), NodeMode::Normal);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn admin_lockdown_exit_endpoint_requires_valid_m_of_n_claim_13_3() {
    let dir = tmp_dir("admin-exit");
    let store = Arc::new(SqliteLockdownStore::new(dir.join("primary.db"), dir.join("lockdown")));
    store.set_lockdown(LockdownEntryReason::GuardDecision).unwrap();
    let mode = NodeModeState::new(NodeMode::Lockdown);
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let tr = Arc::new(make_trust_root(&pa, &rm));
    let profile = Arc::new(sample_profile([4u8; 16]));
    let payload = LockdownExitPayload { node_id: "node1".into(), issued_at_est: 1_000, reason: "ok".into(), envelope_profile_id: profile.profile_id };

    let mut state = AdminState::default();
    state.trust_root = Some(tr);
    state.lockdown_store = Some(store.clone());
    state.node_mode = Some(mode.clone());
    state.envelope_profile = Some(profile);

    let mut op_bad = SignedOperation::new(&payload, 1_000, None).unwrap();
    op_bad.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    let bad = serde_json::json!({"cmd":"lockdown-exit","payload":{"operation":op_bad,"payload":payload}}).to_string();
    let resp = dispatch_admin_command_at(&bad, Some(&state), 1_000);
    assert!(resp.contains("\"status\":409"), "single-role exit must fail: {resp}");

    let mut op_ok = SignedOperation::new(&payload, 1_000, None).unwrap();
    op_ok.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    op_ok.sign_with(&rm, CommandRole::RevocationManager).unwrap();
    let ok = serde_json::json!({"cmd":"lockdown-exit","payload":{"operation":op_ok,"payload":payload}}).to_string();
    let resp = dispatch_admin_command_at(&ok, Some(&state), 1_000);
    assert!(resp.contains("\"status\":200"), "valid M-of-N exit must succeed: {resp}");
    assert_eq!(mode.get(), NodeMode::Normal);
    let _ = std::fs::remove_dir_all(dir);
}

// ── CLAIM-13.5 / INV-5 ─────────────────────────────────────────────────────
#[derive(Debug)]
struct MemController { id: String, armed: AtomicBool, value: Mutex<String>, safe: Mutex<String> }
impl MemController {
    fn new(id: &str, initial: &str) -> Self {
        MemController { id: id.into(), armed: AtomicBool::new(false), value: Mutex::new(initial.into()), safe: Mutex::new(String::new()) }
    }
    fn simulate_guard_death(&self) {
        if self.armed.load(Ordering::SeqCst) { *self.value.lock().unwrap() = self.safe.lock().unwrap().clone(); }
    }
}
impl SafeDefaultBinding for MemController {
    fn controller_id(&self) -> &str { &self.id }
    fn arm_watchdog(&self, _timeout_secs: u32, safe_default: &str) -> Result<(), String> {
        *self.safe.lock().unwrap() = safe_default.to_string(); self.armed.store(true, Ordering::SeqCst); Ok(())
    }
    fn refresh_watchdog(&self) -> Result<(), String> { Ok(()) }
    fn current_value(&self) -> String { self.value.lock().unwrap().clone() }
}

#[test]
fn guard_death_results_in_safe_default_via_option_a_watchdog_claim_13_5() {
    let c = MemController::new("chiller-1", "commanded:18C");
    arm_controller_watchdogs(&[&c as &dyn SafeDefaultBinding], 5, "safe:22C").unwrap();
    c.simulate_guard_death();
    assert_eq!(c.current_value(), "safe:22C", "controller must self-revert to safe default on guard death (INV-5/option a)");
}

// ── CLAIM-13.6 / S24 ───────────────────────────────────────────────────────
#[test]
fn n_crashes_within_window_escalates_to_security_lockdown_claim_13_6_s24() {
    let dir = tmp_dir("s24");
    let store = SqliteLockdownStore::new(dir.join("primary.db"), dir.join("lockdown"));
    let mode = NodeModeState::new(NodeMode::Starting);
    let mut tracker = CrashLoopTracker::new(3, 300); // 3/5 min

    assert!(matches!(apply_crash_decision(tracker.record_crash(0), &store, &mode).map(|_| mode.get()), Ok(NodeMode::Normal)));
    assert!(matches!(apply_crash_decision(tracker.record_crash(100), &store, &mode).map(|_| mode.get()), Ok(NodeMode::Normal)));
    assert!(!store.is_lockdown().unwrap());
    // 3rd within window -> LOCKDOWN
    apply_crash_decision(tracker.record_crash(200), &store, &mode).unwrap();
    assert_eq!(mode.get(), NodeMode::Lockdown);
    assert!(store.is_lockdown().unwrap(), "crash-loop escalation must persist LOCKDOWN (S24)");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn admin_mode_endpoint_reports_lockdown_claim_13_1() {
    let mode = NodeModeState::new(NodeMode::Lockdown);
    let mut state = AdminState::default();
    state.node_mode = Some(mode);
    let resp = dispatch_admin_command_at(r#"{"cmd":"mode"}"#, Some(&state), 0);
    let v: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
    assert_eq!(v["status"], 200);
    assert_eq!(v["mode"], "Lockdown");
    assert_eq!(v["allows_commands"], false);
    assert_eq!(v["allows_mesh_sync"], true);
    assert_eq!(v["allows_log_export"], true);
}

// ── CLAIM-13.7 ─────────────────────────────────────────────────────────────
#[derive(Debug, Default)]
struct CountingNotifier(AtomicU64);
impl WatchdogNotifier for CountingNotifier {
    fn notify_watchdog(&self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[tokio::test]
async fn health_loop_sends_watchdog_keepalive_each_iteration_claim_13_7() {
    let state = HealthLoopState::new();
    let notifier = Arc::new(CountingNotifier::default());
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(run_health_loop(state.clone(), notifier.clone() as Arc<dyn WatchdogNotifier>, Duration::from_millis(20), shutdown.clone()));
    tokio::time::sleep(Duration::from_millis(120)).await;
    shutdown.notify_waiters();
    let _ = task.await;
    assert!(state.ticks() >= 3);
    assert!(notifier.0.load(Ordering::SeqCst) >= 3);
}
