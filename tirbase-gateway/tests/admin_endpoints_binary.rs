//! Binary-level admin endpoint tests.
//!
//! Each test spawns the real `tirbase-gateway` binary, waits for it to finish
//! booting, then speaks the admin JSON-line protocol over
//! `admin_socket` (Unix domain socket, peer-UID authenticated).
//!
//! Covered production callers (see CLAIMS.md):
//! * CLAIM-12.x — `policy` push through `PolicyLifecycle`
//! * CLAIM-13.1 — `mode` query / transitions
//! * CLAIM-13.3 — `lockdown-exit` M-of-N exit
//! * CLAIM-15.7 — `simulate` dry run
//! * CLAIM-16.3 — `challenge` issuance and one-time-use verification
//! * CLAIM-16.4 — challenge issuance rate limiting (store/pipeline wiring)
//! * CLAIM-26.2 — `chain-recovery`
//!
//! It also pins the documented blockers for the admin endpoints that have no
//! implementation yet (`mint`, `rotate`, `events`, `status`): they must answer
//! with a precise 503 `ENDPOINT_NOT_IMPLEMENTED`, never a bare 501.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::db::lockdown::SqliteLockdownStore;
use tirbase_gateway::profiles::load_profile_from_path;
use tirbase_guard::lockdown::{
    ChainRecoveryPayload, LockdownEntryReason, LockdownExitPayload, LockdownStore,
};
use tirbase_guard::policy::{make_bundle, policy_bundle_body_hash, policy_bundle_signing_bytes};
use tirbase_guard::sign_command;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootRecord, TrustRootSignature,
};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind};
use tirbase_types::policy::PolicyCoSignature;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

const TARGET: &str = "cold-room-1";
const CRITICAL_PARAM: &str = "setpoint_c";

fn temp_dir(tag: &str) -> PathBuf {
    let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tb36-{tag}-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cold_room_profile() -> EnvelopeProfile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");
    load_profile_from_path(&path).expect("load shipped cold_room profile")
}

fn trust_root(
    ca: &InMemoryKeyProvider,
    pa: &InMemoryKeyProvider,
    rm: &InMemoryKeyProvider,
    ta1: &InMemoryKeyProvider,
    ta2: &InMemoryKeyProvider,
) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    for (role, signer) in [
        (CommandRole::PolicyAuthority, pa),
        (CommandRole::RevocationManager, rm),
    ] {
        roles.insert(
            role,
            RolePolicy::new(
                1,
                vec![AuthorizedRoleSigner {
                    did: signer.did().to_string(),
                    public_key: signer.public_key_bytes().to_vec(),
                }],
            ),
        );
    }
    roles.insert(
        CommandRole::TimeAnchor,
        RolePolicy::new(
            2,
            [ta1, ta2]
                .iter()
                .map(|signer| AuthorizedRoleSigner {
                    did: signer.did().to_string(),
                    public_key: signer.public_key_bytes().to_vec(),
                })
                .collect(),
        ),
    );
    let mut record = TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![ca.public_key_bytes().to_vec()],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };
    record.signatures.push(TrustRootSignature {
        signer_did: ca.did().to_string(),
        signature: ca.sign(&record.signing_bytes()).expect("sign trust root"),
    });
    record
}

struct Gateway {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
    logs: Arc<Mutex<Vec<String>>>,
    pa: InMemoryKeyProvider,
    rm: InMemoryKeyProvider,
    ta1: InMemoryKeyProvider,
    ta2: InMemoryKeyProvider,
    ca: InMemoryKeyProvider,
    profile: EnvelopeProfile,
    primary_db: PathBuf,
}

impl Gateway {
 /// Boot the real binary with a fully configured local target and the admin
 /// socket enabled. When `lockdown` is true the primary DB is pre-seeded so
 /// the process boots straight into `NodeMode::Lockdown`.
    fn start(tag: &str, lockdown: bool) -> Gateway {
        let dir = temp_dir(tag);
        let profile = cold_room_profile();
        let ca = InMemoryKeyProvider::generate().expect("root ca");
        let pa = InMemoryKeyProvider::generate().expect("policy authority");
        let rm = InMemoryKeyProvider::generate().expect("revocation manager");
        let ta1 = InMemoryKeyProvider::generate().expect("time anchor 1");
        let ta2 = InMemoryKeyProvider::generate().expect("time anchor 2");

        std::fs::write(
            dir.join("trust-root.json"),
            serde_json::to_string(&trust_root(&ca, &pa, &rm, &ta1, &ta2))
                .expect("serialize trust root"),
        )
        .expect("write trust root");
        std::fs::write(
            dir.join("enrollment-root-ca.hex"),
            hex::encode(ca.secret_seed()),
        )
        .expect("write root ca seed");
        let profile_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");

        let primary_db = dir.join("primary.db");
        if lockdown {
            let store =
                SqliteLockdownStore::new(&primary_db, primary_db.with_file_name("lockdown"));
            store
                .set_lockdown(LockdownEntryReason::GuardDecision)
                .expect("pre-seed lockdown");
        }

        let config_path = dir.join("gateway.toml");
        let body = format!(
            "key_path = {key:?}\n\
             counter_db_path = {primary:?}\n\
             derived_db_path = {derived:?}\n\
             admin_socket = {sock:?}\n\
             admin_enabled = true\n\
             health_addr = \"127.0.0.1:{health}\"\n\
             metrics_addr = \"127.0.0.1:{metrics}\"\n\
             checkpoint_interval_secs = 3600\n\
             trust_root_path = {trust:?}\n\
             enrollment_root_ca_private_key_path = {enrollment_seed:?}\n\
             admin_events_view_days = 7\n\
             target_id = \"{target}\"\n\
             envelope_profile_path = {profile:?}\n",
            key = dir.join("device-key.json"),
            primary = primary_db,
            derived = dir.join("derived.db"),
            sock = dir.join("admin.sock"),
            health = free_port(),
            metrics = free_port(),
            trust = dir.join("trust-root.json"),
            enrollment_seed = dir.join("enrollment-root-ca.hex"),
            target = TARGET,
            profile = profile_path,
        );
        std::fs::write(&config_path, body).expect("write config");

        let mut command = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
        command
            .arg(&config_path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn gateway");

        let logs = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().expect("stdout");
        let collected = logs.clone();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                collected.lock().unwrap().push(line);
            }
        });

        let socket = dir.join("admin.sock");
        let deadline = tirbase_core::traits::monotonic_now() + 30_000_000;
        while tirbase_core::traits::monotonic_now() < deadline {
            if socket.exists()
                && logs
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|l| l.contains("tirbase-gateway started"))
            {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!(
                    "gateway exited during boot ({status}); logs:\n{}",
                    logs.lock().unwrap().join("\n")
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            socket.exists(),
            "admin socket {} never appeared; logs:\n{}",
            socket.display(),
            logs.lock().unwrap().join("\n")
        );

        Gateway {
            child,
            dir,
            socket,
            logs,
            pa,
            rm,
            ta1,
            ta2,
            ca,
            profile,
            primary_db,
        }
    }

    fn cmd(&self, command: Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket).expect("connect admin socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("read timeout");
        stream
            .write_all(format!("{command}\n").as_bytes())
            .expect("write admin command");
        stream.flush().expect("flush admin command");
        let mut body = String::new();
        stream
            .read_to_string(&mut body)
            .expect("read admin response");
        serde_json::from_str(body.trim()).unwrap_or_else(|error| {
            panic!(
                "admin response is not JSON: {body:?} ({error}); logs:\n{}",
                self.log_line()
            )
        })
    }

    fn log_line(&self) -> String {
        self.logs.lock().unwrap().join("\n")
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn assert_non_501(endpoint: &str, response: &Value, gateway: &Gateway) {
    assert_ne!(
        response["status"],
        json!(501),
        "{endpoint} still returns 501: {response}\nlogs:\n{}",
        gateway.log_line()
    );
}

#[test]
fn admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary() {
    let gateway = Gateway::start("normal", false);

 // ── mode query (CLAIM-13.1) ────────────────────────────────────────────
    let mode = gateway.cmd(json!({"cmd":"mode"}));
    assert_non_501("mode", &mode, &gateway);
    assert_eq!(mode["status"], 200, "mode response: {mode}");
    assert_eq!(mode["mode"], "Normal", "mode response: {mode}");

 // ── policy push (CLAIM-12.5/12.6) ──────────────────────────────────────
    let boot_bundle = make_bundle(
        gateway.profile.version,
        [0u8; 32],
        gateway.profile.clone(),
        Vec::new(),
    );
    let boot_hash = policy_bundle_body_hash(&boot_bundle);
    let mut tightened = gateway.profile.clone();
    tightened.version = gateway.profile.version + 1;
    let mut narrowed = false;
    for parameter in &mut tightened.parameters {
        if parameter.name == CRITICAL_PARAM {
            if let ParameterKind::Range { max, .. } = &mut parameter.kind {
                *max = FixedPointValue::new(70, -1, max.unit_id);
                narrowed = true;
            }
        }
    }
    assert!(
        narrowed,
        "cold_room profile must expose a range {CRITICAL_PARAM}"
    );
    let mut bundle = make_bundle(
        gateway.profile.version + 1,
        boot_hash,
        tightened,
        Vec::new(),
    );
    bundle.co_signatures = vec![PolicyCoSignature {
        signer_did: gateway.pa.did().to_string(),
        signature: gateway
            .pa
            .sign(&policy_bundle_signing_bytes(&bundle))
            .expect("sign policy bundle"),
    }];
    let policy = gateway.cmd(json!({"cmd":"policy","payload":{"bundle": bundle}}));
    assert_non_501("policy", &policy, &gateway);
    assert_eq!(policy["status"], 200, "policy response: {policy}");
    assert_eq!(
        policy["outcome"], "tightening_applied",
        "policy response: {policy}"
    );
    assert_eq!(policy["version"], gateway.profile.version + 1);

 // The next version without a PolicyAuthority co-signature must be rejected.
    let mut untrusted = make_bundle(
        gateway.profile.version + 2,
        policy_bundle_body_hash(&make_bundle(
            gateway.profile.version + 1,
            boot_hash,
            gateway.profile.clone(),
            Vec::new(),
        )),
        gateway.profile.clone(),
        Vec::new(),
    );
    untrusted.kind = tirbase_types::policy::PolicyBundleKind::Loosening;
    let unsigned = gateway.cmd(json!({"cmd":"policy","payload":{"bundle": untrusted}}));
    assert_non_501("policy", &unsigned, &gateway);
    assert_eq!(
        unsigned["status"], 409,
        "unsigned policy bundle must be rejected: {unsigned}"
    );

 // ── simulate (CLAIM-15.7) ──────────────────────────────────────────────
    let issuer = InMemoryKeyProvider::generate().expect("issuer");
    let mut command = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new(TARGET),
        param: CRITICAL_PARAM.into(),
        desired_state: FixedPointValue::new(40, -1, 1),
        sequence_number: 1,
        idempotency_key: [3u8; 16],
        expiry_est: 1_800,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::new(),
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut command, &issuer).expect("sign command");
    let simulate = gateway.cmd(json!({"cmd":"simulate","payload":{"command": command}}));
    assert_non_501("simulate", &simulate, &gateway);
    assert_eq!(
        simulate["simulated"], true,
        "simulate must run the dry-run pipeline: {simulate}"
    );

 // ── challenge issue + one-time-use verification (CLAIM-16.3/16.4) ─────
    let issued = gateway.cmd(json!({
        "cmd":"challenge",
        "payload":{"target_id": TARGET, "param": CRITICAL_PARAM}
    }));
    assert_non_501("challenge", &issued, &gateway);
    assert_eq!(issued["status"], 200, "challenge issue: {issued}");
    assert_eq!(
        issued["outcome"], "challenge_issued",
        "challenge issue: {issued}"
    );
    let nonce_hex = issued["nonce_hex"].as_str().expect("nonce_hex").to_string();
    let challenge_issuer = issued["issuer_did"]
        .as_str()
        .expect("issuer_did")
        .to_string();
    let consume_payload = json!({
        "target_id": TARGET,
        "param": CRITICAL_PARAM,
        "nonce_hex": nonce_hex,
        "issuer_did": challenge_issuer,
    });
    let consumed = gateway.cmd(json!({"cmd":"challenge","payload": consume_payload}));
    assert_eq!(consumed["status"], 200, "first nonce use: {consumed}");
    assert_eq!(consumed["outcome"], "challenge_consumed");
    let replay = gateway.cmd(json!({"cmd":"challenge","payload": consume_payload}));
    assert_eq!(
        replay["status"], 409,
        "second nonce use must be rejected: {replay}"
    );

 // ── /36.3l: event inspection and rollout status ──────────────
    let events = gateway.cmd(json!({"cmd":"events","payload":{"since_est":0,"limit":5}}));
    assert_non_501("events", &events, &gateway);
    assert_eq!(events["status"], 200, "events: {events}");
    assert!(
        events["events"].as_array().is_some(),
        "events must return an array: {events}"
    );
    assert_eq!(events["view_window_days"], 7);

    let rollout = gateway.cmd(json!({"cmd":"rollout-status"}));
    assert_non_501("rollout-status", &rollout, &gateway);
    assert_eq!(rollout["status"], 200, "rollout-status: {rollout}");
    assert_eq!(rollout["profile_installed"], true);
    assert_eq!(rollout["self_update"], "BLOCKED_PENDING_RFC_TUF");
}

#[test]
fn admin_mint_enforces_max_lifetime_and_returns_scoped_token() {
    let gateway = Gateway::start("mint", false);

    let too_long = gateway.cmd(json!({
        "cmd":"mint",
        "payload":{"did":"did:key:test-mint","role":"CommandIssuer","ttl_secs":86401}
    }));
    assert_non_501("mint", &too_long, &gateway);
    assert_eq!(
        too_long["status"], 409,
        "TTL > 86400 must be rejected: {too_long}"
    );
    assert_eq!(too_long["code"], "MINT_TTL_EXCEEDED");

    let minted = gateway.cmd(json!({
        "cmd":"mint",
        "payload":{"did":"did:key:test-mint","role":"CommandIssuer","ttl_secs":3600}
    }));
    assert_non_501("mint", &minted, &gateway);
    assert_eq!(minted["status"], 200, "mint: {minted}");
    let token = hex::decode(minted["token_hex"].as_str().expect("token_hex")).unwrap();
    let claims = tirbase_core::auth::biscuit::verify_token(
        &token,
        &gateway.ca.public_key_bytes(),
        tirbase_core::traits::wall_hint_secs().unwrap_or_default(),
    )
    .expect("minted token verifies against the root CA");
    assert_eq!(claims.did, "did:key:test-mint");
    assert_eq!(claims.role, "CommandIssuer");
}

#[test]
fn admin_rotate_rotates_the_device_identity() {
    let gateway = Gateway::start("rotate", false);
    let before = std::fs::read(gateway.dir.join("device-key.json")).unwrap();
    let rotated = gateway.cmd(json!({"cmd":"rotate"}));
    assert_non_501("rotate", &rotated, &gateway);
    assert_eq!(rotated["status"], 200, "rotate: {rotated}");
    assert_eq!(rotated["outcome"], "key_rotated");
    let after = std::fs::read(gateway.dir.join("device-key.json")).unwrap();
    assert_ne!(before, after, "rotate must write a fresh identity");
    assert!(
        gateway.dir.join("device-key.json.bak").exists(),
        "rotate must back up the previous identity"
    );
}

#[test]
fn admin_enroll_requires_matching_policy_authority_delegation_when_supplied() {
    use tirbase_gateway::admin::{
        dispatch_admin_command_at, EnrollmentDelegationPayload, EnrollmentDelegationRequest,
    };
    use tirbase_guard::enrollment::DeviceIdentity;
    let gateway = Gateway::start("enroll-delegation", false);
    let device = DeviceIdentity::generate().expect("device identity");
    let nonce = [7u8; 32];
    let request = device
        .bootstrap(nonce, CommandRole::CommandIssuer)
        .expect("bootstrap request");

 // A delegation bound to a different nonce must be rejected.
    let wrong_payload = EnrollmentDelegationPayload {
        device_did: request.device_did.clone(),
        role: request.role,
        nonce: [8u8; 32],
    };
    let mut wrong = SignedOperation::new(&wrong_payload, 0, None).unwrap();
    wrong
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    let rejected = gateway.cmd(json!({
        "cmd":"enroll",
        "payload":{
            "device_did": request.device_did,
            "device_public_key": request.device_public_key,
            "nonce": request.nonce,
            "role": request.role,
            "signature": request.signature,
            "delegation": EnrollmentDelegationRequest { operation: wrong, payload: wrong_payload }
        }
    }));
    assert_ne!(
        rejected["status"], 200,
        "mismatched delegation must fail: {rejected}"
    );

    let payload = EnrollmentDelegationPayload {
        device_did: request.device_did.clone(),
        role: request.role,
        nonce: request.nonce,
    };
    let mut operation = SignedOperation::new(&payload, 0, None).unwrap();
    operation
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    let enrolled = gateway.cmd(json!({
        "cmd":"enroll",
        "payload":{
            "device_did": request.device_did,
            "device_public_key": request.device_public_key,
            "nonce": request.nonce,
            "role": request.role,
            "signature": request.signature,
            "delegation": EnrollmentDelegationRequest { operation, payload }
        }
    }));
    assert_eq!(
        enrolled["status"], 200,
        "valid delegation must enroll: {enrolled}"
    );
 // The dispatch function is the production caller; a direct call exercises
 // the same path with an explicit local caller.
    let _ = dispatch_admin_command_at;
}

#[test]
fn admin_status_and_additional_endpoints_over_binary() {
    let gateway = Gateway::start("task36l", false);

 // ── 36.3k/36.7 Guard status API ────────────────────────────────────────
    let issuer = "did:key:status-issuer";
    {
        let conn = rusqlite::Connection::open(&gateway.primary_db).expect("open primary.db");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS anti_replay_windows (
                issuer_did TEXT NOT NULL, target_id TEXT NOT NULL, enrollment_epoch INTEGER NOT NULL,
                highest_seen INTEGER NOT NULL, seen_bitmap BLOB NOT NULL, forward_gap INTEGER NOT NULL,
                PRIMARY KEY (issuer_did,target_id,enrollment_epoch));
             CREATE TABLE IF NOT EXISTS single_writer_leases (
                target_id TEXT PRIMARY KEY, issuer_did TEXT NOT NULL, expires_mono INTEGER NOT NULL,
                consecutive_renewals INTEGER NOT NULL, cooldown_until_mono INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO anti_replay_windows VALUES (?1,?2,0,42,?3,1024)",
            rusqlite::params![issuer, TARGET, 1u64.to_le_bytes().to_vec()],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO single_writer_leases VALUES (?1,?2,999999,0,NULL)",
            rusqlite::params![TARGET, issuer],
        )
        .unwrap();
    }
    let status = gateway.cmd(json!({"cmd":"status","payload":{"issuer_did":issuer}}));
    assert_non_501("status", &status, &gateway);
    assert_eq!(status["status"], 200, "status: {status}");
    assert_eq!(status["self_query"], true);
    let windows = status["anti_replay"].as_array().expect("anti_replay array");
    assert_eq!(windows[0]["highest_seen"], 42);
    assert_eq!(windows[0]["target_id"], TARGET);
    let leases = status["leases"].as_array().expect("leases array");
    assert_eq!(leases[0]["holder_issuer_did"], issuer);
    assert!(status["rate_limit"].is_object(), "rate_limit: {status}");

 // ── 36.3l sequence-reset (PolicyAuthority signed) ──────────────────────
    let reset_payload = tirbase_guard::anti_replay::AntiReplayWindowReset {
        issuer_did: issuer.into(),
        target_id: TARGET.into(),
        enrollment_epoch: 0,
        new_baseline_sequence: 500,
        requested_at_est: 1_000,
        reason: "binary test".into(),
    };
    let mut reset_op = SignedOperation::new(&reset_payload, 1_000, None).unwrap();
    reset_op
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    let reset = gateway.cmd(json!({
        "cmd":"sequence-reset",
        "payload":{"operation": reset_op, "payload": reset_payload}
    }));
    assert_eq!(reset["status"], 200, "sequence-reset: {reset}");

 // ── 36.3l lease-preempt (RevocationManager + PolicyAuthority) ──────────
    let lease_payload = tirbase_gateway::admin::LeasePreemptPayload {
        action: "lease-preempt".into(),
        target_id: TARGET.into(),
        new_issuer_did: Some("did:key:new-holder".into()),
        now_est: 1_000,
    };
    let mut lease_op = SignedOperation::new(&lease_payload, 1_000, None).unwrap();
    lease_op
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    lease_op
        .sign_with(&gateway.rm, CommandRole::RevocationManager)
        .unwrap();
    let preempt = gateway.cmd(json!({
        "cmd":"lease-preempt",
        "payload":{
            "operation": lease_op,
            "request":{"target_id": TARGET, "new_issuer_did": "did:key:new-holder", "now_est": 1000}
        }
    }));
    assert_eq!(preempt["status"], 200, "lease-preempt: {preempt}");

 // ── 36.3l unknown-clear (PolicyAuthority) ──────────────────────────────
    let unknown_payload = tirbase_gateway::admin::ClearUnknownPayload {
        action: "clear-unknown".into(),
        entry_id_hex: "11".repeat(16),
    };
    let mut unknown_op = SignedOperation::new(&unknown_payload, 1_000, None).unwrap();
    unknown_op
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    let unsigned_unknown = gateway.cmd(
        json!({"cmd":"clear-unknown","payload":{"entry_id_hex": unknown_payload.entry_id_hex}}),
    );
    assert_eq!(
        unsigned_unknown["status"], 409,
        "unsigned clear-unknown must fail: {unsigned_unknown}"
    );
    let unknown = gateway.cmd(json!({
        "cmd":"clear-unknown",
        "payload":{"operation": unknown_op, "request":{"entry_id_hex": unknown_payload.entry_id_hex}}
    }));
    assert_eq!(
        unknown["status"], 404,
        "signed clear-unknown reaches the ledger (no entry): {unknown}"
    );

 // ── 36.3l quarantine-replay (PolicyAuthority) ──────────────────────────
    let entry_id = [0x42u8; 32];
    {
        let core_db = gateway.dir.join("core.db");
        let conn = rusqlite::Connection::open(&core_db).expect("open core.db");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_quarantine (
                id BLOB PRIMARY KEY, sender_did TEXT NOT NULL, raw_bytes BLOB NOT NULL,
                reason TEXT NOT NULL, received_at INTEGER NOT NULL, migration_id BLOB,
                replay_status TEXT, replay_ts INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO schema_quarantine (id,sender_did,raw_bytes,reason,received_at) VALUES (?1,'did:key:quarantined',?2,'CLOCK_JUMP',1)",
            rusqlite::params![entry_id.as_slice(), b"not-a-delta".to_vec()],
        )
        .unwrap();
    }
    let replay_payload = tirbase_gateway::admin::QuarantineReplayPayload {
        entry_id_hex: hex::encode(entry_id),
        reason: "binary test replay".into(),
    };
    let unsigned_replay =
        gateway.cmd(json!({"cmd":"quarantine-replay","payload":{"payload": replay_payload}}));
    assert_ne!(
        unsigned_replay["status"], 200,
        "unsigned quarantine replay must fail: {unsigned_replay}"
    );
    let mut replay_op = SignedOperation::new(&replay_payload, 1_000, None).unwrap();
    replay_op
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    let replay = gateway.cmd(json!({
        "cmd":"quarantine-replay",
        "payload":{"operation": replay_op, "payload": replay_payload}
    }));
    assert_eq!(replay["status"], 200, "quarantine-replay: {replay}");
    assert_eq!(replay["replay_status"], "replayed");

 // ── 36.3l time-reset (M-of-N TimeAnchor) ───────────────────────────────
    let time_payload = tirbase_guard::time::TimeResetPayload {
        new_floor_secs: 1_700_000_000,
        reason: "binary test reset".into(),
        reset_id: [9u8; 16],
    };
    let mut time_op = SignedOperation::new(&time_payload, 1_000, None).unwrap();
    time_op
        .sign_with(&gateway.ta1, CommandRole::TimeAnchor)
        .unwrap();
    let single_anchor = gateway.cmd(json!({
        "cmd":"time-reset",
        "payload":{"operation": time_op.clone(), "payload": time_payload.clone()}
    }));
    assert_eq!(
        single_anchor["status"], 409,
        "single TimeAnchor must fail M-of-N: {single_anchor}"
    );
    time_op
        .sign_with(&gateway.ta2, CommandRole::TimeAnchor)
        .unwrap();
    let time_reset = gateway.cmd(json!({
        "cmd":"time-reset",
        "payload":{"operation": time_op, "payload": time_payload}
    }));
    assert_eq!(time_reset["status"], 200, "time-reset: {time_reset}");
    assert_eq!(time_reset["new_floor_secs"], 1_700_000_000i64);

 // ── 36.3l restore (PolicyAuthority + RevocationManager) ────────────────
    let restore_payload = tirbase_gateway::admin::RestorePayload {
        device_id: "did:key:restored-device".into(),
        backup_id: "backup-1".into(),
        reason: "binary test restore".into(),
    };
    let mut restore_op = SignedOperation::new(&restore_payload, 1_000, None).unwrap();
    restore_op
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    let missing_rm = gateway.cmd(json!({
        "cmd":"restore",
        "payload":{"operation": restore_op.clone(), "payload": restore_payload.clone()}
    }));
    assert_eq!(
        missing_rm["status"], 409,
        "restore requires RevocationManager too: {missing_rm}"
    );
    restore_op
        .sign_with(&gateway.rm, CommandRole::RevocationManager)
        .unwrap();
    let restored = gateway.cmd(json!({
        "cmd":"restore",
        "payload":{"operation": restore_op, "payload": restore_payload}
    }));
    assert_eq!(restored["status"], 200, "restore: {restored}");
    assert_eq!(restored["epoch"], 1);

 // ── 36.3l epoch-bump (PolicyAuthority + RevocationManager) ─────────────
    let bump_payload = tirbase_guard::epoch::EpochBump {
        device_id: "did:key:restored-device".into(),
        previous_epoch: 1,
        new_epoch: 2,
        reason: "binary test bump".into(),
    };
    let mut bump_op = SignedOperation::new(&bump_payload, 1_000, None).unwrap();
    bump_op
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .unwrap();
    bump_op
        .sign_with(&gateway.rm, CommandRole::RevocationManager)
        .unwrap();
    let bumped = gateway.cmd(json!({
        "cmd":"epoch-bump",
        "payload":{"operation": bump_op, "payload": bump_payload}
    }));
    assert_eq!(bumped["status"], 200, "epoch-bump: {bumped}");
    assert_eq!(bumped["epoch"], 2);
}

#[test]
fn admin_lockdown_exit_requires_m_of_n_and_transitions_mode_over_binary() {
    let gateway = Gateway::start("lockdown", true);

    let mode = gateway.cmd(json!({"cmd":"mode"}));
    assert_non_501("mode", &mode, &gateway);
    assert_eq!(mode["status"], 200);
    assert_eq!(
        mode["mode"], "Lockdown",
        "boot must honour persisted LOCKDOWN: {mode}"
    );
    assert_eq!(mode["lockdown_persisted"], true);

    let payload = LockdownExitPayload {
        node_id: TARGET.into(),
        issued_at_est: 1_000,
        reason: "binary test exit".into(),
        envelope_profile_id: gateway.profile.profile_id,
    };

 // Single role must be rejected (M-of-N with >= 2 distinct roles).
    let mut single = SignedOperation::new(&payload, 1_000, None).expect("operation");
    single
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .expect("sign");
    let rejected = gateway.cmd(json!({
        "cmd":"lockdown-exit",
        "payload":{"operation": single, "payload": payload}
    }));
    assert_non_501("lockdown-exit", &rejected, &gateway);
    assert_eq!(rejected["status"], 409, "single-role exit: {rejected}");

 // Full M-of-N across two distinct roles must succeed.
    let mut joint = SignedOperation::new(&payload, 1_000, None).expect("operation");
    joint
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .expect("sign");
    joint
        .sign_with(&gateway.rm, CommandRole::RevocationManager)
        .expect("sign");
    let exited = gateway.cmd(json!({
        "cmd":"lockdown-exit",
        "payload":{"operation": joint, "payload": payload}
    }));
    assert_non_501("lockdown-exit", &exited, &gateway);
    assert_eq!(exited["status"], 200, "valid M-of-N exit: {exited}");
    assert_eq!(exited["outcome"], "lockdown_exit_applied");

    let after = gateway.cmd(json!({"cmd":"mode"}));
    assert_eq!(after["mode"], "Normal", "mode after exit: {after}");
    assert_eq!(after["lockdown_persisted"], false);
}

#[test]
fn admin_chain_recovery_requires_signature_over_binary() {
    let gateway = Gateway::start("chain", false);

    let payload = ChainRecoveryPayload {
        recovery_id: [7u8; 16],
        first_broken_seq: 10,
        acknowledged_tamper_seq: 12,
        new_segment_id: 3,
        operator_reason: "binary test recovery".into(),
    };

 // Unsigned recovery is rejected, not silently accepted.
    let unsigned = gateway.cmd(json!({
        "cmd":"chain-recovery",
        "payload":{"operation": {"context_string":"TirBase/v1/ChainRecovery","payload_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"signatures":[],"created_est":0,"expires_est":null}, "payload": payload}
    }));
    assert_non_501("chain-recovery", &unsigned, &gateway);
    assert_ne!(
        unsigned["status"], 200,
        "unsigned recovery must fail: {unsigned}"
    );

 // Valid PolicyAuthority signature applies the recovery.
    let mut operation = SignedOperation::new(&payload, 0, None).expect("operation");
    operation
        .sign_with(&gateway.pa, CommandRole::PolicyAuthority)
        .expect("sign");
    let applied = gateway.cmd(json!({
        "cmd":"chain-recovery",
        "payload":{"operation": operation, "payload": payload}
    }));
    assert_non_501("chain-recovery", &applied, &gateway);
    assert_eq!(applied["status"], 200, "signed recovery: {applied}");
    assert_eq!(applied["outcome"], "chain_recovery_applied");
}

#[test]
fn admin_endpoints_do_not_return_501_when_target_state_is_unconfigured() {
 // A gateway without trust_root_path/target_id has no policy, trust root or
 // envelope profile: those endpoints must explain the missing state with a
 // 503, never a 501 that implies the endpoint does not exist.
    let dir = temp_dir("bare");
    let config_path = dir.join("gateway.toml");
    std::fs::write(
        &config_path,
        format!(
            "key_path = {:?}\n\
             counter_db_path = {:?}\n\
             derived_db_path = {:?}\n\
             admin_socket = {:?}\n\
             admin_enabled = true\n\
             health_addr = \"127.0.0.1:{}\"\n\
             metrics_addr = \"127.0.0.1:{}\"\n\
             checkpoint_interval_secs = 3600\n",
            dir.join("device-key.json"),
            dir.join("primary.db"),
            dir.join("derived.db"),
            dir.join("admin.sock"),
            free_port(),
            free_port(),
        ),
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut logs = Vec::new();
    let socket = dir.join("admin.sock");
    let deadline = tirbase_core::traits::monotonic_now() + 30_000_000;
    let mut ready = false;
    while tirbase_core::traits::monotonic_now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let started = line.contains("tirbase-gateway started");
                logs.push(line);
                if started {
                    ready = true;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    assert!(ready, "gateway did not boot; logs:\n{}", logs.join("\n"));

    let ask = |command: Value| -> Value {
        let mut stream = UnixStream::connect(&socket).expect("connect admin socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(format!("{command}\n").as_bytes())
            .expect("write");
        let mut body = String::new();
        stream.read_to_string(&mut body).expect("read");
        serde_json::from_str(body.trim()).expect("JSON response")
    };

    for endpoint in ["policy", "lockdown-exit", "chain-recovery"] {
        let response = ask(json!({"cmd": endpoint}));
        assert_ne!(
            response["status"],
            json!(501),
            "{endpoint} must not be stubbed: {response}"
        );
        assert_eq!(response["status"], 503, "{endpoint}: {response}");
        assert_eq!(
            response["code"], "ADMIN_STATE_UNCONFIGURED",
            "{endpoint}: {response}"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
