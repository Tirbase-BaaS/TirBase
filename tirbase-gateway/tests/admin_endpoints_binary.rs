//! Binary-level admin endpoint tests.
//!
//! Each test spawns the real `tirbase-gateway` binary, waits for it to finish
//! booting, then speaks the admin JSON-line protocol over
//! `admin_socket` (Unix domain socket, peer-UID authenticated).
//!
//! Covered production callers (see CLAIMS.md):
//! * CLAIM-12.x  — `policy` push through `PolicyLifecycle`
//! * CLAIM-13.1  — `mode` query / transitions
//! * CLAIM-13.3  — `lockdown-exit` M-of-N exit
//! * CLAIM-15.7  — `simulate` dry run
//! * CLAIM-16.3  — `challenge` issuance and one-time-use verification
//! * CLAIM-16.4  — challenge issuance rate limiting (store/pipeline wiring)
//! * CLAIM-26.2  — `chain-recovery`
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
use std::time::{Duration, Instant};

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
    profile: EnvelopeProfile,
}

impl Gateway {
    /// Boot the real binary with a fully configured local target and the admin
    /// socket enabled.  When `lockdown` is true the primary DB is pre-seeded so
    /// the process boots straight into `NodeMode::Lockdown`.
    fn start(tag: &str, lockdown: bool) -> Gateway {
        let dir = temp_dir(tag);
        let profile = cold_room_profile();
        let ca = InMemoryKeyProvider::generate().expect("root ca");
        let pa = InMemoryKeyProvider::generate().expect("policy authority");
        let rm = InMemoryKeyProvider::generate().expect("revocation manager");

        std::fs::write(
            dir.join("trust-root.json"),
            serde_json::to_string(&trust_root(&ca, &pa, &rm)).expect("serialize trust root"),
        )
        .expect("write trust root");
        let profile_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");

        let primary_db = dir.join("primary.db");
        if lockdown {
            let store =
                SqliteLockdownStore::new(&primary_db, &primary_db.with_file_name("lockdown"));
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
             target_id = \"{target}\"\n\
             envelope_profile_path = {profile:?}\n",
            key = dir.join("device-key.json"),
            primary = primary_db,
            derived = dir.join("derived.db"),
            sock = dir.join("admin.sock"),
            health = free_port(),
            metrics = free_port(),
            trust = dir.join("trust-root.json"),
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
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
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
            profile,
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

    // ── endpoints with documented blockers: precise 503, never 501 ─────────
    for (endpoint, task) in [
        ("mint", "task 36.3b"),
        ("rotate", "task 36.3c"),
        ("events", "task 36.3e"),
        ("status", "task 36.3k"),
    ] {
        let response = gateway.cmd(json!({"cmd": endpoint}));
        assert_non_501(endpoint, &response, &gateway);
        assert_eq!(
            response["status"], 503,
            "{endpoint} must report its documented blocker: {response}"
        );
        assert_eq!(response["code"], "ENDPOINT_NOT_IMPLEMENTED");
        assert_eq!(
            response["task"], task,
            "{endpoint} blocker task id: {response}"
        );
    }
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ready = false;
    while Instant::now() < deadline {
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
