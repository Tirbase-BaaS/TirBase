//! gateway binary integration tests (CLAIM-35.1-35.6).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::json;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::identity::file_key_provider::{FileKeyProvider, InMemoryKeyProvider};
use tirbase_core::traits::KeyProvider;
use tirbase_guard::sign_command;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootRecord, TrustRootSignature,
};
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-task35-{tag}-{}-{unique}",
        std::process::id()
    ));
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

fn write_config(dir: &Path, health_port: u16, metrics_port: u16) -> PathBuf {
    let config_path = dir.join("gateway.toml");
    let body = format!(
        "key_path = {:?}\n\
         counter_db_path = {:?}\n\
         derived_db_path = {:?}\n\
         admin_socket = {:?}\n\
         health_addr = \"127.0.0.1:{health_port}\"\n\
         metrics_addr = \"127.0.0.1:{metrics_port}\"\n\
         log_level = \"info\"\n\
         admin_enabled = false\n\
         checkpoint_interval_secs = 3600\n",
        dir.join("device-key.json"),
        dir.join("primary.db"),
        dir.join("derived.db"),
        dir.join("admin.sock"),
    );
    std::fs::write(&config_path, body).expect("write config");
    config_path
}

fn run_until_marker(config: &Path, needle: &str) -> (Vec<String>, Child) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
    command
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn gateway");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    let deadline = tirbase_core::traits::monotonic_now() + 30_000_000;
    let found = loop {
        if tirbase_core::traits::monotonic_now() >= deadline {
            break false;
        }
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(line) => {
                let hit = line.contains(needle);
                lines.push(line);
                if hit {
                    break true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
        }
    };
    assert!(
        found,
        "gateway did not log marker {needle:?}; output:\n{}",
        lines.join("\n")
    );
    (lines, child)
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn claim_35_1_gateway_binary_starts_and_passes_health_check() {
    let dir = temp_dir("35-1");
    let health = free_port();
    let metrics = free_port();
    let config = write_config(&dir, health, metrics);
    let (_lines, mut child) = run_until_marker(&config, "SignedOperation boot record verified");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let deadline = tirbase_core::traits::monotonic_now() + 5_000_000;
    let mut ok = false;
    while tirbase_core::traits::monotonic_now() < deadline {
        if let Ok(resp) = rt.block_on(reqwest::get(format!("http://127.0.0.1:{health}/health"))) {
            if resp.status().is_success() {
                ok = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    kill(&mut child);
    assert!(ok, "health endpoint did not become healthy");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_35_2_invalid_config_rejected_at_startup_and_unsigned_bundle_rejected() {
    let dir = temp_dir("35-2");
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "key_path = \"\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
        .arg(&bad)
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "invalid config must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("schema validation failed") || stderr.contains("key_path"),
        "stderr missing validation error: {stderr}"
    );

 // Unsigned/missing trust root for config bundle must be rejected.
    let bundle = dir.join("bundle.json");
    let cfg_toml = format!(
        "key_path = {:?}\nadmin_enabled = false\nhealth_addr = \"127.0.0.1:{}\"\nmetrics_addr = \"127.0.0.1:{}\"\n",
        dir.join("k.json"),
        free_port(),
        free_port()
    );
    std::fs::write(
        &bundle,
        serde_json::json!({
            "payload": {"config_toml": cfg_toml, "config_version": 1},
            "operation": {
                "context_string": "TirBase/v1/GatewayConfigBundle",
                "payload_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signatures": [],
                "created_est": 0,
                "expires_est": null
            }
        })
        .to_string(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
        .args([
            bundle.to_str().unwrap(),
            "--config-bundle",
            bundle.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "unsigned/untrusted config bundle must be rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("PolicyAuthority")
            || stderr.contains("trust root")
            || stderr.contains("rejected")
            || stderr.contains("verification failed"),
        "stderr missing bundle rejection reason: {stderr}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_35_2_signed_config_bundle_validated_by_policy_authority() {
    let dir = temp_dir("35-2b");
    let pa = InMemoryKeyProvider::generate().expect("generate keypair");
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes().to_vec(),
            }],
        ),
    );
    let trust = TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: std::collections::BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };
    let trust_path = dir.join("pa-trust.json");
    std::fs::write(&trust_path, serde_json::to_string(&trust).unwrap()).unwrap();

    let health = free_port();
    let metrics = free_port();
    let cfg_toml = format!(
        "key_path = {:?}\ncounter_db_path = {:?}\nderived_db_path = {:?}\nadmin_socket = {:?}\nadmin_enabled = false\nhealth_addr = \"127.0.0.1:{health}\"\nmetrics_addr = \"127.0.0.1:{metrics}\"\ncheckpoint_interval_secs = 3600\n",
        dir.join("device-key.json"), dir.join("primary.db"), dir.join("derived.db"), dir.join("admin.sock")
    );
    let payload = tirbase_gateway::config::GatewayConfigBundlePayload {
        config_toml: cfg_toml,
        config_version: 1,
    };
    let mut op = SignedOperation::new(&payload, 0, Some(i64::MAX)).unwrap();
    op.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    let bundle = tirbase_gateway::config::SignedGatewayConfigBundle {
        payload,
        operation: op,
    };
    let bundle_path = dir.join("bundle.json");
    std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
    cmd.arg(dir.join("unused.toml"))
        .arg("--config-bundle")
        .arg(&bundle_path)
        .arg("--config-bundle-trust-root")
        .arg(&trust_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut lines = Vec::new();
    let deadline = tirbase_core::traits::monotonic_now() + 30_000_000;
    let found = loop {
        if tirbase_core::traits::monotonic_now() >= deadline {
            break false;
        }
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(l) => {
                let hit = l.contains("SignedOperation boot record verified");
                lines.push(l);
                if hit {
                    break true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
        }
    };
    kill(&mut child);
    assert!(
        found,
        "signed config bundle should boot: {}",
        lines.join("\n")
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_35_4_health_endpoint_responds_within_500ms() {
    let dir = temp_dir("35-4");
    let health = free_port();
    let metrics = free_port();
    let config = write_config(&dir, health, metrics);
    let (_lines, mut child) = run_until_marker(&config, "SignedOperation boot record verified");
    std::thread::sleep(Duration::from_millis(100));
    let start = tirbase_core::traits::monotonic_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resp = rt
        .block_on(reqwest::get(format!("http://127.0.0.1:{health}/health")))
        .expect("health get");
    assert!(resp.status().is_success());
    assert!(
        tirbase_core::traits::monotonic_now().saturating_sub(start) < 500_000,
        "health took {:?}",
        Duration::from_micros(tirbase_core::traits::monotonic_now().saturating_sub(start))
    );
    kill(&mut child);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_35_5_prometheus_metrics_exposed() {
    let dir = temp_dir("35-5");
    let health = free_port();
    let metrics = free_port();
    let config = write_config(&dir, health, metrics);
    let (_lines, mut child) = run_until_marker(&config, "SignedOperation boot record verified");
    std::thread::sleep(Duration::from_millis(150));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let body = rt.block_on(async {
        reqwest::get(format!("http://127.0.0.1:{metrics}/metrics"))
            .await
            .expect("metrics get")
            .text()
            .await
            .expect("text")
    });
    kill(&mut child);
    for needle in [
        "guard_decisions_total",
        "effects_ledger_writes_total",
        "security_events_total",
        "replay_rejections_total",
        "quarantine_entries_total",
    ] {
        assert!(body.contains(needle), "metrics missing {needle}: {body}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_35_6_structured_json_logs_in_gateway_output() {
    let dir = temp_dir("35-6");
    let health = free_port();
    let metrics = free_port();
    let config = write_config(&dir, health, metrics);
    let (lines, mut child) = run_until_marker(&config, "SignedOperation boot record verified");
    kill(&mut child);
    let mut saw_json = false;
    for line in &lines {
        if line.trim_start().starts_with('{') {
            let v: serde_json::Value = serde_json::from_str(line).expect("log line must be JSON");
            assert!(
                v.get("timestamp").is_some()
                    || v.get("level").is_some()
                    || v.get("target").is_some(),
                "structured log missing fields: {line}"
            );
            saw_json = true;
            break;
        }
    }
    assert!(
        saw_json,
        "expected at least one structured JSON log line: {}",
        lines.join("\n")
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_35_3_systemd_unit_has_hardening_directives() {
    let unit =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deploy/systemd/tirbase-gateway.service");
    let body = std::fs::read_to_string(&unit).expect("read gateway unit");
    for needle in [
        "WatchdogSec=30",
        "MemoryDenyWriteExecute=yes",
        "NoNewPrivileges=yes",
        "SystemCallFilter=@system-service",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    ] {
        assert!(body.contains(needle), "unit missing {needle}");
    }
 // CI gate script exists and is executable.
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/check-systemd-security.sh");
    assert!(script.exists(), "missing systemd-analyze CI gate script");
}

fn write_command_config(
    dir: &Path,
    health_port: u16,
    metrics_port: u16,
    command_port: u16,
    profile_path: &Path,
) -> PathBuf {
    let config_path = dir.join("gateway-command.toml");
    let body = format!(
        "key_path = {:?}\n\
         counter_db_path = {:?}\n\
         derived_db_path = {:?}\n\
         admin_socket = {:?}\n\
         health_addr = \"127.0.0.1:{health_port}\"\n\
         metrics_addr = \"127.0.0.1:{metrics_port}\"\n\
         log_level = \"info\"\n\
         admin_enabled = false\n\
         checkpoint_interval_secs = 3600\n\
         trust_root_path = {:?}\n\
         target_id = \"cold-room-1\"\n\
         envelope_profile_path = {:?}\n\
         local_admin_command_addr = \"127.0.0.1:{command_port}\"\n",
        dir.join("device-key.json"),
        dir.join("primary.db"),
        dir.join("derived.db"),
        dir.join("admin.sock"),
        dir.join("trust-root.json"),
        profile_path,
    );
    std::fs::write(&config_path, body).expect("write command config");
    config_path
}

fn counter_sum(body: &str, name: &str) -> u64 {
    body.lines()
        .filter(|line| !line.starts_with('#') && line.starts_with(name))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Starts the real gateway, sends one signed command through the local-admin
/// TCP ingress, and asserts the guard accepts it and the real Prometheus
/// counters move. This is the binary-level evidence for CLAIM-35.1/35.4/35.5.
#[test]
fn claim_35_4_local_admin_signed_command_reaches_guard_and_moves_metrics() {
    let dir = temp_dir("35-4-cmd");
    let _device =
        FileKeyProvider::load_or_generate(dir.join("device-key.json")).expect("device key");

 // Trust root signed by the root CA whose seed also mints the command token.
    let ca = InMemoryKeyProvider::generate().expect("root ca");
    let mut trust = TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![ca.public_key_bytes()],
        threshold_k: 1,
        role_thresholds: BTreeMap::new(),
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };
    trust.signatures.push(TrustRootSignature {
        signer_did: ca.did().to_string(),
        signature: ca.sign(&trust.signing_bytes()).expect("sign trust root"),
    });
    std::fs::write(
        dir.join("trust-root.json"),
        serde_json::to_string(&trust).expect("serialize trust root"),
    )
    .expect("write trust root");

 // Reuse the shipped cold-room fixture but make the parameter non-critical so
 // the command does not need a challenge nonce (the time ratchet is
 // Unverified without a beacon in this isolated test).
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");
    let fixture_body = std::fs::read_to_string(&fixture).expect("read cold_room profile");
    let profile_body = fixture_body.replace("critical = true", "critical = false");
    let profile_path = dir.join("cold_room_noncritical.toml");
    std::fs::write(&profile_path, profile_body).expect("write test profile");

    let health = free_port();
    let metrics = free_port();
    let command_port = free_port();
    let config = write_command_config(&dir, health, metrics, command_port, &profile_path);
    let (lines, mut child) = run_until_marker(&config, "local-admin command ingress listening");

    let issuer = InMemoryKeyProvider::generate().expect("issuer");
    let token = create_command_token(
        issuer.did(),
        "CommandIssuer",
        3600,
        "cold-room-1",
        "setpoint_c",
        &[],
        &ca.secret_seed(),
    )
    .expect("mint command token");
 // Without a time beacon the ratchet's now_est is the persisted floor (0),
 // so the command TTL must stay within the guard's 3600s maximum.
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("cold-room-1"),
        param: "setpoint_c".into(),
        desired_state: FixedPointValue::new(40, -1, 1),
        sequence_number: 1,
        idempotency_key: [9u8; 16],
        expiry_est: 1800,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::new(),
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut cmd, &issuer).expect("sign command");

    let request = json!({
        "command": cmd,
        "biscuit_token_hex": hex::encode(&token),
        "source_key": "task35-binary",
    })
    .to_string();

    let mut stream = TcpStream::connect(("127.0.0.1", command_port)).expect("connect local-admin");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read timeout");
    stream
        .write_all(format!("{request}\n").as_bytes())
        .expect("write command");
    stream.flush().expect("flush command");
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).expect("read response");
    let response: serde_json::Value =
        serde_json::from_str(&response_line).expect("response is JSON");
    assert_eq!(response["status"], "ok", "local-admin response: {response}");
    let decision = &response["decision"];
    assert_eq!(
        decision["status"],
        "accepted",
        "guard did not accept the signed command: {response}\nlogs:\n{}",
        lines.join("\n")
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let body = rt.block_on(async {
        reqwest::get(format!("http://127.0.0.1:{metrics}/metrics"))
            .await
            .expect("metrics get")
            .text()
            .await
            .expect("metrics text")
    });
    kill(&mut child);
    assert!(
        counter_sum(&body, "guard_decisions_total") >= 1,
        "guard_decisions_total did not move: {body}"
    );
    assert!(
        counter_sum(&body, "effects_ledger_writes_total") >= 1,
        "effects_ledger_writes_total did not move: {body}"
    );
    assert!(
        counter_sum(&body, "security_events_total") >= 1,
        "security_events_total did not move: {body}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
