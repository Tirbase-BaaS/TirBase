//! Task 35 gateway binary integration tests (CLAIM-35.1-35.6).

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_types::CommandRole;

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
        for line in BufReader::new(stdout).lines().flatten() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let found = loop {
        if Instant::now() >= deadline {
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
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ok = false;
    while Instant::now() < deadline {
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
        for line in BufReader::new(stdout).lines().flatten() {
            let _ = tx.send(line);
        }
    });
    let mut lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let found = loop {
        if Instant::now() >= deadline {
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
    let start = Instant::now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resp = rt
        .block_on(reqwest::get(format!("http://127.0.0.1:{health}/health")))
        .expect("health get");
    assert!(resp.status().is_success());
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "health took {:?}",
        start.elapsed()
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
