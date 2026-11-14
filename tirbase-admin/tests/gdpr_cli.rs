// SPDX-License-Identifier: AGPL-3.0-only

//! CLI integration tests (CLAIM-27.2, 27.3, 27.4).

use std::path::{Path, PathBuf};
use std::process::Command;

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = tirbase_core::traits::monotonic_now();
    let dir = std::env::temp_dir().join(format!(
        "tirbase_admin27_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn admin_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tirbase-admin"))
}
fn verify_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tirbase-verify-log"))
}

fn make_key(dir: &Path) -> PathBuf {
    let path = dir.join("device.key.json");
    tirbase_core::identity::file_key_provider::FileKeyProvider::generate(&path).unwrap();
    path
}
fn make_db(dir: &Path) -> PathBuf {
    let db = dir.join("primary.db");
    let log =
        tirbase_gateway::security_log::SecurityEventLog::new_persistent(db.clone(), None, false);
    for _ in 0..3 {
        log.append_payload(tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::CommandDecision,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        ));
    }
    db
}

#[test]
fn verify_log_cli_exit_zero_intact_nonzero_broken() {
    let dir = unique_temp_dir("verifycli");
    let db = make_db(&dir);
    let ok = Command::new(verify_bin())
        .arg("--db-path")
        .arg(&db)
        .status()
        .expect("run");
    assert!(ok.success(), "intact chain must exit 0");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("UPDATE security_events SET prev_hash=X'01' WHERE seq=2", [])
        .unwrap();
    drop(conn);
    let bad = Command::new(verify_bin())
        .arg("--db-path")
        .arg(&db)
        .output()
        .expect("run");
    assert!(!bad.status.success(), "broken chain must exit non-zero");
    let out =
        String::from_utf8_lossy(&bad.stdout).to_string() + &String::from_utf8_lossy(&bad.stderr);
    assert!(
        out.contains("broken range")
            || out.contains("FAILED")
            || out.contains("mismatch")
            || out.contains("gap"),
        "must report broken range/mismatch: {out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_log_cli_json_cbor_signed_pseudonymized_disclaimer() {
    let dir = unique_temp_dir("exportcli");
    let db = make_db(&dir);
    let key = make_key(&dir);
    let out = dir.join("log.json");
    let st = Command::new(admin_bin())
        .args(["export-log", "--db-path"])
        .arg(&db)
        .args(["--key-path"])
        .arg(&key)
        .args(["--output"])
        .arg(&out)
        .args(["--format", "json"])
        .status()
        .expect("run");
    assert!(st.success());
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert!(
        !v["signature_hex"].as_str().unwrap_or("").is_empty(),
        "signed export"
    );
    let out2 = dir.join("log.cbor");
    let st2 = Command::new(admin_bin())
        .args(["export-log", "--db-path"])
        .arg(&db)
        .args(["--key-path"])
        .arg(&key)
        .args(["--output"])
        .arg(&out2)
        .args(["--format", "cbor"])
        .status()
        .expect("run");
    assert!(st2.success());
    assert!(!std::fs::read(&out2).unwrap().is_empty());
    let out3 = dir.join("pseudo.json");
    let st3 = Command::new(admin_bin())
        .args(["export-log", "--db-path"])
        .arg(&db)
        .args(["--key-path"])
        .arg(&key)
        .args(["--output"])
        .arg(&out3)
        .args(["--pseudonymized"])
        .status()
        .expect("run");
    assert!(st3.success());
    let pv: serde_json::Value = serde_json::from_slice(&std::fs::read(&out3).unwrap()).unwrap();
    assert!(
        pv["disclaimer"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("not chain-verified"),
        "must include explicit non-chain-verified disclaimer"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_evidence_bundle_cli_contains_required_parts() {
    let dir = unique_temp_dir("bundlecli");
    let db = make_db(&dir);
    let key = make_key(&dir);
    let out = dir.join("evidence.bundle");
    let st = Command::new(admin_bin())
        .args(["export-evidence-bundle", "--db-path"])
        .arg(&db)
        .args(["--key-path"])
        .arg(&key)
        .args(["--output"])
        .arg(&out)
        .status()
        .expect("run");
    assert!(st.success());
    let bytes = std::fs::read(&out).unwrap();
    let s = String::from_utf8_lossy(&bytes);
    for req in [
        "log.json",
        "checkpoints.json",
        "device_public_key.txt",
        "verify_report.json",
        "manifest.json",
        "signature.hex",
        "export_timestamp_unix",
    ] {
        assert!(s.contains(req), "missing {req}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
