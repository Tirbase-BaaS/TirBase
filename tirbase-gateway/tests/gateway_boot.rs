//! Gateway-binary integration tests for task 6 (CLAIM-6.1, 6.5, 6.7a).
//!
//! These tests spawn the real `tirbase-gateway` binary with a temporary
//! configuration, wait for a boot marker on stdout, then terminate it and
//! inspect the durable SQLite state.
//!
//! Covered:
//! * the gateway boots with `FileKeyProvider` (CLAIM-6.1);
//! * its boot diagnostic reports `Level1` assurance for the durable SQLite
//!   counter (CLAIM-6.5);
//! * a simulated hardware counter ahead of the software counter causes a
//!   persisted LOCKDOWN and the `MonotonicCounterRegression` event
//!   (CLAIM-6.7a, scenario S22).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-gateway-it-{tag}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_config(dir: &Path) -> PathBuf {
    let config_path = dir.join("gateway.toml");
    let body = format!(
        "key_path = {:?}\n\
         counter_db_path = {:?}\n\
         admin_socket = {:?}\n\
         health_addr = \"127.0.0.1:0\"\n\
         log_level = \"info\"\n\
         checkpoint_interval_secs = 3600\n",
        dir.join("device-key.json"),
        dir.join("monotonic.db"),
        dir.join("admin.sock"),
    );
    std::fs::write(&config_path, body).expect("write config");
    config_path
}

/// Spawn the gateway and collect stdout lines until `needle` appears.
///
/// Returns the collected lines.  The child is killed before returning.
fn run_until_marker(config: &Path, env: &[(&str, &str)], needle: &str) -> Vec<String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
    command
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = command.spawn().expect("spawn gateway");
    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut lines = Vec::new();
    // Use the workspace TimeSource (PV-3.12) rather than a direct clock call.
    let deadline_us = tirbase_core::traits::monotonic_now() + 30_000_000;
    let found = loop {
        if tirbase_core::traits::monotonic_now() >= deadline_us {
            break false;
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
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

    kill(&mut child);
    assert!(
        found,
        "gateway did not log marker {needle:?} before timeout; output:\n{}",
        lines.join("\n")
    );
    lines
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn counter_value(db: &Path, key: &str) -> Option<i64> {
    let conn = rusqlite::Connection::open(db).expect("open counter db");
    conn.query_row(
        "SELECT value FROM monotonic_counters WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .ok()
}

fn counter_table_value(db: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open counter db");
    conn.query_row(
        "SELECT value FROM monotonic_counter WHERE id = 1",
        [],
        |row| row.get(0),
    )
    .expect("counter row")
}

#[test]
fn gateway_boots_with_file_key_provider_and_reports_level1() {
    let dir = temp_dir("key-provider");
    let config = write_config(&dir);

    let lines = run_until_marker(&config, &[], "SignedOperation boot record verified");

    assert!(
        lines.iter().any(|line| line.contains("did:key:z6Mk")),
        "boot log must include the file-backed DID: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("Level1")),
        "boot diagnostic must report Level1 assurance (CLAIM-6.5): {lines:?}"
    );
    assert!(
        dir.join("device-key.json").exists(),
        "FileKeyProvider must persist the device key file (CLAIM-6.1)"
    );
    assert!(
        counter_table_value(&dir.join("monotonic.db")) >= 1,
        "durable counter must have been incremented at boot"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn simulated_hardware_counter_ahead_of_software_enters_lockdown() {
    let dir = temp_dir("rollback");
    let config = write_config(&dir);

    // Hardware NV counter is at 900 while the freshly-created software DB has
    // never recorded a hardware write (sw_counter_at_last_hw_write = 0):
    // this is the snapshot-restore attack of scenario S22.
    let lines = run_until_marker(
        &config,
        &[("TIRBASE_SIMULATED_HW_COUNTER", "900")],
        "monotonic counter regression detected",
    );

    assert!(
        lines
            .iter()
            .any(|line| line.contains("hw_counter") && line.contains("900")),
        "boot log must report the hardware counter value: {lines:?}"
    );

    let db = dir.join("monotonic.db");
    assert_eq!(
        counter_value(&db, "lockdown_state"),
        Some(1),
        "rollback must persist LOCKDOWN in monotonic_counters (CLAIM-6.7a)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
