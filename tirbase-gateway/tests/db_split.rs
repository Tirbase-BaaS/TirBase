//! Gateway-binary integration tests for (CLAIM-18.1–18.4, PV-9, PV-9.3)
//! and (CLAIM-32.1) schema migrations.
//!
//! Spawns the real `tirbase-gateway` binary and verifies:
//! - `primary.db` and `derived.db` are created and opened at boot
//! - `primary.db` uses WAL + `synchronous=FULL` (PrimaryLedger durability)
//! - `derived.db` uses WAL + `synchronous=NORMAL`
//! - hardening pragmas (`trusted_schema=OFF, foreign_keys=ON, cache_size=-4096`)
//! are applied to both DBs
//! - schema migrations are applied and `schema_version` is queryable
//! - injected `SQLITE_IOERR` on primary open triggers `Restricted` mapping
//! (CLAIM-18.4) observable via gateway log output

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
        "tirbase-task18-{tag}-{}-{unique}",
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
         derived_db_path = {:?}\n\
         admin_socket = {:?}\n\
         admin_enabled = false\n\
         health_addr = \"127.0.0.1:0\"\n\
         log_level = \"info\"\n\
         checkpoint_interval_secs = 3600\n",
        dir.join("device-key.json"),
        dir.join("primary.db"),
        dir.join("derived.db"),
        dir.join("admin.sock"),
    );
    std::fs::write(&config_path, body).expect("write config");
    config_path
}

fn spawn_gateway(config: &Path, env: &[(&str, &str)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
    command
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().expect("spawn gateway")
}

fn run_until_marker(config: &Path, env: &[(&str, &str)], needle: &str) -> Vec<String> {
    let mut child = spawn_gateway(config, env);
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx2.send(line);
        }
    });

    let mut lines = Vec::new();
    let deadline_us = tirbase_core::traits::monotonic_now() + 30_000_000;
    let found = loop {
        if tirbase_core::traits::monotonic_now() >= deadline_us {
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
            Err(mpsc::RecvTimeoutError::Timeout) => {
 // drain any exited process output
                if let Ok(Some(_)) = child.try_wait() {
                    while let Ok(line) = rx.try_recv() {
                        let hit = line.contains(needle);
                        lines.push(line);
                        if hit {
                            return {
                                kill(&mut child);
                                lines
                            };
                        }
                    }
                    break false;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
        }
    };
    kill(&mut child);
    if !found {
        panic!("marker {needle:?} not found; output:\n{}", lines.join("\n"));
    }
    lines
}

fn run_until_exit(config: &Path, env: &[(&str, &str)]) -> (std::process::ExitStatus, Vec<String>) {
    let mut child = spawn_gateway(config, env);
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx2.send(line);
        }
    });
    let status = child.wait().expect("wait");
    thread::sleep(Duration::from_millis(100));
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    (status, lines)
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn pragma_i64_via_open(path: &Path, kind_primary: bool, pragma: &str) -> i64 {
    let conn = if kind_primary {
        tirbase_gateway::db::open_primary(path).expect("open primary")
    } else {
        tirbase_gateway::db::open_derived(path).expect("open derived")
    };
    conn.query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))
        .unwrap_or_else(|e| panic!("PRAGMA {pragma} on {}: {e}", path.display()))
}

fn pragma_str_via_open(path: &Path, kind_primary: bool, pragma: &str) -> String {
    let conn = if kind_primary {
        tirbase_gateway::db::open_primary(path).expect("open primary")
    } else {
        tirbase_gateway::db::open_derived(path).expect("open derived")
    };
    conn.query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))
        .unwrap_or_else(|e| panic!("PRAGMA {pragma} on {}: {e}", path.display()))
}

fn has_table(db: &Path, name: &str) -> bool {
    let conn = rusqlite::Connection::open(db).expect("open db");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |r| r.get(0),
        )
        .unwrap();
    n > 0
}

fn schema_version(db: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )
    .expect("schema_version")
}

#[test]
fn gateway_creates_primary_and_derived_dbs_with_required_pragmas_and_tables() {
    let dir = temp_dir("split");
    let config = write_config(&dir);

 // Boot marker: gateway logs DB readiness and later boot attestation.
    let lines = run_until_marker(&config, &[], "SignedOperation boot record verified");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("primary.db ready") && l.contains("synchronous=FULL")),
        "primary.db readiness marker missing: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("derived.db ready") && l.contains("synchronous=NORMAL")),
        "derived.db readiness marker missing: {lines:?}"
    );

    let primary = dir.join("primary.db");
    let derived = dir.join("derived.db");
    assert!(primary.exists(), "primary.db must be created at boot");
    assert!(derived.exists(), "derived.db must be created at boot");

 // CLAIM-18.1: primary.db WAL + synchronous=FULL. Mutation-sensitive: removing
 // the synchronous=FULL pragma in migrations/open_primary must fail this.
 // Verified through the production `open_primary` helper so the test catches
 // a wiring mutation in the same code path the gateway uses.
    assert_eq!(
        pragma_str_via_open(&primary, true, "journal_mode").to_ascii_lowercase(),
        "wal",
        "primary.db must use WAL (CLAIM-18.1)"
    );
    assert_eq!(
        pragma_i64_via_open(&primary, true, "synchronous"),
        2,
        "primary.db must use synchronous=FULL (2) (CLAIM-18.1)"
    );

 // CLAIM-18.2: derived.db WAL + synchronous=NORMAL.
    assert_eq!(
        pragma_str_via_open(&derived, false, "journal_mode").to_ascii_lowercase(),
        "wal",
        "derived.db must use WAL (CLAIM-18.2)"
    );
    assert_eq!(
        pragma_i64_via_open(&derived, false, "synchronous"),
        1,
        "derived.db must use synchronous=NORMAL (1) (CLAIM-18.2)"
    );

 // CLAIM-18.3: hardening pragmas on both DBs (checked through open helpers).
    assert_eq!(
        pragma_i64_via_open(&primary, true, "trusted_schema"),
        0,
        "primary trusted_schema=OFF"
    );
    assert_eq!(
        pragma_i64_via_open(&primary, true, "foreign_keys"),
        1,
        "primary foreign_keys=ON"
    );
    assert_eq!(
        pragma_i64_via_open(&primary, true, "cache_size"),
        -4096,
        "primary cache_size=-4096"
    );
    assert_eq!(
        pragma_i64_via_open(&derived, false, "trusted_schema"),
        0,
        "derived trusted_schema=OFF"
    );
    assert_eq!(
        pragma_i64_via_open(&derived, false, "foreign_keys"),
        1,
        "derived foreign_keys=ON"
    );
    assert_eq!(
        pragma_i64_via_open(&derived, false, "cache_size"),
        -4096,
        "derived cache_size=-4096"
    );

 // CLAIM-18.1: PrimaryLedger tables created via migration framework.
    for table in [
        "applied_effects_ledger",
        "anti_replay_windows",
        "single_writer_leases",
        "policy_bundles",
        "security_events",
        "monotonic_counters",
        "time_ratchet",
        "device_epoch",
        "idempotency_keys",
        "challenge_nonces",
        "drift_rate_history",
        "drift_rate_summary",
        "target_state",
        "pending_approvals",
        "peer_checkpoint_witnesses",
        "security_event_segments",
        "security_event_personal_fields",
        "schema_migrations",
    ] {
        assert!(
            has_table(&primary, table),
            "primary.db missing {table} (CLAIM-18.1)"
        );
    }

 // CLAIM-18.2: DerivedLedger tables.
    for table in [
        "automerge_docs",
        "dag_nodes",
        "dag_edges",
        "schema_quarantine",
        "sidecar_ledger",
        "device_identity",
        "schema_migrations",
    ] {
        assert!(
            has_table(&derived, table),
            "derived.db missing {table} (CLAIM-18.2)"
        );
    }

 // CLAIM-32.1: schema version queryable; migrations idempotent across reboot.
    assert!(
        schema_version(&primary) >= 1,
        "primary schema version must be recorded"
    );
    assert!(
        schema_version(&derived) >= 1,
        "derived schema version must be recorded"
    );
    let v1p = schema_version(&primary);
    let v1d = schema_version(&derived);
    let _ = run_until_marker(&config, &[], "SignedOperation boot record verified");
    assert_eq!(
        schema_version(&primary),
        v1p,
        "primary migrations must be idempotent"
    );
    assert_eq!(
        schema_version(&derived),
        v1d,
        "derived migrations must be idempotent"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn injected_sqlite_ioerr_on_primary_open_triggers_restricted_mapping() {
    let dir = temp_dir("ioerr");
    let config = write_config(&dir);

 // Injection fires after open_primary succeeds in creating/migrating; the
 // gateway must apply SqliteErrorAction (StorageError + EnteredRestricted,
 // NodeMode=Restricted) and fail the boot (CLAIM-18.4).
    let (status, lines) =
        run_until_exit(&config, &[("TIRBASE_TEST_INJECT_PRIMARY_SQLITE", "IOERR")]);
    assert!(
        !status.success(),
        "gateway must fail boot on injected SQLITE_IOERR: {lines:?}"
    );
    let joined = lines.join("\n");
 // Strip ANSI escape codes for robust assertions (tracing may colorize fields).
    let plain = {
        let mut out = String::with_capacity(joined.len());
        let mut chars = joined.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    while let Some(&nc) = chars.peek() {
                        chars.next();
                        if nc.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    assert!(
        plain.contains("node_mode") && plain.contains("Restricted"),
        "expected NodeMode=Restricted in output (CLAIM-18.4):\n{joined}"
    );
    assert!(
        plain.contains("SQLITE_IOERR") || plain.contains("injected sqlite primary code 10"),
        "expected SQLITE_IOERR/injection detail in output (CLAIM-18.4):\n{joined}"
    );
    assert!(
        plain.contains("SQLite error mapping applied"),
        "expected SQLite error mapping to be applied (CLAIM-18.4):\n{joined}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
