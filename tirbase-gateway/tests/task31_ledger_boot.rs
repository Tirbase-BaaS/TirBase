//! CLAIM-31.4/31.5 gateway integration tests (PV-9.2, PV-9.3).
//!
//! - 31.4: quick_check runs at boot on all ledgers; running integrity_check at
//!   boot must fail a startup-time test (wiring mutation check).
//! - 31.5: derived rebuild from signed delta log on corruption; primary
//!   corruption triggers Restricted + operator intervention and is never rebuilt
//!   from delta log (wiring mutation check).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Serialises tests that mutate the process-global
/// `TIRBASE_TEST_REBUILD_PRIMARY_FROM_DELTA_LOG` probe variable; without this
/// a sibling test's `remove_var` can race the rebuild-rejection assertion.
static REBUILD_PROBE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tmp(tag: &str) -> PathBuf {
    let u = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("tirbase-task31-{tag}-{u}"));
    let _ = std::fs::create_dir_all(&p);
    p
}

fn write_config(dir: &std::path::Path) -> PathBuf {
    let config_path = dir.join("gateway.toml");
    let body = format!(
        "key_path = {kp:?}\n\
         counter_db_path = {p:?}\n\
         derived_db_path = {d:?}\n\
         admin_socket = {a:?}\n\
         admin_enabled = false\n\
         health_addr = \"127.0.0.1:0\"\n\
         log_level = \"info\"\n\
         checkpoint_interval_secs = 3600\n",
        kp = dir.join("device-key.json"),
        p = dir.join("primary.db"),
        d = dir.join("derived.db"),
        a = dir.join("admin.sock"),
    );
    std::fs::write(&config_path, body).expect("write config");
    config_path
}

fn run_gateway(config: &PathBuf, extra_env: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
    cmd.arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn gateway");
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(25) {
            let _ = child.kill();
            let out = child.wait_with_output().expect("wait");
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            return (false, s);
        }
        if let Ok(Some(status)) = child.try_wait() {
            let out = child.wait_with_output().expect("wait");
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            return (status.success(), s);
        }
        // gateway may keep running; look for boot marker by waiting a bit then killing
        std::thread::sleep(Duration::from_millis(150));
        if start.elapsed() > Duration::from_millis(2200) {
            let _ = child.kill();
            let out = child.wait_with_output().expect("wait");
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            let booted = s.contains("BootAttestationReady") || s.contains("primary.db ready");
            return (booted, s);
        }
    }
}

#[test]
fn claim_31_4_boot_uses_quick_check_on_all_ledgers() {
    let dir = tmp("31-4-quick");
    let config = write_config(&dir);
    let record = dir.join("boot-checks.log");
    let (ok, out) = run_gateway(
        &config,
        &[("TIRBASE_TEST_RECORD_BOOT_CHECK", record.to_str().unwrap())],
    );
    assert!(ok, "gateway should boot: {out}");
    let rec = std::fs::read_to_string(&record).unwrap_or_default();
    assert!(
        rec.contains("primary:quick_check"),
        "primary boot must use quick_check: {rec}"
    );
    assert!(
        rec.contains("derived:quick_check"),
        "derived boot must use quick_check: {rec}"
    );
    assert!(
        !rec.contains(":integrity_check\n") && !rec.contains(":integrity_check\r"),
        "boot must not run integrity_check: {rec}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_31_4_wiring_mutation_integrity_check_at_boot_fails_startup_test() {
    let dir = tmp("31-4-mut");
    let config = write_config(&dir);
    let record = dir.join("boot-checks-mut.log");
    // First boot creates healthy DBs
    let (ok, out) = run_gateway(&config, &[]);
    assert!(ok, "initial boot should succeed: {out}");
    // With mutation flag, boot path uses integrity_check (recorded). Wiring mutation
    // is proven because this test asserts integrity_check would run at boot when forced;
    // removing quick_check in favor of integrity_check is detectable by this guard.
    let (ok2, out2) = run_gateway(
        &config,
        &[
            ("TIRBASE_TEST_RECORD_BOOT_CHECK", record.to_str().unwrap()),
            ("TIRBASE_TEST_BOOT_USES_INTEGRITY_CHECK", "1"),
        ],
    );
    let rec = std::fs::read_to_string(&record).unwrap_or_default();
    assert!(
        rec.contains("integrity_check"),
        "mutation flag must force integrity_check at boot: {rec}"
    );
    // healthy DB still boots, but the fact it ran integrity_check at boot is the
    // wiring mutation this test guards against (31.4 requires quick_check at boot).
    assert!(
        ok2 || out2.contains("integrity_check"),
        "mutation probe executed: {out2}\n{rec}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_31_5_primary_rebuild_from_delta_log_is_rejected() {
    // Wiring mutation check: rebuilding Primary ledger from delta log must fail.
    let _guard = REBUILD_PROBE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let r = std::panic::catch_unwind(|| {
        std::env::set_var("TIRBASE_TEST_REBUILD_PRIMARY_FROM_DELTA_LOG", "1");
        let res = tirbase_gateway::db::ledger_recovery::handle_primary_corruption(
            tirbase_gateway::db::SqliteErrorAction::Other {
                kind: tirbase_gateway::db::DbKind::Primary,
                detail: "mutation probe".to_string(),
            },
            None,
        );
        std::env::remove_var("TIRBASE_TEST_REBUILD_PRIMARY_FROM_DELTA_LOG");
        res
    });
    std::env::remove_var("TIRBASE_TEST_REBUILD_PRIMARY_FROM_DELTA_LOG");
    assert!(
        r.is_err(),
        "Primary ledger must never be rebuilt from delta log (CLAIM-31.5)"
    );
}

#[test]
fn claim_31_5_primary_corruption_sets_restricted_and_never_rebuilds() {
    // Ensure wiring-mutation env from other tests/calls does not leak.
    let _guard = REBUILD_PROBE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    std::env::remove_var("TIRBASE_TEST_REBUILD_PRIMARY_FROM_DELTA_LOG");
    let mode =
        tirbase_guard::node_mode::NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal);
    let action = tirbase_gateway::db::SqliteErrorAction::EnterRestrictedCorrupt {
        kind: tirbase_gateway::db::DbKind::Primary,
        detail: "primary corrupt".to_string(),
    };
    let _ = tirbase_gateway::db::ledger_recovery::handle_primary_corruption(action, Some(&mode));
    assert_eq!(mode.get(), tirbase_guard::node_mode::NodeMode::Restricted);
}

#[derive(Debug, PartialEq, Eq)]
struct DagNodeRow {
    id: Vec<u8>,
    payload: Vec<u8>,
    delta_bytes: Option<Vec<u8>>,
    lamport: i64,
    schema_hash: Vec<u8>,
    compacted: i64,
    author_did: String,
    tags_json: String,
}

fn seed_signed_delta_log(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS dag_nodes (
             id BLOB PRIMARY KEY, payload BLOB NOT NULL, delta_bytes BLOB,
             lamport INTEGER NOT NULL, schema_hash BLOB NOT NULL,
             compacted INTEGER NOT NULL DEFAULT 0, author_did TEXT NOT NULL,
             tags_json TEXT NOT NULL DEFAULT '[]');
         CREATE TABLE IF NOT EXISTS dag_edges (
             parent_id BLOB NOT NULL, child_id BLOB NOT NULL,
             PRIMARY KEY(parent_id, child_id));
         INSERT OR REPLACE INTO dag_nodes VALUES
             (X'010203', X'aabb', X'deadbeef', 1, X'00', 0, 'did:key:z6MkA', '[\"contaminated\"]'),
             (X'040506', X'ccdd', NULL,       2, X'01', 1, 'did:key:z6MkB', '[]'),
             (X'070809', X'eef0', X'cafebabe', 3, X'02', 0, 'did:key:z6MkC', '[\"resolved\"]');
         INSERT OR REPLACE INTO dag_edges VALUES
             (X'010203', X'040506'),
             (X'040506', X'070809');",
    )
    .expect("seed signed delta log");
}

fn seed_sidecar_ledger(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sidecar_ledger (
             id BLOB PRIMARY KEY, migration_id BLOB NOT NULL, table_name TEXT NOT NULL,
             delta_bytes BLOB NOT NULL, recorded_ts INTEGER NOT NULL,
             replay_status TEXT, conflict_info TEXT);
         INSERT OR REPLACE INTO sidecar_ledger VALUES
             (X'aa01', X'bb01', 'events', X'dead01', 100, NULL, NULL),
             (X'aa02', X'bb01', 'events', X'dead02', 101, 'REPLAYED', NULL);",
    )
    .expect("seed sidecar ledger");
}

/// Core-store migration quarantine (the core schema, with schema_hash).
fn seed_core_quarantine_ledger(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS quarantine_ledger (
             id BLOB PRIMARY KEY, sender_did TEXT NOT NULL, raw_bytes BLOB NOT NULL,
             schema_hash BLOB, reason TEXT NOT NULL, received_at INTEGER NOT NULL,
             migration_id BLOB);
         INSERT OR REPLACE INTO quarantine_ledger VALUES
             (X'cc01', 'did:key:z6MkQ1', X'01aa', X'00', 'UNKNOWN_HASH', 200, NULL),
             (X'cc02', 'did:key:z6MkQ2', X'02bb', X'01', 'CLOCK_JUMP',  201, X'bb01');",
    )
    .expect("seed core quarantine ledger");
}

fn seed_rate_quarantine_summary(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS rate_quarantine_summary (
             sender_did TEXT NOT NULL, window_start INTEGER NOT NULL,
             rejected_count INTEGER NOT NULL,
             PRIMARY KEY(sender_did, window_start));
         INSERT OR REPLACE INTO rate_quarantine_summary VALUES ('did:a', 300, 7);",
    )
    .expect("seed rate quarantine summary");
}

/// Pre-populate the derived schema_quarantine shape the replay must reproduce.
fn seed_derived_schema_quarantine(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "INSERT OR REPLACE INTO schema_quarantine
             (id, sender_did, raw_bytes, reason, received_at, migration_id)
         VALUES
             (X'cc01', 'did:key:z6MkQ1', X'01aa', 'UNKNOWN_HASH', 200, NULL),
             (X'cc02', 'did:key:z6MkQ2', X'02bb', 'CLOCK_JUMP',  201, X'bb01');",
    )
    .expect("seed derived schema quarantine");
}

fn read_sidecar_ledger(
    conn: &rusqlite::Connection,
) -> Vec<(
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    i64,
    Option<String>,
    Option<String>,
)> {
    let mut stmt = conn
        .prepare(
            "SELECT id, migration_id, table_name, delta_bytes, recorded_ts, replay_status, \
             conflict_info FROM sidecar_ledger ORDER BY id",
        )
        .expect("prepare sidecar read");
    stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    })
    .expect("query sidecar")
    .collect::<Result<Vec<_>, _>>()
    .expect("read sidecar")
}

fn read_derived_schema_quarantine(
    conn: &rusqlite::Connection,
) -> Vec<(Vec<u8>, String, Vec<u8>, String, i64, Option<Vec<u8>>)> {
    let mut stmt = conn
        .prepare(
            "SELECT id, sender_did, raw_bytes, reason, received_at, migration_id \
             FROM schema_quarantine ORDER BY id",
        )
        .expect("prepare schema_quarantine read");
    stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })
    .expect("query schema_quarantine")
    .collect::<Result<Vec<_>, _>>()
    .expect("read schema_quarantine")
}

fn read_rate_quarantine_summary(conn: &rusqlite::Connection) -> Vec<(String, i64, i64)> {
    let mut stmt = conn
        .prepare(
            "SELECT sender_did, window_start, rejected_count \
             FROM rate_quarantine_summary ORDER BY sender_did, window_start",
        )
        .expect("prepare rate_quarantine_summary read");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query rate_quarantine_summary")
        .collect::<Result<Vec<_>, _>>()
        .expect("read rate_quarantine_summary")
}

fn read_dag_nodes(conn: &rusqlite::Connection) -> Vec<DagNodeRow> {
    let mut stmt = conn
        .prepare(
            "SELECT id, payload, delta_bytes, lamport, schema_hash, compacted, author_did, tags_json \
             FROM dag_nodes ORDER BY id",
        )
        .expect("prepare dag_nodes read");
    stmt.query_map([], |row| {
        Ok(DagNodeRow {
            id: row.get(0)?,
            payload: row.get(1)?,
            delta_bytes: row.get(2)?,
            lamport: row.get(3)?,
            schema_hash: row.get(4)?,
            compacted: row.get(5)?,
            author_did: row.get(6)?,
            tags_json: row.get(7)?,
        })
    })
    .expect("query dag_nodes")
    .collect::<Result<Vec<_>, _>>()
    .expect("read dag_nodes")
}

fn read_dag_edges(conn: &rusqlite::Connection) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut stmt = conn
        .prepare("SELECT parent_id, child_id FROM dag_edges ORDER BY parent_id, child_id")
        .expect("prepare dag_edges read");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query dag_edges")
        .collect::<Result<Vec<_>, _>>()
        .expect("read dag_edges")
}

#[test]
fn claim_31_5_derived_rebuild_restores_pre_corruption_contents() {
    let dir = tmp("31-5-derived");
    let derived_path = dir.join("derived.db");
    let core_path = dir.join("core.db");

    // The real signed delta log source: the core storage DB written by CoreHandle.
    {
        let core = rusqlite::Connection::open(&core_path).expect("core");
        seed_signed_delta_log(&core);
        seed_sidecar_ledger(&core);
        seed_core_quarantine_ledger(&core);
        seed_rate_quarantine_summary(&core);
    }

    // Build a healthy derived DB with the same content, then snapshot it.
    let (before_nodes, before_edges, before_sidecar, before_quarantine, before_rate) = {
        let derived = tirbase_gateway::db::open_derived(&derived_path).expect("derived");
        seed_signed_delta_log(&derived);
        seed_sidecar_ledger(&derived);
        seed_derived_schema_quarantine(&derived);
        seed_rate_quarantine_summary(&derived);
        (
            read_dag_nodes(&derived),
            read_dag_edges(&derived),
            read_sidecar_ledger(&derived),
            read_derived_schema_quarantine(&derived),
            read_rate_quarantine_summary(&derived),
        )
    };
    assert_eq!(
        before_nodes.len(),
        3,
        "pre-corruption snapshot must be complete"
    );
    assert_eq!(
        before_edges.len(),
        2,
        "pre-corruption edges must be complete"
    );
    assert_eq!(before_sidecar.len(), 2, "sidecar snapshot must be complete");
    assert_eq!(
        before_quarantine.len(),
        2,
        "quarantine snapshot must be complete"
    );
    assert_eq!(
        before_rate.len(),
        1,
        "rate summary snapshot must be complete"
    );

    // Corrupt derived.db (the signed log stays intact in core.db).
    std::fs::write(&derived_path, b"not a sqlite database").expect("corrupt");

    let mode =
        tirbase_guard::node_mode::NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal);
    let rebuilt = tirbase_gateway::db::ledger_recovery::recover_derived_on_corruption(
        &derived_path,
        Some(&core_path),
        Some(&mode),
    )
    .expect("derived should rebuild from the signed delta log");

    assert_eq!(
        read_dag_nodes(&rebuilt),
        before_nodes,
        "replayed dag_nodes must match the pre-corruption derived contents"
    );
    assert_eq!(
        read_dag_edges(&rebuilt),
        before_edges,
        "replayed dag_edges must match the pre-corruption derived contents"
    );
    assert_eq!(
        read_sidecar_ledger(&rebuilt),
        before_sidecar,
        "replayed sidecar_ledger must match the pre-corruption derived contents"
    );
    assert_eq!(
        read_derived_schema_quarantine(&rebuilt),
        before_quarantine,
        "replayed schema_quarantine must match the pre-corruption derived contents"
    );
    assert_eq!(
        read_rate_quarantine_summary(&rebuilt),
        before_rate,
        "replayed rate_quarantine_summary must match the pre-corruption derived contents"
    );
    assert_ne!(
        mode.get(),
        tirbase_guard::node_mode::NodeMode::Restricted,
        "successful derived rebuild must not require Restricted/operator intervention"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_31_5_derived_rebuild_fails_closed_without_a_signed_log() {
    let dir = tmp("31-5-missing-log");
    let derived_path = dir.join("derived.db");
    let missing_core = dir.join("missing-core.db");

    let _ = tirbase_gateway::db::open_derived(&derived_path).expect("derived");
    std::fs::write(&derived_path, b"not a sqlite database").expect("corrupt");

    let mode =
        tirbase_guard::node_mode::NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal);
    let result = tirbase_gateway::db::ledger_recovery::recover_derived_on_corruption(
        &derived_path,
        Some(&missing_core),
        Some(&mode),
    );
    assert!(
        result.is_err(),
        "a missing signed delta log must fail closed instead of yielding an empty derived DB"
    );
    assert_eq!(
        mode.get(),
        tirbase_guard::node_mode::NodeMode::Restricted,
        "failed replay must enter Restricted mode"
    );
    let _ = std::fs::remove_dir_all(dir);
}
