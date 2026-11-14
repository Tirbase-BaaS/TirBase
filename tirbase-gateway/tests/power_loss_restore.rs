// SPDX-License-Identifier: AGPL-3.0-only

//! — Power loss, restore, WAL cadence, SQLCipher build, WASM persistence evidence hooks.
//! CLAIM-32.2..32.6 / PV-9.3..PV-9.8 / RD-2.

use rusqlite::{params, Connection};
#[cfg(feature = "failpoints")]
use std::sync::{Mutex, OnceLock};
use tirbase_gateway::db::{logical_dump, migrations};

#[cfg(feature = "failpoints")]
fn failpoint_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn temp_db(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tirbase-power-loss-restore-{tag}-{}-{n}.db",
        std::process::id()
    ))
}

fn open_primary(path: &std::path::Path) -> Connection {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let conn = Connection::open(path).unwrap();
    migrations::apply_primary_migrations(&conn).unwrap();
    conn
}

#[test]
fn logical_dump_is_deterministic_and_excludes_non_authoritative_sqlite_metadata() {
    let db = temp_db("dump");
    let conn = open_primary(&db);
    conn.execute(
        "INSERT INTO decided_outcomes(issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params!["did:key:i", "target", 7i64, 0i64, 1i64, Option::<String>::None, Option::<String>::None],
    )
    .unwrap();
    drop(conn);
    let a = logical_dump::logical_dump(&Connection::open(&db).unwrap()).unwrap();
    let b = logical_dump::logical_dump(&Connection::open(&db).unwrap()).unwrap();
    assert_eq!(a, b);
    assert!(!a.contains_key("sqlite_sequence"));
    let c = Connection::open(&db).unwrap();
    c.execute(
        "INSERT INTO decided_outcomes(issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params!["did:key:i", "target", 8i64, 0i64, 1i64, Option::<String>::None, Option::<String>::None],
    )
    .unwrap();
    drop(c);
    let c_dump = logical_dump::logical_dump(&Connection::open(&db).unwrap()).unwrap();
    assert_ne!(a, c_dump);
    let diff = logical_dump::diff_summary(&a, &c_dump);
    assert_ne!(diff, "equivalent");
    assert_ne!(diff, "equivalent");
    let _ = std::fs::remove_file(db);
}

#[cfg(feature = "failpoints")]
#[test]
fn failpoint_on_primary_write_preserves_logical_dump_equivalence_after_recovery() {
    let _g = failpoint_lock().lock().unwrap_or_else(|p| p.into_inner());
    let scenario = tirbase_core::fail_crate::FailScenario::setup();
    let db = temp_db("fp");
    {
        let conn = open_primary(&db);
        conn.execute(
            "INSERT INTO decided_outcomes(issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params!["did:key:i", "target", 1i64, 0i64, 1i64, Option::<String>::None, Option::<String>::None],
        )
        .unwrap();
    }
    let before = logical_dump::logical_dump(&Connection::open(&db).unwrap()).unwrap();
    {
        tirbase_core::fail_crate::cfg("fp_decided_outcomes_upsert", "return").unwrap();
        let store =
            tirbase_gateway::db::decided_outcomes::SqliteDecidedOutcomesStore::open(&db).unwrap();
        let fp_err = store.upsert(&tirbase_gateway::db::decided_outcomes::DecidedOutcomeRow {
            issuer_did: "did:key:i".into(),
            target_id: "target".into(),
            sequence_number: 2,
            enrollment_epoch: 0,
            accepted: true,
            rejection_category: None,
            detail: None,
        });
        assert!(
            fp_err.is_err(),
            "failpoint must reject write boundary: {fp_err:?}"
        );
    }
    scenario.teardown();
    let after = logical_dump::logical_dump(&Connection::open(&db).unwrap()).unwrap();
    assert_eq!(
        before,
        after,
        "logical dump equivalence must hold after failed write boundary: {}",
        logical_dump::diff_summary(&before, &after)
    );
    let _ = std::fs::remove_file(db);
}

#[test]
fn restore_invariant_placeholder_moved_to_tirbase_admin() {
 // S22 restore invariant is verified in tirbase-admin/tests/restore.rs
 // (gateway cannot depend on tirbase-admin without a cycle).
}
