// SPDX-License-Identifier: AGPL-3.0-only

//! F-07 acceptance: reversible migrations, auditable legal-hold retention,
//! backup/restore/PITR/DR root-hash equality, encrypted exports, budgets.

use std::sync::Arc;

use rusqlite::{params, Connection};
use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_gateway::backup;
use tirbase_gateway::db::migrations::{self, Migration};
use tirbase_gateway::db::verticals::{self, VerticalMigration};
use tirbase_gateway::db::DbKind;
use tirbase_gateway::retention::{self, RecordClass};
use tirbase_gateway::security_log::SecurityEventLog;
use tirbase_gateway::storage_budget::{self, StorageBudget};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tirbase-f07-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key() -> InMemoryKeyProvider {
    InMemoryKeyProvider::from_seed([21u8; 32])
}

fn open_db(dir: &std::path::Path) -> Connection {
    let db = dir.join("primary.db");
    migrations::open_primary(&db).expect("open primary")
}

fn append(log: &SecurityEventLog, n: u64) {
    for i in 0..n {
        log.append_payload(
            SecurityEvent::new(
                SecurityEventCategory::CommandDecision,
                Severity::Low,
                ReasonCode::CommandAccepted,
            )
            .with_target(format!("f07-{i}")),
        );
    }
}

fn audit_event_count(db: &std::path::Path) -> i64 {
    Connection::open(db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM security_events", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn f07_forward_and_backward_migrations_round_trip() {
    let dir = temp_dir("mig");
    let conn = open_db(&dir);
    assert_eq!(
        migrations::schema_version(&conn, DbKind::Primary).unwrap(),
        5
    );

    let report = migrations::rollback_migrations(
        &conn,
        DbKind::Primary,
        migrations::primary_migrations(),
        3,
    )
    .expect("rollback");
    assert_eq!(report.from_version, 5);
    assert_eq!(report.to_version, 3);
    assert!(report.applied.contains(&5));
    assert!(report.applied.contains(&4));
    let has_registry: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='provisioning_registry'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(has_registry, 0);
    // Previous schema is still usable after rollback.
    conn.execute(
        "INSERT INTO decided_outcomes(issuer_did,target_id,sequence_number,enrollment_epoch,accepted)
         VALUES ('did:key:i','t',1,0,1)",
        [],
    )
    .unwrap();

    let forward =
        migrations::apply_migrations(&conn, DbKind::Primary, migrations::primary_migrations())
            .expect("forward again");
    assert_eq!(forward.to_version, 5);
    assert_eq!(forward.applied, vec![4, 5]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_failed_migration_preserves_previous_schema() {
    let dir = temp_dir("mig-fail");
    let conn = open_db(&dir);
    let mut list: Vec<Migration> = migrations::primary_migrations().to_vec();
    list.push(Migration {
        version: 6,
        name: "f07_intentionally_broken",
        sql: "CREATE TABLE broken_schema (id INTEGER); INSERT INTO missing_table VALUES (1);",
        down_sql: "DROP TABLE IF EXISTS broken_schema;",
    });
    let err = migrations::apply_migrations(&conn, DbKind::Primary, &list)
        .expect_err("broken migration must fail");
    assert!(
        format!("{err:?}").contains("broken_schema")
            || format!("{err:?}").contains("missing_table")
    );
    // Version did not advance and the previous schema still accepts writes.
    assert_eq!(
        migrations::schema_version(&conn, DbKind::Primary).unwrap(),
        5
    );
    conn.execute(
        "INSERT INTO decided_outcomes(issuer_did,target_id,sequence_number,enrollment_epoch,accepted)
         VALUES ('did:key:i','t',2,0,1)",
        [],
    )
    .unwrap();
    let broken: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='broken_schema'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(broken, 0, "failed migration must not leave partial DDL");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_retention_blocks_legal_hold_and_audits_purge() {
    let dir = temp_dir("retention");
    let db = dir.join("primary.db");
    let conn = migrations::open_primary(&db).unwrap();
    retention::ensure_schema(&conn).unwrap();
    let log = SecurityEventLog::new_persistent(&db, Some(Arc::new(key())), false);
    append(&log, 2);

    conn.execute(
        "INSERT INTO idempotency_keys(issuer_did,target_id,idempotency_key,original_result,recorded_at_est,expires_at_est)
         VALUES ('did:key:i','t',x'01','ok',0,1)",
        [],
    )
    .unwrap();

    retention::add_legal_hold(
        &conn,
        "hold-1",
        RecordClass::Operational,
        None,
        "litigation",
        100,
    )
    .unwrap();
    let cfg = retention::RetentionConfig::default();
    let blocked = retention::apply_retention(&conn, &log, &cfg, 10_000, 10_000).unwrap();
    assert!(blocked
        .blocked_by_legal_hold
        .contains(&"operational".to_string()));
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM idempotency_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 1, "legal hold must prevent deletion");

    retention::release_legal_hold(&conn, "hold-1", 20_000).unwrap();
    let applied = retention::apply_retention(&conn, &log, &cfg, 30_000, 30_000).unwrap();
    assert_eq!(applied.purged.get("operational"), Some(&1));
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM idempotency_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 0);
    // The purge is auditable in the hash chain.
    let audit = log.chained_events();
    assert!(audit.iter().any(|e| {
        e.reason_code == ReasonCode::LogRotated && e.target.as_deref() == Some("operational")
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_audit_retention_cannot_delete_held_records() {
    let dir = temp_dir("retention-audit");
    let db = dir.join("primary.db");
    let conn = migrations::open_primary(&db).unwrap();
    retention::ensure_schema(&conn).unwrap();
    let log = SecurityEventLog::new_persistent(&db, Some(Arc::new(key())), false);
    append(&log, 3);
    let before = audit_event_count(&db);

    log.set_retention(tirbase_gateway::security_log::SecurityLogRetentionConfig {
        max_age_secs: 1,
        max_bytes: 1,
        archive_dir: dir.join("archive"),
        check_interval: std::time::Duration::from_secs(1),
    });
    retention::add_legal_hold(
        &conn,
        "hold-audit",
        RecordClass::Audit,
        None,
        "regulatory",
        1,
    )
    .unwrap();
    let rotated = log.rotate_retention_if_needed().unwrap();
    assert_eq!(rotated, 0);
    // The blocked-retention notice is itself an audit record; no historical
    // records may be removed.
    assert_eq!(audit_event_count(&db), before + 1, "held audit rows stay");
    assert!(log
        .chained_events()
        .iter()
        .any(|e| e.reason_code == ReasonCode::LogRotated && e.target.as_deref() == Some("audit")));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_restore_reproduces_ledger_root_and_pitr_drill_passes() {
    let dir = temp_dir("dr");
    let db = dir.join("primary.db");
    let log = SecurityEventLog::new_persistent(&db, Some(Arc::new(key())), false);
    append(&log, 4);
    let backup_dir = dir.join("backup");
    let manifest = backup::create_backup(&db, &backup_dir, &key(), 1_000).expect("create backup");
    let after_backup_seq = manifest.max_security_event_seq;
    assert_eq!(manifest.ledger_root_hash.len(), 64);

    let restored_db = dir.join("restored.db");
    let restored = backup::restore_backup(&backup_dir, &restored_db).expect("restore");
    assert!(restored.matches_manifest);
    assert_eq!(restored.ledger_root_hash, manifest.ledger_root_hash);

    // PITR: append more records to the live DB, replay the delta onto the
    // snapshot, and require the live root hash.
    append(&log, 3);
    let live_conn = Connection::open(&db).unwrap();
    let live_root = backup::ledger_root_hash(&live_conn).unwrap();
    let delta = backup::export_delta(&db, after_backup_seq).expect("delta");
    let pitr_db = dir.join("pitr.db");
    let pitr = backup::pitr_restore(&backup_dir, &delta, &pitr_db, Some(&live_root))
        .expect("pitr restore");
    assert!(pitr.matches_expected);
    assert_eq!(pitr.ledger_root_hash, live_root);
    assert!(pitr.delta_records_applied >= 3);

    let drill = backup::dr_drill(&db, &dir.join("drill"), &key(), 2_000, &delta).expect("drill");
    assert!(drill.passed);
    assert_eq!(drill.live_root_hash.as_deref(), Some(live_root.as_str()));

    // Tampered manifest or snapshot is rejected.
    let manifest_path = backup_dir.join(backup::BACKUP_MANIFEST_FILE);
    let mut parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    parsed["ledger_root_hash"] = serde_json::json!("00");
    std::fs::write(&manifest_path, serde_json::to_vec(&parsed).unwrap()).unwrap();
    assert!(backup::verify_backup(&backup_dir).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_encrypted_exports_authenticate_and_reject_tamper() {
    let key = key();
    let plaintext = b"ledger export with personal data";
    let sealed = backup::encrypt_export_records(&key, plaintext, b"range=1..4").unwrap();
    let opened = backup::decrypt_export_records(&key, &sealed, b"range=1..4").unwrap();
    assert_eq!(opened, plaintext);
    assert_ne!(sealed.ciphertext_hex, hex::encode(plaintext));

    let mut tampered = sealed.clone();
    let mut bytes = hex::decode(&tampered.ciphertext_hex).unwrap();
    bytes[0] ^= 0x40;
    tampered.ciphertext_hex = hex::encode(bytes);
    assert!(backup::decrypt_export_records(&key, &tampered, b"range=1..4").is_err());

    // AAD binding: the same ciphertext must not open under another range.
    assert!(backup::decrypt_export_records(&key, &sealed, b"range=5..9").is_err());

    let out = std::env::temp_dir().join(format!("tirbase-f07-sealed-{}.json", std::process::id()));
    backup::write_encrypted_export(&key, plaintext, b"aad", &out).unwrap();
    assert_eq!(
        backup::read_encrypted_export(&key, &out, b"aad").unwrap(),
        plaintext
    );
    let _ = std::fs::remove_file(out);
}

#[test]
fn f07_storage_budget_reports_ledger_and_archive_usage() {
    let dir = temp_dir("budget");
    std::fs::write(dir.join("primary.db"), vec![0u8; 1000]).unwrap();
    std::fs::write(dir.join("derived.db"), vec![0u8; 500]).unwrap();
    std::fs::create_dir_all(dir.join("archive")).unwrap();
    std::fs::write(dir.join("archive").join("seg-1.json"), vec![0u8; 250]).unwrap();

    let small = storage_budget::evaluate_default(
        &dir,
        StorageBudget {
            ledgers_bytes: 2000,
            archive_bytes: 100,
        },
    );
    assert_eq!(small.primary_db_bytes, 1000);
    assert_eq!(small.derived_db_bytes, 500);
    assert_eq!(small.archive_bytes, 250);
    assert!(!small.within_budget);
    assert!(small.reclaimable_classes.contains(&"audit".to_string()));

    let ok = storage_budget::evaluate_default(&dir, StorageBudget::default());
    assert!(ok.within_budget);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_restore_preserves_audit_chain_rows() {
    let dir = temp_dir("chain-restore");
    let db = dir.join("primary.db");
    let log = SecurityEventLog::new_persistent(&db, Some(Arc::new(key())), false);
    append(&log, 5);
    let original = log.chained_events();

    let backup_dir = dir.join("backup");
    backup::create_backup(&db, &backup_dir, &key(), 10).unwrap();
    let target = dir.join("restored.db");
    backup::restore_backup(&backup_dir, &target).unwrap();

    let restored = Connection::open(&target).unwrap();
    let restored_seqs: Vec<u64> = {
        let mut stmt = restored
            .prepare("SELECT seq FROM security_events ORDER BY seq ASC")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(|r| r.unwrap() as u64)
            .collect()
    };
    let original_seqs: Vec<u64> = original.iter().map(|e| e.seq).collect();
    assert_eq!(restored_seqs, original_seqs);
    let last_prev: Vec<u8> = restored
        .query_row(
            "SELECT prev_hash FROM security_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        Some(last_prev),
        original.last().map(|e| e.prev_hash.to_vec())
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_retention_run_rows_record_every_sweep() {
    let dir = temp_dir("retention-runs");
    let db = dir.join("primary.db");
    let conn = migrations::open_primary(&db).unwrap();
    retention::ensure_schema(&conn).unwrap();
    let log = SecurityEventLog::new_persistent(&db, Some(Arc::new(key())), false);
    let cfg = retention::RetentionConfig::default();
    retention::apply_retention(&conn, &log, &cfg, 10, 10).unwrap();

    let rows: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT record_class FROM retention_runs ORDER BY record_class")
            .unwrap();
        stmt.query_map(params![], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert!(rows.contains(&"audit".to_string()));
    assert!(rows.contains(&"safety".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

const VERTICAL_MIGRATIONS: [VerticalMigration; 2] = [
    VerticalMigration {
        version: 1,
        name: "cold_room_readings",
        sql: "CREATE TABLE IF NOT EXISTS cold_room_readings (id INTEGER PRIMARY KEY, celsius_milli INTEGER NOT NULL);",
        down_sql: "DROP TABLE IF EXISTS cold_room_readings;",
    },
    VerticalMigration {
        version: 2,
        name: "cold_room_readings_site_index",
        sql: "CREATE INDEX IF NOT EXISTS idx_cold_room_site ON cold_room_readings(id);",
        down_sql: "DROP INDEX IF EXISTS idx_cold_room_site;",
    },
];

#[test]
fn f07_vertical_schema_migrations_advance_and_roll_back() {
    let dir = temp_dir("vertical");
    let conn = open_db(&dir);
    let version = verticals::apply_vertical_migrations(&conn, "cold-chain", &VERTICAL_MIGRATIONS)
        .expect("apply vertical");
    assert_eq!(version, 2);
    conn.execute(
        "INSERT INTO cold_room_readings(id,celsius_milli) VALUES (1,-18500)",
        [],
    )
    .unwrap();

    let rolled =
        verticals::rollback_vertical_migrations(&conn, "cold-chain", &VERTICAL_MIGRATIONS, 1)
            .expect("rollback vertical");
    assert_eq!(rolled, 1);
    let index_gone: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cold_room_site'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(index_gone, 0);
    // The v1 table and its data remain usable after the failed/rolled-back step.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM cold_room_readings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);

    let reapplied = verticals::apply_vertical_migrations(&conn, "cold-chain", &VERTICAL_MIGRATIONS)
        .expect("reapply vertical");
    assert_eq!(reapplied, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f07_vertical_migration_failure_keeps_previous_version() {
    let dir = temp_dir("vertical-fail");
    let conn = open_db(&dir);
    verticals::apply_vertical_migrations(&conn, "venue", &VERTICAL_MIGRATIONS[..1]).unwrap();
    let broken = VerticalMigration {
        version: 2,
        name: "broken",
        sql: "CREATE TABLE broken_gate_events (id INTEGER); INSERT INTO no_such_table VALUES (1);",
        down_sql: "DROP TABLE IF EXISTS broken_gate_events;",
    };
    assert!(verticals::apply_vertical_migrations(
        &conn,
        "venue",
        &[VERTICAL_MIGRATIONS[0], broken]
    )
    .is_err());
    assert_eq!(verticals::vertical_version(&conn, "venue").unwrap(), 1);
    let broken_table: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='broken_gate_events'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(broken_table, 0);
    let _ = std::fs::remove_dir_all(&dir);
}
