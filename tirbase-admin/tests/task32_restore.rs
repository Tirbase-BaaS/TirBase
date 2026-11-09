//! Task 32.3 restore command test (CLAIM-32.3, PV-9.5, RD-2, S22).
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use tirbase_gateway::db::migrations;

fn temp_db(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tirbase-task32-admin-{tag}-{}-{n}.db",
        std::process::id()
    ))
}

#[test]
fn restore_never_silently_updates_sequence_or_anti_rollback_counters_s22() {
    let backup = temp_db("backup");
    let target = temp_db("target");
    let epoch_db = temp_db("epoch");
    let lockdown_db = temp_db("lockdown");
    let out = std::env::temp_dir().join(format!(
        "tirbase-restore-report-{}.json",
        std::process::id()
    ));
    {
        let conn = Connection::open(&backup).unwrap();
        migrations::apply_primary_migrations(&conn).unwrap();
        conn.execute(
            "INSERT INTO decided_outcomes(issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params!["did:key:i", "target", 42i64, 0i64, 1i64, Option::<String>::None, Option::<String>::None],
        ).unwrap();
        conn.execute(
            "INSERT INTO anti_replay_windows(issuer_did,target_id,enrollment_epoch,highest_seen,seen_bitmap,forward_gap) VALUES (?1,?2,?3,?4,?5,?6)",
            params!["did:key:i", "target", 0i64, 99i64, vec![1u8,0,0,0,0,0,0,0], 1024i64],
        ).unwrap();
    }
    {
        let conn = Connection::open(&epoch_db).unwrap();
        conn.execute_batch("CREATE TABLE IF NOT EXISTS device_epoch (key TEXT PRIMARY KEY, device_epoch INTEGER NOT NULL, enrollment_epoch INTEGER NOT NULL); INSERT OR REPLACE INTO device_epoch(key,device_epoch,enrollment_epoch) VALUES ('gateway',0,3);").unwrap();
    }
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let report = tirbase_admin::cmd::restore::run(&tirbase_admin::cmd::restore::RestoreArgs {
        backup_db: backup.clone(),
        target_db: target.clone(),
        delta_log: None,
        epoch_store_db: epoch_db.clone(),
        lockdown_db: lockdown_db.clone(),
        signer_seed_hex: hex::encode(sk.to_bytes()),
        output: out.clone(),
    })
    .unwrap();
    assert!(report.quick_check_ok && report.lockdown_entered && !report.counters_silently_updated);
    assert_eq!(
        (
            report.previous_enrollment_epoch,
            report.new_enrollment_epoch
        ),
        (3, 4)
    );
    let conn = Connection::open(&target).unwrap();
    let seq: i64 = conn.query_row("SELECT sequence_number FROM decided_outcomes WHERE issuer_did='did:key:i' AND target_id='target'", [], |r| r.get(0)).unwrap();
    let hi: i64 = conn.query_row("SELECT highest_seen FROM anti_replay_windows WHERE issuer_did='did:key:i' AND target_id='target' AND enrollment_epoch=0", [], |r| r.get(0)).unwrap();
    assert_eq!((seq, hi), (42, 99));
    let ld: String = Connection::open(&lockdown_db)
        .unwrap()
        .query_row(
            "SELECT value FROM lockdown_state WHERE key='gateway'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ld, "LOCKDOWN");
    for p in [backup, target, epoch_db, lockdown_db, out] {
        let _ = std::fs::remove_file(p);
    }
}
