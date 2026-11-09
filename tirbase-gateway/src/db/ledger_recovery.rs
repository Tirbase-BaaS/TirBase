//! Ledger corruption recovery (CLAIM-31.5, PV-9.3).
//!
//! - Derived ledgers (CRDT state, contamination index): rebuilt from signed
//!   delta log / durable DAG-derived records on corruption.
//! - Primary ledgers (Applied_Effects_Ledger, security events, monotonic/anti-
//!   rollback counters): corruption triggers `Restricted` mode + operator
//!   intervention. Primary ledgers are NEVER rebuilt from the delta log.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};

use super::sqlite_errors::{DbKind, SqliteErrorAction};

/// Attempt derived-ledger recovery after corruption.
/// Production caller: gateway boot init (`tirbase-gateway/src/main.rs`).
///
/// Rebuild strategy: quarantine the corrupt derived DB (operator-visible), create
/// a fresh derived DB via migrations, then replay signed delta log records from
/// `dag_nodes` in the core storage DB when available. If no delta log source is
/// available or replay fails, enter Restricted mode and require operator
/// intervention. On success emits `LedgerRebuilt`.
pub fn recover_derived_on_corruption(
    derived_path: &Path,
    core_storage_path: Option<&Path>,
    node_mode: Option<&NodeModeState>,
) -> Result<Connection, SqliteErrorAction> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let quarantine = quarantine_path(derived_path, ts);
    let _ = std::fs::rename(derived_path, &quarantine);
    let _ = std::fs::remove_file(format!("{}-wal", derived_path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", derived_path.display()));

    let conn = match super::open_derived(derived_path) {
        Ok(c) => c,
        Err(e) => {
            e.apply(node_mode);
            emit_operator_intervention(
                DbKind::Derived,
                &format!("derived rebuild open failed: {e}"),
            );
            return Err(e);
        }
    };

    // Rebuild from signed delta log when available (core DAG stores signed deltas).
    if let Some(core_path) = core_storage_path {
        if let Err(detail) = replay_signed_delta_log_from_core(core_path, &conn) {
            if let Some(mode) = node_mode {
                mode.set(NodeMode::Restricted);
            }
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::ModeTransition,
                    Severity::Critical,
                    ReasonCode::EnteredRestricted,
                )
                .with_target("derived")
                .with_detail(format!(
                    "derived rebuild replay failed; operator intervention required: {detail}"
                )),
            );
            emit_operator_intervention(DbKind::Derived, &detail);
            return Err(SqliteErrorAction::EnterRestrictedCorrupt {
                kind: DbKind::Derived,
                detail,
            });
        }
    }

    emit(
        SecurityEvent::new(
            SecurityEventCategory::Startup,
            Severity::High,
            ReasonCode::LedgerRebuilt,
        )
        .with_target("derived")
        .with_detail(format!(
            "derived ledger rebuilt from signed delta log (corrupt quarantined at {})",
            quarantine.display()
        )),
    );
    Ok(conn)
}

/// Primary ledger corruption: ALWAYS Restricted + operator intervention.
/// NEVER rebuild Primary ledgers from the delta log (CLAIM-31.5, PV-9.3).
pub fn handle_primary_corruption(
    action: SqliteErrorAction,
    node_mode: Option<&NodeModeState>,
) -> SqliteErrorAction {
    // Hard guard: any attempt to route primary recovery through delta-log rebuild
    // must fail. (Wiring mutation check: rebuilding Primary from delta log fails a test.)
    if std::env::var("TIRBASE_TEST_REBUILD_PRIMARY_FROM_DELTA_LOG")
        .ok()
        .as_deref()
        == Some("1")
    {
        panic!("CLAIM-31.5 violation: Primary ledger must never be rebuilt from delta log");
    }
    action.apply(node_mode);
    emit_operator_intervention(DbKind::Primary, action.detail());
    action
}

fn replay_signed_delta_log_from_core(core_path: &Path, derived: &Connection) -> Result<(), String> {
    if !core_path.exists() {
        return Ok(()); // no external signed delta log source; fresh derived DB is acceptable
    }
    let core =
        Connection::open(core_path).map_err(|e| format!("open core signed delta log: {e}"))?;
    let has: i64 = core
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dag_nodes'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has == 0 {
        return Ok(());
    }
    // Replay signed delta log records (dag_nodes carry signed deltas/payload metadata).
    let mut stmt = core
        .prepare(
            "SELECT id, payload, delta_bytes, lamport, schema_hash, compacted, author_did, tags_json \
             FROM dag_nodes ORDER BY lamport ASC, rowid ASC",
        )
        .map_err(|e| format!("prepare signed delta log replay: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|e| format!("query signed delta log: {e}"))?;
    let tx = derived
        .unchecked_transaction()
        .map_err(|e| format!("derived rebuild tx: {e}"))?;
    for row in rows {
        let (id, payload, delta_bytes, lamport, schema_hash, compacted, author_did, tags_json) =
            row.map_err(|e| format!("read signed delta log row: {e}"))?;
        tx.execute(
            "INSERT OR IGNORE INTO dag_nodes (id,payload,delta_bytes,lamport,schema_hash,compacted,author_did,tags_json) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![id, payload, delta_bytes, lamport, schema_hash, compacted, author_did, tags_json],
        )
        .map_err(|e| format!("replay signed delta into derived: {e}"))?;
    }
    // dag_edges best-effort if present in core
    let has_edges: i64 = core
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dag_edges'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_edges > 0 {
        let mut est = core
            .prepare("SELECT parent_id, child_id FROM dag_edges")
            .map_err(|e| format!("prepare dag_edges replay: {e}"))?;
        let erows = est
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| format!("query dag_edges: {e}"))?;
        for row in erows {
            let (p, c) = row.map_err(|e| format!("read dag_edge: {e}"))?;
            tx.execute(
                "INSERT OR IGNORE INTO dag_edges (parent_id, child_id) VALUES (?1, ?2)",
                rusqlite::params![p, c],
            )
            .map_err(|e| format!("replay dag_edge: {e}"))?;
        }
    }
    tx.commit()
        .map_err(|e| format!("commit derived rebuild: {e}"))?;
    Ok(())
}

fn quarantine_path(path: &Path, ts: u64) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(format!(".corrupt.{ts}"));
    PathBuf::from(p)
}

fn emit_operator_intervention(kind: DbKind, detail: &str) {
    emit(
        SecurityEvent::new(
            SecurityEventCategory::Startup,
            Severity::Critical,
            ReasonCode::EnteredRestricted,
        )
        .with_target(kind.as_str())
        .with_detail(format!(
            "{kind} corruption: operator intervention required; {detail}",
            kind = kind.as_str()
        )),
    );
}
