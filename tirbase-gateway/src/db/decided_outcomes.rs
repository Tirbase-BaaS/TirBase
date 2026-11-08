//! `decided_outcomes` SQLite store (PV-5, CLAIM-14.11 / design schema support).

use std::path::Path;
use std::sync::Mutex;
use rusqlite::{params, Connection, OptionalExtension};

pub const DECIDED_OUTCOMES_TABLE: &str = "decided_outcomes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecidedOutcomeRow {
    pub issuer_did: String,
    pub target_id: String,
    pub sequence_number: u64,
    pub enrollment_epoch: u64,
    pub accepted: bool,
    pub rejection_category: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct SqliteDecidedOutcomesStore {
    conn: Mutex<Connection>,
}

impl SqliteDecidedOutcomesStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() { if !parent.as_os_str().is_empty() { std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?; } }
        let conn = Connection::open(path).map_err(|e| format!("open: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(|e| format!("synchronous: {e}"))?;
        conn.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {DECIDED_OUTCOMES_TABLE} (issuer_did TEXT NOT NULL, target_id TEXT NOT NULL, sequence_number INTEGER NOT NULL, enrollment_epoch INTEGER NOT NULL, accepted INTEGER NOT NULL, rejection_category TEXT, detail TEXT, PRIMARY KEY(issuer_did,target_id,sequence_number,enrollment_epoch));")).map_err(|e| format!("create decided_outcomes: {e}"))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> { match self.conn.lock() { Ok(g)=>g, Err(p)=>p.into_inner() } }
    pub fn upsert(&self, row: &DecidedOutcomeRow) -> Result<(), String> {
        self.lock().execute(&format!("INSERT OR REPLACE INTO {DECIDED_OUTCOMES_TABLE} (issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)"), params![row.issuer_did,row.target_id,row.sequence_number as i64,row.enrollment_epoch as i64,if row.accepted{1i64}else{0i64},row.rejection_category,row.detail]).map_err(|e| format!("upsert decided outcome: {e}"))?; Ok(())
    }
    pub fn lookup(&self, issuer_did: &str, target_id: &str, sequence_number: u64, enrollment_epoch: u64) -> Result<Option<DecidedOutcomeRow>, String> {
        self.lock().query_row(&format!("SELECT issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail FROM {DECIDED_OUTCOMES_TABLE} WHERE issuer_did=?1 AND target_id=?2 AND sequence_number=?3 AND enrollment_epoch=?4"), params![issuer_did,target_id,sequence_number as i64,enrollment_epoch as i64], |row| Ok(DecidedOutcomeRow{issuer_did:row.get(0)?,target_id:row.get(1)?,sequence_number:row.get::<_,i64>(2)? as u64,enrollment_epoch:row.get::<_,i64>(3)? as u64,accepted:row.get::<_,i64>(4)?!=0,rejection_category:row.get(5)?,detail:row.get(6)?})).optional().map_err(|e| format!("lookup decided outcome: {e}"))
    }
}
