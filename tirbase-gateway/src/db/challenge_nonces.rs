//! `challenge_nonces` SQLite store (PV-22.3, CLAIM-14.10/16.1/16.2 path).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

pub const CHALLENGE_NONCES_TABLE: &str = "challenge_nonces";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeNonceRow {
    pub nonce_hex: String,
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    pub expires_mono_secs: i64,
    pub consumed: bool,
}

#[derive(Debug)]
pub struct SqliteChallengeNonceStore {
    conn: Mutex<Connection>,
}

impl SqliteChallengeNonceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() { std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?; }
        }
        let conn = Connection::open(path).map_err(|e| format!("open: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(|e| format!("synchronous: {e}"))?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {CHALLENGE_NONCES_TABLE} (
                 nonce_hex          TEXT PRIMARY KEY,
                 issuer_did         TEXT NOT NULL,
                 target_id          TEXT NOT NULL,
                 param              TEXT NOT NULL,
                 expires_mono_secs  INTEGER NOT NULL,
                 consumed           INTEGER NOT NULL DEFAULT 0
             );"
        )).map_err(|e| format!("create challenge_nonces: {e}"))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> { match self.conn.lock() { Ok(g)=>g, Err(p)=>p.into_inner() } }
    pub fn insert(&self, row: &ChallengeNonceRow) -> Result<(), String> {
        self.lock().execute(&format!("INSERT OR REPLACE INTO {CHALLENGE_NONCES_TABLE} (nonce_hex,issuer_did,target_id,param,expires_mono_secs,consumed) VALUES (?1,?2,?3,?4,?5,?6)"), params![row.nonce_hex,row.issuer_did,row.target_id,row.param,row.expires_mono_secs, if row.consumed {1i64} else {0i64}]).map_err(|e| format!("insert nonce: {e}"))?;
        Ok(())
    }
    pub fn consume_if_valid(&self, nonce_hex: &str, issuer_did: &str, target_id: &str, param: &str, mono_secs_now: i64) -> Result<bool, String> {
        let conn = self.lock();
        let changed = conn.execute(&format!("UPDATE {CHALLENGE_NONCES_TABLE} SET consumed=1 WHERE nonce_hex=?1 AND issuer_did=?2 AND target_id=?3 AND param=?4 AND consumed=0 AND expires_mono_secs>=?5"), params![nonce_hex,issuer_did,target_id,param,mono_secs_now]).map_err(|e| format!("consume nonce: {e}"))?;
        Ok(changed > 0)
    }
    pub fn load(&self, nonce_hex: &str) -> Result<Option<ChallengeNonceRow>, String> {
        self.lock().query_row(&format!("SELECT nonce_hex,issuer_did,target_id,param,expires_mono_secs,consumed FROM {CHALLENGE_NONCES_TABLE} WHERE nonce_hex=?1"), params![nonce_hex], |row| Ok(ChallengeNonceRow{nonce_hex:row.get(0)?,issuer_did:row.get(1)?,target_id:row.get(2)?,param:row.get(3)?,expires_mono_secs:row.get(4)?,consumed:row.get::<_,i64>(5)?!=0})).optional().map_err(|e| format!("load nonce: {e}"))
    }
}
