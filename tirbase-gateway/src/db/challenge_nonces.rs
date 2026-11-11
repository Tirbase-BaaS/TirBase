//! `challenge_nonces` SQLite store (PV-22.3, CLAIM-14.10/16.1/16.2).
//!
//! Task 16.1/16.2: stores `ChallengeNonce` rows with `device_id, param,
//! nonce: [u8;32], issued_at_mono, expires_at_mono`; nonce is consumed after a
//! single valid use. Pipeline binding also persists `issuer_did`/`target_id`
//! so Stage 9 can enforce the command binding on consumption.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use tirbase_guard::{ChallengeNonce, ChallengeNonceStore};

pub const CHALLENGE_NONCES_TABLE: &str = "challenge_nonces";
pub const CHALLENGE_NONCE_COLUMNS: [&str; 8] = [
    "device_id",
    "param",
    "nonce",
    "issued_at_mono",
    "expires_at_mono",
    "issuer_did",
    "target_id",
    "consumed",
];

/// Backward-compatible row view used by existing gateway DB tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeNonceRow {
    pub nonce_hex: String,
    pub device_id: String,
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    pub issued_at_mono: i64,
    pub expires_mono_secs: i64,
    pub consumed: bool,
}

#[derive(Debug)]
pub struct SqliteChallengeNonceStore {
    conn: Mutex<Connection>,
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for i in 0..32 {
        let hi = (b[i * 2] as char).to_digit(16)? as u8;
        let lo = (b[i * 2 + 1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

impl SqliteChallengeNonceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
            }
        }
        let conn = Connection::open(path).map_err(|e| format!("open: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("synchronous: {e}"))?;
        conn.pragma_update(None, "trusted_schema", "OFF").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {CHALLENGE_NONCES_TABLE} (
                 device_id        TEXT NOT NULL,
                 param            TEXT NOT NULL,
                 nonce            BLOB NOT NULL,
                 issued_at_mono   INTEGER NOT NULL,
                 expires_at_mono  INTEGER NOT NULL,
                 issuer_did       TEXT NOT NULL,
                 target_id        TEXT NOT NULL,
                 consumed         INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (nonce)
             );
             CREATE INDEX IF NOT EXISTS idx_challenge_nonces_device_param
               ON {CHALLENGE_NONCES_TABLE}(device_id, target_id, param, issued_at_mono);"
        ))
        .map_err(|e| format!("create challenge_nonces: {e}"))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Insert a challenge nonce row (test/compat convenience).
    pub fn insert_row(&self, row: &ChallengeNonceRow) -> Result<(), String> {
        let nonce = hex_decode_32(&row.nonce_hex)
            .ok_or_else(|| format!("invalid nonce_hex {:?}", row.nonce_hex))?;
        let challenge = ChallengeNonce {
            device_id: row.device_id.clone(),
            param: row.param.clone(),
            nonce,
            issued_at_mono: row.issued_at_mono,
            expires_at_mono: row.expires_mono_secs,
            issuer_did: row.issuer_did.clone(),
            target_id: row.target_id.clone(),
        };
        <Self as ChallengeNonceStore>::insert(self, &challenge)?;
        if row.consumed {
            // test convenience: mark consumed
            self.lock()
                .execute(
                    &format!("UPDATE {CHALLENGE_NONCES_TABLE} SET consumed=1 WHERE nonce=?1"),
                    params![nonce.as_slice()],
                )
                .map_err(|e| format!("mark consumed: {e}"))?;
        }
        Ok(())
    }

    /// Legacy hex-based consumption helper retained for existing tests.
    pub fn consume_if_valid_hex(
        &self,
        nonce_hex: &str,
        issuer_did: &str,
        target_id: &str,
        param: &str,
        mono_secs_now: i64,
    ) -> Result<bool, String> {
        let Some(nonce) = hex_decode_32(nonce_hex) else {
            return Ok(false);
        };
        <Self as ChallengeNonceStore>::consume_if_valid(
            self,
            &nonce,
            issuer_did,
            target_id,
            param,
            mono_secs_now,
            true,
        )
    }

    pub fn load_by_hex(&self, nonce_hex: &str) -> Result<Option<ChallengeNonceRow>, String> {
        let Some(nonce) = hex_decode_32(nonce_hex) else {
            return Ok(None);
        };
        self.lock()
            .query_row(
                &format!(
                    "SELECT device_id,param,nonce,issued_at_mono,expires_at_mono,issuer_did,target_id,consumed \
                     FROM {CHALLENGE_NONCES_TABLE} WHERE nonce=?1"
                ),
                params![nonce.as_slice()],
                |row| {
                    let nonce: Vec<u8> = row.get(2)?;
                    Ok(ChallengeNonceRow {
                        device_id: row.get(0)?,
                        param: row.get(1)?,
                        nonce_hex: hex_encode(&nonce),
                        issued_at_mono: row.get(3)?,
                        expires_mono_secs: row.get(4)?,
                        issuer_did: row.get(5)?,
                        target_id: row.get(6)?,
                        consumed: row.get::<_, i64>(7)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| format!("load nonce: {e}"))
    }

    /// `GET /admin/challenge` and tests: count recent issuance events for S32
    /// rate limiting. Counts unexpired rows (consumed or not) issued in the
    /// current minute window for the device/target/param key.
    pub fn count_recent_issuance(
        &self,
        device_id: &str,
        target_id: &str,
        param: &str,
        since_mono_secs: i64,
    ) -> Result<i64, String> {
        self.lock()
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {CHALLENGE_NONCES_TABLE}
                     WHERE device_id=?1 AND target_id=?2 AND param=?3 AND issued_at_mono>=?4"
                ),
                params![device_id, target_id, param, since_mono_secs],
                |row| row.get(0),
            )
            .map_err(|e| format!("count recent issuance: {e}"))
    }

    pub fn prune_expired(&self, mono_secs_now: i64) -> Result<usize, String> {
        self.lock()
            .execute(
                &format!("DELETE FROM {CHALLENGE_NONCES_TABLE} WHERE expires_at_mono < ?1"),
                params![mono_secs_now],
            )
            .map_err(|e| format!("prune challenge_nonces: {e}"))
    }
}

impl ChallengeNonceStore for SqliteChallengeNonceStore {
    fn insert(&self, nonce: &ChallengeNonce) -> Result<(), String> {
        self.lock()
            .execute(
                &format!(
                    "INSERT INTO {CHALLENGE_NONCES_TABLE}
                     (device_id,param,nonce,issued_at_mono,expires_at_mono,issuer_did,target_id,consumed)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,0)"
                ),
                params![
                    nonce.device_id,
                    nonce.param,
                    nonce.nonce.as_slice(),
                    nonce.issued_at_mono,
                    nonce.expires_at_mono,
                    nonce.issuer_did,
                    nonce.target_id,
                ],
            )
            .map_err(|e| format!("insert nonce: {e}"))?;
        Ok(())
    }

    fn consume_if_valid(
        &self,
        nonce: &[u8; 32],
        issuer_did: &str,
        target_id: &str,
        param: &str,
        mono_secs_now: i64,
        consume: bool,
    ) -> Result<bool, String> {
        tirbase_core::fail_crate::fail_point!("fp_challenge_nonce_consume", |_| Err(
            "failpoint fp_challenge_nonce_consume".to_string()
        ));
        let conn = self.lock();
        let exists: Option<i64> = conn
            .query_row(
                &format!(
                    "SELECT 1 FROM {CHALLENGE_NONCES_TABLE}
                     WHERE nonce=?1 AND issuer_did=?2 AND target_id=?3 AND param=?4
                       AND consumed=0 AND expires_at_mono>=?5"
                ),
                params![
                    nonce.as_slice(),
                    issuer_did,
                    target_id,
                    param,
                    mono_secs_now
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("check nonce: {e}"))?;
        if exists.is_none() {
            return Ok(false);
        }
        if consume {
            let changed = conn
                .execute(
                    &format!(
                        "UPDATE {CHALLENGE_NONCES_TABLE} SET consumed=1
                         WHERE nonce=?1 AND issuer_did=?2 AND target_id=?3 AND param=?4
                           AND consumed=0 AND expires_at_mono>=?5"
                    ),
                    params![
                        nonce.as_slice(),
                        issuer_did,
                        target_id,
                        param,
                        mono_secs_now
                    ],
                )
                .map_err(|e| format!("consume nonce: {e}"))?;
            Ok(changed > 0)
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tirbase-challenge-{tag}-{}-{}.db",
            std::process::id(),
            tirbase_core::traits::monotonic_now()
        ))
    }

    #[test]
    fn challenge_nonces_table_has_required_fields_and_enforces_one_time_use() {
        let db = tmp("schema");
        let store = SqliteChallengeNonceStore::open(&db).unwrap();
        let conn = store.lock();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({CHALLENGE_NONCES_TABLE})"))
            .unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for required in CHALLENGE_NONCE_COLUMNS {
            assert!(
                cols.contains(&required.to_string()),
                "missing {required}: {cols:?}"
            );
        }
        drop(stmt);
        drop(conn);
        let nonce = ChallengeNonce {
            device_id: "dev-1".into(),
            param: "setpoint".into(),
            nonce: [7u8; 32],
            issued_at_mono: 100,
            expires_at_mono: 200,
            issuer_did: "did:key:issuer".into(),
            target_id: "target-a".into(),
        };
        ChallengeNonceStore::insert(&store, &nonce).unwrap();
        assert!(ChallengeNonceStore::consume_if_valid(
            &store,
            &[7u8; 32],
            "did:key:issuer",
            "target-a",
            "setpoint",
            150,
            true
        )
        .unwrap());
        assert!(
            !ChallengeNonceStore::consume_if_valid(
                &store,
                &[7u8; 32],
                "did:key:issuer",
                "target-a",
                "setpoint",
                150,
                true
            )
            .unwrap(),
            "second use must be rejected (CLAIM-16.1)"
        );
        let _ = std::fs::remove_file(db);
    }
}
