//! `enrollment_nonces` SQLite store (CLAIM-8.5, PV-3.13).
//!
//! The bootstrap nonce is recorded for a bounded retention window (default
//! 72 hours, configurable through `GatewayConfig`). A background task started
//! by the gateway calls [`SqliteEnrollmentNonceStore::purge_expired`] on the
//! configured cadence. Reusing a nonce inside the window returns `false` from
//! [`EnrollmentNonceStore::record`] and the enrollment service rejects the
//! replay.
//!
//! The store is durable so a gateway restart does not forget nonces that are
//! still inside their retention window (which is what makes the bootstrap
//! replay-safe across restarts).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use tirbase_guard::epoch::{
    EnrollmentNonceStore, EpochError, DEFAULT_ENROLLMENT_NONCE_CAPACITY,
    DEFAULT_ENROLLMENT_NONCE_RETENTION_SECS,
};

/// Table name for retained bootstrap nonces.
pub const ENROLLMENT_NONCES_TABLE: &str = "enrollment_nonces";

/// SQLite-backed [`EnrollmentNonceStore`].
#[derive(Debug)]
pub struct SqliteEnrollmentNonceStore {
    conn: Mutex<Connection>,
    retention_secs: i64,
    capacity: usize,
}

impl SqliteEnrollmentNonceStore {
 /// Open with the default 72-hour retention and default capacity.
    pub fn open_default(path: impl AsRef<Path>) -> Result<Self, EpochError> {
        Self::open(
            path,
            DEFAULT_ENROLLMENT_NONCE_RETENTION_SECS,
            DEFAULT_ENROLLMENT_NONCE_CAPACITY,
        )
    }

 /// Open `primary.db` with an explicit retention window and capacity.
 ///
 /// `retention_secs` is clamped to `>= 0`; `capacity` to `>= 1`.
    pub fn open(
        path: impl AsRef<Path>,
        retention_secs: i64,
        capacity: usize,
    ) -> Result<Self, EpochError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| EpochError::Store(format!("create {parent:?}: {error}")))?;
            }
        }

        let conn =
            Connection::open(path).map_err(|error| EpochError::Store(format!("open: {error}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| EpochError::Store(format!("journal_mode: {error}")))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|error| EpochError::Store(format!("synchronous: {error}")))?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {ENROLLMENT_NONCES_TABLE} (
                 nonce         BLOB PRIMARY KEY,
                 recorded_at_est INTEGER NOT NULL,
                 expires_at_est  INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS {ENROLLMENT_NONCES_TABLE}_expires
                 ON {ENROLLMENT_NONCES_TABLE} (expires_at_est);"
        ))
        .map_err(|error| EpochError::Store(format!("create enrollment_nonces: {error}")))?;

        Ok(SqliteEnrollmentNonceStore {
            conn: Mutex::new(conn),
            retention_secs: retention_secs.max(0),
            capacity: capacity.max(1),
        })
    }

 /// Configured retention window in seconds.
    pub fn retention_secs(&self) -> i64 {
        self.retention_secs
    }

 /// Configured maximum number of retained nonces.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl EnrollmentNonceStore for SqliteEnrollmentNonceStore {
    fn record(&self, nonce: [u8; 32], now_est: i64) -> Result<bool, EpochError> {
        let mut conn = self.lock();
        let tx = conn
            .transaction()
            .map_err(|error| EpochError::Store(format!("begin record: {error}")))?;

 // Expired rows are re-usable even before the background purge runs.
        tx.execute(
            &format!("DELETE FROM {ENROLLMENT_NONCES_TABLE} WHERE expires_at_est < ?1"),
            params![now_est],
        )
        .map_err(|error| EpochError::Store(format!("prune expired nonces: {error}")))?;

        let existing: i64 = tx
            .query_row(
                &format!("SELECT COUNT(*) FROM {ENROLLMENT_NONCES_TABLE} WHERE nonce = ?1"),
                params![nonce.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| EpochError::Store(format!("check nonce: {error}")))?;
        if existing > 0 {
            tx.commit()
                .map_err(|error| EpochError::Store(format!("commit reuse: {error}")))?;
            return Ok(false);
        }

        let count: i64 = tx
            .query_row(
                &format!("SELECT COUNT(*) FROM {ENROLLMENT_NONCES_TABLE}"),
                [],
                |row| row.get(0),
            )
            .map_err(|error| EpochError::Store(format!("count nonces: {error}")))?;
        if count as usize >= self.capacity {
 // Evict the row closest to expiry (deterministic ordering).
            tx.execute(
                &format!(
                    "DELETE FROM {ENROLLMENT_NONCES_TABLE}
                     WHERE nonce = (
                         SELECT nonce FROM {ENROLLMENT_NONCES_TABLE}
                         ORDER BY expires_at_est ASC, nonce ASC LIMIT 1
                     )"
                ),
                [],
            )
            .map_err(|error| EpochError::Store(format!("evict nonce: {error}")))?;
        }

        tirbase_core::fail_crate::fail_point!("fp_enrollment_nonce_record", |_| Err(
            EpochError::Store("failpoint fp_enrollment_nonce_record".to_string())
        ));
        tx.execute(
            &format!(
                "INSERT INTO {ENROLLMENT_NONCES_TABLE}
                     (nonce, recorded_at_est, expires_at_est)
                 VALUES (?1, ?2, ?3)"
            ),
            params![
                nonce.as_slice(),
                now_est,
                now_est.saturating_add(self.retention_secs)
            ],
        )
        .map_err(|error| EpochError::Store(format!("insert nonce: {error}")))?;

        tx.commit()
            .map_err(|error| EpochError::Store(format!("commit record: {error}")))?;
        Ok(true)
    }

    fn purge_expired(&self, now_est: i64) -> Result<usize, EpochError> {
        let conn = self.lock();
        conn.execute(
            &format!("DELETE FROM {ENROLLMENT_NONCES_TABLE} WHERE expires_at_est < ?1"),
            params![now_est],
        )
        .map_err(|error| EpochError::Store(format!("purge expired nonces: {error}")))
    }

    fn contains(&self, nonce: &[u8; 32]) -> Result<bool, EpochError> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {ENROLLMENT_NONCES_TABLE} WHERE nonce = ?1"),
                params![nonce.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| EpochError::Store(format!("contains: {error}")))?;
        Ok(count > 0)
    }

    fn len(&self) -> Result<usize, EpochError> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {ENROLLMENT_NONCES_TABLE}"),
                [],
                |row| row.get(0),
            )
            .map_err(|error| EpochError::Store(format!("len: {error}")))?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_db(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-enrollment-nonce-{tag}-{}-{unique}.db",
            std::process::id()
        ))
    }

    #[test]
    fn defaults_are_seventy_two_hours() {
        let path = temp_db("defaults");
        let store = SqliteEnrollmentNonceStore::open_default(&path).unwrap();
        assert_eq!(store.retention_secs(), 72 * 60 * 60);
        assert_eq!(store.capacity(), DEFAULT_ENROLLMENT_NONCE_CAPACITY);
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn nonce_reuse_is_rejected_and_expiry_allows_reuse() {
        let path = temp_db("reuse");
        let store = SqliteEnrollmentNonceStore::open(&path, 100, 10).unwrap();
        assert!(store.record([1u8; 32], 1_000).unwrap());
        assert!(!store.record([1u8; 32], 1_000).unwrap(), "reuse rejected");
        assert!(store.contains(&[1u8; 32]).unwrap());
        assert_eq!(store.len().unwrap(), 1);

 // 1,100 is still inside (expires_at = 1,100 >= now).
        assert_eq!(store.purge_expired(1_100).unwrap(), 0);
 // At 1,101 the row is expired and may be recorded again.
        assert_eq!(store.purge_expired(1_101).unwrap(), 1);
        assert!(store.record([1u8; 32], 1_200).unwrap());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn retention_survives_reopen() {
        let path = temp_db("durable");
        {
            let store = SqliteEnrollmentNonceStore::open_default(&path).unwrap();
            assert!(store.record([7u8; 32], 1_000).unwrap());
        }
        let store = SqliteEnrollmentNonceStore::open_default(&path).unwrap();
        assert!(
            !store.record([7u8; 32], 1_001).unwrap(),
            "nonce is still retained after a restart (replay-safe bootstrap)"
        );
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn capacity_eviction_is_bounded() {
        let path = temp_db("capacity");
        let store = SqliteEnrollmentNonceStore::open(&path, 1_000, 2).unwrap();
        assert!(store.record([1u8; 32], 1_000).unwrap());
        assert!(store.record([2u8; 32], 1_010).unwrap());
        assert!(store.record([3u8; 32], 1_020).unwrap());
        assert_eq!(store.len().unwrap(), 2, "capacity is an upper bound");
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
