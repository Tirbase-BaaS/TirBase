//! LOCKDOWN persistence for the gateway (task 13.2 — CLAIM-13.2, PV-4.13).
//!
//! Persists to `primary.db` `monotonic_counters(lockdown_state)` (durable) and
//! writes `/var/lib/tirbase/lockdown` as a secondary indicator.  `/run` is
//! tmpfs and never used as sole persistence.

use std::path::{Path, PathBuf};

use tirbase_guard::lockdown::{
    LockdownEntryReason, LockdownError, LockdownFileMarker, LockdownStore, LOCKDOWN_DB_KEY,
};

/// SQLite-backed lockdown store over `primary.db`.
#[derive(Debug, Clone)]
pub struct SqliteLockdownStore {
    db_path: PathBuf,
    marker: LockdownFileMarker,
}

impl SqliteLockdownStore {
    pub fn new(db_path: impl Into<PathBuf>, marker_path: impl Into<PathBuf>) -> Self {
        SqliteLockdownStore {
            db_path: db_path.into(),
            marker: LockdownFileMarker::new(marker_path),
        }
    }

    pub fn with_db(db_path: impl Into<PathBuf>) -> Self {
        Self::new(db_path, tirbase_guard::LOCKDOWN_FILE_PATH)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
    pub fn marker_path(&self) -> &Path {
        self.marker.path()
    }

    fn open_db(&self) -> Result<rusqlite::Connection, LockdownError> {
        if let Some(parent) = self.db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(LockdownError::Io)?;
            }
        }
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| LockdownError::Store(format!("open {}: {e}", self.db_path.display())))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| LockdownError::Store(format!("journal_mode: {e}")))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| LockdownError::Store(format!("synchronous: {e}")))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS monotonic_counters (
                 key   TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );",
        )
        .map_err(|e| LockdownError::Store(format!("create monotonic_counters: {e}")))?;
        Ok(conn)
    }

    fn set_value(&self, value: i64) -> Result<(), LockdownError> {
        let conn = self.open_db()?;
        tirbase_core::fail_crate::fail_point!("fp_lockdown_set_value", |_| Err(
            LockdownError::Store("failpoint fp_lockdown_set_value".into())
        ));
        conn.execute(
            "INSERT INTO monotonic_counters (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![LOCKDOWN_DB_KEY, value],
        )
        .map_err(|e| LockdownError::Store(format!("persist lockdown_state: {e}")))?;
        Ok(())
    }
}

impl LockdownStore for SqliteLockdownStore {
    fn set_lockdown(&self, reason: LockdownEntryReason) -> Result<(), LockdownError> {
        self.set_value(1)?;
        self.marker.write(reason)?;
        Ok(())
    }

    fn clear_lockdown(&self) -> Result<(), LockdownError> {
        self.set_value(0)?;
        self.marker.remove()?;
        Ok(())
    }

    fn is_lockdown(&self) -> Result<bool, LockdownError> {
        if !self.db_path.exists() {
            return Ok(false);
        }
        let conn = self.open_db()?;
        let value: Option<i64> = conn
            .query_row(
                "SELECT value FROM monotonic_counters WHERE key = ?1",
                rusqlite::params![LOCKDOWN_DB_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| LockdownError::Store(format!("read lockdown_state: {e}")))?;
        Ok(value.unwrap_or(0) == 1)
    }
}

trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}
impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp(tag: &str) -> (PathBuf, PathBuf) {
        static N: AtomicU64 = AtomicU64::new(0);
        let u = N.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "tirbase-lockdown-db-{tag}-{}-{u}",
            std::process::id()
        ));
        (base.join("primary.db"), base.join("var").join("lockdown"))
    }

    #[test]
    fn lockdown_persists_to_db_and_file_and_survives_reopen() {
        let (db, marker) = tmp("persist");
        {
            let store = SqliteLockdownStore::new(&db, &marker);
            assert!(!store.is_lockdown().unwrap());
            store
                .set_lockdown(LockdownEntryReason::GuardDecision)
                .unwrap();
            assert!(store.is_lockdown().unwrap());
            assert!(marker.exists());
            let conn = rusqlite::Connection::open(&db).unwrap();
            let v: i64 = conn
                .query_row(
                    "SELECT value FROM monotonic_counters WHERE key=?1",
                    [LOCKDOWN_DB_KEY],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(v, 1);
        }
        {
            let store = SqliteLockdownStore::new(&db, &marker);
            assert!(
                store.is_lockdown().unwrap(),
                "LOCKDOWN must persist across restart (CLAIM-13.2)"
            );
        }
        let _ = std::fs::remove_dir_all(db.parent().unwrap().parent().unwrap());
    }
}
