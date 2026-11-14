// SPDX-License-Identifier: AGPL-3.0-only

//! `time_ratchet` table and its SQLite-backed store (7.6 —
//! CLAIM-7.2, CLAIM-7.6, PV-22.2).
//!
//! The ratchet state is a PrimaryLedger: it must survive restarts, so it lives in
//! `primary.db` (the same database that holds the monotonic counters) opened in
//! WAL mode with `PRAGMA synchronous=FULL`. A ratchet advance is committed
//! before the in-memory ratchet moves, so a crash can never leave the process
//! accepting time it did not durably commit.
//!
//! Schema (design.md §4.13):
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS time_ratchet (
//! id INTEGER PRIMARY KEY CHECK (id = 1),
//! last_beacon_time INTEGER NOT NULL DEFAULT 0,
//! mono_at_beacon INTEGER NOT NULL DEFAULT 0,
//! beacon_boot_id INTEGER NOT NULL DEFAULT 0,
//! persisted_floor INTEGER NOT NULL DEFAULT 0,
//! updated_at_mono INTEGER NOT NULL DEFAULT 0
//! );
//! ```

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use tirbase_guard::time::{TimeRatchetError, TimeRatchetRecord, TimeRatchetStore};

/// Name of the ratchet table.
pub const TIME_RATCHET_TABLE: &str = "time_ratchet";

/// Columns created by [`SqliteTimeRatchetStore::open`], in definition order.
pub const TIME_RATCHET_COLUMNS: [&str; 6] = [
    "id",
    "last_beacon_time",
    "mono_at_beacon",
    "beacon_boot_id",
    "persisted_floor",
    "updated_at_mono",
];

fn db_error(context: &str, error: rusqlite::Error) -> TimeRatchetError {
    TimeRatchetError::Store(format!("{TIME_RATCHET_TABLE} {context}: {error}"))
}

/// SQLite INTEGER is signed; bit-cast `u64` so hashed boot ids round-trip
/// without overflow (`i64::try_from` would reject ids above `i64::MAX`).
fn u64_to_i64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

fn i64_to_u64(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

/// Durable [`TimeRatchetStore`] over the `time_ratchet` table in `primary.db`.
#[derive(Debug)]
pub struct SqliteTimeRatchetStore {
    conn: Mutex<Connection>,
}

impl SqliteTimeRatchetStore {
 /// Open (creating if needed) the ratchet table at `db_path`.
 ///
 /// This is called from the gateway boot path, which is how the table exists
 /// in `primary.db` and how the persisted floor is read at boot (CLAIM-7.6).
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, TimeRatchetError> {
        let db_path = db_path.as_ref();
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    TimeRatchetError::Store(format!(
                        "create primary.db directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }

        let conn = Connection::open(db_path).map_err(|e| db_error("open", e))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| db_error("set journal_mode=WAL", e))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| db_error("set synchronous=FULL", e))?;

        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {TIME_RATCHET_TABLE} (
                 id               INTEGER PRIMARY KEY CHECK (id = 1),
                 last_beacon_time INTEGER NOT NULL DEFAULT 0,
                 mono_at_beacon   INTEGER NOT NULL DEFAULT 0,
                 beacon_boot_id   INTEGER NOT NULL DEFAULT 0,
                 persisted_floor  INTEGER NOT NULL DEFAULT 0,
                 updated_at_mono  INTEGER NOT NULL DEFAULT 0
             );"
        ))
        .map_err(|e| db_error("create table", e))?;

        Ok(SqliteTimeRatchetStore {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl TimeRatchetStore for SqliteTimeRatchetStore {
    fn load(&self) -> Result<Option<TimeRatchetRecord>, TimeRatchetError> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT last_beacon_time, mono_at_beacon, persisted_floor, beacon_boot_id, \
                 updated_at_mono FROM {TIME_RATCHET_TABLE} WHERE id = 1"
            ))
            .map_err(|e| db_error("prepare load", e))?;
        let mut rows = stmt.query([]).map_err(|e| db_error("load", e))?;
        let Some(row) = rows.next().map_err(|e| db_error("load row", e))? else {
            return Ok(None);
        };

        let last_beacon_time: i64 = row
            .get(0)
            .map_err(|e| db_error("read last_beacon_time", e))?;
        let mono_at_beacon: i64 = row.get(1).map_err(|e| db_error("read mono_at_beacon", e))?;
        let persisted_floor: i64 = row
            .get(2)
            .map_err(|e| db_error("read persisted_floor", e))?;
        let beacon_boot_id: i64 = row.get(3).map_err(|e| db_error("read beacon_boot_id", e))?;
        let updated_at_mono: i64 = row
            .get(4)
            .map_err(|e| db_error("read updated_at_mono", e))?;

        Ok(Some(TimeRatchetRecord {
            last_beacon_time,
            mono_at_beacon: i64_to_u64(mono_at_beacon),
            persisted_floor,
            beacon_boot_id: i64_to_u64(beacon_boot_id),
            updated_at_mono: i64_to_u64(updated_at_mono),
        }))
    }

    fn save(&self, record: &TimeRatchetRecord) -> Result<(), TimeRatchetError> {
        tirbase_core::fail_crate::fail_point!("fp_time_ratchet_save", |_| Err(
            TimeRatchetError::Store("failpoint fp_time_ratchet_save".to_string())
        ));
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT INTO {TIME_RATCHET_TABLE} (
                     id, last_beacon_time, mono_at_beacon, beacon_boot_id, persisted_floor, \
                     updated_at_mono
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                     last_beacon_time = excluded.last_beacon_time,
                     mono_at_beacon   = excluded.mono_at_beacon,
                     beacon_boot_id   = excluded.beacon_boot_id,
                     persisted_floor  = excluded.persisted_floor,
                     updated_at_mono  = excluded.updated_at_mono"
            ),
            params![
                record.last_beacon_time,
                u64_to_i64(record.mono_at_beacon),
                u64_to_i64(record.beacon_boot_id),
                record.persisted_floor,
                u64_to_i64(record.updated_at_mono),
            ],
        )
        .map_err(|e| db_error("save", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-ratchet-{tag}-{}-{unique}.db",
            std::process::id()
        ))
    }

    #[test]
    fn table_has_the_documented_columns() {
        let db = temp_db("schema");
        let store = SqliteTimeRatchetStore::open(&db).expect("open store");
        let conn = store.lock();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({TIME_RATCHET_TABLE})"))
            .unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(columns, TIME_RATCHET_COLUMNS);
        drop(stmt);
        drop(conn);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn record_round_trips_including_high_bit_boot_ids() {
        let db = temp_db("roundtrip");
        let store = SqliteTimeRatchetStore::open(&db).expect("open store");
        assert!(store.load().unwrap().is_none());

        let record = TimeRatchetRecord {
            last_beacon_time: 1_800_000_000,
            mono_at_beacon: 12_345_678,
            persisted_floor: 1_800_000_000,
            beacon_boot_id: u64::MAX - 3,
            updated_at_mono: 12_345_678,
        };
        store.save(&record).unwrap();
        assert_eq!(store.load().unwrap(), Some(record));

 // A second save overwrites the single row rather than appending.
        let updated = TimeRatchetRecord {
            persisted_floor: 1_800_000_500,
            ..record
        };
        store.save(&updated).unwrap();
        assert_eq!(store.load().unwrap(), Some(updated));
        drop(store);

        let _ = std::fs::remove_file(&db);
    }
}
