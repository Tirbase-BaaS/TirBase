//! `device_epoch` SQLite store (CLAIM-8.7, PV-5.5, PV-9.8).
//!
//! The table lives in `primary.db` and mirrors design.md §4.13:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS device_epoch (
//! device_id TEXT PRIMARY KEY,
//! epoch INTEGER NOT NULL DEFAULT 0,
//! bumped_at_est INTEGER NOT NULL,
//! co_sig_pa BLOB, -- PolicyAuthority signature; NULL for epoch 0
//! co_sig_rm BLOB -- RevocationManager signature; NULL for epoch 0
//! );
//! ```
//!
//! The epoch starts at 0 on first enrollment and is only advanced by a signed
//! [`EpochBump`](tirbase_guard::epoch::EpochBump). Keeping the row here (not
//! in memory) means a restart cannot silently resurrect a prior epoch.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use tirbase_guard::epoch::{DeviceEpoch, DeviceEpochStore, EpochError};
use tirbase_types::DeviceSignature;

/// Table name (design.md §4.13).
pub const DEVICE_EPOCH_TABLE: &str = "device_epoch";

/// SQLite-backed [`DeviceEpochStore`].
#[derive(Debug)]
pub struct SqliteDeviceEpochStore {
    conn: Mutex<Connection>,
}

impl SqliteDeviceEpochStore {
 /// Open `primary.db`, creating the `device_epoch` table idempotently.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EpochError> {
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
            "CREATE TABLE IF NOT EXISTS {DEVICE_EPOCH_TABLE} (
                 device_id     TEXT PRIMARY KEY,
                 epoch         INTEGER NOT NULL DEFAULT 0,
                 bumped_at_est INTEGER NOT NULL,
                 co_sig_pa     BLOB,
                 co_sig_rm     BLOB
             );"
        ))
        .map_err(|error| EpochError::Store(format!("create device_epoch: {error}")))?;

        Ok(SqliteDeviceEpochStore {
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

fn signature_to_blob(signature: &DeviceSignature) -> Result<Vec<u8>, EpochError> {
    serde_json::to_vec(signature)
        .map_err(|error| EpochError::Store(format!("encode co-signature: {error}")))
}

fn signature_from_blob(blob: &[u8]) -> Result<DeviceSignature, EpochError> {
    serde_json::from_slice(blob)
        .map_err(|error| EpochError::Store(format!("decode co-signature: {error}")))
}

impl DeviceEpochStore for SqliteDeviceEpochStore {
    fn load(&self, device_id: &str) -> Result<Option<DeviceEpoch>, EpochError> {
        let conn = self.lock();
        let row = conn
            .query_row(
                &format!(
                    "SELECT device_id, epoch, bumped_at_est, co_sig_pa, co_sig_rm
                     FROM {DEVICE_EPOCH_TABLE} WHERE device_id = ?1"
                ),
                params![device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| EpochError::Store(format!("load: {error}")))?;

        let Some((device_id, epoch, bumped_at_est, co_sig_pa, co_sig_rm)) = row else {
            return Ok(None);
        };
        let epoch = u64::try_from(epoch)
            .map_err(|_| EpochError::Store(format!("negative epoch {epoch} stored")))?;
        Ok(Some(DeviceEpoch {
            device_id,
            epoch,
            bumped_at_est,
            co_sig_pa: co_sig_pa.as_deref().map(signature_from_blob).transpose()?,
            co_sig_rm: co_sig_rm.as_deref().map(signature_from_blob).transpose()?,
        }))
    }

    fn save(&self, record: &DeviceEpoch) -> Result<(), EpochError> {
        let epoch = i64::try_from(record.epoch)
            .map_err(|_| EpochError::Store("epoch exceeds i64::MAX".to_string()))?;
        let co_sig_pa = record
            .co_sig_pa
            .as_ref()
            .map(signature_to_blob)
            .transpose()?;
        let co_sig_rm = record
            .co_sig_rm
            .as_ref()
            .map(signature_to_blob)
            .transpose()?;

        let conn = self.lock();
        tirbase_core::fail_crate::fail_point!("fp_device_epoch_save", |_| Err(EpochError::Store(
            "failpoint fp_device_epoch_save".into()
        )));
        conn.execute(
            &format!(
                "INSERT INTO {DEVICE_EPOCH_TABLE}
                     (device_id, epoch, bumped_at_est, co_sig_pa, co_sig_rm)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(device_id) DO UPDATE SET
                     epoch = excluded.epoch,
                     bumped_at_est = excluded.bumped_at_est,
                     co_sig_pa = excluded.co_sig_pa,
                     co_sig_rm = excluded.co_sig_rm"
            ),
            params![
                record.device_id,
                epoch,
                record.bumped_at_est,
                co_sig_pa,
                co_sig_rm
            ],
        )
        .map_err(|error| EpochError::Store(format!("save: {error}")))?;
        Ok(())
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
            "tirbase-device-epoch-{tag}-{}-{unique}.db",
            std::process::id()
        ))
    }

    #[test]
    fn table_has_the_documented_columns() {
        let path = temp_db("columns");
        let store = SqliteDeviceEpochStore::open(&path).expect("open");
        let conn = store.lock();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({DEVICE_EPOCH_TABLE})"))
            .unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            columns,
            vec![
                "device_id",
                "epoch",
                "bumped_at_est",
                "co_sig_pa",
                "co_sig_rm"
            ]
        );
        drop(stmt);
        drop(conn);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epoch_zero_row_has_null_signatures_and_survives_reopen() {
        let path = temp_db("roundtrip");
        {
            let store = SqliteDeviceEpochStore::open(&path).expect("open");
            store
                .save(&DeviceEpoch {
                    device_id: "did:key:zDevice".to_string(),
                    epoch: 0,
                    bumped_at_est: 1_000,
                    co_sig_pa: None,
                    co_sig_rm: None,
                })
                .unwrap();
        }

        let store = SqliteDeviceEpochStore::open(&path).expect("reopen");
        let row = store.load("did:key:zDevice").unwrap().expect("row");
        assert_eq!(row.epoch, 0);
        assert!(row.co_sig_pa.is_none());
        assert!(row.co_sig_rm.is_none());
        assert!(store.load("did:key:unknown").unwrap().is_none());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bumped_row_round_trips_both_co_signatures() {
        let path = temp_db("signatures");
        let store = SqliteDeviceEpochStore::open(&path).expect("open");
        let record = DeviceEpoch {
            device_id: "did:key:zDevice".to_string(),
            epoch: 2,
            bumped_at_est: 5_000,
            co_sig_pa: Some(DeviceSignature::Ed25519([1u8; 64])),
            co_sig_rm: Some(DeviceSignature::Ed25519([2u8; 64])),
        };
        store.save(&record).unwrap();
        assert_eq!(store.load("did:key:zDevice").unwrap(), Some(record));
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
