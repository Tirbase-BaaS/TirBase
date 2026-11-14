// SPDX-License-Identifier: AGPL-3.0-only

//! Durable `provisioning_registry` store in `primary.db` (F-04).
//!
//! The registry is persisted as a versioned, transactionally replaced JSON
//! snapshot. The gateway is the single writer for `primary.db`, so one row is
//! sufficient and every lifecycle mutation is atomic: the snapshot is written
//! in the same transaction that commits the operation, and a crash before
//! commit leaves the previous registry intact.
//!
//! The table is created both here (idempotently, for stores opened without the
//! migration framework) and by primary migration v4.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use tirbase_core::provisioning::DeviceLifecycleRegistry;

/// Table holding the durable lifecycle registry snapshot.
pub const PROVISIONING_REGISTRY_TABLE: &str = "provisioning_registry";

/// Row id of the single registry snapshot.
pub const PROVISIONING_REGISTRY_ROW: &str = "gateway";

/// Schema version of the snapshot encoding.
pub const PROVISIONING_REGISTRY_SCHEMA_VERSION: i64 = 1;

/// Store errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningStoreError {
    Unavailable(String),
    Corrupt(String),
}

impl std::fmt::Display for ProvisioningStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisioningStoreError::Unavailable(reason) => {
                write!(f, "provisioning registry unavailable: {reason}")
            }
            ProvisioningStoreError::Corrupt(reason) => {
                write!(f, "provisioning registry is corrupt: {reason}")
            }
        }
    }
}

impl std::error::Error for ProvisioningStoreError {}

impl From<rusqlite::Error> for ProvisioningStoreError {
    fn from(error: rusqlite::Error) -> Self {
        ProvisioningStoreError::Unavailable(error.to_string())
    }
}

/// SQLite-backed durable lifecycle registry.
#[derive(Debug)]
pub struct SqliteProvisioningStore {
    conn: Mutex<Connection>,
}

impl SqliteProvisioningStore {
    /// Open `primary.db`, creating the registry table and seeding an empty
    /// registry when no snapshot exists yet.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProvisioningStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    ProvisioningStoreError::Unavailable(format!("create {parent:?}: {error}"))
                })?;
            }
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {PROVISIONING_REGISTRY_TABLE} (
                 registry_id    TEXT PRIMARY KEY,
                 schema_version INTEGER NOT NULL,
                 updated_at_est INTEGER NOT NULL,
                 snapshot_json  TEXT NOT NULL
             );"
        ))?;
        let store = SqliteProvisioningStore {
            conn: Mutex::new(conn),
        };
        if store.load()?.is_none() {
            store.create_empty()?;
        }
        Ok(store)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn create_empty(&self) -> Result<(), ProvisioningStoreError> {
        let snapshot = serde_json::to_string(&DeviceLifecycleRegistry::new())
            .map_err(|error| ProvisioningStoreError::Corrupt(error.to_string()))?;
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {PROVISIONING_REGISTRY_TABLE}
                     (registry_id, schema_version, updated_at_est, snapshot_json)
                 VALUES (?1, ?2, ?3, ?4)"
            ),
            params![
                PROVISIONING_REGISTRY_ROW,
                PROVISIONING_REGISTRY_SCHEMA_VERSION,
                0i64,
                snapshot
            ],
        )?;
        Ok(())
    }

    /// Load the durable registry.
    pub fn load(&self) -> Result<Option<DeviceLifecycleRegistry>, ProvisioningStoreError> {
        let conn = self.lock();
        let row: Option<(i64, String)> = conn
            .query_row(
                &format!(
                    "SELECT schema_version, snapshot_json FROM {PROVISIONING_REGISTRY_TABLE}
                     WHERE registry_id = ?1"
                ),
                params![PROVISIONING_REGISTRY_ROW],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((schema_version, snapshot)) = row else {
            return Ok(None);
        };
        if schema_version != PROVISIONING_REGISTRY_SCHEMA_VERSION {
            return Err(ProvisioningStoreError::Corrupt(format!(
                "unsupported registry snapshot schema version {schema_version}"
            )));
        }
        let registry = serde_json::from_str(&snapshot)
            .map_err(|error| ProvisioningStoreError::Corrupt(error.to_string()))?;
        Ok(Some(registry))
    }

    /// Transactionally persist the complete registry snapshot.
    pub fn save(
        &self,
        registry: &DeviceLifecycleRegistry,
        now_est: i64,
    ) -> Result<(), ProvisioningStoreError> {
        let snapshot = serde_json::to_string(registry)
            .map_err(|error| ProvisioningStoreError::Corrupt(error.to_string()))?;
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT INTO {PROVISIONING_REGISTRY_TABLE}
                     (registry_id, schema_version, updated_at_est, snapshot_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(registry_id) DO UPDATE SET
                     schema_version = excluded.schema_version,
                     updated_at_est = excluded.updated_at_est,
                     snapshot_json = excluded.snapshot_json"
            ),
            params![
                PROVISIONING_REGISTRY_ROW,
                PROVISIONING_REGISTRY_SCHEMA_VERSION,
                now_est,
                snapshot
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::provisioning::DeviceState;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tb-f04-store-{tag}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn snapshot_survives_reopen() {
        let path = temp_path("reopen");
        {
            let store = SqliteProvisioningStore::open(&path).unwrap();
            let mut registry = store.load().unwrap().unwrap();
            assert_eq!(
                registry.query(&Default::default()).len(),
                0,
                "fresh registry is empty"
            );
            registry.issue_claim_code(
                tirbase_types::identity::TenantPath::new(vec![
                    tirbase_types::identity::TenantSegment::new(
                        tirbase_types::identity::TenantLevel::Organisation,
                        "acme",
                    ),
                ]),
                None,
                None,
                "op",
                1000,
                600,
                b"nonce",
            );
            store.save(&registry, 1000).unwrap();
        }
        let reopened = SqliteProvisioningStore::open(&path).unwrap();
        let registry = reopened.load().unwrap().unwrap();
        assert_eq!(registry.query(&Default::default()).len(), 0);
        assert!(!registry.audit_log().is_empty(), "audit survives reopen");
        let _ = DeviceState::Active;
        let _ = std::fs::remove_file(&path);
    }
}
