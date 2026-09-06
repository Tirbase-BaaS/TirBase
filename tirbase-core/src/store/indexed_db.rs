//! IndexedDB persistence layer for the WASM LocalStore (Req 3.1, Subphase 6.3).
//!
//! The WASM build has no SQLite, so the LocalStore's durable story is a
//! browser IndexedDB database — one database per storage path
//! (`tirbase:{storage_path}`).
//!
//! [`IdbStore`] wraps an [`idb::Database`] handle that contains four object
//! stores:
//!   - `kv` — application rows (key = composite `"{table}\u{1f}{key}"`, value = JSON string)
//!   - `compaction_snapshots` — compacted Automerge doc snapshots (Req 3.4/3.5, WASM)
//!   - `quarantine_ledger` — quarantined Delta raw bytes (Req 17.5, WASM)
//!   - `sidecar_ledger` — Side-Car write entries for corrupted-schema replay (Req 19.2/19.3, WASM)
//!
//! All object stores are created during the schema-version upgrade callback in
//! [`IdbStore::open`], so a single database open establishes the full WASM
//! persistence contract.

#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;

use idb::DatabaseEvent;
use serde_json::Value;
use wasm_bindgen::JsValue;

use crate::errors::TirBaseError;

/// Object store holding all rows (key = composite string, value = JSON string).
const KV_STORE: &str = "kv";

/// Object store for compacted Automerge doc snapshots (Req 3.4/3.5, WASM).
/// Key: table_name (string). Value: JSON-serialised CompactionSnapshot.
const COMPACTION_STORE: &str = "compaction_snapshots";

/// Object store for quarantined Delta raw bytes (Req 17.5, WASM).
/// Key: schema_hash (hex string). Value: JSON-serialised QuarantineEntry.
const QUARANTINE_STORE: &str = "quarantine_ledger";

/// Object store for Side-Car write entries (Req 19.2/19.3, WASM).
/// Key: delta_id (hex string). Value: JSON-serialised SideCarEntry.
const SIDECAR_STORE: &str = "sidecar_ledger";

/// Schema version of the IndexedDB database.
/// v1: `kv` object store only (initial Subphase 6.3).
/// v2: adds `compaction_snapshots`, `quarantine_ledger`, and `sidecar_ledger`
///     object stores for real WASM-side persistence of compaction, quarantine,
///     and Side-Car data (Req 3.4/3.5, 17.5, 19.2/19.3).
const DB_VERSION: u32 = 2;

/// Separator between the table name and row key inside the composite IndexedDB
/// key.  `\u{1f}` (unit separator) is not a character TirBase table names,
/// row keys, or JSON values can contain, so the split is unambiguous.
const KEY_SEP: char = '\u{1f}';

/// IndexedDB database name for a storage path (distinct paths → distinct DBs).
fn database_name(path: &str) -> String {
    format!("tirbase:{path}")
}

/// Compose the IndexedDB key for `(table, key)`.
pub(crate) fn composite_key(table: &str, key: &str) -> String {
    format!("{table}{KEY_SEP}{key}")
}

/// Split a composite IndexedDB key back into `(table, key)`.
fn split_composite_key(composite: &str) -> Result<(String, String), TirBaseError> {
    match composite.split_once(KEY_SEP) {
        Some((table, key)) => Ok((table.to_string(), key.to_string())),
        None => Err(js_error(format!(
            "corrupt IndexedDB key (no separator): {composite:?}"
        ))),
    }
}

/// Wrap a message as a `LocalStoreWriteFailed` (the store's error type on both
/// build targets).
fn js_error(reason: impl std::fmt::Display) -> TirBaseError {
    TirBaseError::LocalStoreWriteFailed {
        reason: reason.to_string(),
    }
}

/// Wrap an `idb::Error` as a `TirBaseError`.
fn idb_error(e: idb::Error) -> TirBaseError {
    js_error(format!("{e:?}"))
}

/// IndexedDB-backed persistent store for the WASM LocalStore.
///
/// Wraps an [`idb::Database`] handle and exposes async `write()`, `read()`,
/// and `query()` methods that persist to IndexedDB — surviving page reloads
/// (Req 3.1: IndexedDB as the WASM analogue of SQLite-on-every-client-device).
pub(crate) struct IdbStore {
    db_name: String,
    store_name: String,
    db: std::rc::Rc<idb::Database>,
}

impl IdbStore {
    /// Open (or create) the IndexedDB database for `db_name`, creating all
    /// object stores (`kv`, `compaction_snapshots`, `quarantine_ledger`,
    /// `sidecar_ledger`) during the schema-version upgrade.
    ///
    /// The returned handle stays live for the lifetime of the
    /// [`LocalStore`](super::LocalStore) and may be cloned to share the
    /// underlying database connection across the store, CRDT engine, and
    /// migration engine.
    pub(crate) async fn open(db_name: &str) -> Result<Self, TirBaseError> {
        let name = database_name(db_name);
        let store_name = KV_STORE.to_string();

        let factory = idb::Factory::new().map_err(idb_error)?;

        let mut open_req = factory
            .open(&name, Some(DB_VERSION))
            .map_err(idb_error)?;

        let store_name_for_upgrade = store_name.clone();
        open_req.on_upgrade_needed(move |event| {
            let database = event.database().expect("on_upgrade_needed: no database");
            // Create each store if it doesn't exist yet (idempotent across
            // version bumps — only newly-required stores need creating).
            let stores: &[(&str, bool)] = &[
                (KV_STORE, false),
                (COMPACTION_STORE, false),
                (QUARANTINE_STORE, false),
                (SIDECAR_STORE, false),
            ];
            for (store_name, _key_path) in stores {
                if !database.store_names().iter().any(|s| s == *store_name) {
                    database
                        .create_object_store(store_name, idb::ObjectStoreParams::new())
                        .unwrap_or_else(|e| panic!("create_object_store({store_name}) failed: {e:?}"));
                }
            }
            // Ensure the kv store is still present.
            let _ = &store_name_for_upgrade;
        });

        let db = std::rc::Rc::new(open_req
            .await
            .map_err(|e| js_error(format!("open IndexedDB database {name} failed: {e:?}")))?);

        Ok(IdbStore {
            db_name: name,
            store_name,
            db,
        })
    }

    /// Write one row through to IndexedDB, awaiting the transaction's
    /// completion.
    ///
    /// Returns only after the `readwrite` transaction has fully committed, so a
    /// successful `LocalStore::write` is durable — the WASM store no longer
    /// acknowledges writes that vanish on reload (Req 3.2 parity).
    pub(crate) async fn write(
        &self,
        table: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), TirBaseError> {
        let composite = composite_key(table, key);
        let value_str = String::from_utf8(value.to_vec()).map_err(|e| {
            js_error(format!("row value is not valid UTF-8: {e}"))
        })?;

        let tx = self
            .db
            .transaction(&[&self.store_name], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction (readwrite) failed: {e:?}")))?;

        let store = tx
            .object_store(&self.store_name)
            .map_err(|e| js_error(format!("object_store({}) failed: {e:?}", self.store_name)))?;

        let value_js = JsValue::from_str(&value_str);
        let composite_js = JsValue::from_str(&composite);
        store
            .put(&value_js, Some(&composite_js))
            .map_err(|e| js_error(format!("put({:?}) failed: {e:?}", composite)))?
            .await
            .map_err(|e| js_error(format!("put({:?}) await failed: {e:?}", composite)))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(())
    }

    /// Read a single row by table and key from IndexedDB.
    pub(crate) async fn read(
        &self,
        table: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, TirBaseError> {
        let composite = composite_key(table, key);

        let tx = self
            .db
            .transaction(&[&self.store_name], idb::TransactionMode::ReadOnly)
            .map_err(|e| js_error(format!("IDB transaction (readonly) failed: {e:?}")))?;

        let store = tx
            .object_store(&self.store_name)
            .map_err(|e| js_error(format!("object_store({}) failed: {e:?}", self.store_name)))?;

        let result = store
            .get(JsValue::from_str(&composite))
            .map_err(|e| js_error(format!("get({:?}) failed: {e:?}", composite)))?
            .await
            .map_err(|e| js_error(format!("get({:?}) await failed: {e:?}", composite)))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        match result {
            Some(value_str) => {
                let value_str = value_str
                    .as_string()
                    .ok_or_else(|| js_error("IndexedDB value is not a string"))?;
                let value: Value = serde_json::from_str(&value_str).map_err(|e| {
                    js_error(format!("row {:?}: stored JSON is invalid: {e}", composite))
                })?;
                let bytes = serde_json::to_vec(&value).map_err(|e| {
                    js_error(format!("row {:?}: re-serialisation failed: {e}", composite))
                })?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Scan all rows in a table from IndexedDB, returning `(key, value)` pairs.
    pub(crate) async fn query(
        &self,
        table: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, TirBaseError> {
        let prefix = format!("{table}{KEY_SEP}");
        let mut results: Vec<(String, Vec<u8>)> = Vec::new();

        let tx = self
            .db
            .transaction(&[&self.store_name], idb::TransactionMode::ReadOnly)
            .map_err(|e| js_error(format!("IDB transaction (readonly) failed: {e:?}")))?;

        let store = tx
            .object_store(&self.store_name)
            .map_err(|e| js_error(format!("object_store({}) failed: {e:?}", self.store_name)))?;

        // Use a key range to scan only rows whose composite key starts with
        // the `{table}\u{1f}` prefix.
        let lower = JsValue::from_str(&format!("{prefix}\u{0000}"));
        let upper = JsValue::from_str(&format!("{prefix}\u{ffff}"));
        let range = idb::KeyRange::bound(&lower, &upper, Some(false), Some(false))
            .map_err(|e| js_error(format!("KeyRange construction failed: {e:?}")))?;

        let query = Some(idb::Query::KeyRange(range));
        let mut cursor = store
            .open_cursor(query, Some(idb::CursorDirection::Next))
            .map_err(|e| js_error(format!("open_cursor failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("open_cursor await failed: {e:?}")))?
            .ok_or_else(|| js_error("cursor is null (store empty or error)"))?
            .into_managed();

        loop {
            match cursor.value() {
                Ok(Some(value_js)) => {
                    let composite = cursor
                        .primary_key()
                        .map_err(|e| js_error(format!("cursor key failed: {e:?}")))?
                        .ok_or_else(|| js_error("cursor key is null"))?
                        .as_string()
                        .ok_or_else(|| js_error("cursor key is not a string"))?;
                    let value_str = value_js
                        .as_string()
                        .ok_or_else(|| js_error("cursor value is not a string"))?;

                    let (_, row_key) = split_composite_key(&composite)?;
                    let value: Value = serde_json::from_str(&value_str)
                        .map_err(|e| {
                            js_error(format!("row {:?}: stored JSON is invalid: {e}", composite))
                        })?;
                    let bytes = serde_json::to_vec(&value)
                        .map_err(|e| {
                            js_error(format!("row {:?}: re-serialisation failed: {e}", composite))
                        })?;

                    results.push((row_key, bytes));

                    cursor
                        .next(None)
                        .await
                        .map_err(|e| js_error(format!("cursor.next() failed: {e:?}")))?;
                }
                Ok(None) => break,
                Err(e) => return Err(js_error(format!("cursor.value() failed: {e:?}"))),
            }
        }

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(results)
    }

    /// Eagerly load every row in the store into an in-memory map, keyed by
    /// `(table, key)`.  Called by `LocalStore::open` so that `read()` and
    /// `query()` can stay synchronous (serving from the in-memory snapshot,
    /// the WASM analogue of native SQLite projection tables).
    pub(crate) async fn load_all(
        &self,
    ) -> Result<HashMap<String, HashMap<String, Value>>, TirBaseError> {
        let mut tables: HashMap<String, HashMap<String, Value>> = HashMap::new();

        let tx = self
            .db
            .transaction(&[&self.store_name], idb::TransactionMode::ReadOnly)
            .map_err(|e| js_error(format!("IDB transaction (readonly) failed: {e:?}")))?;

        let store = tx
            .object_store(&self.store_name)
            .map_err(|e| js_error(format!("object_store({}) failed: {e:?}", self.store_name)))?;

        let mut cursor = store
            .open_cursor(None, Some(idb::CursorDirection::Next))
            .map_err(|e| js_error(format!("open_cursor failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("open_cursor await failed: {e:?}")))?
            .ok_or_else(|| js_error("cursor is null (store empty or error)"))?
            .into_managed();

        loop {
            match cursor.value() {
                Ok(Some(value_js)) => {
                    let composite = cursor
                        .primary_key()
                        .map_err(|e| js_error(format!("cursor key failed: {e:?}")))?
                        .ok_or_else(|| js_error("cursor key is null"))?
                        .as_string()
                        .ok_or_else(|| js_error("cursor key is not a string"))?;
                    let value_str = value_js
                        .as_string()
                        .ok_or_else(|| js_error("cursor value is not a string"))?;

                    let value: Value = serde_json::from_str(&value_str)
                        .map_err(|e| {
                            js_error(format!("row {:?}: stored JSON is invalid: {e}", composite))
                        })?;

                    let (table, row_key) = split_composite_key(&composite)?;
                    tables
                        .entry(table)
                        .or_insert_with(HashMap::new)
                        .insert(row_key, value);

                    cursor
                        .next(None)
                        .await
                        .map_err(|e| js_error(format!("cursor.next() failed: {e:?}")))?;
                }
                Ok(None) => break,
                Err(e) => return Err(js_error(format!("cursor.value() failed: {e:?}"))),
            }
        }

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(tables)
    }

    /// Returns the database name (for diagnostics / test reset).
    pub(crate) fn db_name(&self) -> &str {
        &self.db_name
    }

    /// Access the underlying `idb::Database` for creating store-specific
    /// transactions.  Used by the compaction, quarantine, and side-car modules
    /// to operate on their dedicated object stores within the same database.
    pub(crate) fn raw_db(&self) -> &idb::Database {
        &self.db
    }
}

impl Clone for IdbStore {
    fn clone(&self) -> Self {
        Self {
            db_name: self.db_name.clone(),
            store_name: self.store_name.clone(),
            db: self.db.clone(),
        }
    }
}

// ─── Compaction snapshot persistence (Req 3.4/3.5, WASM) ────────────────────────

/// A single compaction snapshot persisted to the `compaction_snapshots` object
/// store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct CompactionSnapshot {
    /// Snapshot bytes (compacted Automerge doc.save()).
    pub snapshot_bytes: Vec<u8>,
    /// UTC timestamp (microseconds) when the snapshot was stored.
    pub compacted_at: i64,
}

impl IdbStore {
    /// Store a compaction snapshot for `table` (Req 3.4/3.5, WASM).
    ///
    /// Writes to the `compaction_snapshots` object store keyed by the table
    /// name (string).  Awaiting the transaction commit makes the snapshot
    /// durable before returning.
    pub(crate) async fn put_compaction_snapshot(
        &self,
        table: &str,
        snapshot: &CompactionSnapshot,
    ) -> Result<(), TirBaseError> {
        let value_json = serde_json::to_string(snapshot)
            .map_err(|e| js_error(format!("compaction snapshot serialisation failed: {e}")))?;
        let value_js = JsValue::from_str(&value_json);
        let key_js = JsValue::from_str(table);

        let tx = self
            .db
            .transaction(&[COMPACTION_STORE], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction (readwrite) for compaction failed: {e:?}")))?;

        let store = tx
            .object_store(COMPACTION_STORE)
            .map_err(|e| js_error(format!("object_store({COMPACTION_STORE}) failed: {e:?}")))?;

        store
            .put(&value_js, Some(&key_js))
            .map_err(|e| js_error(format!("put(compaction {table}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("put(compaction {table}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(())
    }

    /// Load a compaction snapshot for `table` (Req 3.4/3.5, WASM).
    pub(crate) async fn get_compaction_snapshot(
        &self,
        table: &str,
    ) -> Result<Option<CompactionSnapshot>, TirBaseError> {
        let key_js = JsValue::from_str(table);

        let tx = self
            .db
            .transaction(&[COMPACTION_STORE], idb::TransactionMode::ReadOnly)
            .map_err(|e| js_error(format!("IDB transaction (readonly) for compaction failed: {e:?}")))?;

        let store = tx
            .object_store(COMPACTION_STORE)
            .map_err(|e| js_error(format!("object_store({COMPACTION_STORE}) failed: {e:?}")))?;

        let result = store
            .get(key_js.clone())
            .map_err(|e| js_error(format!("get(compaction {table}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("get(compaction {table}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        match result {
            Some(value_js) => {
                let value_str = value_js
                    .as_string()
                    .ok_or_else(|| js_error("compaction snapshot value is not a string"))?;
                let snapshot: CompactionSnapshot = serde_json::from_str(&value_str)
                    .map_err(|e| js_error(format!("compaction snapshot JSON invalid: {e}")))?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    /// Delete all compaction snapshots for a table (used when the snapshot is
    /// reloaded and a re-compaction is needed).
    pub(crate) async fn delete_compaction_snapshot(&self, table: &str) -> Result<(), TirBaseError> {
        let key_js = JsValue::from_str(table);

        let tx = self
            .db
            .transaction(&[COMPACTION_STORE], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction (readwrite) for compaction delete failed: {e:?}")))?;

        let store = tx
            .object_store(COMPACTION_STORE)
            .map_err(|e| js_error(format!("object_store({COMPACTION_STORE}) failed: {e:?}")))?;

        store
            .delete(key_js.clone())
            .map_err(|e| js_error(format!("delete(compaction {table}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("delete(compaction {table}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(())
    }
}

// ─── Quarantine ledger persistence (Req 17.5, WASM) ───────────────────────────

impl IdbStore {
    /// Store a quarantined `QuarantineEntry` in the `quarantine_ledger` object
    /// store (Req 17.5).
    ///
    /// The entry is keyed by `id` hex so it can be fetched or checked for
    /// existence quickly.  Awaiting the transaction commit makes the entry
    /// durable before returning.
    pub(crate) async fn put_quarantine_entry(
        &self,
        entry: &crate::migration::quarantine::QuarantineEntry,
    ) -> Result<(), TirBaseError> {
        let key = hex::encode(&entry.id[..]);
        let value_json = serde_json::to_string(entry)
            .map_err(|e| js_error(format!("quarantine entry serialisation failed: {e}")))?;
        let value_js = JsValue::from_str(&value_json);
        let key_js = JsValue::from_str(&key);

        let tx = self
            .db
            .transaction(&[QUARANTINE_STORE], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction for quarantine failed: {e:?}")))?;

        let store = tx
            .object_store(QUARANTINE_STORE)
            .map_err(|e| js_error(format!("object_store({QUARANTINE_STORE}) failed: {e:?}")))?;

        store
            .put(&value_js, Some(&key_js))
            .map_err(|e| js_error(format!("put(quarantine {key}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("put(quarantine {key}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(())
    }

    /// Scan every entry in the `quarantine_ledger` object store.
    pub(crate) async fn scan_quarantine_entries(
        &self,
    ) -> Result<Vec<crate::migration::quarantine::QuarantineEntry>, TirBaseError> {
        let mut results: Vec<crate::migration::quarantine::QuarantineEntry> = Vec::new();

        let tx = self
            .db
            .transaction(&[QUARANTINE_STORE], idb::TransactionMode::ReadOnly)
            .map_err(|e| js_error(format!("IDB transaction for quarantine scan failed: {e:?}")))?;

        let store = tx
            .object_store(QUARANTINE_STORE)
            .map_err(|e| js_error(format!("object_store({QUARANTINE_STORE}) failed: {e:?}")))?;

        let mut cursor = store
            .open_cursor(None, Some(idb::CursorDirection::Next))
            .map_err(|e| js_error(format!("open_cursor for quarantine failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("open_cursor await for quarantine failed: {e:?}")))?
            .ok_or_else(|| js_error("quarantine cursor is null"))?
            .into_managed();

        loop {
            match cursor.value() {
                Ok(Some(value_js)) => {
                    let value_str = value_js
                        .as_string()
                        .ok_or_else(|| js_error("quarantine value is not a string"))?;
                    let entry: crate::migration::quarantine::QuarantineEntry =
                        serde_json::from_str(&value_str)
                            .map_err(|e| js_error(format!("quarantine JSON invalid: {e}")))?;
                    results.push(entry);

                    cursor
                        .next(None)
                        .await
                        .map_err(|e| js_error(format!("quarantine cursor.next() failed: {e:?}")))?;
                }
                Ok(None) => break,
                Err(e) => return Err(js_error(format!("quarantine cursor.value() failed: {e:?}"))),
            }
        }

        tx.commit()
            .map_err(|e| js_error(format!("quarantine tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("quarantine tx commit await failed: {e:?}")))?;

        Ok(results)
    }

    /// Update the `migration_id` field on a quarantine entry in-place.
    pub(crate) async fn update_quarantine_migration_id(
        &self,
        entry_id: &[u8],
        migration_id: Option<[u8; 32]>,
    ) -> Result<(), TirBaseError> {
        let key = hex::encode(entry_id);

        let tx = self
            .db
            .transaction(&[QUARANTINE_STORE], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction for quarantine update failed: {e:?}")))?;

        let store = tx
            .object_store(QUARANTINE_STORE)
            .map_err(|e| js_error(format!("object_store({QUARANTINE_STORE}) failed: {e:?}")))?;

        let current_js = store
            .get(JsValue::from_str(&key))
            .map_err(|e| js_error(format!("get(quarantine {key}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("get(quarantine {key}) await failed: {e:?}")))?
            .ok_or_else(|| js_error(format!("quarantine entry {key} not found for update")))?;

        let mut entry: crate::migration::quarantine::QuarantineEntry = {
            let value_str = current_js
                .as_string()
                .ok_or_else(|| js_error("quarantine value is not a string"))?;
            serde_json::from_str(&value_str)
                .map_err(|e| js_error(format!("quarantine JSON invalid: {e}")))?
        };
        entry.migration_id = migration_id;

        let value_json = serde_json::to_string(&entry)
            .map_err(|e| js_error(format!("quarantine re-serialisation failed: {e}")))?;
        store
            .put(
                &JsValue::from_str(&value_json),
                Some(&JsValue::from_str(&key)),
            )
            .map_err(|e| js_error(format!("put(quarantine {key}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("put(quarantine {key}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("quarantine tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("quarantine tx commit await failed: {e:?}")))?;

        Ok(())
    }
}

// ─── Side-Car ledger persistence (Req 19.2/19.3, WASM) ────────────────────────

impl IdbStore {
    /// Record a Side-Car entry in the `sidecar_ledger` object store (Req 19.2).
    pub(crate) async fn put_sidecar_entry(
        &self,
        entry: &crate::migration::sidecar::SideCarEntry,
    ) -> Result<(), TirBaseError> {
        let key = hex::encode(&entry.id[..]);
        let value_json = serde_json::to_string(entry)
            .map_err(|e| js_error(format!("sidecar entry serialisation failed: {e}")))?;
        let value_js = JsValue::from_str(&value_json);
        let key_js = JsValue::from_str(&key);

        let tx = self
            .db
            .transaction(&[SIDECAR_STORE], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction for sidecar failed: {e:?}")))?;

        let store = tx
            .object_store(SIDECAR_STORE)
            .map_err(|e| js_error(format!("object_store({SIDECAR_STORE}) failed: {e:?}")))?;

        store
            .put(&value_js, Some(&key_js))
            .map_err(|e| js_error(format!("put(sidecar {key}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("put(sidecar {key}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

        Ok(())
    }

    /// Scan all Side-Car entries for a `migration_id`, returning them in
    /// recorded-timestamp order (Req 19.3).
    pub(crate) async fn scan_sidecar_entries_for_migration(
        &self,
        migration_id: crate::migration::migration_delta::MigrationId,
    ) -> Result<Vec<crate::migration::sidecar::SideCarEntry>, TirBaseError> {
        let mut results: Vec<crate::migration::sidecar::SideCarEntry> = Vec::new();
        let mig_hex = hex::encode(&migration_id[..]);

        let tx = self
            .db
            .transaction(&[SIDECAR_STORE], idb::TransactionMode::ReadOnly)
            .map_err(|e| js_error(format!("IDB transaction for sidecar scan failed: {e:?}")))?;

        let store = tx
            .object_store(SIDECAR_STORE)
            .map_err(|e| js_error(format!("object_store({SIDECAR_STORE}) failed: {e:?}")))?;

        let mut cursor = store
            .open_cursor(None, Some(idb::CursorDirection::Next))
            .map_err(|e| js_error(format!("open_cursor for sidecar failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("open_cursor await for sidecar failed: {e:?}")))?
            .ok_or_else(|| js_error("sidecar cursor is null"))?
            .into_managed();

        loop {
            match cursor.value() {
                Ok(Some(value_js)) => {
                    let value_str = value_js
                        .as_string()
                        .ok_or_else(|| js_error("sidecar value is not a string"))?;
                    let entry: crate::migration::sidecar::SideCarEntry =
                        serde_json::from_str(&value_str)
                            .map_err(|e| js_error(format!("sidecar JSON invalid: {e}")))?;
                    if hex::encode(&entry.migration_id[..]) == mig_hex {
                        results.push(entry);
                    }
                    cursor
                        .next(None)
                        .await
                        .map_err(|e| js_error(format!("sidecar cursor.next() failed: {e:?}")))?;
                }
                Ok(None) => break,
                Err(e) => return Err(js_error(format!("sidecar cursor.value() failed: {e:?}"))),
            }
        }

        tx.commit()
            .map_err(|e| js_error(format!("sidecar tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("sidecar tx commit await failed: {e:?}")))?;

        results.sort_by_key(|e| e.recorded_ts);
        Ok(results)
    }

    /// Update the `replay_status` and `conflict_info` on a Side-Car entry.
    pub(crate) async fn update_sidecar_status(
        &self,
        entry_id: &[u8],
        status_json: &str,
    ) -> Result<(), TirBaseError> {
        let key = hex::encode(entry_id);

        let tx = self
            .db
            .transaction(&[SIDECAR_STORE], idb::TransactionMode::ReadWrite)
            .map_err(|e| js_error(format!("IDB transaction for sidecar update failed: {e:?}")))?;

        let store = tx
            .object_store(SIDECAR_STORE)
            .map_err(|e| js_error(format!("object_store({SIDECAR_STORE}) failed: {e:?}")))?;

        let current_js = store
            .get(JsValue::from_str(&key))
            .map_err(|e| js_error(format!("get(sidecar {key}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("get(sidecar {key}) await failed: {e:?}")))?
            .ok_or_else(|| js_error(format!("sidecar entry {key} not found for update")))?;

        let mut entry: crate::migration::sidecar::SideCarEntry = {
            let value_str = current_js
                .as_string()
                .ok_or_else(|| js_error("sidecar value is not a string"))?;
            serde_json::from_str(&value_str)
                .map_err(|e| js_error(format!("sidecar JSON invalid: {e}")))?
        };
        entry.replay_status = serde_json::from_str(status_json)
            .map_err(|e| js_error(format!("sidecar status JSON invalid: {e}")))?;

        let value_json = serde_json::to_string(&entry)
            .map_err(|e| js_error(format!("sidecar re-serialisation failed: {e}")))?;
        store
            .put(&JsValue::from_str(&value_json), Some(&JsValue::from_str(&key)))
            .map_err(|e| js_error(format!("put(sidecar {key}) failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("put(sidecar {key}) await failed: {e:?}")))?;

        tx.commit()
            .map_err(|e| js_error(format!("sidecar tx.commit() failed: {e:?}")))?
            .await
            .map_err(|e| js_error(format!("sidecar tx commit await failed: {e:?}")))?;

        Ok(())
    }
}

/// Delete the entire IndexedDB database for `path` (test hygiene / factory
/// reset).  Deleting a non-existent database still succeeds.
pub(crate) async fn delete_database(path: &str) -> Result<(), TirBaseError> {
    let name = database_name(path);
    let factory = idb::Factory::new().map_err(idb_error)?;

    factory
        .delete(&name)
        .map_err(idb_error)?
        .await
        .map_err(|e| js_error(format!("deleteDatabase({name}) failed: {e:?}")))?;

    Ok(())
}

// ─── Backwards-compatible free functions ─────────────────────────────────────
//
// These were the original API used by the first version of the IndexedDB
// integration (using web-sys directly).  They are retained for any external
// callers that need a raw `idb::Database` handle or the original free-function
// signatures, but the preferred path is now [`IdbStore`].

/// Open (creating on first use) the IndexedDB database for `path` and return
/// the raw `idb::Database` handle by re-opening after the `IdbStore` has
/// created the schema.
pub(crate) async fn open_database(path: &str) -> Result<idb::Database, TirBaseError> {
    // First open via IdbStore so the object stores are created on first use.
    let _store = IdbStore::open(path).await?;
    // Re-open to get a standalone handle that the caller owns.
    let name = database_name(path);
    let factory = idb::Factory::new().map_err(idb_error)?;
    let mut open_req = factory
        .open(&name, Some(DB_VERSION))
        .map_err(idb_error)?;
    open_req.on_upgrade_needed(move |event| {
        let database = event.database().expect("on_upgrade_needed: no database");
        for store_name in [KV_STORE, COMPACTION_STORE, QUARANTINE_STORE, SIDECAR_STORE] {
            if !database.store_names().iter().any(|s| s == store_name) {
                database
                    .create_object_store(store_name, idb::ObjectStoreParams::new())
                    .expect("create_object_store failed");
            }
        }
    });
    open_req
        .await
        .map_err(|e| js_error(format!("await open_database({name}) failed: {e:?}")))
}

/// Eager-load every row into an in-memory `HashMap<table, HashMap<key, Value>>`
/// from a raw `idb::Database` handle.
pub(crate) async fn load_all_into(
    db: &idb::Database,
) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, TirBaseError> {
    // Construct a temporary IdbStore wrapping the caller's database handle
    // purely to reuse load_all's cursor logic.  We can't clone idb::Database,
    // so we reconstruct the IdbStore struct fields manually — the db field
    // is not Clone, so we use a different approach: inline the cursor scan.
    let tx = db
        .transaction(&[KV_STORE], idb::TransactionMode::ReadOnly)
        .map_err(|e| js_error(format!("IDB transaction (readonly) failed: {e:?}")))?;

    let store = tx
        .object_store(KV_STORE)
        .map_err(|e| js_error(format!("object_store({KV_STORE}) failed: {e:?}")))?;

    let mut tables: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();

    let mut cursor = store
        .open_cursor(None, Some(idb::CursorDirection::Next))
        .map_err(|e| js_error(format!("open_cursor failed: {e:?}")))?
        .await
        .map_err(|e| js_error(format!("open_cursor await failed: {e:?}")))?
        .ok_or_else(|| js_error("cursor is null (store empty or error)"))?
        .into_managed();

    loop {
        match cursor.value() {
            Ok(Some(value_js)) => {
                let composite = cursor
                    .primary_key()
                    .map_err(|e| js_error(format!("cursor key failed: {e:?}")))?
                    .ok_or_else(|| js_error("cursor key is null"))?
                    .as_string()
                    .ok_or_else(|| js_error("cursor key is not a string"))?;
                let value_str = value_js
                    .as_string()
                    .ok_or_else(|| js_error("cursor value is not a string"))?;

                let value: serde_json::Value = serde_json::from_str(&value_str).map_err(|e| {
                    js_error(format!("row {:?}: stored JSON is invalid: {e}", composite))
                })?;

                let (table, row_key) = split_composite_key(&composite)?;
                tables
                    .entry(table)
                    .or_insert_with(HashMap::new)
                    .insert(row_key, value);

                cursor
                    .next(None)
                    .await
                    .map_err(|e| js_error(format!("cursor.next() failed: {e:?}")))?;
            }
            Ok(None) => break,
            Err(e) => return Err(js_error(format!("cursor.value() failed: {e:?}"))),
        }
    }

    tx.commit()
        .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
        .await
        .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

    Ok(tables)
}

/// Write one row through to IndexedDB, awaiting the transaction's completion.
pub(crate) async fn put_row(
    db: &idb::Database,
    table: &str,
    key: &str,
    data: &serde_json::Value,
) -> Result<(), TirBaseError> {
    let value_json = serde_json::to_string(data)
        .map_err(|e| js_error(format!("row serialisation failed: {e}")))?;
    let composite = composite_key(table, key);

    let tx = db
        .transaction(&[KV_STORE], idb::TransactionMode::ReadWrite)
        .map_err(|e| js_error(format!("IDB transaction (readwrite) failed: {e:?}")))?;

    let store = tx
        .object_store(KV_STORE)
        .map_err(|e| js_error(format!("object_store({KV_STORE}) failed: {e:?}")))?;

    let value_js = JsValue::from_str(&value_json);
    let composite_js = JsValue::from_str(&composite);
    store
        .put(&value_js, Some(&composite_js))
        .map_err(|e| js_error(format!("put({:?}) failed: {e:?}", composite)))?
        .await
        .map_err(|e| js_error(format!("put({:?}) await failed: {e:?}", composite)))?;

    tx.commit()
        .map_err(|e| js_error(format!("tx.commit() failed: {e:?}")))?
        .await
        .map_err(|e| js_error(format!("tx commit await failed: {e:?}")))?;

    Ok(())
}
