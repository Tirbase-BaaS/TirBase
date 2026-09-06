//! IndexedDB persistence layer for the WASM LocalStore (Req 3.1, Subphase 6.3).
//!
//! The WASM build has no SQLite, so the LocalStore's durable story is a
//! browser IndexedDB database — one database per storage path
//! (`tirbase:{storage_path}`).  Rows are stored as JSON strings in a single
//! `kv` object store, keyed by the composite string `"{table}\u{1f}{key}"`.
//!
//! [`IdbStore`] wraps an [`idb::Database`] handle and exposes async
//! `write()` / `read()` / `query()` methods that persist to IndexedDB —
//! surviving page reloads (Req 3.1: IndexedDB as the WASM analogue of
//! SQLite-on-every-client-device).
//!
//! * [`IdbStore::open`] — open (creating on first use) the database for a
//!   storage path, creating the `kv` store during the schema-version upgrade;
//! * [`IdbStore::write`] — write one row through to IndexedDB, awaiting the
//!   transaction's completion so `LocalStore::write` cannot return success
//!   before the row is durably stored (Req 3.2 write-before-ack parity on the
//!   WASM target);
//! * [`IdbStore::read`] — read a single row by key from IndexedDB;
//! * [`IdbStore::query`] — scan all rows in a table from IndexedDB;
//! * [`delete_database`] — drop an entire database (test hygiene / factory
//!   reset).

#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;

use idb::DatabaseEvent;
use serde_json::Value;
use wasm_bindgen::JsValue;

use crate::errors::TirBaseError;

/// Object store holding all rows (key = composite string, value = JSON string).
const KV_STORE: &str = "kv";

/// Schema version of the `kv` object store.  Bump when the layout changes;
/// the `onupgradeneeded` handler fires only when the version increases.
const DB_VERSION: u32 = 1;

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
    db: idb::Database,
}

impl IdbStore {
    /// Open (or create) the IndexedDB database for `db_name` with an object
    /// store named `store_name`.
    ///
    /// On first open the schema-version upgrade callback creates the object
    /// store.  The returned handle stays live for the lifetime of the
    /// [`LocalStore`](super::LocalStore).
    pub(crate) async fn open(db_name: &str, store_name: &str) -> Result<Self, TirBaseError> {
        let name = database_name(db_name);
        let store_name = store_name.to_string();

        let factory = idb::Factory::new().map_err(idb_error)?;

        let mut open_req = factory
            .open(&name, Some(DB_VERSION))
            .map_err(idb_error)?;

        let store_name_for_upgrade = store_name.clone();
        open_req.on_upgrade_needed(move |event| {
            let database = event.database().expect("on_upgrade_needed: no database");
            if !database.store_names().contains(&store_name_for_upgrade) {
                database
                    .create_object_store(&store_name_for_upgrade, idb::ObjectStoreParams::new())
                    .expect("create_object_store failed");
            }
        });

        let db = open_req
            .await
            .map_err(|e| js_error(format!("open IndexedDB database {name} failed: {e:?}")))?;

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
    // First open via IdbStore so the object store is created on first use.
    let _store = IdbStore::open(path, KV_STORE).await?;
    // Re-open to get a standalone handle that the caller owns.
    let name = database_name(path);
    let factory = idb::Factory::new().map_err(idb_error)?;
    let mut open_req = factory
        .open(&name, Some(DB_VERSION))
        .map_err(idb_error)?;
    open_req.on_upgrade_needed(move |event| {
        let database = event.database().expect("on_upgrade_needed: no database");
        let store_name = KV_STORE.to_string();
        if !database.store_names().contains(&store_name) {
            database
                .create_object_store(&store_name, idb::ObjectStoreParams::new())
                .expect("create_object_store failed");
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
