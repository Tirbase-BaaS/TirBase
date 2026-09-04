//! IndexedDB persistence layer for the WASM LocalStore (Subphase 6.3).
//!
//! The WASM build has no SQLite, so the LocalStore's durable story is a
//! browser IndexedDB database — one database per storage path
//! (`tirbase:{storage_path}`).  Rows are stored as JSON strings in a single
//! `kv` object store, keyed by the composite string `"{table}\u{1f}{key}"`.
//!
//! * [`open_database`] — open (creating on first use) the database for a
//!   storage path, creating the `kv` store during the schema-version upgrade;
//! * [`load_all`] — eager-load every row into an in-memory
//!   `HashMap<table, HashMap<key, Value>>` at open, so `LocalStore::read` /
//!   `LocalStore::query` stay synchronous and never touch IndexedDB after
//!   initialisation;
//! * [`put_row`] — write one row through to IndexedDB, awaiting the
//!   transaction's completion so `LocalStore::write` cannot return success
//!   before the row is durably stored (Req 3.2 write-before-ack parity on the
//!   WASM target);
//! * [`delete_database`] — drop an entire database (test hygiene / factory
//!   reset).
//!
//! IndexedDB requests are event-based rather than promise-based, so
//! [`request_to_promise`] / [`transaction_to_promise`] bridge the DOM event
//! handlers into `js_sys::Promise` values awaited via `JsFuture`.  Handlers
//! are installed synchronously inside the promise executor — before the next
//! cursor `continue_()` or request completion can dispatch (IndexedDB events
//! are always asynchronous), so no event can be missed.

#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;

use js_sys::Promise;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    IdbDatabase, IdbRequest, IdbTransaction, IdbTransactionMode,
};

use crate::errors::TirBaseError;

/// Object store holding all rows (key = composite string, value = JSON string).
const KV_STORE: &str = "kv";

/// Schema version of the `kv` object store.  Bump when the layout changes;
/// `IDBFactory::open` fires `onupgradeneeded` only when the version increases.
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

/// Human-readable description of a DOM error (name + message).
fn dom_error_description(exception: &web_sys::DomException) -> String {
    format!("{}: {}", exception.name(), exception.message())
}

/// Await an `IDBRequest` through its promise bridge, mapping the JS error to
/// `TirBaseError` with `what` naming the failing operation.
async fn await_request(request: &IdbRequest, what: &str) -> Result<JsValue, TirBaseError> {
    JsFuture::from(request_to_promise(request))
        .await
        .map_err(|e| js_error(format!("{what} failed: {e:?}")))
}

/// Await an `IDBTransaction` through its promise bridge, mapping the JS error
/// to `TirBaseError` with `what` naming the failing operation.
async fn await_transaction(tx: &IdbTransaction, what: &str) -> Result<(), TirBaseError> {
    JsFuture::from(transaction_to_promise(tx))
        .await
        .map(|_| ())
        .map_err(|e| js_error(format!("{what} failed: {e:?}")))
}

// ─── Event → Promise bridges ─────────────────────────────────────────────────

/// Bridge a DOM `IDBRequest` to a `js_sys::Promise` resolved with the request's
/// `result` (or rejected with its error).
fn request_to_promise(request: &IdbRequest) -> Promise {
    let request = request.clone();
    Promise::new(&mut |resolve, reject| {
        let onsuccess = Closure::once({
            let request = request.clone();
            let reject = reject.clone();
            move |_event: web_sys::Event| match request.result() {
                Ok(result) => {
                    let _ = resolve.call1(&JsValue::UNDEFINED, &result);
                }
                Err(e) => {
                    let _ = reject.call1(&JsValue::UNDEFINED, &e);
                }
            }
        });
        request.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
        std::mem::forget(onsuccess);

        let onerror = Closure::once({
            let request = request.clone();
            move |_event: web_sys::Event| {
                let message = request
                    .error()
                    .ok()
                    .flatten()
                    .map(|e| dom_error_description(&e))
                    .unwrap_or_else(|| "IDBRequest failed".to_string());
                let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str(&message));
            }
        });
        request.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        std::mem::forget(onerror);
    })
}

/// Bridge a DOM `IDBTransaction` to a `js_sys::Promise` resolved on
/// `oncomplete` and rejected on `onerror` / `onabort`.
fn transaction_to_promise(tx: &IdbTransaction) -> Promise {
    let tx = tx.clone();
    Promise::new(&mut |resolve, reject| {
        let oncomplete = Closure::once(move |_event: web_sys::Event| {
            let _ = resolve.call0(&JsValue::UNDEFINED);
        });
        tx.set_oncomplete(Some(oncomplete.as_ref().unchecked_ref()));
        std::mem::forget(oncomplete);

        let onerror = Closure::once({
            let tx = tx.clone();
            let reject = reject.clone();
            move |_event: web_sys::Event| {
                let message = tx
                    .error()
                    .map(|e| dom_error_description(&e))
                    .unwrap_or_else(|| "IDBTransaction failed".to_string());
                let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str(&message));
            }
        });
        tx.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        std::mem::forget(onerror);

        let onabort = Closure::once(move |_event: web_sys::Event| {
            let _ = reject.call1(
                &JsValue::UNDEFINED,
                &JsValue::from_str("IDBTransaction aborted"),
            );
        });
        tx.set_onabort(Some(onabort.as_ref().unchecked_ref()));
        std::mem::forget(onabort);
    })
}

// ─── Database open / load / write ────────────────────────────────────────────

/// Open (creating on first use) the IndexedDB database for `path`.
///
/// The `kv` object store is created during the first-open schema upgrade.  The
/// returned handle stays live for the lifetime of the [`LocalStore`](super::LocalStore);
/// rows are written through it by [`put_row`].
pub(crate) async fn open_database(path: &str) -> Result<IdbDatabase, TirBaseError> {
    let window =
        web_sys::window().ok_or_else(|| js_error("no window available (not a browser?)"))?;
    let factory = window
        .indexed_db()
        .map_err(|e| js_error(format!("window.indexedDB unavailable: {e:?}")))?
        .ok_or_else(|| js_error("window.indexedDB unavailable (blocked / private mode?)"))?;

    let name = database_name(path);
    let request = factory
        .open_with_u32(&name, DB_VERSION)
        .map_err(|e| js_error(format!("IDBFactory.open({name}) failed: {e:?}")))?;
    let request_idb: &IdbRequest = request.unchecked_ref();

    let promise = Promise::new(&mut |resolve, reject| {
        // Schema setup on first open (version 0 → 1 upgrade).  Fires only when
        // the database is created (or the version bumped); on every later open
        // of an existing DB the handler simply never fires.
        let upgrader = Closure::once({
            let request_idb = request_idb.clone();
            let reject = reject.clone();
            move |_event: web_sys::IdbVersionChangeEvent| {
                let db: Option<IdbDatabase> = request_idb
                    .result()
                    .ok()
                    .and_then(|r| r.dyn_into::<IdbDatabase>().ok());
                match db {
                    Some(db) => {
                        if !db.object_store_names().contains(KV_STORE) {
                            if let Err(e) = db.create_object_store(KV_STORE) {
                                let _ = reject.call1(
                                    &JsValue::UNDEFINED,
                                    &JsValue::from_str(&format!(
                                        "create_object_store({KV_STORE}) failed: {e:?}"
                                    )),
                                );
                            }
                        }
                    }
                    None => {
                        let _ = reject.call1(
                            &JsValue::UNDEFINED,
                            &JsValue::from_str("open upgrade: no database result"),
                        );
                    }
                }
            }
        });
        request.set_onupgradeneeded(Some(upgrader.as_ref().unchecked_ref()));
        std::mem::forget(upgrader);

        // Success — resolve with the opened database.
        let onsuccess = Closure::once({
            let request_idb = request_idb.clone();
            let reject = reject.clone();
            move |_event: web_sys::Event| match request_idb.result() {
                Ok(db_value) => {
                    let _ = resolve.call1(&JsValue::UNDEFINED, &db_value);
                }
                Err(e) => {
                    let _ = reject.call1(&JsValue::UNDEFINED, &e);
                }
            }
        });
        request.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
        std::mem::forget(onsuccess);

        // Error — reject with the request's DOM error.
        let onerror = Closure::once({
            let request_idb = request_idb.clone();
            move |_event: web_sys::Event| {
                let message = request_idb
                    .error()
                    .ok()
                    .flatten()
                    .map(|e| dom_error_description(&e))
                    .unwrap_or_else(|| "IDBOpenDBRequest failed".to_string());
                let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str(&message));
            }
        });
        request.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        std::mem::forget(onerror);
    });

    let db_value = JsFuture::from(promise)
        .await
        .map_err(|e| js_error(format!("open IndexedDB database {name} failed: {e:?}")))?;
    db_value.dyn_into::<IdbDatabase>().map_err(|_| {
        js_error(format!(
            "open IndexedDB database {name}: result was not an IDBDatabase"
        ))
    })
}

/// Eager-load every row of the `kv` store into an in-memory
/// `HashMap<table, HashMap<key, Value>>`.
///
/// Iterates a cursor over the whole store once at `open()`; after that,
/// reads and queries are served from the in-memory map (the WASM analogue of
/// the native SQLite projection tables).
pub(crate) async fn load_all(
    db: &IdbDatabase,
) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, TirBaseError> {
    let tx = db
        .transaction_with_str(KV_STORE)
        .map_err(|e| js_error(format!("IDB transaction (readonly) failed: {e:?}")))?;
    let store = tx
        .object_store(KV_STORE)
        .map_err(|e| js_error(format!("object_store({KV_STORE}) failed: {e:?}")))?;
    let cursor_request = store
        .open_cursor()
        .map_err(|e| js_error(format!("open_cursor failed: {e:?}")))?;

    let mut tables: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();

    loop {
        let result = await_request(&cursor_request, "cursor read").await?;
        // Each success carries either the next IdbCursorWithValue or null
        // (iteration complete).
        if result.is_null() {
            break;
        }
        let cursor: web_sys::IdbCursorWithValue = result.dyn_into().map_err(|_| {
            js_error("cursor request resolved to a non-cursor value")
        })?;

        let key_js = cursor
            .key()
            .map_err(|e| js_error(format!("cursor.key() failed: {e:?}")))?;
        let value_js = cursor
            .value()
            .map_err(|e| js_error(format!("cursor.value() failed: {e:?}")))?;
        let composite = key_js
            .as_string()
            .ok_or_else(|| js_error("cursor key is not a string"))?;
        let value_str = value_js
            .as_string()
            .ok_or_else(|| js_error("cursor value is not a string"))?;
        let value: serde_json::Value = serde_json::from_str(&value_str).map_err(|e| {
            js_error(format!("row {composite:?}: stored JSON is invalid: {e}"))
        })?;

        let (table, row_key) = split_composite_key(&composite)?;
        tables
            .entry(table)
            .or_default()
            .insert(row_key, value);

        cursor
            .continue_()
            .map_err(|e| js_error(format!("cursor.continue() failed: {e:?}")))?;
    }

    // The snapshot is fully consistent once the readonly transaction completes.
    await_transaction(&tx, "readonly transaction").await?;
    Ok(tables)
}

/// Write one row through to IndexedDB, awaiting the transaction's completion.
///
/// Returns only after the `readwrite` transaction has fully committed, so a
/// successful `LocalStore::write` is durable — the WASM store no longer
/// acknowledges writes that vanish on reload.
pub(crate) async fn put_row(
    db: &IdbDatabase,
    table: &str,
    key: &str,
    data: &serde_json::Value,
) -> Result<(), TirBaseError> {
    let value_json = serde_json::to_string(data)
        .map_err(|e| js_error(format!("row serialisation failed: {e}")))?;
    let composite = composite_key(table, key);

    let tx = db
        .transaction_with_str_and_mode(KV_STORE, IdbTransactionMode::Readwrite)
        .map_err(|e| js_error(format!("IDB transaction (readwrite) failed: {e:?}")))?;
    let store = tx
        .object_store(KV_STORE)
        .map_err(|e| js_error(format!("object_store({KV_STORE}) failed: {e:?}")))?;
    let request = store
        .put_with_key(&JsValue::from_str(&value_json), &JsValue::from_str(&composite))
        .map_err(|e| js_error(format!("put({composite:?}) failed: {e:?}")))?;

    // Await the put request, then the transaction completion (durability).
    await_request(&request, "put").await?;
    await_transaction(&tx, "readwrite transaction").await?;
    Ok(())
}

/// Delete the entire IndexedDB database for `path` (test hygiene / factory
/// reset).  Deleting a non-existent database still succeeds.
pub(crate) async fn delete_database(path: &str) -> Result<(), TirBaseError> {
    let window =
        web_sys::window().ok_or_else(|| js_error("no window available (not a browser?)"))?;
    let factory = window
        .indexed_db()
        .map_err(|e| js_error(format!("window.indexedDB unavailable: {e:?}")))?
        .ok_or_else(|| js_error("window.indexedDB unavailable (blocked / private mode?)"))?;

    let name = database_name(path);
    let request = factory
        .delete_database(&name)
        .map_err(|e| js_error(format!("IDBFactory.deleteDatabase({name}) failed: {e:?}")))?;
    await_request(request.unchecked_ref::<IdbRequest>(), &format!("deleteDatabase({name})")).await?;
    Ok(())
}