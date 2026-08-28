//! LocalStore — SQLite-backed local replica (Req 3).
//!
//! All writes land synchronously in SQLite before the Rust Core returns success.
//! The store remains fully readable and writable with no connectivity (Req 3.3).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod compaction;
pub mod projection;
pub mod sqlite;

use crate::errors::TirBaseError;
use serde_json::Value;

/// The local SQLite store — one Automerge doc per table, plus DAG node storage.
pub struct LocalStore {
    // TODO(task-3): hold rusqlite Connection (native) or WASM bridge (wasm)
}

impl LocalStore {
    /// Open or create the local store at `path`.
    pub fn open(path: &str) -> Result<Self, TirBaseError> {
        todo!("Task 3: open SQLite and run schema creation")
    }

    /// Commit a write to the LocalStore inside a synchronous SQLite transaction (Req 3.2).
    ///
    /// Returns `LocalStoreWriteFailed` on failure; leaves the store in pre-write state.
    /// Does **not** produce a Delta — that is the caller's responsibility (Req 3.6).
    pub fn write(&mut self, table: &str, key: &str, data: &Value) -> Result<(), TirBaseError> {
        todo!("Task 3: implement synchronous SQLite transaction")
    }

    /// Read a single record by table and key (Req 3.3).
    pub fn read(&self, table: &str, key: &str) -> Result<Option<Value>, TirBaseError> {
        todo!("Task 3: implement read")
    }

    /// Query records in a table with an optional filter (Req 3.3).
    pub fn query(
        &self,
        table: &str,
        filter: Option<&Value>,
    ) -> Result<Vec<(String, Value)>, TirBaseError> {
        todo!("Task 3: implement query")
    }
}
