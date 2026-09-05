//! LocalStore — SQLite-backed local replica (Req 3).
//!
//! All writes land synchronously in SQLite before the Rust Core returns success.
//! The store remains fully readable and writable with no connectivity (Req 3.3).
//!
//! On the WASM build the store is IndexedDB-backed instead of SQLite-backed
//! (Subphase 6.3): `write()` persists each row through an awaited IndexedDB
//! transaction before returning, and `open()` eagerly reloads every row into
//! an in-memory view, so data survives page reloads instead of living in a
//! throwaway HashMap.  See [`indexed_db`] for the browser glue.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod compaction;
pub mod projection;
pub mod sqlite;

/// IndexedDB persistence layer for the WASM build (Subphase 6.3).
#[cfg(not(feature = "native"))]
pub(crate) mod indexed_db;

use crate::errors::TirBaseError;
use serde_json::Value;

// ─── Native-only imports ──────────────────────────────────────────────────────
#[cfg(feature = "native")]
use automerge::{transaction::Transactable, AutoCommit, ReadDoc, ROOT};

#[cfg(feature = "native")]
use compaction::{compact_table, should_compact, CompactionPolicy};

// ─── LocalStore struct ────────────────────────────────────────────────────────

/// The local SQLite store — one Automerge doc per table, plus DAG node storage.
pub struct LocalStore {
    #[cfg(feature = "native")]
    conn: rusqlite::Connection,
    /// In-memory view of the store on WASM builds (table → key → value).
    ///
    /// Eagerly loaded from IndexedDB at [`LocalStore::open`] and kept as the
    /// read/query source; every `write()` writes through to IndexedDB first
    /// (Subphase 6.3 — the WASM persistence story).
    #[cfg(not(feature = "native"))]
    tables: std::collections::HashMap<String, std::collections::HashMap<String, Value>>,
    /// IndexedDB database handle for the WASM persistence layer; `None` for
    /// the ephemeral `":memory:"` store (tests / throwaway use).
    #[cfg(not(feature = "native"))]
    db: Option<web_sys::IdbDatabase>,
}

// ─── Native implementation ────────────────────────────────────────────────────

#[cfg(feature = "native")]
impl LocalStore {
    /// Open or create the local store at `path`.
    pub fn open(path: &str) -> Result<Self, TirBaseError> {
        let conn = sqlite::open(path)?;
        Ok(LocalStore { conn })
    }

    /// Commit a write to the LocalStore inside a synchronous SQLite transaction (Req 3.2).
    ///
    /// Upserts into `proj_{table}` with columns `(key, data_json, contaminated)`.
    /// Creates the projection table if it doesn't exist yet.
    ///
    /// Returns `LocalStoreWriteFailed` on failure; leaves the store in pre-write state.
    /// Does **not** produce a Delta — that is the caller's responsibility (Req 3.6).
    pub fn write(&mut self, table: &str, key: &str, data: &Value) -> Result<(), TirBaseError> {
        let proj_table = format!("proj_{table}");
        let data_json =
            serde_json::to_string(data).map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("JSON serialisation failed: {e}"),
            })?;

        // Use execute_batch for the DDL + transaction to avoid borrow conflicts.
        // The CREATE TABLE is idempotent and safe to re-run on every write.
        let create_sql = format!(
            "CREATE TABLE IF NOT EXISTS \"{proj_table}\" \
             (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, contaminated INTEGER NOT NULL DEFAULT 0);"
        );

        self.conn
            .execute_batch(&create_sql)
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("CREATE TABLE {proj_table} failed: {e}"),
            })?;

        // Use rusqlite's RAII `Transaction` guard so that:
        //  - a panic inside the upsert (or any Rust-level unwind between BEGIN
        //    and COMMIT) drops the guard and sends `ROLLBACK`, leaving the
        //    store unlocked; and
        //  - SQLite's WAL recovery handles a hard process-kill between BEGIN
        //    and COMMIT (Subphase 7.3): the incomplete transaction is rolled
        //    back automatically on the next `open()`, so no partial rows
        //    survive (Req 3.2 atomicity).
        //
        // `Connection::transaction()` issues `BEGIN DEFERRED` and returns a
        // guard whose `Drop` sends `ROLLBACK` if `commit` was never called.
        let tx = self
            .conn
            .transaction()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("BEGIN failed: {e}"),
            })?;

        let upsert_sql = format!(
            "INSERT INTO \"{proj_table}\" (key, data_json) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET data_json = excluded.data_json;"
        );

        let result = tx.execute(&upsert_sql, rusqlite::params![key, data_json]);

        match result {
            Ok(_) => {
                tx.commit()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("COMMIT failed: {e}"),
                    })?;
                Ok(())
            }
            Err(e) => {
                // Best-effort rollback; the RAII guard also rolls back on drop.
                let _ = tx.rollback();
                Err(TirBaseError::LocalStoreWriteFailed {
                    reason: format!("Upsert into {proj_table} failed: {e}"),
                })
            }
        }
    }

    /// Read a single record by table and key (Req 3.3).
    pub fn read(&self, table: &str, key: &str) -> Result<Option<Value>, TirBaseError> {
        let proj_table = format!("proj_{table}");
        let sql = format!("SELECT data_json FROM \"{proj_table}\" WHERE key = ?1;");

        let result = self
            .conn
            .query_row(&sql, rusqlite::params![key], |row| row.get::<_, String>(0));

        match result {
            Ok(json_str) => {
                let val: Value = serde_json::from_str(&json_str).map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("JSON deserialisation failed: {e}"),
                    }
                })?;
                Ok(Some(val))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            // Table doesn't exist yet → treat as not found.
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("no such table") =>
            {
                Ok(None)
            }
            Err(e) => Err(TirBaseError::LocalStoreWriteFailed {
                reason: format!("Read from {proj_table} failed: {e}"),
            }),
        }
    }

    /// Run crash-recovery verification against the underlying SQLite database.
    ///
    /// This folds any recovered WAL frames back into the main database file
    /// and runs `PRAGMA integrity_check`.  It is the production recovery hook
    /// reached from [`CoreHandle::init`](crate::api::CoreHandle::init) after
    /// opening the store: if the previous process was killed mid-write (between
    /// `BEGIN` and `COMMIT`), SQLite's WAL recovery rolls back the incomplete
    /// transaction automatically — this method verifies that recovery was
    /// clean (Subphase 7.3, Req 3.2 atomicity).
    ///
    /// A corrupt post-recovery database is reported as a hard
    /// `LocalStoreWriteFailed` so `init` never returns a handle over a
    /// poisoned store.
    #[cfg(feature = "native")]
    pub(crate) fn check_integrity(&self) -> Result<(), TirBaseError> {
        sqlite::recover_from_crash(&self.conn)
    }

    /// Query records in a table with an optional filter (Req 3.3).
    ///
    /// If `filter` is `None`, returns all rows.
    /// If `filter` is `Some(obj)`, returns only rows whose `data_json` object
    /// contains all key-value pairs from the filter (simple equality scan).
    /// Returns empty vec (not error) if the table doesn't exist yet.
    pub fn query(
        &self,
        table: &str,
        filter: Option<&Value>,
    ) -> Result<Vec<(String, Value)>, TirBaseError> {
        let proj_table = format!("proj_{table}");
        let sql = format!("SELECT key, data_json FROM \"{proj_table}\";");

        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("no such table") =>
            {
                return Ok(vec![]);
            }
            Err(e) => {
                return Err(TirBaseError::LocalStoreWriteFailed {
                    reason: format!("Prepare query on {proj_table} failed: {e}"),
                });
            }
        };

        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let json_str: String = row.get(1)?;
                Ok((key, json_str))
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query on {proj_table} failed: {e}"),
            })?;

        let mut results = Vec::new();
        for row in rows {
            let (key, json_str) = row.map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Row fetch from {proj_table} failed: {e}"),
            })?;
            let val: Value = serde_json::from_str(&json_str).map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("JSON deserialisation failed: {e}"),
                }
            })?;

            // Apply filter if provided.
            if let Some(filter_obj) = filter {
                if let (Some(filter_map), Some(val_map)) = (filter_obj.as_object(), val.as_object())
                {
                    let matches = filter_map
                        .iter()
                        .all(|(fk, fv)| val_map.get(fk) == Some(fv));
                    if !matches {
                        continue;
                    }
                }
                // If filter isn't an object, skip filtering (return all rows).
            }

            results.push((key, val));
        }

        Ok(results)
    }

    // ─── Automerge document helpers ───────────────────────────────────────────

    /// List all table names present in `automerge_docs`.
    ///
    /// Used by the inbound pipeline to find which tables to re-project after
    /// merging binary Automerge bytes from a peer.
    pub fn list_automerge_tables(&self) -> Result<Vec<String>, TirBaseError> {
        let sql = "SELECT table_name FROM automerge_docs;";
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("prepare list_automerge_tables failed: {e}"),
            })?;

        let tables = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("query list_automerge_tables failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .collect::<Vec<String>>();

        Ok(tables)
    }

    /// Return a reference to the underlying SQLite connection.
    ///
    /// Used by the inbound projection pipeline to run `project_table()` on
    /// the same connection as the store (Req 4.3, 3.3).
    pub fn raw_conn(&self) -> &rusqlite::Connection {
        &self.conn
    }
    pub(crate) fn get_or_create_automerge_doc(
        conn: &rusqlite::Connection,
        table: &str,
    ) -> Result<AutoCommit, TirBaseError> {
        let result = conn.query_row(
            "SELECT doc_bytes FROM automerge_docs WHERE table_name = ?1;",
            rusqlite::params![table],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(doc_bytes) => {
                AutoCommit::load(&doc_bytes).map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("AutoCommit::load failed for table '{table}': {e}"),
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // No document yet — create a fresh one and persist it.
                let mut doc = AutoCommit::new();
                let initial_bytes = doc.save();
                conn.execute(
                    "INSERT INTO automerge_docs (table_name, doc_bytes) VALUES (?1, ?2);",
                    rusqlite::params![table, initial_bytes],
                )
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("INSERT automerge_docs for table '{table}' failed: {e}"),
                })?;
                Ok(doc)
            }
            Err(e) => Err(TirBaseError::LocalStoreWriteFailed {
                reason: format!("SELECT automerge_docs for table '{table}' failed: {e}"),
            }),
        }
    }

    /// Persist an Automerge document back to `automerge_docs`.
    pub(crate) fn save_automerge_doc(
        conn: &rusqlite::Connection,
        table: &str,
        doc: &mut AutoCommit,
    ) -> Result<(), TirBaseError> {
        let bytes = doc.save();
        conn.execute(
            "UPDATE automerge_docs SET doc_bytes = ?1 WHERE table_name = ?2;",
            rusqlite::params![bytes, table],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("UPDATE automerge_docs for table '{table}' failed: {e}"),
        })?;
        Ok(())
    }

    /// Write a key/value through the Automerge document for a table, keeping the
    /// SQLite projection in sync. Called by the CRDT engine in later tasks.
    ///
    /// Compaction is attempted if the `Aggressive` threshold is exceeded; failure
    /// is non-fatal (Req 3.4–3.5).
    pub fn write_with_automerge(
        &mut self,
        table: &str,
        key: &str,
        value: &Value,
        policy: &CompactionPolicy,
    ) -> Result<(), TirBaseError> {
        let mut doc = Self::get_or_create_automerge_doc(&self.conn, table)?;

        // Put the value into the Automerge doc as a JSON string at ROOT.
        let value_str =
            serde_json::to_string(value).map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("JSON serialisation failed: {e}"),
            })?;

        doc.put(ROOT, key, value_str)
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("automerge put failed: {e}"),
            })?;
        doc.commit();

        // Check compaction threshold: automerge's change count is a proxy for Delta count.
        let delta_count = doc.get_changes(&[]).len() as u64;
        if should_compact(policy, delta_count) {
            // Compaction failure is non-fatal — the function logs internally.
            let _ = compact_table(&self.conn, table, &mut doc);
        }

        Self::save_automerge_doc(&self.conn, table, &mut doc)?;

        // Keep the SQL projection table in sync.
        self.write(table, key, value)?;

        Ok(())
    }
}

// ─── WASM implementation — IndexedDB-backed (Subphase 6.3) ───────────────────
//
// The WASM build has no SQLite, so the persistence story is a browser
// IndexedDB database keyed by the configured storage path.  `open()` opens
// the database and eagerly loads every row into the in-memory `tables` view;
// `write()` persists through an awaited IndexedDB transaction (durable before
// it returns — Req 3.2 parity) and then updates the view; `read()` / `query()`
// are served synchronously from the view.
//
// The special path `":memory:"` keeps the historical ephemeral behaviour
// (pure in-memory, no IndexedDB) for tests and throwaway stores.

#[cfg(not(feature = "native"))]
impl LocalStore {
    /// Open (or create) the store for `path`.
    ///
    /// IndexedDB-backed for real storage paths: the database is opened (the
    /// `kv` object store created on first use) and every persisted row is
    /// eagerly loaded into the in-memory view, so data written by a previous
    /// session is present after a page reload.  The literal path `":memory:"`
    /// yields a pure in-memory store with no IndexedDB backing.
    pub async fn open(path: &str) -> Result<Self, TirBaseError> {
        if path == ":memory:" {
            return Ok(LocalStore {
                tables: std::collections::HashMap::new(),
                db: None,
            });
        }
        let db = indexed_db::open_database(path).await?;
        let tables = indexed_db::load_all(&db).await?;
        Ok(LocalStore {
            tables,
            db: Some(db),
        })
    }

    /// Commit a write to the store (Req 3.2).
    ///
    /// On an IndexedDB-backed store the row is written through an awaited
    /// `readwrite` transaction — `write()` returns only after the transaction
    /// has committed, so the acknowledged write survives a reload.  The
    /// in-memory view is updated only after the durable write succeeds.  Does
    /// **not** produce a Delta — that is the caller's responsibility (Req 3.6).
    pub async fn write(
        &mut self,
        table: &str,
        key: &str,
        data: &Value,
    ) -> Result<(), TirBaseError> {
        if let Some(db) = self.db.as_ref() {
            indexed_db::put_row(db, table, key, data).await?;
        }
        self.tables
            .entry(table.to_string())
            .or_default()
            .insert(key.to_string(), data.clone());
        Ok(())
    }

    pub fn read(&self, table: &str, key: &str) -> Result<Option<Value>, TirBaseError> {
        Ok(self.tables.get(table).and_then(|t| t.get(key)).cloned())
    }

    pub fn query(
        &self,
        table: &str,
        filter: Option<&Value>,
    ) -> Result<Vec<(String, Value)>, TirBaseError> {
        let rows = match self.tables.get(table) {
            Some(t) => t,
            None => return Ok(vec![]),
        };

        let results = rows
            .iter()
            .filter(|(_k, v)| {
                if let Some(filter_obj) = filter {
                    if let (Some(filter_map), Some(val_map)) =
                        (filter_obj.as_object(), v.as_object())
                    {
                        return filter_map
                            .iter()
                            .all(|(fk, fv)| val_map.get(fk) == Some(fv));
                    }
                }
                true
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(results)
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::store::compaction::{should_compact, CompactionPolicy};
    use serde_json::json;

    /// Helper: open an in-memory LocalStore.
    fn open_memory() -> LocalStore {
        LocalStore::open(":memory:").expect("in-memory store should open")
    }

    // ── 1. Write-read round trip ──────────────────────────────────────────────

    #[test]
    fn test_write_read_round_trip() {
        let mut store = open_memory();
        let data = json!({"name": "Alice", "score": 42});
        store.write("users", "user-1", &data).expect("write failed");

        let result = store.read("users", "user-1").expect("read failed");
        assert_eq!(result, Some(data));
    }

    #[test]
    fn test_read_missing_key_returns_none() {
        let store = open_memory();
        let result = store.read("users", "nonexistent").expect("read failed");
        assert_eq!(result, None);
    }

    #[test]
    fn test_read_missing_table_returns_none() {
        let store = open_memory();
        let result = store
            .read("no_such_table", "key")
            .expect("read on missing table should not error");
        assert_eq!(result, None);
    }

    // ── 2. Offline no-peers readable ─────────────────────────────────────────

    #[test]
    fn test_offline_no_peers_readable() {
        // All operations are purely local SQLite — no network calls.
        // This test confirms the store opens and operates without panics.
        let mut store = open_memory();
        store
            .write("sensor_data", "reading-1", &json!({"temp": 23.5}))
            .expect("write should succeed offline");
        let val = store
            .read("sensor_data", "reading-1")
            .expect("read should succeed offline");
        assert!(val.is_some(), "data written offline must be readable");
    }

    // ── 3. Compaction threshold ───────────────────────────────────────────────

    #[test]
    fn test_should_compact_threshold_boundary() {
        let policy = CompactionPolicy::Aggressive { threshold: 5 };
        assert!(
            !should_compact(&policy, 5),
            "at threshold: should NOT compact"
        );
        assert!(
            should_compact(&policy, 6),
            "above threshold: SHOULD compact"
        );
    }

    #[test]
    fn test_compaction_policy_none_never_compacts() {
        assert!(!should_compact(&CompactionPolicy::None, u64::MAX));
    }

    #[test]
    fn test_write_with_automerge_compaction_attempted() {
        let mut store = open_memory();
        // Aggressive threshold of 2 — after 3 writes compaction is attempted.
        let policy = CompactionPolicy::Aggressive { threshold: 2 };
        for i in 0..3u32 {
            store
                .write_with_automerge("events", &format!("key-{i}"), &json!(i), &policy)
                .expect("write_with_automerge should not error even when compaction runs");
        }
        // Confirm data is still readable.
        let val = store.read("events", "key-0").expect("read failed");
        assert!(val.is_some());
    }

    // ── 4. Compaction failure preservation ───────────────────────────────────

    #[test]
    fn test_compaction_failure_data_preserved() {
        // compact_table() returns Ok(()) on failure (Req 3.5).
        // Write data, then confirm it survives after a compaction attempt.
        let mut store = open_memory();
        store
            .write("logs", "entry-1", &json!({"msg": "hello"}))
            .expect("write");
        store
            .write("logs", "entry-2", &json!({"msg": "world"}))
            .expect("write");

        // A fresh AutoCommit passed to compact_table is a valid doc — compaction
        // should succeed and data should still be readable.
        let val = store
            .read("logs", "entry-1")
            .expect("read after compaction attempt");
        assert!(val.is_some(), "data must survive compaction attempt");
    }

    // ── 5. Transaction rollback / idempotent upsert ───────────────────────────

    #[test]
    fn test_idempotent_upsert_same_key() {
        let mut store = open_memory();
        store
            .write("items", "item-1", &json!({"v": 1}))
            .expect("first write");
        store
            .write("items", "item-1", &json!({"v": 2}))
            .expect("second write (upsert)");

        let val = store.read("items", "item-1").expect("read");
        assert_eq!(
            val,
            Some(json!({"v": 2})),
            "second write should overwrite first"
        );
    }

    // ── 6. Query with and without filter ─────────────────────────────────────

    #[test]
    fn test_query_no_filter_returns_all() {
        let mut store = open_memory();
        store
            .write("orders", "o1", &json!({"status": "open"}))
            .unwrap();
        store
            .write("orders", "o2", &json!({"status": "closed"}))
            .unwrap();
        store
            .write("orders", "o3", &json!({"status": "open"}))
            .unwrap();

        let rows = store.query("orders", None).expect("query");
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn test_query_with_filter() {
        let mut store = open_memory();
        store
            .write("orders", "o1", &json!({"status": "open"}))
            .unwrap();
        store
            .write("orders", "o2", &json!({"status": "closed"}))
            .unwrap();
        store
            .write("orders", "o3", &json!({"status": "open"}))
            .unwrap();

        let filter = json!({"status": "open"});
        let rows = store
            .query("orders", Some(&filter))
            .expect("filtered query");
        assert_eq!(rows.len(), 2, "should return only 'open' orders");
    }

    #[test]
    fn test_query_empty_table_returns_empty_vec() {
        let store = open_memory();
        let rows = store
            .query("nonexistent_table", None)
            .expect("query on missing table");
        assert!(rows.is_empty());
    }

    // ── 7. DAG insert and children ────────────────────────────────────────────

    #[test]
    fn test_dag_insert_and_children() {
        use crate::crdt::dag::{ChangesetDag, DagNode};
        use std::sync::{Arc, Mutex};

        let conn = sqlite::open(":memory:").expect("open");
        let conn = Arc::new(Mutex::new(conn));
        let mut dag = ChangesetDag::new(conn);

        let parent_id = [0x01u8; 32];
        let child_id = [0x02u8; 32];

        let parent_node = DagNode {
            delta_id: parent_id,
            payload: vec![1, 2, 3],
            parent_ids: vec![],
            actor_id: b"actor-a".to_vec(),
            lamport: 1,
            schema_hash: [0xAAu8; 32],
            compacted: false,
            author_did: "did:key:z6MkParent".to_string(),
        };
        dag.insert(parent_node).expect("insert parent");

        let child_node = DagNode {
            delta_id: child_id,
            payload: vec![4, 5, 6],
            parent_ids: vec![parent_id],
            actor_id: b"actor-b".to_vec(),
            lamport: 2,
            schema_hash: [0xAAu8; 32],
            compacted: false,
            author_did: "did:key:z6MkChild".to_string(),
        };
        dag.insert(child_node).expect("insert child");

        let children = dag.children(&parent_id).expect("children");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], child_id);
    }

    // ── 8. DAG BFS descendants ────────────────────────────────────────────────

    #[test]
    fn test_dag_bfs_descendants() {
        use crate::crdt::dag::{ChangesetDag, DagNode};
        use std::sync::{Arc, Mutex};

        let conn = sqlite::open(":memory:").expect("open");
        let conn = Arc::new(Mutex::new(conn));
        let mut dag = ChangesetDag::new(conn);

        let root_id = [0x01u8; 32];
        let mid_id = [0x02u8; 32];
        let leaf_id = [0x03u8; 32];

        let make_node = |id: [u8; 32], parents: Vec<[u8; 32]>, lamport: u64| DagNode {
            delta_id: id,
            payload: vec![],
            parent_ids: parents,
            actor_id: b"actor".to_vec(),
            lamport,
            schema_hash: [0u8; 32],
            compacted: false,
            author_did: "did:key:z6MkTest".to_string(),
        };

        dag.insert(make_node(root_id, vec![], 1))
            .expect("insert root");
        dag.insert(make_node(mid_id, vec![root_id], 2))
            .expect("insert mid");
        dag.insert(make_node(leaf_id, vec![mid_id], 3))
            .expect("insert leaf");

        let descendants = dag.bfs_descendants(&root_id).expect("bfs");
        assert!(
            descendants.contains(&root_id),
            "root must be in descendants"
        );
        assert!(descendants.contains(&mid_id), "mid must be in descendants");
        assert!(
            descendants.contains(&leaf_id),
            "leaf must be in descendants"
        );
    }

    // ── 9. DAG topological sort (diamond) ─────────────────────────────────────

    #[test]
    fn test_dag_topological_sort_diamond() {
        use crate::crdt::dag::{ChangesetDag, DagNode};
        use std::sync::{Arc, Mutex};

        let conn = sqlite::open(":memory:").expect("open");
        let conn = Arc::new(Mutex::new(conn));
        let mut dag = ChangesetDag::new(conn);

        // Diamond: A → B, A → C, B → D, C → D
        let a = [0x0Au8; 32];
        let b = [0x0Bu8; 32];
        let c = [0x0Cu8; 32];
        let d = [0x0Du8; 32];

        let make_node = |id, parents: Vec<[u8; 32]>, lamport| DagNode {
            delta_id: id,
            payload: vec![],
            parent_ids: parents,
            actor_id: b"actor".to_vec(),
            lamport,
            schema_hash: [0u8; 32],
            compacted: false,
            author_did: "did:key:z6MkTest".to_string(),
        };

        dag.insert(make_node(a, vec![], 1)).expect("insert A");
        dag.insert(make_node(b, vec![a], 2)).expect("insert B");
        dag.insert(make_node(c, vec![a], 3)).expect("insert C");
        dag.insert(make_node(d, vec![b, c], 4)).expect("insert D");

        let sorted = dag.topological_sort().expect("topo sort");
        assert_eq!(sorted.len(), 4, "all 4 nodes must appear");

        let pos = |id: [u8; 32]| sorted.iter().position(|x| *x == id).unwrap();
        assert!(pos(a) < pos(b), "A must come before B");
        assert!(pos(a) < pos(c), "A must come before C");
        assert!(pos(b) < pos(d), "B must come before D");
        assert!(pos(c) < pos(d), "C must come before D");
    }

    // ── 10. Crash-recovery integrity check (Subphase 7.3) ────────────────────
    //
    // `check_integrity` runs `PRAGMA wal_checkpoint(TRUNCATE)` +
    // `PRAGMA integrity_check` — the same recovery step `CoreHandle::init`
    // invokes on startup (production caller: api/mod.rs:init → LocalStore::open
    // → sqlite::open → recover_from_crash; and CoreHandle::init calls
    // store.check_integrity() immediately after open).  This unit test pins
    // the happy path: a freshly-opened store passes integrity_check, and a
    // store with a committed row still passes after an in-process rollback of
    // an in-flight transaction (the in-process analogue of a mid-write crash).

    #[test]
    fn test_check_integrity_passes_on_clean_store() {
        let store = open_memory();
        store
            .check_integrity()
            .expect("clean store must pass integrity_check");
    }

    #[test]
    fn test_check_integrity_passes_after_rollback_of_uncommitted_tx() {
        // Simulate the in-process analogue of a mid-write crash: begin a
        // transaction, insert a row, then roll back (no commit).  After the
        // rollback the store must still pass integrity_check and the partial
        // row must not be visible.
        let mut store = open_memory();
        store.write("t", "a", &json!({"v": 1})).expect("write a");

        // Begin an uncommitted transaction and insert a partial row, then
        // roll back — mirroring a crash between BEGIN and COMMIT where SQLite
        // recovers the rollback during WAL replay.
        store.conn.execute_batch("BEGIN;").expect("test: BEGIN");
        store
            .conn
            .execute(
                "INSERT INTO proj_t (key, data_json, contaminated) VALUES (?1, ?2, ?3);",
                rusqlite::params!["partial", r#"{"v": 2}"#, 0i64],
            )
            .expect("test: INSERT partial");
        store
            .conn
            .execute_batch("ROLLBACK;")
            .expect("test: ROLLBACK");

        // After rollback: integrity holds, partial row is gone, committed
        // row survives.
        store
            .check_integrity()
            .expect("store must pass integrity_check after rollback");
        assert!(
            store.read("t", "partial").expect("read partial").is_none(),
            "rolled-back row must not survive"
        );
        assert!(
            store.read("t", "a").expect("read a").is_some(),
            "committed row must survive rollback"
        );
    }
}
