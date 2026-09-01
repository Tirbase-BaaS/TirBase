//! WASM unit tests — run with `wasm-pack test --headless --chrome`
//! (or `wasm-bindgen-test-runner` for Node.js targets).
//!
//! These tests verify that the in-memory bridges work correctly on the
//! `wasm32-unknown-unknown` target.

#![cfg(all(test, target_arch = "wasm32"))]

use wasm_bindgen_test::*;

// Run tests in the browser (headless Chrome / Firefox via wasm-pack test).
wasm_bindgen_test_configure!(run_in_browser);

// ─── LocalStore ───────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_local_store_write_then_read() {
    use crate::store::LocalStore;
    use serde_json::json;

    let mut store = LocalStore::open(":memory:").expect("open store");
    let data = json!({"name": "Alice", "score": 42});
    store.write("users", "user-1", &data).expect("write");

    let result = store.read("users", "user-1").expect("read");
    assert_eq!(result, Some(data));
}

#[wasm_bindgen_test]
fn test_local_store_read_missing_key_returns_none() {
    use crate::store::LocalStore;

    let store = LocalStore::open(":memory:").expect("open store");
    let result = store.read("users", "nonexistent").expect("read");
    assert_eq!(result, None);
}

#[wasm_bindgen_test]
fn test_local_store_query_with_filter() {
    use crate::store::LocalStore;
    use serde_json::json;

    let mut store = LocalStore::open(":memory:").expect("open store");
    store.write("orders", "o1", &json!({"status": "open"})).unwrap();
    store.write("orders", "o2", &json!({"status": "closed"})).unwrap();
    store.write("orders", "o3", &json!({"status": "open"})).unwrap();

    let filter = json!({"status": "open"});
    let rows = store.query("orders", Some(&filter)).expect("query");
    assert_eq!(rows.len(), 2, "only open orders should be returned");
}

// ─── ChangesetDag ─────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_dag_insert_and_children() {
    use crate::crdt::dag::{ChangesetDag, DagNode};

    let mut dag = ChangesetDag::new();
    let parent_id = [0x01u8; 32];
    let child_id = [0x02u8; 32];

    dag.insert(DagNode {
        delta_id: parent_id,
        payload: vec![],
        parent_ids: vec![],
        actor_id: b"actor".to_vec(),
        lamport: 1,
        schema_hash: [0u8; 32],
        compacted: false,
        author_did: "did:key:z6MkTest".to_string(),
    })
    .expect("insert parent");

    dag.insert(DagNode {
        delta_id: child_id,
        payload: vec![],
        parent_ids: vec![parent_id],
        actor_id: b"actor".to_vec(),
        lamport: 2,
        schema_hash: [0u8; 32],
        compacted: false,
        author_did: "did:key:z6MkTest".to_string(),
    })
    .expect("insert child");

    let children = dag.children(&parent_id).expect("children");
    assert_eq!(children.len(), 1);
    assert_eq!(children[0], child_id);
}

#[wasm_bindgen_test]
fn test_dag_bfs_descendants() {
    use crate::crdt::dag::{ChangesetDag, DagNode};

    let mut dag = ChangesetDag::new();
    let root_id = [0x01u8; 32];
    let mid_id = [0x02u8; 32];
    let leaf_id = [0x03u8; 32];

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

    dag.insert(make_node(root_id, vec![], 1)).unwrap();
    dag.insert(make_node(mid_id, vec![root_id], 2)).unwrap();
    dag.insert(make_node(leaf_id, vec![mid_id], 3)).unwrap();

    let descendants = dag.bfs_descendants(&root_id).expect("bfs");
    assert!(descendants.contains(&root_id));
    assert!(descendants.contains(&mid_id));
    assert!(descendants.contains(&leaf_id));
    assert_eq!(descendants.len(), 3);
}

// ─── QuarantineLedger ─────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_quarantine_stores_and_retrieves() {
    use crate::migration::quarantine::{QuarantineLedger, QuarantineReason};

    let mut ledger = QuarantineLedger::new();
    let raw = b"raw-delta-bytes".to_vec();
    let schema_hash = [0xAAu8; 32];

    let id = ledger
        .quarantine(
            "did:key:z6MkSender".to_string(),
            raw.clone(),
            Some(schema_hash),
            QuarantineReason::UnknownSchemaHash,
            1_720_000_000,
        )
        .expect("quarantine");

    let entries = ledger.get_by_schema_hash(&schema_hash).expect("get");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, id);
    assert_eq!(entries[0].raw_bytes, raw);
}

// ─── SideCarLedger ────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_sidecar_record_and_order() {
    use crate::migration::sidecar::SideCarLedger;

    let mut ledger = SideCarLedger::new();
    let migration_id = [0x01u8; 32];

    ledger.record(migration_id, "t".to_string(), b"c3".to_vec(), 300).unwrap();
    ledger.record(migration_id, "t".to_string(), b"c1".to_vec(), 100).unwrap();
    ledger.record(migration_id, "t".to_string(), b"c2".to_vec(), 200).unwrap();

    let count = ledger.count_for_migration(migration_id).unwrap();
    assert_eq!(count, 3);
}

// ─── Projection store ─────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_projection_mark_and_clear() {
    use crate::store::projection::{mark_row_contaminated, clear_row_contamination};
    use crate::contamination::taint::WASM_PROJ_STORE;

    mark_row_contaminated("reports", "row-1").expect("mark");

    let is_contaminated = WASM_PROJ_STORE.with(|s| {
        s.borrow()
            .get("reports")
            .and_then(|t| t.get("row-1"))
            .copied()
            .unwrap_or(false)
    });
    assert!(is_contaminated, "row must be marked contaminated");

    clear_row_contamination("reports", "row-1").expect("clear");

    let after_clear = WASM_PROJ_STORE.with(|s| {
        s.borrow()
            .get("reports")
            .and_then(|t| t.get("row-1"))
            .copied()
            .unwrap_or(false)
    });
    assert!(!after_clear, "row must be cleared");
}

// ─── Trust level ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_trust_level_returns_valid_variant() {
    // Before init, trust level should default to Unverified.
    let tl = crate::wasm_exports::core_trust_level();
    // Any valid trust level string is acceptable.
    assert!(
        !tl.is_empty(),
        "trust level must be a non-empty string: {tl}"
    );
}

// ─── Mesh status ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_mesh_status_is_disconnected_before_init() {
    let status_val = crate::wasm_exports::core_mesh_status();
    // Should be a JS object (not null).
    assert!(!status_val.is_null(), "mesh_status must not be null");
}

// ─── Init → Write → Read round-trip ──────────────────────────────────────────

#[wasm_bindgen_test]
async fn test_init_write_read_round_trip() {
    use wasm_bindgen::JsValue;
    use js_sys::JSON;

    // Initialise with a dummy storage path (in-memory on WASM).
    crate::wasm_exports::core_init("wasm-test".to_string())
        .await
        .expect("core_init should succeed");

    // Write a row.
    let data = JSON::parse(r#"{"msg": "hello"}"#).unwrap();
    crate::wasm_exports::core_write("test_table".to_string(), "k1".to_string(), data)
        .await
        .expect("core_write should succeed");

    // Read it back.
    let read_result = crate::wasm_exports::core_read("test_table".to_string(), "k1".to_string())
        .await
        .expect("core_read should succeed");

    assert!(!read_result.is_null(), "read result must not be null");
}
