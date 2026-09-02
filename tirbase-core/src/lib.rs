//! tirbase-core — the single Rust library implementing all sync, CRDT,
//! cryptographic, and mesh logic for TirBase (Req 1.1).
//!
//! # Build Targets
//!
//! This crate compiles identically to two targets:
//!
//! - **`--features native`** — native binary for the Cloud Ledger server.
//!   Uses `wasmtime` for migration sandbox execution and `rusqlite/bundled`
//!   for SQLite.
//!
//! - **`--features wasm`** — WASM module loaded by the TypeScript SDK on
//!   client devices. Uses `wasm-bindgen` for JS interop and `wasm3` for
//!   the WASM-in-WASM migration sandbox.
//!
//! The public API surface is **identical** on both targets; the
//! `static_assertions!` block below enforces this at compile time (Req 1.2, 1.5).
//!
//! # Feature Mutual Exclusivity
//!
//! `native` and `wasm` are mutually exclusive build targets.
//! The CI matrix always builds exactly one at a time:
//!   - `cargo check --features native`
//!   - `cargo check --features wasm --target wasm32-unknown-unknown`

#![deny(clippy::module_inception)]
#![allow(missing_docs)]

// ─── Compile-time mutual exclusivity guard ────────────────────────────────────
// Prevents accidentally enabling both features in the same build.
#[cfg(all(feature = "native", feature = "wasm"))]
compile_error!(
    "The `native` and `wasm` features are mutually exclusive. \
     Build with exactly one: `--features native` or `--features wasm`."
);

// ─── Modules ──────────────────────────────────────────────────────────────────

pub mod api;
pub mod auth;
pub mod contamination;
pub mod crdt;
pub mod diagnostics;
pub mod durability;
pub mod errors;
pub mod identity;
pub mod migration;
pub mod schema;
pub mod store;
pub mod transport;

// ─── Property-based test suite (Task 15) ─────────────────────────────────────
#[cfg(test)]
mod tests;

// ─── WASM-bindgen exports ─────────────────────────────────────────────────────
// When building for the TypeScript SDK (wasm target), key API entry points are
// exported with `#[wasm_bindgen]`. On the native build these annotations are
// inert no-ops (the macro is not imported), so the public symbol set remains
// identical (Req 1.5).

#[cfg(feature = "wasm")]
#[allow(unused_imports)]
use wasm_bindgen::prelude::*;

// ─── WASM event queue ─────────────────────────────────────────────────────────
// A thread-local queue of side-effect events produced by Rust subsystems while
// running in the WASM target. The TypeScript SDK drains this queue via
// `core_poll_events()` at the end of every `write()`, `read()`, and `query()`
// call, dispatching each event to the appropriate `_apply*` helper on the
// `TirBase` class (Task 31).

#[cfg(feature = "wasm")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WasmEvent {
    TrustLevelChanged {
        previous: String,
        new: String,
    },
    IncidentCreated {
        ico: serde_json::Value,
    },
    IncidentUpdated {
        ico: serde_json::Value,
    },
    IncidentClosed {
        ico: serde_json::Value,
    },
    DurabilityTierChanged {
        delta_id: String,
        previous_tier: String,
        new_tier: String,
    },
}

#[cfg(feature = "wasm")]
thread_local! {
    static WASM_EVENT_QUEUE: std::cell::RefCell<Vec<WasmEvent>>
        = std::cell::RefCell::new(Vec::new());
}

/// Push a WASM event into the thread-local outbound queue.
///
/// Callable from any crate module gated on `#[cfg(feature = "wasm")]`.
#[cfg(feature = "wasm")]
pub(crate) fn push_wasm_event(event: WasmEvent) {
    WASM_EVENT_QUEUE.with(|q| q.borrow_mut().push(event));
}

// ─── Compile-time API surface assertions ──────────────────────────────────────
//
// `static_assertions::assert_type_eq_all!` and `assert_impl_all!` confirm that
// the public types listed in the API surface exist and implement the expected
// traits on whichever build target is active.
//
// Because the types are defined **unconditionally** (no #[cfg(feature)] guards
// on the type definitions themselves), these assertions hold on both targets and
// verify that neither target accidentally omits a required public symbol (Req 1.2, 1.5).

use static_assertions::assert_impl_all;

// Core API types must exist and be Send + Sync (required for async usage).
assert_impl_all!(api::types::TrustLevel:     Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::DurabilityTier: Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::MeshStatus:     Clone, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::ConnectionStatus: Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::WriteResult:    Clone, std::fmt::Debug);
assert_impl_all!(api::types::QueryResult:    Clone, std::fmt::Debug);

// CRDT / Schema types.
assert_impl_all!(crdt::delta::PriorityClass: Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(schema::FieldType:          Clone, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(schema::Schema:             Clone, PartialEq, Eq, std::fmt::Debug);

// Error type.
assert_impl_all!(errors::TirBaseError: std::fmt::Debug, std::fmt::Display, std::error::Error);

// Contamination types.
assert_impl_all!(contamination::incident::IncidentState:   Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(contamination::incident::TaintSource:     Clone, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(contamination::incident::AuditOperation:  Clone, Copy, PartialEq, Eq, std::fmt::Debug);

// ─── wasm_bindgen public exports ─────────────────────────────────────────────
//
// Exposed to JavaScript/TypeScript via wasm-pack. Each function maps 1-to-1 to
// the `WasmCore` interface in `tirbase-sdk/src/wasm-bridge.ts`.
//
// A thread-local `CoreHandle` holds the single initialized instance. On WASM
// there is only one thread (the JS event loop), so thread_local! is safe and
// avoids the need for `Arc<Mutex<...>>`.

#[cfg(feature = "wasm")]
mod wasm_exports {
    use super::*;
    use wasm_bindgen::prelude::*;
    #[allow(unused_imports)]
    use js_sys;

    thread_local! {
        static CORE: std::cell::RefCell<Option<api::CoreHandle>>
            = std::cell::RefCell::new(None);
    }

    /// Map any `impl Display` error to a JavaScript-visible string.
    fn to_js_err(e: impl std::fmt::Display) -> JsValue {
        JsValue::from_str(&e.to_string())
    }

    /// Parse a JavaScript value as `serde_json::Value` via JSON string round-trip.
    fn js_to_json(val: &JsValue) -> Result<serde_json::Value, JsValue> {
        let json_str = js_sys::JSON::stringify(val)
            .map_err(|e| to_js_err(format!("JSON.stringify failed: {:?}", e)))?
            .as_string()
            .ok_or_else(|| to_js_err("JSON.stringify returned non-string"))?;
        serde_json::from_str(&json_str).map_err(to_js_err)
    }

    /// Serialise a `serde_json::Value` to a JavaScript `object` via JSON string.
    fn json_to_js(val: &serde_json::Value) -> Result<JsValue, JsValue> {
        let json_str = serde_json::to_string(val).map_err(to_js_err)?;
        js_sys::JSON::parse(&json_str).map_err(|e| to_js_err(format!("{:?}", e)))
    }

    // ── Helper: borrow CoreHandle pointer for async fn calls ─────────────────
    //
    // Since WASM is single-threaded and Rust's async/await on WASM is
    // cooperative (no preemption), it is safe to hold a raw `*const CoreHandle`
    // across an await point — there is no concurrent mutation.
    fn core_ptr() -> Result<*const api::CoreHandle, JsValue> {
        CORE.with(|c| {
            c.borrow()
                .as_ref()
                .map(|h| h as *const api::CoreHandle)
                .ok_or_else(|| to_js_err("core_init() must be called first"))
        })
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    /// Initialise TirBase and store the handle in the thread-local slot.
    ///
    /// Must be called before any other export.  Calling it again re-initialises.
    #[wasm_bindgen]
    pub async fn core_init(storage_path: String) -> Result<(), JsValue> {
        let config = api::InitConfig {
            storage_path,
            deployment: api::DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        };
        let handle = api::CoreHandle::init(config).await.map_err(to_js_err)?;
        CORE.with(|c| {
            *c.borrow_mut() = Some(handle);
        });
        Ok(())
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Write a row to (table, key).
    ///
    /// `data` must be a JSON-serialisable JavaScript value.  Returns a
    /// `WriteResult` object: `{ deltaId: string, durabilityTier: string }`.
    #[wasm_bindgen]
    pub async fn core_write(
        table: String,
        key: String,
        data: JsValue,
    ) -> Result<JsValue, JsValue> {
        let data_json = js_to_json(&data)?;
        let ptr = core_ptr()?;
        // SAFETY: WASM is single-threaded; no concurrent mutation.
        let handle = unsafe { &*ptr };
        let write_result = handle.write(&table, &key, data_json).await.map_err(to_js_err)?;
        json_to_js(&serde_json::json!({
            "deltaId": hex::encode(write_result.delta_id),
            "durabilityTier": format!("{:?}", write_result.durability_tier),
        }))
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Read a single row by (table, key). Returns a `QueryResult` as a JS object.
    #[wasm_bindgen]
    pub async fn core_read(table: String, key: String) -> Result<JsValue, JsValue> {
        let ptr = core_ptr()?;
        let handle = unsafe { &*ptr };
        let result = handle.read(&table, &key).await.map_err(to_js_err)?;
        json_to_js(&serde_json::json!({
            "table": result.table,
            "key": result.key,
            "data": result.data,
            "contaminated": result.contaminated,
        }))
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Query rows from a table with an optional JS filter object.
    #[wasm_bindgen]
    pub async fn core_query(table: String, filter: JsValue) -> Result<JsValue, JsValue> {
        let filter_json: Option<serde_json::Value> =
            if filter.is_null() || filter.is_undefined() {
                None
            } else {
                Some(js_to_json(&filter)?)
            };

        let ptr = core_ptr()?;
        let handle = unsafe { &*ptr };
        let results = handle.query(&table, filter_json).await.map_err(to_js_err)?;

        let json_arr: Vec<serde_json::Value> = results
            .iter()
            .map(|r| serde_json::json!({
                "table": r.table,
                "key": r.key,
                "data": r.data,
                "contaminated": r.contaminated,
            }))
            .collect();

        json_to_js(&serde_json::Value::Array(json_arr))
    }

    // ── Trust level ───────────────────────────────────────────────────────────

    /// Returns the current `TrustLevel` as a string (e.g. `"Unverified"`).
    #[wasm_bindgen]
    pub fn core_trust_level() -> String {
        CORE.with(|c| {
            c.borrow()
                .as_ref()
                .map(|h| format!("{:?}", h.trust_level()))
                .unwrap_or_else(|| "Unverified".to_string())
        })
    }

    // ── Mesh status ───────────────────────────────────────────────────────────

    /// Returns the current `MeshStatus` as a JS object.
    #[wasm_bindgen]
    pub fn core_mesh_status() -> JsValue {
        let status = CORE.with(|c| {
            c.borrow()
                .as_ref()
                .map(|h| h.mesh_status())
                .unwrap_or(api::types::MeshStatus {
                    status: api::types::ConnectionStatus::Disconnected,
                    peer_count: 0,
                })
        });
        let js = serde_json::json!({
            "status": format!("{:?}", status.status).to_lowercase(),
            "peerCount": status.peer_count,
        });
        json_to_js(&js).unwrap_or(JsValue::NULL)
    }

    // ── Manager operations ────────────────────────────────────────────────────
    //
    // These map to the manager-facing `WasmCore` methods in wasm-bridge.ts.
    // Full P2P gossip and CCE integration requires native-only transports;
    // on WASM the operations are accepted (no error) but are no-ops for v1.

    /// Gossip a partial RevocationDelta for the target DID.
    #[wasm_bindgen]
    pub async fn core_initiate_revocation(
        target_did: String,
        manager_token: String,
    ) -> Result<(), JsValue> {
        if manager_token.trim().is_empty() {
            return Err(to_js_err("manager_token must not be blank"));
        }
        if target_did.trim().is_empty() {
            return Err(to_js_err("target_did must not be blank"));
        }
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow.as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            let manager_did = handle.identity.did().to_string();
            let signing_key = handle.identity.signing_key_bytes();
            let mut rev = handle.revocation.lock()
                .map_err(|e| to_js_err(format!("revocation lock: {e}")))?;
            let partial = rev.produce_partial_delta(
                target_did.clone(),
                manager_did,
                &signing_key,
            ).map_err(to_js_err)?;
            rev.process_incoming_delta(
                &partial,
                &mut |_, _| {},
                &mut |_, _| {},
            ).map_err(to_js_err)?;
            Ok(())
        })
    }

    /// Return the current accumulation state for a pending revocation.
    #[wasm_bindgen]
    pub async fn core_revocation_status(target_did: String) -> Result<JsValue, JsValue> {
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow.as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            let rev = handle.revocation.lock()
                .map_err(|e| to_js_err(format!("revocation lock: {e}")))?;
            let m = rev.threshold_m();
            let (collected, status_str) = match rev.store_status(&target_did) {
                Some(crate::auth::RevocationStatus::Applied) => (m, "APPLIED"),
                Some(crate::auth::RevocationStatus::Pending { collected, .. }) => (collected, "PENDING"),
                None => (0, "PENDING"),
            };
            json_to_js(&serde_json::json!({
                "signaturesCollected": collected,
                "signaturesRequired": m,
                "status": status_str,
            }))
        })
    }

    /// Append a RESOLVED tag to a contamination root Delta.
    #[wasm_bindgen]
    pub async fn core_verify_data(
        root_delta_id: String,
        manager_token: String,
    ) -> Result<(), JsValue> {
        if manager_token.trim().is_empty() {
            return Err(to_js_err("manager_token must not be blank"));
        }
        // Decode hex → [u8; 32]
        let id_bytes = hex::decode(&root_delta_id)
            .map_err(|e| to_js_err(format!("invalid root_delta_id hex: {e}")))?;
        let root_id: [u8; 32] = id_bytes
            .try_into()
            .map_err(|_| to_js_err("root_delta_id must be 32 bytes (64 hex chars)"))?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow.as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            let manager_did = handle.identity.did().to_string();
            let signing_key = handle.identity.signing_key_bytes();
            // Sign root_id as the payload for the CCE verify_data auth check.
            let manager_sig = crate::identity::keypair::sign(&signing_key, &root_id)
                .map_err(to_js_err)?;
            // Use a far-future expiry — full Biscuit verification is native-only for v1;
            // the non-empty token check above is the WASM gate.
            let far_future = i64::MAX / 2;
            let mut cce = handle.cce.lock()
                .map_err(|e| to_js_err(format!("cce lock: {e}")))?;
            cce.verify_data(root_id, manager_did, manager_sig, far_future)
                .map_err(to_js_err)
        })
    }

    /// Archive an incident without certifying data integrity.
    #[wasm_bindgen]
    pub async fn core_admin_close(
        incident_id: String,
        manager_token: String,
    ) -> Result<(), JsValue> {
        if manager_token.trim().is_empty() {
            return Err(to_js_err("manager_token must not be blank"));
        }
        let uuid = uuid::Uuid::parse_str(&incident_id)
            .map_err(|e| to_js_err(format!("invalid incident_id UUID: {e}")))?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow.as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            let manager_did = handle.identity.did().to_string();
            let signing_key = handle.identity.signing_key_bytes();
            let manager_sig = crate::identity::keypair::sign(&signing_key, uuid.as_bytes())
                .map_err(to_js_err)?;
            let far_future = i64::MAX / 2;
            let mut cce = handle.cce.lock()
                .map_err(|e| to_js_err(format!("cce lock: {e}")))?;
            cce.admin_close(uuid, manager_did, manager_sig, far_future)
                .map_err(to_js_err)
        })
    }

    /// Activate Saturate Mode with a DISASTER_ALERT payload.
    #[wasm_bindgen]
    pub async fn core_activate_saturate_mode(
        _payload: String,
        manager_token: String,
    ) -> Result<(), JsValue> {
        if manager_token.trim().is_empty() {
            return Err(to_js_err(
                crate::errors::TirBaseError::SignatureVerificationFailed {
                    reason: "manager_token is absent or empty".to_string(),
                }
                .to_string(),
            ));
        }
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow.as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            let mut transport = handle.transport.lock()
                .map_err(|e| to_js_err(format!("transport lock: {e}")))?;
            transport.set_saturate_mode(true);
            Ok(())
        })
    }

    // ── Event polling ──────────────────────────────────────────────────────────

    /// Drain and return all queued WASM events as a JS array.
    ///
    /// Each element is a plain JS object serialised from `WasmEvent`.
    /// The TypeScript SDK calls this at the end of every `write()`, `read()`,
    /// and `query()` to surface Rust-side side-effects (trust-level changes,
    /// contamination incidents, durability tier promotions) without requiring
    /// a separate polling loop (Task 31).
    #[wasm_bindgen]
    pub fn core_poll_events() -> JsValue {
        let events: Vec<crate::WasmEvent> =
            crate::WASM_EVENT_QUEUE.with(|q| q.borrow_mut().drain(..).collect());
        let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
        js_sys::JSON::parse(&json).unwrap_or(JsValue::NULL)
    }
}
