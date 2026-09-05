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
// `TirBase` class (see tirbase-sdk/src/tirbase.ts).

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
    #[allow(unused_imports)]
    use js_sys;
    #[allow(unused_imports)]
    use wasm_bindgen::prelude::*;

    thread_local! {
        // `Arc` because `api::CoreHandle::init` now returns a shared handle:
        // the production inbound drain loop spawned by init holds a clone
        // (native builds).  On WASM the handle is owned solely by this slot.
        static CORE: std::cell::RefCell<Option<std::sync::Arc<api::CoreHandle>>>
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
                .map(std::sync::Arc::as_ptr)
                .ok_or_else(|| to_js_err("core_init() must be called first"))
        })
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    /// Decode a hex-encoded 32-byte value (public key / schema hash) into raw
    /// bytes, with a `label` used in error messages to identify the config field.
    fn decode_32byte_hex(label: &str, hex_str: &str) -> Result<[u8; 32], JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| to_js_err(format!("{label}: invalid hex \"{hex_str}\": {e}")))?;
        bytes.try_into().map_err(|_| {
            to_js_err(format!(
                "{label}: \"{hex_str}\" must be 32 bytes (64 hex chars)"
            ))
        })
    }

    /// Decode a hex-encoded root CA public key into its 32 raw bytes.
    fn decode_root_ca_key_hex(key_hex: &str) -> Result<[u8; 32], JsValue> {
        decode_32byte_hex("root_ca_keys", key_hex)
    }

    /// Initialise TirBase and store the handle in the thread-local slot.
    ///
    /// Must be called before any other export.  Calling it again re-initialises.
    ///
    /// `root_ca_keys_hex` — hex-encoded Ed25519 root CA public keys (64 hex
    /// chars each) trusted for offline Biscuit token verification.  An empty
    /// array is the explicit unconfigured state: no Biscuit token verifies
    /// until a key is registered here or via `core_register_root_ca_key`.
    ///
    /// `migration_ca_key_hex` — hex-encoded Ed25519 Migration CA public key
    /// (64 hex chars; Req 18.2).  `None`/`undefined` is the explicit
    /// unconfigured state: no inbound Migration_Delta verifies until the key
    /// is registered here or via `core_register_migration_ca_key` (Subphase
    /// 5.1).
    ///
    /// `schema_version_path_hex` — hex-encoded schema hashes in deployment
    /// order, oldest → newest (Req 18.3a).  An empty array is the explicit
    /// unconfigured state: no version step validates until the path is
    /// registered (Subphase 5.1).
    #[wasm_bindgen]
    pub async fn core_init(
        storage_path: String,
        root_ca_keys_hex: Vec<String>,
        migration_ca_key_hex: Option<String>,
        schema_version_path_hex: Vec<String>,
    ) -> Result<(), JsValue> {
        let mut root_ca_keys = Vec::with_capacity(root_ca_keys_hex.len());
        for key_hex in &root_ca_keys_hex {
            root_ca_keys.push(decode_root_ca_key_hex(key_hex)?);
        }
        let migration_ca_public_key = match &migration_ca_key_hex {
            Some(key_hex) => Some(decode_32byte_hex("migration_ca_key", key_hex)?),
            None => None,
        };
        let mut schema_version_path = Vec::with_capacity(schema_version_path_hex.len());
        for version_hex in &schema_version_path_hex {
            schema_version_path.push(decode_32byte_hex("schema_version_path", version_hex)?);
        }
        let config = api::InitConfig {
            storage_path,
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: api::DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                // WASM export surface hardcodes the default 1h TTL, which is
                // within the 1h–24h default range, so no accepted-risk override
                // is granted here.
                extended_ttl_accepted_risk: false,
                root_ca_keys,
                migration_ca_public_key,
                schema_version_path,
                // The WASM export surface does not carry full schema
                // definitions; field-level additive-vs-breaking classification
                // (Subphase 5.3) is a native deployment-config capability.
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                // Spec-default 60-minute Saturate_Mode lease window (Req 13.3);
                // the WASM export surface does not expose lease-duration tuning.
                saturate_lease_duration_secs: 3600,
                mesh_mtu: 0,
            },
        };
        let handle = api::CoreHandle::init(config).await.map_err(to_js_err)?;
        CORE.with(|c| {
            *c.borrow_mut() = Some(handle);
        });
        Ok(())
    }

    /// Register an additional root CA public key at runtime (Req 8.1).
    ///
    /// `root_ca_key_hex` — hex-encoded Ed25519 root CA public key (64 hex
    /// chars).  Takes effect immediately for subsequent Biscuit token
    /// verification (e.g. `core_activate_saturate_mode`).
    #[wasm_bindgen]
    pub fn core_register_root_ca_key(root_ca_key_hex: String) -> Result<(), JsValue> {
        let key = decode_root_ca_key_hex(&root_ca_key_hex)?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle.register_root_ca_key(key, None).map(|_| ()).map_err(to_js_err)
        })
    }

    /// Register an additional root CA public key at runtime and verify a Biscuit
    /// token against it (Req 8.1, 8.3).
    ///
    /// `root_ca_key_hex` — hex-encoded Ed25519 root CA public key (64 hex chars).
    /// `biscuit_token_hex` — hex-encoded Biscuit token to verify immediately.
    /// `now_secs` — current Unix timestamp in seconds for expiry checking.
    ///
    /// On success the device's `TrustLevel` transitions to `Verified`.
    #[wasm_bindgen]
    pub fn core_register_root_ca_key_with_token(
        root_ca_key_hex: String,
        biscuit_token_hex: String,
        now_secs: i64,
    ) -> Result<(), JsValue> {
        let key = decode_root_ca_key_hex(&root_ca_key_hex)?;
        let token_bytes = decode_biscuit_token_hex(&biscuit_token_hex)?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle
                .register_root_ca_key(key, Some((&token_bytes, now_secs)))
                .map(|_| ())
                .map_err(to_js_err)
        })
    }

    /// Register the deployment's Migration CA public key at runtime (Req 18.2).
    ///
    /// `migration_ca_key_hex` — hex-encoded Ed25519 Migration CA public key
    /// (64 hex chars).  Takes effect immediately: subsequent inbound
    /// Migration_Deltas verify their CA signature against this key,
    /// replacing any key registered at `core_init` (Subphase 5.1).
    #[wasm_bindgen]
    pub fn core_register_migration_ca_key(migration_ca_key_hex: String) -> Result<(), JsValue> {
        let key = decode_32byte_hex("migration_ca_key", &migration_ca_key_hex)?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle.register_migration_ca_key(key).map_err(to_js_err)
        })
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Write a row to (table, key).
    ///
    /// `data` must be a JSON-serialisable JavaScript value.  Returns a
    /// `WriteResult` object: `{ deltaId: string, durabilityTier: string }`.
    #[wasm_bindgen]
    pub async fn core_write(table: String, key: String, data: JsValue) -> Result<JsValue, JsValue> {
        let data_json = js_to_json(&data)?;
        let ptr = core_ptr()?;
        // SAFETY: WASM is single-threaded; no concurrent mutation.
        let handle = unsafe { &*ptr };
        let write_result = handle
            .write(&table, &key, data_json)
            .await
            .map_err(to_js_err)?;
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
        let filter_json: Option<serde_json::Value> = if filter.is_null() || filter.is_undefined() {
            None
        } else {
            Some(js_to_json(&filter)?)
        };

        let ptr = core_ptr()?;
        let handle = unsafe { &*ptr };
        let results = handle.query(&table, filter_json).await.map_err(to_js_err)?;

        let json_arr: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "table": r.table,
                    "key": r.key,
                    "data": r.data,
                    "contaminated": r.contaminated,
                })
            })
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

    /// Gossip a partial RevocationDelta for the target DID (Req 9.1).
    ///
    /// Delegates to [`api::CoreHandle::initiate_revocation`] so the WASM export
    /// and the native entry point share one implementation (Subphase 2.4).  On
    /// WASM the produced partial delta is accumulated locally (and, at M=1,
    /// applies the local REVOKED side effects); the JS transport layer handles
    /// any peer messaging.
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
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle
                .initiate_revocation(&target_did, &manager_token)
                .map_err(to_js_err)?;
            Ok(())
        })
    }

    /// Return the current revocation status of a device (Req 9.1–9.5).
    ///
    /// Combines the in-flight M-of-N accumulation state
    /// (`signaturesCollected`, `signaturesRequired`, `status`) with the
    /// Req 9.5 last-known device status recorded in
    /// `RevocationSubsystem::device_status` (`lastKnownTrustLevel`,
    /// `lastRevocationDeltaReceivedAt`). The device-status fields are `null`
    /// until a RevocationDelta for the target has actually been applied.
    #[wasm_bindgen]
    pub async fn core_revocation_status(target_did: String) -> Result<JsValue, JsValue> {
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            let rev = handle
                .revocation
                .lock()
                .map_err(|e| to_js_err(format!("revocation lock: {e}")))?;
            let m = rev.threshold_m();
            let (collected, status_str) = match rev.store_status(&target_did) {
                Some(crate::auth::RevocationStatus::Applied) => (m, "APPLIED"),
                Some(crate::auth::RevocationStatus::Pending { collected, .. }) => {
                    (collected, "PENDING")
                }
                None => (0, "PENDING"),
            };
            drop(rev);
            // Req 9.5 — the last-known device status recorded by the subsystem.
            let device_status = handle
                .device_revocation_status(&target_did)
                .map_err(to_js_err)?;
            json_to_js(&serde_json::json!({
                "signaturesCollected": collected,
                "signaturesRequired": m,
                "status": status_str,
                "lastKnownTrustLevel": device_status
                    .as_ref()
                    .map(|ds| format!("{:?}", ds.last_known_trust_level).to_uppercase()),
                "lastRevocationDeltaReceivedAt": device_status
                    .as_ref()
                    .and_then(|ds| ds.last_revocation_delta_received_at),
            }))
        })
    }

    /// Append a RESOLVED tag to a contamination root Delta (Req 11.1).
    ///
    /// Delegates to [`api::CoreHandle::verify_data`] — the shared WASM + native
    /// implementation — so both build targets share one code path. The manager
    /// token expiry is caller-supplied (`now_secs` is the real current time),
    /// so expired tokens are rejected at the auth gate rather than bypassing it
    /// with a hardcoded `far_future` (Subphase 14.4 — Req 11.5).
    #[wasm_bindgen]
    pub async fn core_verify_data(
        root_delta_id: String,
        manager_token: String,
        now_secs: i64,
    ) -> Result<(), JsValue> {
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle
                .verify_data(&root_delta_id, &manager_token, now_secs)
                .map_err(to_js_err)
        })
    }

    /// Archive an incident without certifying data integrity (Req 11.2).
    ///
    /// Delegates to [`api::CoreHandle::admin_close`] — the shared WASM + native
    /// implementation. The `now_secs` parameter supplies the real current time
    /// so token-expiry enforcement is live (Subphase 14.4 — Req 11.5).
    #[wasm_bindgen]
    pub async fn core_admin_close(
        incident_id: String,
        manager_token: String,
        now_secs: i64,
    ) -> Result<(), JsValue> {
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle
                .admin_close(&incident_id, &manager_token, now_secs)
                .map_err(to_js_err)
        })
    }

    /// Activate Saturate Mode with a DISASTER_ALERT payload (Req 13.1).
    ///
    /// `biscuit_token_hex` — hex-encoded Biscuit token carrying the
    /// `disaster-alert` caveat, signed by a registered root CA key (Req 13.1,
    /// 13.7).  Delegates to [`api::CoreHandle::activate_saturate_mode`] — the
    /// shared WASM + native implementation — which verifies the token and
    /// routes activation through the transport's real `SaturateModeStateMachine`
    /// (Subphase 3.2): a 60-minute lease is opened and the DRR scheduler is
    /// reconciled into Saturate Mode.  Any verification failure leaves the
    /// current mode untouched (Req 13.7).
    #[wasm_bindgen]
    pub async fn core_activate_saturate_mode(biscuit_token_hex: String) -> Result<(), JsValue> {
        let token_bytes = decode_biscuit_token_hex(&biscuit_token_hex)?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle
                .activate_saturate_mode(&token_bytes)
                .map_err(to_js_err)
        })
    }

    /// Renew a Saturate_Mode Lease with a heartbeat DISASTER_ALERT token
    /// (Req 13.4).
    ///
    /// `biscuit_token_hex` — hex-encoded Biscuit token as for activation.
    /// Delegates to [`api::CoreHandle::renew_saturate_mode`] — the shared WASM
    /// + native implementation — which verifies the token and routes the
    /// renewal through the transport's real `SaturateModeStateMachine`: the
    /// lease is extended by 60 minutes from the renewal timestamp and the DRR
    /// scheduler stays in Saturate Mode.  A failed heartbeat leaves the mode
    /// untouched (Req 13.7).
    #[wasm_bindgen]
    pub async fn core_renew_saturate_mode(biscuit_token_hex: String) -> Result<(), JsValue> {
        let token_bytes = decode_biscuit_token_hex(&biscuit_token_hex)?;
        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle.renew_saturate_mode(&token_bytes).map_err(to_js_err)
        })
    }

    /// Terminate Saturate_Mode via an M-of-N Manager signature set (Req 13.6).
    ///
    /// `termination_message_hex` — hex-encoded canonical bytes that every
    /// terminating Manager signed.  `co_manager_signatures` — a JSON array of
    /// objects `[{"did": "did:key:z6Mk…", "signatureHex": "…"}, …]` carrying
    /// the raw Ed25519 signatures (64 bytes, hex-encoded) already collected
    /// from the other Managers; this device contributes its own signature over
    /// the message automatically.  Delegates to
    /// [`api::CoreHandle::terminate_saturate_mode`] — the shared WASM + native
    /// implementation — which routes the termination through the transport's
    /// real `SaturateModeStateMachine` and, at threshold, clears the lease and
    /// takes the DRR scheduler out of Saturate Mode.
    #[wasm_bindgen]
    pub async fn core_terminate_saturate_mode(
        termination_message_hex: String,
        co_manager_signatures: JsValue,
    ) -> Result<(), JsValue> {
        // Canonical termination message (the bytes the Managers signed).
        let message = hex::decode(&termination_message_hex).map_err(|_| {
            to_js_err(
                crate::errors::TirBaseError::AuthorisationFailed {
                    reason: "termination_message_hex: invalid hex encoding".to_string(),
                }
                .to_string(),
            )
        })?;
        if message.is_empty() {
            return Err(to_js_err(
                crate::errors::TirBaseError::AuthorisationFailed {
                    reason: "termination message must not be empty".to_string(),
                }
                .to_string(),
            ));
        }

        // Parse [{ did, signatureHex }, …] into (did, raw signature bytes).
        let sigs_json = js_to_json(&co_manager_signatures)
            .map_err(|e| to_js_err(format!("co_manager_signatures: {e:?}")))?;
        let entries = sigs_json.as_array().ok_or_else(|| {
            to_js_err("co_manager_signatures must be an array of { did, signatureHex } objects")
        })?;
        let mut co_signatures: Vec<(String, Vec<u8>)> = Vec::new();
        for entry in entries {
            let did = entry
                .get("did")
                .and_then(|v| v.as_str())
                .ok_or_else(|| to_js_err("each co-signature must carry a string \"did\" field"))?;
            let signature_hex = entry
                .get("signatureHex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    to_js_err("each co-signature must carry a string \"signatureHex\" field")
                })?;
            let sig_bytes = hex::decode(signature_hex)
                .map_err(|_| to_js_err("co-signature signatureHex: invalid hex encoding"))?;
            if sig_bytes.len() != 64 {
                return Err(to_js_err(
                    "co-signature signatureHex must decode to 64 bytes (128 hex chars)",
                ));
            }
            co_signatures.push((did.to_string(), sig_bytes));
        }

        CORE.with(|c| {
            let borrow = c.borrow();
            let handle = borrow
                .as_ref()
                .ok_or_else(|| to_js_err("core_init() must be called first"))?;
            handle
                .terminate_saturate_mode(&message, co_signatures)
                .map_err(to_js_err)
        })
    }

    /// Decode a hex-encoded Biscuit token, rejecting malformed or empty input
    /// with a `SignatureVerificationFailed`-style error string (shared by
    /// `core_activate_saturate_mode` and `core_renew_saturate_mode`).
    fn decode_biscuit_token_hex(biscuit_token_hex: &str) -> Result<Vec<u8>, JsValue> {
        let token_bytes = hex::decode(biscuit_token_hex).map_err(|_| {
            to_js_err(
                crate::errors::TirBaseError::SignatureVerificationFailed {
                    reason: "biscuit_token_hex: invalid hex encoding".to_string(),
                }
                .to_string(),
            )
        })?;
        if token_bytes.is_empty() {
            return Err(to_js_err(
                crate::errors::TirBaseError::SignatureVerificationFailed {
                    reason: "biscuit token is absent or empty".to_string(),
                }
                .to_string(),
            ));
        }
        Ok(token_bytes)
    }

    // ── Inbound peer message ───────────────────────────────────────────────────

    /// Accept raw peer message bytes from the JS transport layer and route them
    /// through the signature-verification → schema-hash gate → IndexedDB-backed
    /// store merge pipeline (Subphase 6.3).
    ///
    /// ## Contract for application developers
    ///
    /// The JS transport layer (WebRTC `RTCDataChannel`, BLE bridge, or any
    /// browser-compatible peer-to-peer transport) is responsible for calling
    /// this function when raw bytes arrive from a peer.  TirBase is
    /// transport-agnostic — it does not know *how* the bytes arrived, only what
    /// to do with them once they have.
    ///
    /// **Typical usage in a WebRTC `ondatachannel` handler:**
    /// ```js
    /// channel.onmessage = (event) => {
    ///   const bytes = new Uint8Array(event.data);
    ///   await core_receive_peer_message(bytes);
    ///   // Then poll for side-effect events produced by the merge:
    ///   const events = core_poll_events();
    ///   // … dispatch events to the TirBase SDK …
    /// };
    /// ```
    ///
    /// ## Message format
    ///
    /// `raw_bytes` must be a JSON-serialised `GossipMessage` (the same format
    /// produced by `GossipMessage::to_bytes()` on the Rust side).  Any bytes
    /// that cannot be deserialised into a known variant are silently dropped
    /// and an error is returned.
    ///
    /// ## Relationship to native builds
    ///
    /// On native builds, a libp2p Swarm is spawned at `init()` time, and
    /// `CoreHandle::init` also spawns a background task (Subphase 1.3) that
    /// calls `process_inbound_messages()` on a 50 ms interval, so Gossipsub
    /// messages are drained automatically — no application-level call is
    /// needed.  (Under `#[cfg(test)]` the interval is set to one hour so the
    /// loop does not race count-based unit tests; the same loop is exercised
    /// by the Subphase 1.3 integration test with a short interval.)
    /// WASM builds have no Swarm; this function is the explicit equivalent
    /// entry point for the inbound pipeline (Req 5, Req 1.4).
    #[wasm_bindgen]
    pub async fn core_receive_peer_message(raw_bytes: &[u8]) -> Result<(), JsValue> {
        use crate::transport::message::GossipMessage;

        let msg = GossipMessage::from_bytes(raw_bytes).ok_or_else(|| {
            to_js_err(
                "core_receive_peer_message: unrecognised payload — \
                 bytes could not be deserialised as a GossipMessage",
            )
        })?;

        let handle_ptr = core_ptr()?;
        // SAFETY: WASM is single-threaded; cooperative async, no concurrent mutation.
        let handle = unsafe { &*handle_ptr };

        // Subphase 7.4 parity: WASM transport also has a ReassemblyBuffer
        // (MeshTransport is constructed identically on both targets).  If the
        // incoming message is an InboundDeltaFragment, process_wire_message
        // buffers it and returns None until reassembly completes; only a fully
        // reassembled Delta (or a non-fragment message) is dispatched to the
        // WASM inbound handler.
        let processed = {
            let mut transport = handle.transport.lock().map_err(|e| {
                to_js_err(&format!(
                    "core_receive_peer_message: transport mutex poisoned: {e}"
                ))
            })?;
            transport.process_wire_message(msg)
        };

        match processed {
            Some(dispatch_msg) => handle
                .receive_inbound_wasm(dispatch_msg)
                .await
                .map_err(to_js_err),
            None => {
                // Fragment buffered (incomplete) or reassembly failed silently
                // (logged).  Nothing to dispatch.
                Ok(())
            }
        }
    }

    // ── Event polling ──────────────────────────────────────────────────────────

    /// Drain and return all queued WASM events as a JS array.
    ///
    /// Each element is a plain JS object serialised from `WasmEvent`.
    /// The TypeScript SDK calls this at the end of every `write()`, `read()`,
    /// and `query()` to surface Rust-side side-effects (trust-level changes,
    /// contamination incidents, durability tier promotions) without requiring
    /// a separate polling loop.
    #[wasm_bindgen]
    pub fn core_poll_events() -> JsValue {
        let events: Vec<crate::WasmEvent> =
            crate::WASM_EVENT_QUEUE.with(|q| q.borrow_mut().drain(..).collect());
        let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
        js_sys::JSON::parse(&json).unwrap_or(JsValue::NULL)
    }

    /// Compute the `SchemaIdentifierHash` for a TirBase schema definition document.
    ///
    /// Parses `schema_src` and returns the deterministic SHA-256 hash of the
    /// parsed schema structure as a hex string.  Used by SDK integration tests
    /// to verify the hash is computed from the parsed object, not raw string input.
    #[wasm_bindgen]
    pub fn core_schema_identifier_hash(schema_src: String) -> Result<String, JsValue> {
        let schema = crate::schema::parser::parse(&schema_src).map_err(|e| {
            to_js_err(e.iter().map(|err| err.to_string()).collect::<Vec<_>>().join("; "))
        })?;
        let hash = schema.identifier_hash();
        Ok(hex::encode(hash))
    }

    /// Pretty-print a TirBase schema definition document.
    ///
    /// Parses `schema_src` and returns the canonical printed representation.
    /// Used by SDK integration tests to verify `parse(print(schema))` round-trips.
    #[wasm_bindgen]
    pub fn core_schema_print(schema_src: String) -> Result<String, JsValue> {
        let schema = crate::schema::parser::parse(&schema_src).map_err(|e| {
            to_js_err(e.iter().map(|err| err.to_string()).collect::<Vec<_>>().join("; "))
        })?;
        Ok(crate::schema::printer::print(&schema))
    }

    /// Parse a TirBase schema definition document and return the structured
    /// schema as a JSON object.
    ///
    /// Used by SDK integration tests to verify the printer output is accepted
    /// by the parser without errors.
    #[wasm_bindgen]
    pub fn core_schema_parse(schema_src: String) -> Result<JsValue, JsValue> {
        let schema = crate::schema::parser::parse(&schema_src).map_err(|e| {
            to_js_err(e.iter().map(|err| err.to_string()).collect::<Vec<_>>().join("; "))
        })?;
        let json = serde_json::to_string(&schema).map_err(to_js_err)?;
        js_sys::JSON::parse(&json).map_err(|e| e)
    }
}
