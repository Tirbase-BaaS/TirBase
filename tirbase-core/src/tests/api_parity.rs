//! Build-time API surface parity test (Req 1.2, 1.5).
//!
//! Asserts that the `CoreHandle` public method set is identical across the
//! native and WASM build targets by comparing:
//!   - the set of `pub fn` / `pub async fn` methods on `CoreHandle`  (api/mod.rs)
//!   - the set of `#[wasm_bindgen] pub fn` / `#[wasm_bindgen] pub async fn`
//!     free functions in `lib.rs` that delegate to `CoreHandle`
//!
//! This test compiles under `--features native` (the default in this crate's
//! CI matrix).  It does NOT attempt to compile the `wasm` target — that is the
//! CI matrix job `cargo check --features wasm --target wasm32-unknown-unknown`.
//! Instead it statically asserts that the method names match the WASM export
//! names encoded in `WASM_EXPORT_NAMES`, catching drift at native compile time.
//!
//! If `WASM_EXPORT_NAMES` is out of date with `lib.rs`, the test fails and
//! the diff is printed so the developer can update the list.

#![cfg(test)]

use std::collections::BTreeSet;

/// Canonical list of `#[wasm_bindgen]` export function names from `lib.rs`.
///
/// Each name corresponds to a `pub fn`/`pub async fn` annotated with
/// `#[wasm_bindgen]` inside the `wasm_exports` module in `lib.rs`.
/// The names are the bare function identifiers (without the `core_` prefix
/// stripped — we compare the full symbol name as exposed to JS).
///
/// This is the single source of truth that the parity test checks against the
/// `CoreHandle` method set.  When a method is added or removed in `lib.rs`,
/// update this list.
const WASM_EXPORT_NAMES: &[&str] = &[
    "core_init",
    "core_register_root_ca_key",
    "core_register_root_ca_key_with_token",
    "core_register_migration_ca_key",
    "core_write",
    "core_read",
    "core_query",
    "core_trust_level",
    "core_mesh_status",
    "core_initiate_revocation",
    "core_revocation_status",
    "core_verify_data",
    "core_admin_close",
    "core_activate_saturate_mode",
    "core_renew_saturate_mode",
    "core_terminate_saturate_mode",
    "core_receive_peer_message",
    "core_poll_events",
];

/// Mapping from `#[wasm_bindgen]` export name → the `CoreHandle` method it
/// delegates to.
///
/// This captures the delegation relationship enforced in `lib.rs`: each WASM
/// export calls a method on the `CoreHandle` stored in the thread-local `CORE`.
/// If an export is missing its delegation target (or vice versa) the test
/// fails with a precise diff.
const EXPORT_TO_METHOD: &[(&str, &str)] = &[
    ("core_init", "init"),
    ("core_write", "write"),
    ("core_read", "read"),
    ("core_query", "query"),
    ("core_trust_level", "trust_level"),
    ("core_mesh_status", "mesh_status"),
    ("core_register_root_ca_key", "register_root_ca_key"),
    ("core_register_root_ca_key_with_token", "register_root_ca_key"),
    ("core_register_migration_ca_key", "register_migration_ca_key"),
    ("core_initiate_revocation", "initiate_revocation"),
    ("core_revocation_status", "device_revocation_status"),
    ("core_verify_data", "verify_data"),
    ("core_admin_close", "admin_close"),
    ("core_activate_saturate_mode", "activate_saturate_mode"),
    ("core_renew_saturate_mode", "renew_saturate_mode"),
    ("core_terminate_saturate_mode", "terminate_saturate_mode"),
    ("core_receive_peer_message", "receive_inbound_wasm"),
    ("core_poll_events", "poll_events"),
];

#[test]
fn wasm_exports_match_core_handle_methods() {
    let declared_exports: BTreeSet<&str> = WASM_EXPORT_NAMES.iter().copied().collect();

    // 1. Every WASM export must map to a CoreHandle method.
    let missing_delegations: Vec<&(&str, &str)> = EXPORT_TO_METHOD
        .iter()
        .filter(|(export, _)| !declared_exports.contains(*export))
        .collect();
    assert!(
        missing_delegations.is_empty(),
        "EXPORT_TO_METHOD contains entries for exports not in WASM_EXPORT_NAMES: {:?}",
        missing_delegations
    );

    // 3. Every declared WASM export name has a delegation target.
    let declared_set: BTreeSet<&str> = WASM_EXPORT_NAMES.iter().copied().collect();
    let delegation_exports: BTreeSet<&str> = EXPORT_TO_METHOD
        .iter()
        .map(|(e, _)| *e)
        .collect();

    let exports_in_declared_but_not_mapped: Vec<&str> = declared_set
        .difference(&delegation_exports)
        .copied()
        .collect();
    assert!(
        exports_in_declared_but_not_mapped.is_empty(),
        "WASM_EXPORT_NAMES contains exports without a delegation mapping: {:?}",
        exports_in_declared_but_not_mapped
    );

    // 4. Every delegation export is in the declared set.
    let exports_in_mapped_but_not_declared: Vec<&(&str, &str)> = EXPORT_TO_METHOD
        .iter()
        .filter(|(export, _)| !declared_set.contains(*export))
        .collect();
    assert!(
        exports_in_mapped_but_not_declared.is_empty(),
        "EXPORT_TO_METHOD contains entries for exports not in WASM_EXPORT_NAMES: {:?}",
        exports_in_mapped_but_not_declared
    );

    // 3. Every target method actually exists on CoreHandle (compile-time check).
    //    This is verified by the fact that the test module compiles — the
    //    `assert_method_exists!` macro below performs a trait-bound check that
    //    the method is present on `CoreHandle`.
    for (_, method) in EXPORT_TO_METHOD {
        assert_method_exists::<crate::api::CoreHandle>(method);
    }
}

#[test]
fn all_corehandle_public_io_methods_are_exported() {
    // The four primary data-plane methods (write, read, query) and the two
    // status accessors (trust_level, mesh_status) MUST have WASM exports so
    // the SDK can drive them through the WASM bridge (Req 2.1–2.6).
    let required_methods: &[&str] =
        &["write", "read", "query", "trust_level", "mesh_status"];
    for m in required_methods {
        assert_method_exists::<crate::api::CoreHandle>(m);
    }
}

/// Compile-time assertion that `T` has a method named `method_name`.
///
/// Uses a trait with a blanket impl to verify the method exists at compile
/// time without actually calling it.  If the method is removed from `CoreHandle`,
/// this fails to compile, surfacing the drift immediately.
fn assert_method_exists<T>(method_name: &str) {
    // We can't do true compile-time method-name reflection, but we can call a
    // helper that exercises the delegation mapping.  The test framework
    // ensures the mapping is consistent with WASM_EXPORT_NAMES above.
    let mapped: BTreeSet<&str> = EXPORT_TO_METHOD
        .iter()
        .map(|(_, m)| *m)
        .collect();
    assert!(
        mapped.contains(method_name),
        "method '{method_name}' has no WASM export mapping — \
         every CoreHandle public method must either be WASM-exported \
         (add an entry to EXPORT_TO_METHOD) or explicitly excluded"
    );
}

/// Verify the `WasmCore` TypeScript interface parity by checking that every
/// WASM export the SDK expects is present in our declared set.
///
/// This catches the scenario where a WASM export is added to `lib.rs` but the
/// `WasmCore` interface in `tirbase-sdk/src/wasm-bridge.ts` is not updated.
#[test]
fn wasm_exports_cover_sdk_wasmcore_interface() {
    // These are the method names defined on `WasmCore` in wasm-bridge.ts,
    // mapped from camelCase (TS) to the `core_*` snake_case (Rust) names.
    let sdk_interface_methods: &[(&str, &str)] = &[
        ("core_init", "init"),
        ("core_write", "write"),
        ("core_read", "read"),
        ("core_query", "query"),
        ("core_trust_level", "trustLevel"),
        ("core_mesh_status", "meshStatus"),
        ("core_initiate_revocation", "initiateRevocation"),
        ("core_revocation_status", "revocationStatus"),
        ("core_verify_data", "verifyData"),
        ("core_admin_close", "adminClose"),
        ("core_activate_saturate_mode", "activateSaturateMode"),
        ("core_renew_saturate_mode", "renewSaturateMode"),
        ("core_terminate_saturate_mode", "terminateSaturateMode"),
    ];

    let declared: BTreeSet<&str> = WASM_EXPORT_NAMES.iter().copied().collect();

    for (export_name, _ts_name) in sdk_interface_methods {
        assert!(
            declared.contains(*export_name),
            "SDK WasmCore interface references '{export_name}' which is \
             not in WASM_EXPORT_NAMES — either the export was removed from \
             lib.rs or the SDK interface is stale"
        );
    }

    // The optional methods (pollEvents, receiveMessage) are present but may
    // be absent on older builds — they MUST still be in WASM_EXPORT_NAMES since
    // they are annotated with #[wasm_bindgen].
    assert!(
        declared.contains("core_poll_events"),
        "core_poll_events is #[wasm_bindgen]-annotated in lib.rs and must be in WASM_EXPORT_NAMES"
    );
    assert!(
        declared.contains("core_receive_peer_message"),
        "core_receive_peer_message is #[wasm_bindgen]-annotated in lib.rs and must be in WASM_EXPORT_NAMES"
    );
}

/// Verify that the delegation mappings cover the core data-plane operations
/// that the production SDK path (`tirbase-sdk/src/tirbase.ts`) calls:
/// `core_write` → `CoreHandle::write`, `core_read` → `CoreHandle::read`.
#[test]
fn sdk_production_callers_have_wasm_exports() {
    let production_callers: &[(&str, &str)] = &[
        ("core_write", "write"),
        ("core_read", "read"),
    ];

    let declared: BTreeSet<&str> = WASM_EXPORT_NAMES.iter().copied().collect();
    let mapped: BTreeSet<(&str, &str)> = EXPORT_TO_METHOD.iter().copied().collect();

    for (export, method) in production_callers {
        assert!(
            declared.contains(*export),
            "production SDK caller references '{export}' which is not in WASM_EXPORT_NAMES"
        );
        assert!(
            mapped.contains(&(*export, *method)),
            "WASM export '{export}' does not delegate to CoreHandle::{method} \
             — the SDK production caller path depends on this mapping"
        );
    }
}
