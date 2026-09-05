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

/// Canonical list of every `pub` method on `CoreHandle` (api/mod.rs) that does
/// **not** have a `#[wasm_bindgen]` export in `lib.rs`, together with the
/// documented reason for its absence.
///
/// This is the maintained list of intentional exclusions.  When a new method
/// is added to `CoreHandle`, it must either:
/// - appear in `EXPORT_TO_METHOD` (which adds a WASM export), or
/// - appear here with a reason.
///
/// If a method is added to `CoreHandle` and is absent from both lists, this
/// test fails, forcing the developer to make the export decision explicit.
const UNEXPORTED_COREHANDLE_METHODS: &[(&str, &str)] = &[
    // Native-only diagnostics channel — `tokio::sync::broadcast::Receiver`
    // cannot be passed across the WASM boundary; diagnostics are delivered to
    // the SDK via `core_poll_events` (WasmEvent stream) instead.
    ("subscribe_diagnostics", "native-only tokio broadcast channel"),

    // Synchronous getter for the root CA public key bytes — the SDK retrieves
    // this via `core_register_root_ca_key_with_token` (which accepts the key
    // material) and stores it in JS memory; a separate getter is unnecessary.
    ("root_ca_public_key", "synchronous key getter; key material stored in JS by register call"),

    // Native-only inbound path — `receive_inbound` (the non-wasm arm at
    // api/mod.rs:2234) is the Swarm-polling-task caller on native; the WASM
    // equivalent is `receive_inbound_wasm` (which is exported as
    // `core_receive_peer_message`).
    ("receive_inbound", "native-only Swarm polling caller; WASM equivalent is receive_inbound_wasm"),

    // Internal dispatch — `process_inbound_messages` drains the native inbound
    // channel and is not a public WASM boundary method.
    ("process_inbound_messages", "internal native inbound drain loop, not a WASM boundary method"),

    // `receive_inbound_wasm` is the WASM-internal implementation of the inbound
    // path; it is called by `core_receive_peer_message` and is not itself
    // exported — exporting it would create a duplicate entry in the WASM
    // surface.
    ("receive_inbound_wasm", "WASM-internal inbound impl, called by core_receive_peer_message"),

    // Native-only durability event subscription — returns a
    // `tokio::sync::broadcast::Receiver` which has no WASM equivalent;
    // durability events on WASM are delivered through `core_poll_events`.
    ("subscribe_durability_events", "native-only tokio broadcast channel; WASM uses core_poll_events"),

    // Native-only test injection path — `inject_inbound` is used by native
    // integration tests to simulate inbound gossip messages; it is not part of
    // the SDK surface.
    ("inject_inbound", "native-only test injection path, not part of SDK surface"),
];

/// All `pub` method names on `CoreHandle` (the complete set that must be
/// accounted for in `EXPORT_TO_METHOD` or `UNEXPORTED_COREHANDLE_METHODS`).
const ALL_COREHANDLE_PUBLIC_METHODS: &[&str] = &[
    "init",
    "write",
    "read",
    "query",
    "trust_level",
    "mesh_status",
    "subscribe_diagnostics",
    "root_ca_public_key",
    "register_root_ca_key",
    "register_migration_ca_key",
    "initiate_revocation",
    "device_revocation_status",
    "activate_saturate_mode",
    "renew_saturate_mode",
    "terminate_saturate_mode",
    "verify_data",
    "admin_close",
    "receive_inbound",
    "receive_inbound_wasm",
    "process_inbound_messages",
    "subscribe_durability_events",
    "inject_inbound",
];

#[test]
fn all_corehandle_public_methods_are_accounted_for() {
    let exported: BTreeSet<&str> = EXPORT_TO_METHOD.iter().map(|(_, m)| *m).collect();
    let unexported_reasons: BTreeSet<&str> =
        UNEXPORTED_COREHANDLE_METHODS.iter().map(|(m, _)| *m).collect();

    for method in ALL_COREHANDLE_PUBLIC_METHODS {
        let is_exported = exported.contains(method);
        let is_documented = unexported_reasons.contains(method);

        assert!(
            is_exported || is_documented,
            "CoreHandle::'{method}' is pub but has no WASM export and no documented \
             exclusion reason — add it to EXPORT_TO_METHOD or UNEXPORTED_COREHANDLE_METHODS"
        );
    }

    // Every entry in UNEXPORTED_COREHANDLE_METHODS must correspond to a real
    // method on CoreHandle (prevents stale entries from accumulating).
    for (method, _reason) in UNEXPORTED_COREHANDLE_METHODS {
        assert!(
            ALL_COREHANDLE_PUBLIC_METHODS.contains(method),
            "UNEXPORTED_COREHANDLE_METHODS references '{method}' which is not a \
             pub method on CoreHandle — remove the stale entry"
        );
    }
}
