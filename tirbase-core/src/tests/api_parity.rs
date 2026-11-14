// SPDX-License-Identifier: AGPL-3.0-only

//! Build-time API surface parity test (Req 1.2, 1.5).
//!
//! Asserts that the three public surfaces cannot drift apart:
//!
//! 1. the complete `CoreHandle` public IO/manager method set
//!    (`tirbase-core/src/api/mod.rs`),
//! 2. the `#[wasm_bindgen]` free-function exports in `tirbase-core/src/lib.rs`,
//! 3. the `WasmCore` TypeScript interface and the `required('core_*')` /
//!    `call('core_*')` delegations in `tirbase-sdk/src/wasm-bridge.ts`.
//!
//! Unlike a hand-maintained name list compared against another hand-maintained
//! name list, this test parses the real source files (`include_str!`) on every
//! run. Adding, renaming or removing a public method / WASM export / SDK
//! interface method without updating the other surfaces fails the test with a
//! precise diff. The constants below are only the *policy* layer (which
//! methods are intentionally not exported, and which exports the SDK relies
//! on); the *facts* come from the sources.

#![cfg(test)]

use std::collections::BTreeSet;

const API_SOURCE: &str = include_str!("../api/mod.rs");
const LIB_SOURCE: &str = include_str!("../lib.rs");
const SDK_BRIDGE_SOURCE: &str = include_str!("../../../tirbase-sdk/src/wasm-bridge.ts");
const SDK_TYPES_SOURCE: &str = include_str!("../../../sdk/typescript/src/types.ts");
const GATEWAY_OPENAPI_SOURCE: &str = include_str!("../../../docs/api/gateway-admin-openapi.yaml");

/// Every `#[wasm_bindgen]` export must either be claimed by the SDK here or
/// be a deliberately SDK-independent helper (schema helpers, registration
/// helpers). The test verifies these exports exist in `lib.rs`.
const SDK_REQUIRED_EXPORTS: &[&str] = &[
    "core_init",
    "core_write",
    "core_read",
    "core_query",
    "core_trust_level",
    "core_present_token",
    "core_mesh_status",
    "core_initiate_revocation",
    "core_revocation_status",
    "core_verify_data",
    "core_admin_close_ico",
    "core_activate_saturate_mode",
    "core_renew_saturate_mode",
    "core_terminate_saturate_mode",
    "core_receive_peer_message",
    "core_drain_outbound_messages",
    "core_local_did",
    "core_poll_events",
];

/// `CoreHandle` method → its `#[wasm_bindgen]` export. Every method listed
/// here must exist as a real `pub fn`/`pub async fn` on `CoreHandle`, must be
/// a real `#[wasm_bindgen]` export in `lib.rs`, and must be present on the
/// TypeScript `WasmCore` interface under `ts_name`.
const IO_MANAGER_EXPORTS: &[(&str, &str, &str)] = &[
    // `core_init` is invoked directly by the WASM loader, so it has no
    // `WasmCore` interface method (the SDK exposes `TirBase.init` instead).
    ("init", "core_init", ""),
    ("write", "core_write", "write"),
    ("read", "core_read", "read"),
    ("query", "core_query", "query"),
    ("trust_level", "core_trust_level", "trustLevel"),
    ("present_biscuit_token", "core_present_token", "core_present_token"),
    ("mesh_status", "core_mesh_status", "meshStatus"),
    (
        "register_root_ca_key",
        "core_register_root_ca_key",
        "",
    ),
    (
        "register_migration_ca_key",
        "core_register_migration_ca_key",
        "",
    ),
    (
        "initiate_revocation",
        "core_initiate_revocation",
        "initiateRevocation",
    ),
    (
        "device_revocation_status",
        "core_revocation_status",
        "revocationStatus",
    ),
    ("verify_contamination", "core_verify_data", "verifyData"),
    ("admin_close_ico", "core_admin_close_ico", "adminClose"),
    (
        "activate_saturate_mode",
        "core_activate_saturate_mode",
        "activateSaturateMode",
    ),
    (
        "renew_saturate_mode",
        "core_renew_saturate_mode",
        "renewSaturateMode",
    ),
    (
        "terminate_saturate_mode",
        "core_terminate_saturate_mode",
        "terminateSaturateMode",
    ),
    (
        "receive_inbound_wasm",
        "core_receive_peer_message",
        "receiveMessage",
    ),
    ("local_did", "core_local_did", "localDid"),
];

/// Canonical list of every `pub` method on `CoreHandle` that deliberately has
/// no `#[wasm_bindgen]` export, with the reason. The source parse below
/// guarantees no new public method can silently bypass this decision.
const UNEXPORTED_COREHANDLE_METHODS: &[(&str, &str)] = &[
    (
        "scheduler_stats",
        "DRR observability over the native transport; not part of the WASM SDK surface",
    ),
    (
        "reset_scheduler_stats",
        "DRR observability over the native transport; not part of the WASM SDK surface",
    ),
    (
        "set_scheduler_link_capacity",
        "native link-speed control; the WASM host owns its own transport",
    ),
    (
        "subscribe_diagnostics",
        "native-only tokio broadcast channel; WASM uses core_poll_events",
    ),
    (
        "root_ca_public_key",
        "synchronous key getter; key material stored in JS by register call",
    ),
    (
        "fleet_provision_device",
        "fleet control plane is native-only (CLI/admin), not an SDK boundary",
    ),
    (
        "fleet_revoke_device",
        "fleet control plane is native-only (CLI/admin), not an SDK boundary",
    ),
    (
        "fleet_inventory_snapshot",
        "fleet control plane is native-only (CLI/admin), not an SDK boundary",
    ),
    (
        "fleet_device",
        "fleet control plane is native-only (CLI/admin), not an SDK boundary",
    ),
    (
        "fleet_is_revoked",
        "fleet control plane is native-only (CLI/admin), not an SDK boundary",
    ),
    (
        "fleet_snapshot_hash",
        "fleet control plane is native-only (CLI/admin), not an SDK boundary",
    ),
    (
        "saturate_termination_message",
        "Saturate_Mode termination collection is a native host/mesh-manager \
         operation; the JS bridge collects co-signatures and calls \
         core_terminate_saturate_mode",
    ),
    (
        "saturate_termination_signature_count",
        "Saturate_Mode termination collection is a native host/mesh-manager \
         operation; the JS bridge collects co-signatures and calls \
         core_terminate_saturate_mode",
    ),
    (
        "request_saturate_termination",
        "Saturate_Mode termination collection is a native host/mesh-manager \
         operation; the JS bridge collects co-signatures and calls \
         core_terminate_saturate_mode",
    ),
    (
        "subscribe_fleet_updates",
        "native-only tokio broadcast channel",
    ),
    (
        "subscribe_checkpoint_observations",
        "native-only tokio broadcast channel",
    ),
    (
        "subscribe_security_event_sync",
        "native-only tokio broadcast channel",
    ),
    (
        "publish_security_event_sync",
        "native-only mesh control plane; no SDK call site",
    ),
    (
        "subscribe_mesh_commands",
        "native-only tokio broadcast channel; the gateway mesh receiver owns it",
    ),
    (
        "publish_mesh_command",
        "native-only mesh command ingress; no SDK call site",
    ),
    (
        "set_checkpoint_provider",
        "native-only callback registration (not serialisable over WASM)",
    ),
    (
        "publish_checkpoint_hash",
        "native-only mesh control plane; no SDK call site",
    ),
    (
        "set_challenge_handler",
        "native-only callback registration (not serialisable over WASM)",
    ),
    (
        "subscribe_mesh_challenge_responses",
        "native-only tokio broadcast channel",
    ),
    (
        "request_mesh_challenge",
        "native-only mesh control plane; no SDK call site",
    ),
    (
        "memory_budget_metrics",
        "native diagnostics accessor",
    ),
    (
        "set_inbound_caps",
        "native hardening configuration; WASM uses fixed compile-time caps",
    ),
    (
        "receive_inbound",
        "native-only Swarm polling caller; WASM equivalent is receive_inbound_wasm",
    ),
    (
        "process_inbound_messages",
        "internal native inbound drain loop, not a WASM boundary method",
    ),
    (
        "subscribe_durability_events",
        "native-only tokio broadcast channel; WASM uses core_poll_events",
    ),
    (
        "subscribe_incident_events",
        "native-only tokio broadcast channel; WASM delivers Incident* via core_poll_events",
    ),
    (
        "publish_migration_delta",
        "native-only mesh control plane; migrations are distributed by managers, not the SDK",
    ),
    (
        "publish_migration_revocation_delta",
        "native-only mesh control plane; migration revocations are distributed by managers, not the SDK",
    ),
    (
        "sidecar_conflicts",
        "native-only Side-Car conflict inspection; WASM reports conflicts in ReplaySummary",
    ),
    (
        "test_cce",
        "test-only accessor for the contamination engine",
    ),
    (
        "inject_inbound",
        "native-only test injection path, not part of the SDK surface",
    ),
    (
        "set_local_spatial_tag",
        "deployment provisioning of the Spatial_Diversity label; no SDK call site",
    ),
    (
        "local_spatial_tag",
        "deployment provisioning getter; no SDK call site",
    ),
];

// ─── Source parsers ───────────────────────────────────────────────────────────

/// Brace-matched body of the first `impl CoreHandle { ... }` block.
fn corehandle_impl_body(src: &str) -> &str {
    let start = src
        .find("impl CoreHandle {")
        .expect("api/mod.rs must contain `impl CoreHandle {`");
    let open = start + src[start..].find('{').expect("impl brace");
    let mut depth = 0usize;
    for (offset, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in `impl CoreHandle` block");
}

/// Every `pub fn` / `pub async fn` on `CoreHandle` (deduplicated).
fn corehandle_public_methods() -> BTreeSet<String> {
    let body = corehandle_impl_body(API_SOURCE);
    body.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let rest = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("pub async fn "))?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
        .collect()
}

/// Every `#[wasm_bindgen] pub fn` / `pub async fn` export in `lib.rs`.
fn wasm_bindgen_exports() -> BTreeSet<String> {
    let mut exports = BTreeSet::new();
    let mut pending_bindgen = false;
    for line in LIB_SOURCE.lines() {
        let trimmed = line.trim();
        if trimmed == "#[wasm_bindgen]" {
            pending_bindgen = true;
            continue;
        }
        if !pending_bindgen {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("pub fn ")
            .or_else(|| trimmed.strip_prefix("pub async fn "))
        {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                exports.insert(name);
            }
            pending_bindgen = false;
        } else {
            // Attribute was not followed by an exported fn — stop scanning it.
            pending_bindgen = false;
        }
    }
    exports
}

/// Method identifiers declared by `export interface WasmCore { ... }`.
fn sdk_wasmcore_methods() -> BTreeSet<String> {
    let marker = "export interface WasmCore {";
    let start = SDK_BRIDGE_SOURCE
        .find(marker)
        .expect("wasm-bridge.ts must declare `export interface WasmCore {`");
    let body_start = start + marker.len();
    let end = SDK_BRIDGE_SOURCE[body_start..]
        .find("\n}")
        .expect("unterminated WasmCore interface")
        + body_start;
    SDK_BRIDGE_SOURCE[body_start..end]
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.is_empty() {
                return None;
            }
            let name: String = trimmed
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let after = trimmed[name.len()..].trim_start();
            // Optional interface methods are declared `name?(...)`.
            let after = after.strip_prefix('?').unwrap_or(after).trim_start();
            if name.is_empty() || !after.starts_with('(') {
                return None;
            }
            Some(name)
        })
        .collect()
}

/// Every `core_*` export named by a `wasm-bridge.ts` delegation.
///
/// The bridge resolves exports through `required(...)`, and calls them through
/// `call(...)` / `callAsync(...)` wrappers that add error normalisation. All
/// three spell the export name as a string literal at the call site, so the
/// parser accepts any of them and still fails if a delegation names an export
/// `lib.rs` does not define.
fn sdk_required_exports() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for needle in ["required('", "call('", "callAsync('"] {
        let mut rest = SDK_BRIDGE_SOURCE;
        while let Some(idx) = rest.find(needle) {
            rest = &rest[idx + needle.len()..];
            let name: String = rest.chars().take_while(|c| *c != '\'').collect();
            if name.starts_with("core_") {
                found.insert(name);
            }
        }
    }
    found
}

/// Map a TypeScript `WasmCore` method name to the Rust export it must use.
///
/// `core_*` methods map to themselves; camelCase methods map to
/// `core_snake_case`; the two names whose Rust export differs from that rule
/// are listed explicitly.
fn ts_method_to_export(ts_name: &str) -> Option<String> {
    if ts_name.starts_with("core_") {
        return Some(ts_name.to_string());
    }
    let explicit = match ts_name {
        "adminClose" => Some("core_admin_close_ico"),
        "receiveMessage" => Some("core_receive_peer_message"),
        _ => None,
    };
    if let Some(name) = explicit {
        return Some(name.to_string());
    }
    let mut snake = String::from("core_");
    for (i, ch) in ts_name.chars().enumerate() {
        if ch.is_uppercase() {
            if i != 0 {
                snake.push('_');
            }
            snake.extend(ch.to_lowercase());
        } else {
            snake.push(ch);
        }
    }
    Some(snake)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// The parser must actually find the known surface — guards against a parser
/// that silently returns an empty set and makes every other assertion vacuous.
#[test]
fn parity_parsers_find_the_real_surfaces() {
    let methods = corehandle_public_methods();
    assert!(
        methods.len() >= 40,
        "parser found only {} CoreHandle public methods — parser is broken",
        methods.len()
    );
    let exports = wasm_bindgen_exports();
    assert!(
        exports.len() >= 20,
        "parser found only {} #[wasm_bindgen] exports — parser is broken",
        exports.len()
    );
    let ts = sdk_wasmcore_methods();
    assert!(
        ts.len() >= 14,
        "parser found only {} WasmCore interface methods — parser is broken",
        ts.len()
    );
}

/// Drift between `lib.rs`'s `#[wasm_bindgen]` exports and the SDK's
/// `required('core_*')` delegations fails the test in both directions.
#[test]
fn sdk_delegations_and_lib_exports_are_in_lockstep() {
    let exports = wasm_bindgen_exports();
    let sdk_required = sdk_required_exports();

    let missing_in_lib: Vec<&String> = sdk_required.difference(&exports).collect();
    assert!(
        missing_in_lib.is_empty(),
        "wasm-bridge.ts delegates to exports that lib.rs does not #[wasm_bindgen]-export: {missing_in_lib:?}"
    );

    let missing_in_sdk: Vec<&str> = SDK_REQUIRED_EXPORTS
        .iter()
        .copied()
        .filter(|name| !exports.contains(*name))
        .collect();
    assert!(
        missing_in_sdk.is_empty(),
        "SDK_REQUIRED_EXPORTS lists names that lib.rs does not export: {missing_in_sdk:?}"
    );
}

/// Every IO/manager operation exists on `CoreHandle`, is exported by
/// `lib.rs`, and is declared on the TypeScript `WasmCore` interface.
#[test]
fn complete_io_and_manager_surface_is_wired_across_all_three_layers() {
    let methods = corehandle_public_methods();
    let exports = wasm_bindgen_exports();
    let ts_methods = sdk_wasmcore_methods();

    for (method, export, ts_name) in IO_MANAGER_EXPORTS {
        assert!(
            methods.contains(*method),
            "CoreHandle::{method} is missing from api/mod.rs — the IO/manager surface shrank"
        );
        assert!(
            exports.contains(*export),
            "lib.rs is missing the #[wasm_bindgen] export `{export}` for CoreHandle::{method}"
        );
        if !ts_name.is_empty() {
            assert!(
                ts_methods.contains(*ts_name),
                "tirbase-sdk/src/wasm-bridge.ts `WasmCore` is missing `{ts_name}` for export `{export}`"
            );
        }
    }

    // Manager operations named explicitly by the spec must all be present.
    for (method, export) in [
        ("initiate_revocation", "core_initiate_revocation"),
        ("device_revocation_status", "core_revocation_status"),
        ("verify_contamination", "core_verify_data"),
        ("admin_close_ico", "core_admin_close_ico"),
        ("activate_saturate_mode", "core_activate_saturate_mode"),
        ("renew_saturate_mode", "core_renew_saturate_mode"),
        ("terminate_saturate_mode", "core_terminate_saturate_mode"),
    ] {
        assert!(methods.contains(method), "missing CoreHandle::{method}");
        assert!(exports.contains(export), "missing WASM export {export}");
        assert!(
            IO_MANAGER_EXPORTS
                .iter()
                .any(|(m, e, _)| *m == method && *e == export),
            "manager op {method} → {export} is not covered by IO_MANAGER_EXPORTS"
        );
    }
}

/// Every TypeScript `WasmCore` method maps to a real `#[wasm_bindgen]` export.
#[test]
fn every_sdk_wasmcore_method_maps_to_a_real_export() {
    let exports = wasm_bindgen_exports();
    let mut unmapped = Vec::new();
    for ts_name in sdk_wasmcore_methods() {
        match ts_method_to_export(&ts_name) {
            Some(export) if exports.contains(&export) => {}
            Some(export) => unmapped.push(format!("{ts_name} → {export} (export missing)")),
            None => unmapped.push(format!("{ts_name} (no mapping rule)")),
        }
    }
    assert!(
        unmapped.is_empty(),
        "WasmCore interface methods without a real Rust export: {unmapped:?}"
    );
}

/// Every public `CoreHandle` method is either exported or explicitly
/// documented as intentionally unexported; every exclusion is real.
#[test]
fn all_corehandle_public_methods_are_accounted_for() {
    let methods = corehandle_public_methods();
    let exports = wasm_bindgen_exports();

    let exported_methods: BTreeSet<&str> =
        IO_MANAGER_EXPORTS.iter().map(|(m, _, _)| *m).collect();
    let excluded: BTreeSet<&str> = UNEXPORTED_COREHANDLE_METHODS
        .iter()
        .map(|(m, _)| *m)
        .collect();

    let mut unaccounted: Vec<&str> = methods
        .iter()
        .map(String::as_str)
        .filter(|m| !exported_methods.contains(m) && !excluded.contains(m))
        .collect();
    unaccounted.sort_unstable();
    assert!(
        unaccounted.is_empty(),
        "CoreHandle public methods with no WASM export and no documented exclusion: {unaccounted:?}"
    );

    let mut stale: Vec<&str> = excluded
        .iter()
        .copied()
        .filter(|m| !methods.contains(*m))
        .collect();
    stale.sort_unstable();
    assert!(
        stale.is_empty(),
        "UNEXPORTED_COREHANDLE_METHODS references methods that are not pub on CoreHandle: {stale:?}"
    );

    for (method, export, _) in IO_MANAGER_EXPORTS {
        assert!(
            methods.contains(*method),
            "IO_MANAGER_EXPORTS references CoreHandle::{method}, which does not exist"
        );
        assert!(
            exports.contains(*export),
            "IO_MANAGER_EXPORTS references export {export}, which lib.rs does not declare"
        );
    }

    // Every declared export must be a method delegation (identity / transport
    // plumbing exports are listed here explicitly so they cannot drift in
    // silently).
    const NON_DELEGATING_EXPORTS: &[&str] = &[
        "core_register_root_ca_key_with_token",
        "core_drain_outbound_messages",
        "core_poll_events",
        "core_schema_identifier_hash",
        "core_schema_print",
        "core_schema_parse",
        // Property 1 cross-build parity probe (feature-gated: wasm+parity-probe).
        // Not a CoreHandle delegation and not part of the production SDK surface.
        "core_cross_build_parity_hash",
    ];
    let mapped_exports: BTreeSet<&str> = IO_MANAGER_EXPORTS.iter().map(|(_, e, _)| *e).collect();
    let mut undocumented: Vec<&str> = exports
        .iter()
        .map(String::as_str)
        .filter(|e| !mapped_exports.contains(e) && !NON_DELEGATING_EXPORTS.contains(e))
        .collect();
    undocumented.sort_unstable();
    assert!(
        undocumented.is_empty(),
        "lib.rs exports with no CoreHandle delegation and no documented exemption: {undocumented:?}"
    );
}

/// The SDK's real production caller path (`tirbase.ts`) depends on
/// `core_write`/`core_read`; both must stay exported and delegated.
#[test]
fn sdk_production_callers_have_wasm_exports() {
    let exports = wasm_bindgen_exports();
    for (method, export) in [("write", "core_write"), ("read", "core_read")] {
        assert!(
            IO_MANAGER_EXPORTS
                .iter()
                .any(|(m, e, _)| *m == method && *e == export),
            "IO_MANAGER_EXPORTS is missing the production SDK mapping {method} → {export}"
        );
        assert!(exports.contains(export), "lib.rs is missing {export}");
    }
}

fn sdk_ts_string_array_const(source: &str, const_name: &str) -> BTreeSet<String> {
    let marker = format!("export const {const_name} = [");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("types.ts must contain `{marker}`"));
    let rest = &source[start + marker.len()..];
    let end = rest
        .find("] as const;")
        .unwrap_or_else(|| panic!("types.ts const {const_name} must end with `] as const;`"));
    rest[..end]
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
                Some(trimmed[1..trimmed.len() - 1].to_string())
            } else {
                None
            }
        })
        .collect()
}

fn openapi_operation_ids(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("operationId:")
                .map(|rest| rest.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .collect()
}

fn openapi_admin_paths(source: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut in_paths = false;
    for line in source.lines() {
        if line == "paths:" {
            in_paths = true;
            continue;
        }
        if !in_paths {
            continue;
        }
        // Next top-level section (e.g. "components:", "security:")
        if !line.starts_with(' ') && !line.is_empty() {
            break;
        }
        // Path item keys are indented by one space under `paths:`.
        if let Some(rest) = line.strip_prefix(" /") {
            if let Some(path) = rest.strip_suffix(':') {
                paths.insert(format!("/{path}"));
            }
        }
    }
    paths
}

/// `sdk/typescript/src/types.ts` ADMIN_PATHS and OPERATION_IDS must stay in
/// lockstep with `docs/api/gateway-admin-openapi.yaml` (auto-generation source
/// of truth, CLAIM-49.2). Prevents SDK↔spec drift.
#[test]
fn sdk_typescript_admin_constants_match_gateway_openapi() {
    let sdk_ops = sdk_ts_string_array_const(SDK_TYPES_SOURCE, "OPERATION_IDS");
    let sdk_paths = sdk_ts_string_array_const(SDK_TYPES_SOURCE, "ADMIN_PATHS");
    let spec_ops = openapi_operation_ids(GATEWAY_OPENAPI_SOURCE);
    let spec_paths = openapi_admin_paths(GATEWAY_OPENAPI_SOURCE);

    assert!(
        !sdk_ops.is_empty() && !sdk_paths.is_empty(),
        "parser found empty SDK constants — parser is broken"
    );
    assert!(
        !spec_ops.is_empty() && !spec_paths.is_empty(),
        "parser found empty OpenAPI operations/paths — parser is broken"
    );

    let missing_ops: Vec<_> = spec_ops.difference(&sdk_ops).collect();
    let extra_ops: Vec<_> = sdk_ops.difference(&spec_ops).collect();
    assert!(
        missing_ops.is_empty() && extra_ops.is_empty(),
        "OPERATION_IDS drift: missing in SDK={missing_ops:?}, extra in SDK={extra_ops:?}"
    );

    let missing_paths: Vec<_> = spec_paths.difference(&sdk_paths).collect();
    let extra_paths: Vec<_> = sdk_paths.difference(&spec_paths).collect();
    assert!(
        missing_paths.is_empty() && extra_paths.is_empty(),
        "ADMIN_PATHS drift: missing in SDK={missing_paths:?}, extra in SDK={extra_paths:?}"
    );
}
