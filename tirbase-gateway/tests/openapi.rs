// SPDX-License-Identifier: AGPL-3.0-only

//! F-03/F-08 contract tests: the admin OpenAPI document, the server routes and
//! both generated SDKs must describe the same surface.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tirbase_gateway::vertical_api::{VerticalApi, VERTICAL_ROUTE_TEMPLATES};

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(relative)
}

fn spec() -> String {
    std::fs::read_to_string(repo_path("docs/api/gateway-admin-openapi.yaml"))
        .expect("admin OpenAPI document exists")
}

fn documented_paths(doc: &str) -> BTreeSet<String> {
    doc.lines()
        .filter_map(|line| {
            let line = line.strip_prefix("  /admin/")?;
            let path = line.strip_suffix(':')?;
            Some(format!("/admin/{path}"))
        })
        .collect()
}

#[test]
fn gateway_admin_openapi_defines_every_admin_endpoint() {
    let doc = spec();
    for endpoint in [
        "/admin/enroll",
        "/admin/mint",
        "/admin/rotate",
        "/admin/policy",
        "/admin/events",
        "/admin/simulate",
        "/admin/challenge",
        "/admin/mode",
        "/admin/lockdown-exit",
        "/admin/chain-recovery",
        "/admin/status/{issuer_did}",
        "/admin/sequence-reset",
        "/admin/lease-preempt",
        "/admin/quarantine-replay",
        "/admin/time-reset",
        "/admin/unknown-clear",
        "/admin/restore",
        "/admin/epoch-bump",
        "/admin/rollout-status",
    ] {
        assert!(
            doc.contains(&format!("\n  {endpoint}:")),
            "OpenAPI document is missing {endpoint}"
        );
    }
    assert!(doc.starts_with("openapi: 3.1."), "OpenAPI 3.1 required");
    assert!(doc.contains("LocalPeerCredential"), "local auth scheme missing");
    assert!(doc.contains("type: mutualTLS"), "remote admin must be mTLS-only");
    assert!(
        doc.contains("Authorization Bearer") || doc.contains("Bearer <hex>"),
        "remote bearer requirement missing"
    );
    assert!(doc.contains("maximum: 86400"), "mint max lifetime missing");
    assert!(doc.contains("idempotency_key"), "idempotency contract missing");
    assert!(doc.contains("next_cursor"), "pagination contract missing");
    assert!(doc.contains("webhooks:"), "webhook contract missing");
    assert!(doc.contains("X-TirBase-Signature"), "webhook signature missing");
    assert!(!doc.contains("/admin/not-implemented"), "stub endpoint documented");
}

#[test]
fn every_vertical_server_route_is_in_openapi() {
    let doc = spec();
    for template in VERTICAL_ROUTE_TEMPLATES {
        assert!(
            doc.contains(&format!("\n  {template}:")),
            "OpenAPI document is missing vertical route {template}"
        );
    }
}

#[test]
fn every_vertical_route_resolves_in_the_server() {
    let dir = std::env::temp_dir().join(format!("tirbase-openapi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let api = VerticalApi::open(dir.join("primary.db")).unwrap();
    for template in VERTICAL_ROUTE_TEMPLATES {
        let probe = template.replace("{id}", "contract-probe");
        let (_, body) = api.dispatch("GET", &probe, None, 1_000);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_ne!(
            value["code"], "VERTICAL_ROUTE_NOT_FOUND",
            "server does not route documented path {template}: {body}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_documented_vertical_operation_is_routed() {
    let doc = spec();
    let mut operations = Vec::new();
    let mut current_path: Option<String> = None;
    for line in doc.lines() {
        if line == "components:" || line == "webhooks:" {
            current_path = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("  /admin/") {
            if let Some(path) = rest.strip_suffix(':') {
                current_path = Some(format!("/admin/{path}"));
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("    ") {
            let method = rest.trim_end_matches(':');
            if matches!(method, "get" | "post" | "patch" | "delete")
                && current_path.as_deref().is_some_and(|p| {
                    p.starts_with("/admin/cold-chain")
                        || p.starts_with("/admin/pos/")
                        || p.starts_with("/admin/venues")
                })
            {
                operations.push((current_path.clone().unwrap(), method.to_string()));
            }
        }
    }
    assert_eq!(operations.len(), 21, "expected 21 vertical operations");

    let dir = std::env::temp_dir().join(format!("tirbase-openapi-ops-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let api = VerticalApi::open(dir.join("primary.db")).unwrap();
    for (path, method) in operations {
        let probe = path.replace("{id}", "contract-probe");
        let (status, body) = api.dispatch(method.to_uppercase().as_str(), &probe, Some("{}"), 1_000);
        assert_ne!(status, 405, "{method} {path} is documented but not routed: {body}");
        assert!(
            !body.contains("VERTICAL_ROUTE_NOT_FOUND"),
            "{method} {path} is documented but not routed: {body}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_documented_path_is_in_both_generated_sdks() {
    let doc = spec();
    let documented = documented_paths(&doc);

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_path("sdk/typescript/generation-manifest.json")).unwrap(),
    )
    .unwrap();
    let sdk_paths: BTreeSet<String> = manifest["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        documented, sdk_paths,
        "generated manifest paths diverge from the OpenAPI document"
    );

    let ts = std::fs::read_to_string(repo_path("sdk/typescript/src/types.ts")).unwrap();
    let python =
        std::fs::read_to_string(repo_path("sdk/python/tirbase_gateway_client.py")).unwrap();
    for path in &documented {
        assert!(
            ts.contains(&format!("\"{path}\"")),
            "TypeScript SDK is missing {path}"
        );
        assert!(
            python.contains(&format!("\"{path}\"")),
            "Python SDK is missing {path}"
        );
    }

    // Every operationId must also be exposed by both clients.
    let operation_ids: BTreeSet<String> = manifest["operation_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    for operation_id in operation_ids {
        assert!(
            ts.contains(&format!("\"{operation_id}\"")),
            "TypeScript SDK is missing operation {operation_id}"
        );
        assert!(
            python.contains(&format!("\"{operation_id}\"")),
            "Python SDK is missing operation {operation_id}"
        );
    }
}
