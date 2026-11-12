//! : the admin OpenAPI document must describe every admin endpoint.
//!
//! Kept as a repository test (no YAML dependency) so a renamed or dropped
//! endpoint shows up as a failure instead of a stale document.

#[test]
fn gateway_admin_openapi_defines_every_admin_endpoint() {
 let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
 .join("../docs/api/gateway-admin-openapi.yaml");
 let doc = std::fs::read_to_string(&path).expect("admin OpenAPI document exists");

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
 doc.contains(&format!(" {endpoint}:")),
 "OpenAPI document is missing {endpoint}"
 );
 }

 assert!(
 doc.contains("LocalPeerCredential"),
 "local auth scheme missing"
 );
 assert!(
 doc.contains("type: mutualTLS"),
 "remote admin must be mTLS-only"
 );
 assert!(doc.contains("maximum: 86400"), "mint max lifetime missing");
 assert!(
 !doc.contains("/admin/not-implemented"),
 "stub endpoint must not be documented"
 );
}
