// SPDX-License-Identifier: AGPL-3.0-only

//! F-04 provisioning/lifecycle integration tests over the gateway admin surface.
//!
//! These drive the real admin dispatch (`dispatch_admin_command_at` and
//! `dispatch_http_request`) against a real SQLite `primary.db` provisioning
//! registry, exercising claim issuance, signed payload minting, enrolment,
//! credential lifecycle, ownership transfer, drift reporting, offline
//! provisioning, registry queries, and durability across reopen.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use tempfile::TempDir;
use tirbase_gateway::admin::{dispatch_admin_command_at, dispatch_http_request, AdminCaller, AdminState};
use tirbase_gateway::provisioning::ProvisioningService;

const ORG_SITE_TENANT: &str = r#"[{"level":"Organisation","id":"acme"},{"level":"Site","id":"s1"}]"#;

struct Fixture {
    _dir: TempDir,
    db_path: std::path::PathBuf,
    authority: SigningKey,
    device: SigningKey,
    state: AdminState,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("primary.db");
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let device = SigningKey::from_bytes(&[9u8; 32]);
        let service = ProvisioningService::open(
            &db_path,
            authority.verifying_key().to_bytes(),
            Some(authority.clone()),
        )
        .expect("open provisioning service");
        let state = AdminState {
            provisioning: Some(Arc::new(service)),
            provisioning_authority_public_key: Some(authority.verifying_key().to_bytes()),
            ..Default::default()
        };
        Fixture {
            _dir: dir,
            db_path,
            authority,
            device,
            state,
        }
    }

    fn cmd(&self, command: Value) -> Value {
        let response = dispatch_admin_command_at(&command.to_string(), Some(&self.state), 1000);
        serde_json::from_str(response.trim()).expect("admin response JSON")
    }

    fn claim(&self, device_type: &str, _now: i64) -> String {
        let response = self.cmd(json!({
            "cmd": "provisioning-claim",
            "payload": {
                "tenant": serde_json::from_str::<Value>(ORG_SITE_TENANT).unwrap(),
                "site": "s1",
                "device_type": device_type,
                "ttl_secs": 3600,
                "issued_by": "operator-1",
            }
        }));
        assert_eq!(response["status"], 200, "claim response: {response}");
        response["claim_code"]["code"]
            .as_str()
            .expect("claim code")
            .to_string()
    }

    fn payload(&self, device_id: &str, claim: &str, _now: i64) -> Value {
        let response = self.cmd(json!({
            "cmd": "provisioning-payload",
            "payload": {
                "tenant": serde_json::from_str::<Value>(ORG_SITE_TENANT).unwrap(),
                "site": "s1",
                "device_id": device_id,
                "device_public_key_hex": hex::encode(self.device.verifying_key().to_bytes()),
                "device_type": "cold-room-gateway",
                "claim_code": claim,
                "firmware_version": "1.0.0",
                "config_version": "cfg-1",
                "ttl_secs": 3600,
                "issued_by": "operator-1",
            }
        }));
        assert_eq!(response["status"], 200, "payload response: {response}");
        response["payload"].clone()
    }
}

#[test]
fn provisioning_lifecycle_over_admin_dispatch_is_durable_and_tenant_scoped() {
    let fixture = Fixture::new();
    let claim = fixture.claim("cold-room-gateway", 1000);
    let payload = fixture.payload("did:key:zDevice1", &claim, 1000);

    // Enrolment via the signed payload.
    let enrolled = fixture.cmd(json!({
        "cmd": "provisioning-enroll",
        "payload": {"actor": "operator-1", "payload": payload}
    }));
    assert_eq!(enrolled["status"], 200, "enroll response: {enrolled}");
    assert_eq!(enrolled["device"]["state"], "Active");
    assert_eq!(enrolled["device"]["tenant"]["segments"][0]["id"], "acme");
    let first_credential = enrolled["device"]["active_credential_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Registry query by tenant, site, type, and state.
    let query = fixture.cmd(json!({
        "cmd": "provisioning-query",
        "payload": {
            "tenant": serde_json::from_str::<Value>(ORG_SITE_TENANT).unwrap(),
            "site": "s1",
            "device_type": "cold-room-gateway",
            "state": "Active",
        }
    }));
    assert_eq!(query["status"], 200, "query response: {query}");
    assert_eq!(query["count"], 1, "query response: {query}");

    // HTTP GET query path (query string parsing).
    let (status, body) = dispatch_http_request(
        "GET",
        "/admin/provisioning/devices?site=s1&type=cold-room-gateway&state=Active",
        None,
        Some(&fixture.state),
        1000,
        &AdminCaller::Local,
    );
    assert_eq!(status, 200, "http query: {body}");
    let http_query: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(http_query["count"], 1, "http query: {http_query}");

    // Version reporting and drift detection.
    let drift = fixture.cmd(json!({
        "cmd": "provisioning-report",
        "payload": {"device_id": "did:key:zDevice1", "firmware_version": "0.9.0", "config_version": "cfg-1"}
    }));
    assert_eq!(drift["status"], 200, "report response: {drift}");
    assert_eq!(drift["drift"]["firmware_drifted"], true);
    let cleared = fixture.cmd(json!({
        "cmd": "provisioning-report",
        "payload": {"device_id": "did:key:zDevice1", "firmware_version": "1.0.0", "config_version": "cfg-1"}
    }));
    assert_eq!(cleared["drift"]["firmware_drifted"], false);

    // Credential rotation.
    let rotated = fixture.cmd(json!({
        "cmd": "provisioning-rotate",
        "payload": {"device_id": "did:key:zDevice1"}
    }));
    assert_eq!(rotated["status"], 200, "rotate response: {rotated}");
    let new_credential = rotated["credential"]["credential_id"].as_str().unwrap();
    assert_ne!(new_credential, first_credential);

    // Ownership transfer: old tenant query is empty, new tenant sees the device.
    let transferred = fixture.cmd(json!({
        "cmd": "provisioning-transfer",
        "payload": {
            "device_id": "did:key:zDevice1",
            "tenant": [{"level":"Organisation","id":"globex"},{"level":"Site","id":"s9"}],
            "site": "s9",
        }
    }));
    assert_eq!(transferred["status"], 200, "transfer response: {transferred}");
    let old_tenant = fixture.cmd(json!({
        "cmd": "provisioning-query",
        "payload": {"tenant": serde_json::from_str::<Value>(ORG_SITE_TENANT).unwrap()}
    }));
    assert_eq!(old_tenant["count"], 0, "old tenant must not see the device: {old_tenant}");
    let new_tenant = fixture.cmd(json!({
        "cmd": "provisioning-query",
        "payload": {"tenant": [{"level":"Organisation","id":"globex"},{"level":"Site","id":"s9"}]}
    }));
    assert_eq!(new_tenant["count"], 1, "new tenant must see the device: {new_tenant}");

    // Durability: a fresh service over the same primary.db retains the device.
    let reopened = ProvisioningService::open(
        &fixture.db_path,
        fixture.authority.verifying_key().to_bytes(),
        None,
    )
    .expect("reopen service");
    let reopened_state = AdminState {
        provisioning: Some(Arc::new(reopened)),
        provisioning_authority_public_key: Some(fixture.authority.verifying_key().to_bytes()),
        ..Default::default()
    };
    let persisted = serde_json::from_str::<Value>(
        dispatch_admin_command_at(
            &json!({"cmd":"provisioning-query","payload":{"site":"s9"}}).to_string(),
            Some(&reopened_state),
            1000,
        )
        .trim(),
    )
    .unwrap();
    assert_eq!(persisted["count"], 1, "registry survives reopen: {persisted}");
}

#[test]
fn offline_provisioning_is_idempotent_and_revocation_blocks_reenrolment() {
    let fixture = Fixture::new();
    let claim = fixture.claim("cold-room-gateway", 1000);
    let payload = fixture.payload("did:key:zOffline", &claim, 1000);

    let first = fixture.cmd(json!({
        "cmd": "provisioning-offline",
        "payload": {"actor": "field-tech", "payload": payload}
    }));
    assert_eq!(first["status"], 200, "offline response: {first}");
    assert_eq!(first["idempotent_replay"], false);

    let replay = fixture.cmd(json!({
        "cmd": "provisioning-offline",
        "payload": {"actor": "field-tech", "payload": payload}
    }));
    assert_eq!(replay["status"], 200, "offline replay: {replay}");
    assert_eq!(replay["idempotent_replay"], true, "replay response: {replay}");

    // Revoke, then a fresh claim+payload for the same identity is refused.
    let revoked = fixture.cmd(json!({
        "cmd": "provisioning-revoke",
        "payload": {"device_id": "did:key:zOffline", "actor": "secops"}
    }));
    assert_eq!(revoked["status"], 200, "revoke response: {revoked}");

    let claim2 = fixture.claim("cold-room-gateway", 2000);
    let payload2 = fixture.payload("did:key:zOffline", &claim2, 2000);
    let blocked = fixture.cmd(json!({
        "cmd": "provisioning-enroll",
        "payload": {"actor": "secops", "payload": payload2}
    }));
    assert_eq!(blocked["status"], 409, "re-enrolment must be blocked: {blocked}");
    assert_eq!(blocked["code"], "REENROLMENT_BLOCKED", "blocked response: {blocked}");

    // Re-issue authorisation is recorded but does not resurrect the old identity.
    let reissue = fixture.cmd(json!({
        "cmd": "provisioning-reissue",
        "payload": {"device_id": "did:key:zOffline", "actor": "secops"}
    }));
    assert_eq!(reissue["status"], 200, "reissue response: {reissue}");
    let still_blocked = fixture.cmd(json!({
        "cmd": "provisioning-enroll",
        "payload": {"actor": "secops", "payload": payload2}
    }));
    assert_eq!(still_blocked["status"], 409, "old identity stays blocked: {still_blocked}");

    // Decommission also clears tenant-scoped state.
    let decommissioned = fixture.cmd(json!({
        "cmd": "provisioning-decommission",
        "payload": {"device_id": "did:key:zOffline", "actor": "secops"}
    }));
    assert_eq!(decommissioned["status"], 200, "decommission response: {decommissioned}");

    // Audit trail records the lifecycle.
    let audit = fixture.cmd(json!({"cmd": "provisioning-audit", "payload": {}}));
    let kinds: Vec<_> = audit["audit"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["kind"].as_str())
        .collect();
    for expected in [
        "ClaimIssued",
        "Enrolled",
        "OfflineProvisionApplied",
        "CredentialRevoked",
        "ReissuePrepared",
        "DeviceDecommissioned",
    ] {
        assert!(kinds.contains(&expected), "missing audit {expected}: {kinds:?}");
    }
}

#[test]
fn provisioning_endpoints_answer_503_when_unconfigured() {
    let state = AdminState::default();
    let response = dispatch_admin_command_at(
        &json!({"cmd":"provisioning-query","payload":{}}).to_string(),
        Some(&state),
        1000,
    );
    let value: Value = serde_json::from_str(response.trim()).unwrap();
    assert_eq!(value["status"], 503, "unconfigured response: {value}");
    assert_eq!(value["code"], "ADMIN_STATE_UNCONFIGURED");
}
