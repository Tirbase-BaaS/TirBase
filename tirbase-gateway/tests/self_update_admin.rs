// SPDX-License-Identifier: AGPL-3.0-only

//! / RD-6: the `/admin/self-update` endpoint is a real production
//! caller of `SelfUpdateController` — UpdateSigner-signed apply, PolicyAuthority
//! signed rollback, and an honest 503 when the deployment has not configured it.

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use tirbase_gateway::admin::{dispatch_admin_command, AdminState};
use tirbase_gateway::self_update::{
    SelfUpdateController, SignedConfigRollback, SignedFirmwareManifest,
};

fn configured_state(
    dir: &std::path::Path,
    update: &SigningKey,
    policy: &SigningKey,
) -> AdminState {
    let config_path = dir.join("gateway.toml");
    std::fs::write(&config_path, "key_path = \"live\"\n").expect("seed config");
    AdminState {
        self_update: Some(Arc::new(Mutex::new(
            SelfUpdateController::new(Some("1".into()))
                .with_config_path(config_path)
                .with_update_signer(update.verifying_key().to_bytes())
                .with_policy_authority(policy.verifying_key().to_bytes()),
        ))),
        ..Default::default()
    }
}

fn call(state: Option<&AdminState>, payload: serde_json::Value) -> (u16, serde_json::Value) {
    let command = json!({"cmd": "self-update", "payload": payload}).to_string();
    let response = dispatch_admin_command(&command, state);
    let parsed: serde_json::Value = serde_json::from_str(response.trim()).expect("json response");
    let status = parsed["status"].as_u64().unwrap_or(0) as u16;
    (status, parsed)
}

#[test]
fn self_update_reports_unconfigured_instead_of_pretending() {
    let state = AdminState::default();
    let (status, body) = call(Some(&state), json!({"action": "status"}));
    assert_eq!(status, 503);
    assert_eq!(body["code"], "ADMIN_STATE_UNCONFIGURED");
    assert!(body["missing"]
        .as_str()
        .unwrap_or_default()
        .contains("UpdateSigner"));
}

#[test]
fn self_update_apply_verifies_update_signer_and_writes_config_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let update = SigningKey::from_bytes(&[0x11u8; 32]);
    let policy = SigningKey::from_bytes(&[0x22u8; 32]);
    let state = configured_state(dir.path(), &update, &policy);

    let mut manifest = SignedFirmwareManifest {
        version: "2".into(),
        artifact_hash_sha256_hex: "ab".repeat(32),
        update_signer_did: "did:key:zUpdateSignerTest".into(),
        signature_hex: String::new(),
    };
    manifest.signature_hex = hex::encode(update.sign(&manifest.canonical_bytes()).to_bytes());

    let (status, body) = call(
        Some(&state),
        json!({
            "action": "apply",
            "manifest": manifest,
            "new_config": "key_path = \"updated\"\n",
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["applied_version"], "2");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("gateway.toml")).expect("read config"),
        "key_path = \"updated\"\n"
    );
}

#[test]
fn self_update_rejects_manifest_signed_by_another_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let update = SigningKey::from_bytes(&[0x11u8; 32]);
    let policy = SigningKey::from_bytes(&[0x22u8; 32]);
    let attacker = SigningKey::from_bytes(&[0x33u8; 32]);
    let state = configured_state(dir.path(), &update, &policy);

    let mut manifest = SignedFirmwareManifest {
        version: "3".into(),
        artifact_hash_sha256_hex: "cd".repeat(32),
        update_signer_did: "did:key:zAttacker".into(),
        signature_hex: String::new(),
    };
    manifest.signature_hex = hex::encode(attacker.sign(&manifest.canonical_bytes()).to_bytes());

    let (status, body) = call(
        Some(&state),
        json!({
            "action": "apply",
            "manifest": manifest,
            "new_config": "key_path = \"evil\"\n",
        }),
    );
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["code"], "SELF_UPDATE_REJECTED");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("gateway.toml")).expect("read config"),
        "key_path = \"live\"\n",
        "a rejected manifest must not modify the live config"
    );
}

#[test]
fn self_update_rollback_requires_policy_authority_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let update = SigningKey::from_bytes(&[0x11u8; 32]);
    let policy = SigningKey::from_bytes(&[0x22u8; 32]);
    let attacker = SigningKey::from_bytes(&[0x33u8; 32]);
    let state = configured_state(dir.path(), &update, &policy);

    let mut rollback = SignedConfigRollback {
        target_config_version: "1".into(),
        policy_authority_did: "did:key:zAttacker".into(),
        signature_hex: String::new(),
    };
    rollback.signature_hex = hex::encode(attacker.sign(&rollback.canonical_bytes()).to_bytes());
    let (status, body) = call(Some(&state), json!({"action": "rollback", "rollback": rollback}));
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["code"], "ROLLBACK_REJECTED");

    let mut rollback = SignedConfigRollback {
        target_config_version: "1".into(),
        policy_authority_did: "did:key:zPolicyAuthorityTest".into(),
        signature_hex: String::new(),
    };
    rollback.signature_hex = hex::encode(policy.sign(&rollback.canonical_bytes()).to_bytes());
    let (status, body) = call(Some(&state), json!({"action": "rollback", "rollback": rollback}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["restored_version"], "1");
}
