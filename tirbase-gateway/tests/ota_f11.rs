// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tirbase_gateway::admin::{dispatch_admin_command_at, AdminState};
use tirbase_gateway::ota::{artifact_sha256_hex, bundle_signing_bytes, AbSlotManager, BootState, SlotName};
use tirbase_types::ota::{OtaBundleBody, OtaCompatibility, OtaComponent, ReleaseChannel, SignedOtaBundle};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn signed_bundle(key: &SigningKey, version: u64, artifact: &[u8], channel: ReleaseChannel) -> SignedOtaBundle {
    let body = OtaBundleBody {
        bundle_version: version,
        release_version: format!("1.0.{version}"),
        channel,
        artifact_hash_sha256_hex: artifact_sha256_hex(artifact),
        artifact_size: artifact.len() as u64,
        compatibility: OtaCompatibility {
            component_versions: BTreeMap::from([(OtaComponent::Gateway, format!("1.0.{version}"))]),
            min_compatible: BTreeMap::from([(OtaComponent::Sdk, "1.0.0".to_string())]),
            ..Default::default()
        },
        metadata: BTreeMap::new(),
    };
    let sig = key.sign(&bundle_signing_bytes(&body).expect("signing bytes"));
    SignedOtaBundle {
        body,
        signer_did: "did:key:zOta".into(),
        signature_hex: hex::encode(sig.to_bytes()),
    }
}

fn ota_state(dir: &std::path::Path, tenant: Option<&str>) -> AdminState {
    let slots = AbSlotManager::new(dir.join("boot.json"), dir.join("slots"));
    let key = signer();
    AdminState {
        ota_slots: Some(Arc::new(slots)),
        ota_signer_public_key: Some(key.verifying_key().to_bytes()),
        ota_channel_policy: Some(tirbase_gateway::ota::ChannelPolicy {
            allowed_channels: vec!["dev".into(), "staging".into(), "pilot".into(), "production".into()],
            tenant_id: tenant.map(|s| s.to_string()),
        }),
        ota_rollout_state_path: Some(dir.join("rollout.json")),
        ..Default::default()
    }
}

fn cmd(action: serde_json::Value, state: &AdminState) -> serde_json::Value {
    let payload = serde_json::json!({"cmd": "ota", "payload": action}).to_string();
    let out = dispatch_admin_command_at(&payload, Some(state), 0);
    serde_json::from_str(out.trim()).expect("json response")
}

#[test]
fn unsigned_or_downgraded_bundle_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let state = ota_state(dir.path(), None);
    let key = signer();
    let artifact = b"artifact-v2";

    // unsigned/tampered: bad signature rejected
    let mut bad = signed_bundle(&key, 2, artifact, ReleaseChannel::Production);
    bad.signature_hex = "00".repeat(64);
    let resp = cmd(serde_json::json!({
        "action": "verify",
        "bundle": bad,
        "artifact_hex": hex::encode(artifact),
    }), &state);
    assert_eq!(resp["status"], 422);
    assert_eq!(resp["code"], "OTA_SIGNATURE_INVALID");

    // install a valid v2 to set committed version
    let ok = signed_bundle(&key, 2, artifact, ReleaseChannel::Production);
    let staged = cmd(serde_json::json!({
        "action": "stage",
        "bundle": ok,
        "artifact_hex": hex::encode(artifact),
    }), &state);
    assert_eq!(staged["status"], 200);
    let committed = cmd(serde_json::json!({"action":"commit"}), &state);
    assert_eq!(committed["status"], 200);
    assert_eq!(committed["boot"]["committed_bundle_version"], 2);

    // downgrade attempt (v1 <= committed v2) rejected
    let downgrade = signed_bundle(&key, 1, artifact, ReleaseChannel::Production);
    let resp = cmd(serde_json::json!({
        "action": "verify",
        "bundle": downgrade,
        "artifact_hex": hex::encode(artifact),
    }), &state);
    assert_eq!(resp["status"], 422);
    assert_eq!(resp["code"], "OTA_DOWNGRADE_REJECTED");
}

#[test]
fn interrupted_update_boots_previous_known_good_version() {
    let dir = tempfile::tempdir().unwrap();
    let slots = AbSlotManager::new(dir.path().join("boot.json"), dir.path().join("slots"));
    let key = signer();

    // seed known-good in slot A at version 1
    let mut boot = BootState::default();
    boot.committed_bundle_version = 1;
    boot.current_slot = SlotName::A;
    boot.known_good_slot = SlotName::A;
    boot.slot_mut(SlotName::A).bundle_version = Some(1);
    boot.slot_mut(SlotName::A).installed = true;
    boot.slot_mut(SlotName::A).healthy = true;
    slots.save_state(&boot).unwrap();

    // stage an update to slot B but do NOT commit (simulate interruption/power loss)
    let artifact = b"v2-bytes";
    let bundle = signed_bundle(&key, 2, artifact, ReleaseChannel::Production);
    slots.stage_bundle(&bundle, artifact).unwrap();

    // reboot/reconcile: must boot previous known-good
    let reconciled = slots.reconcile_on_boot().unwrap();
    assert_eq!(reconciled.current_slot, SlotName::A, "must boot previous known-good slot");
    assert_eq!(reconciled.known_good_slot, SlotName::A);
    assert!(reconciled.pending_slot.is_none());
    assert_eq!(reconciled.committed_bundle_version, 1);
    assert!(reconciled.last_rollback_reason.as_deref().unwrap_or("").contains("known-good slot"));
}

#[test]
fn version_skewed_client_receives_typed_error_not_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let state = ota_state(dir.path(), None);
    let resp = cmd(serde_json::json!({
        "action": "check_skew",
        "peer_versions": { "sdk": "0.9.0", "gateway": "1.0.0", "guard": "1.0.0", "driver": "1.0.0" },
        "compatibility": { "min_compatible": { "sdk": "1.0.0" }, "max_compatible": {}, "component_versions": {} }
    }), &state);
    assert_eq!(resp["status"], 409);
    assert_eq!(resp["compatible"], false);
    assert_eq!(resp["error"], "VERSION_SKEW");
    assert_eq!(resp["skew"]["code"], "BELOW_MINIMUM");
    assert_eq!(resp["skew"]["component"], "sdk");
}

#[test]
fn offline_update_path_and_channels_and_staged_rollout() {
    let dir = tempfile::tempdir().unwrap();
    let state = ota_state(dir.path(), Some("tenant-a"));
    let key = signer();
    let artifact = b"offline-v3";

    // tenant-pinned bundle for another tenant rejected (channel rule)
    let wrong_tenant = signed_bundle(&key, 3, artifact, ReleaseChannel::TenantPinned { tenant_id: "tenant-b".into() });
    let resp = cmd(serde_json::json!({
        "action": "verify",
        "bundle": wrong_tenant,
        "artifact_hex": hex::encode(artifact),
    }), &state);
    assert_eq!(resp["status"], 422);
    assert_eq!(resp["code"], "OTA_CHANNEL_REJECTED");

    // offline path ingest (sites without connectivity)
    let offline = dir.path().join("offline-bundle");
    std::fs::create_dir_all(&offline).unwrap();
    let bundle = signed_bundle(&key, 3, artifact, ReleaseChannel::TenantPinned { tenant_id: "tenant-a".into() });
    std::fs::write(offline.join("manifest.json"), serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    std::fs::write(offline.join("artifact.bin"), artifact).unwrap();
    let staged = cmd(serde_json::json!({"action": "stage", "offline_path": offline.to_str().unwrap()}), &state);
    assert_eq!(staged["status"], 200, "offline stage failed: {staged}");
    assert_eq!(staged["channel"]["kind"], "tenant_pinned");

    // staged rollout with health gates and automatic pause
    let started = cmd(serde_json::json!({
        "action":"rollout_start","rollout_id":"r1","bundle_version":3,"target_count":10,
        "health_gates":[{"name":"boot","required":true},{"name":"health","required":true}]
    }), &state);
    assert_eq!(started["status"], 200);
    assert_eq!(started["rollout"]["phase"], "canary");

    let bad_health = cmd(serde_json::json!({"action":"rollout_health","healthy":false}), &state);
    assert_eq!(bad_health["status"], 409);
    assert_eq!(bad_health["error"], "ROLLOUT_AUTO_PAUSED");
    assert_eq!(bad_health["rollout"]["auto_paused"], true);
    assert_eq!(bad_health["rollout"]["phase"], "paused");
}
