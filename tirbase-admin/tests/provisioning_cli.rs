// SPDX-License-Identifier: AGPL-3.0-only

//! F-04 `tirbase-admin provisioning` integration test.
//!
//! Drives the production CLI entry points against a real SQLite `primary.db`:
//! claim issuance, signed payload minting, online enrolment, registry query,
//! credential rotation, ownership transfer, and offline provisioning.

use ed25519_dalek::SigningKey;
use tirbase_admin::cmd::provisioning::{self, ProvisioningArgs};

fn fixture() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("primary.db").display().to_string();
    let seed_hex = hex::encode([7u8; 32]);
    (dir, db_path, seed_hex)
}

fn args(db_path: &str, seed_hex: &str, action: &str) -> ProvisioningArgs {
    ProvisioningArgs {
        action: action.to_string(),
        db_path: Some(db_path.into()),
        signer_seed_hex: Some(seed_hex.to_string()),
        ..Default::default()
    }
}

#[test]
fn cli_claim_payload_enroll_query_rotate_transfer_and_offline() {
    let (_dir, db_path, seed_hex) = fixture();
    let signer = SigningKey::from_bytes(&[7u8; 32]);
    let device = SigningKey::from_bytes(&[9u8; 32]);

    let claim = provisioning::run(&ProvisioningArgs {
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        site: Some("s1".to_string()),
        device_type: Some("cold-room-gateway".to_string()),
        issued_by: Some("operator-1".to_string()),
        ttl_secs: Some(3600),
        ..args(&db_path, &seed_hex, "claim")
    })
    .expect("claim");
    let claim_code = claim["claim_code"]["code"].as_str().unwrap().to_string();

    let payload = provisioning::run(&ProvisioningArgs {
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        site: Some("s1".to_string()),
        device_id: Some("did:key:zCliDevice".to_string()),
        device_type: Some("cold-room-gateway".to_string()),
        device_public_key_hex: Some(hex::encode(device.verifying_key().to_bytes())),
        claim_code: Some(claim_code.clone()),
        firmware_version: Some("1.0.0".to_string()),
        config_version: Some("cfg-1".to_string()),
        ttl_secs: Some(3600),
        ..args(&db_path, &seed_hex, "payload")
    })
    .expect("payload");
    assert_eq!(
        payload["payload"]["signature"].as_array().unwrap().len(),
        64
    );

    let enrolled = provisioning::run(&ProvisioningArgs {
        device_id: Some("did:key:zCliDevice".to_string()),
        device_type: Some("cold-room-gateway".to_string()),
        device_public_key_hex: Some(hex::encode(device.verifying_key().to_bytes())),
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        site: Some("s1".to_string()),
        claim_code: Some(claim_code),
        firmware_version: Some("1.0.0".to_string()),
        config_version: Some("cfg-1".to_string()),
        ..args(&db_path, &seed_hex, "enroll")
    })
    .expect("enroll");
    assert_eq!(enrolled["device"]["state"], "Active");

    let queried = provisioning::run(&ProvisioningArgs {
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        site: Some("s1".to_string()),
        device_type: Some("cold-room-gateway".to_string()),
        state: Some("Active".to_string()),
        ..args(&db_path, &seed_hex, "query")
    })
    .expect("query");
    assert_eq!(queried["count"], 1);

    let rotated = provisioning::run(&ProvisioningArgs {
        device_id: Some("did:key:zCliDevice".to_string()),
        ..args(&db_path, &seed_hex, "rotate")
    })
    .expect("rotate");
    assert_eq!(rotated["outcome"], "credential_rotated");

    let transferred = provisioning::run(&ProvisioningArgs {
        device_id: Some("did:key:zCliDevice".to_string()),
        tenant: Some("/Organisation:globex/Site:s9".to_string()),
        site: Some("s9".to_string()),
        ..args(&db_path, &seed_hex, "transfer")
    })
    .expect("transfer");
    assert_eq!(transferred["outcome"], "ownership_transferred");

    let old_tenant = provisioning::run(&ProvisioningArgs {
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        ..args(&db_path, &seed_hex, "query")
    })
    .expect("query old tenant");
    assert_eq!(old_tenant["count"], 0);

    // Offline provisioning through the CLI is idempotent.
    let claim2 = provisioning::run(&ProvisioningArgs {
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        site: Some("s1".to_string()),
        device_type: Some("cold-room-gateway".to_string()),
        ttl_secs: Some(3600),
        ..args(&db_path, &seed_hex, "claim")
    })
    .expect("claim 2");
    let claim2_code = claim2["claim_code"]["code"].as_str().unwrap().to_string();
    let offline_args = ProvisioningArgs {
        tenant: Some("/Organisation:acme/Site:s1".to_string()),
        site: Some("s1".to_string()),
        device_id: Some("did:key:zCliOffline".to_string()),
        device_type: Some("cold-room-gateway".to_string()),
        device_public_key_hex: Some(hex::encode(device.verifying_key().to_bytes())),
        claim_code: Some(claim2_code),
        ttl_secs: Some(3600),
        ..args(&db_path, &seed_hex, "offline")
    };
    let first = provisioning::run(&offline_args).expect("offline");
    assert_eq!(first["idempotent_replay"], false);
    // Same payload id is derived from device_id + now; a second invocation at
    // the same authenticated-time second is an idempotent replay.
    let second = provisioning::run(&offline_args).expect("offline replay");
    assert_eq!(second["idempotent_replay"], true);

    let _ = signer;
}
