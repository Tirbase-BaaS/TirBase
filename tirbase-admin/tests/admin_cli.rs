//! Task 9 integration tests (CLAIM-9.1..9.5, PV-3.10).
//!
//! 9.1 is satisfied by `cargo check -p tirbase-admin` and the clap-based CLI
//! subcommand declaration in `src/main.rs`.  9.2/9.3/9.4/9.5 drive the
//! production command modules; 9.2 also verifies the issued token with two
//! real `CoreHandle` instances.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::tempdir;
use tirbase_admin::{cmd, REQUIRED_SUBCOMMANDS};
use tirbase_core::api::types::TrustLevel;
use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::auth::biscuit;
use tirbase_core::identity::keypair;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str, name: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tirbase-admin-{tag}-{}-{n}-{name}",
        std::process::id()
    ))
}

fn core_config(storage: &std::path::Path, root_public: [u8; 32]) -> InitConfig {
    InitConfig {
        storage_path: storage.to_string_lossy().into_owned(),
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        deployment: DeploymentConfig {
            root_ca_keys: vec![root_public],
            ..Default::default()
        },
    }
}

#[test]
fn task9_1_cli_declares_all_required_subcommands() {
    assert!(
        REQUIRED_SUBCOMMANDS.starts_with(&["enroll", "mint", "rotate", "inspect-identities"]),
        "task 9 subcommands must remain present: {REQUIRED_SUBCOMMANDS:?}"
    );
    for req in ["export-log", "export-evidence-bundle", "verify-log"] {
        assert!(
            REQUIRED_SUBCOMMANDS.contains(&req),
            "task 27 subcommand missing: {req}"
        );
    }
}

#[tokio::test]
async fn task9_2_enroll_issues_token_verified_by_two_real_core_handles() {
    let (root_seed, root_public) = keypair::generate_keypair().unwrap();
    let device_key_path = temp_path("enroll", "device.json");

    let result = cmd::enroll::run(&cmd::enroll::EnrollArgs {
        root_ca_seed_hex: hex::encode(root_seed),
        role: "CommandIssuer".to_string(),
        ttl_secs: 3600,
        device_key_path: Some(device_key_path.clone()),
        nonce_hex: Some(hex::encode([7u8; 32])),
    })
    .expect("enroll command must succeed");

    assert!(result.device_id.starts_with("did:key:"));
    assert_eq!(result.epoch, 0);
    let token_hex = hex::encode(&result.token);

    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let handle_a = CoreHandle::init(core_config(&dir_a.path().join("a.db"), root_public))
        .await
        .unwrap();
    let handle_b = CoreHandle::init(core_config(&dir_b.path().join("b.db"), root_public))
        .await
        .unwrap();
    assert_eq!(
        handle_a.present_biscuit_token(&token_hex).unwrap(),
        TrustLevel::Verified
    );
    assert_eq!(
        handle_b.present_biscuit_token(&token_hex).unwrap(),
        TrustLevel::Verified
    );

    drop(handle_a);
    drop(handle_b);
    let _ = std::fs::remove_file(&device_key_path);
}

#[tokio::test]
async fn task9_3_mint_enforces_maximum_lifetime_86400s() {
    let (root_seed, root_public) = keypair::generate_keypair().unwrap();
    let did = "did:key:z6MkMintTestDevice";

    let over_limit = cmd::mint::run(&cmd::mint::MintArgs {
        did: did.to_string(),
        role: "CommandIssuer".to_string(),
        ttl_secs: 86_401,
        root_ca_seed_hex: hex::encode(root_seed),
    });
    assert!(
        over_limit.is_err(),
        "mint must reject ttl_secs > 86400; got {over_limit:?}"
    );
    let message = over_limit.unwrap_err().to_string();
    assert!(
        message.contains("86400") || message.contains("maximum"),
        "error must explain the max lifetime: {message}"
    );

    let token = cmd::mint::run(&cmd::mint::MintArgs {
        did: did.to_string(),
        role: "CommandIssuer".to_string(),
        ttl_secs: 3600,
        root_ca_seed_hex: hex::encode(root_seed),
    })
    .expect("mint within limit must succeed");
    let token_hex = hex::encode(&token);
    let claims = biscuit::verify_token(&token, &root_public, 0).expect("token verifies");
    assert_eq!(claims.did, did);
    assert_eq!(claims.role, "CommandIssuer");

    let dir = tempdir().unwrap();
    let handle = CoreHandle::init(core_config(&dir.path().join("core.db"), root_public))
        .await
        .unwrap();
    assert_eq!(
        handle.present_biscuit_token(&token_hex).unwrap(),
        TrustLevel::Verified
    );
}

#[test]
fn task9_4_rotate_generates_new_identity_and_backs_up_old_key() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("device-key.json");
    let initial = serde_json::json!({
        "did": "did:key:zOldDevice",
        "secret_key_hex": hex::encode([1u8; 32]),
        "public_key_hex": hex::encode([2u8; 32]),
    });
    std::fs::write(&key_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

    let result = cmd::rotate::run(&cmd::rotate::RotateArgs {
        key_path: key_path.clone(),
        backup_path: None,
    })
    .expect("rotate must succeed");

    assert_eq!(result.old_did.as_deref(), Some("did:key:zOldDevice"));
    assert!(result.new_did.starts_with("did:key:"));
    assert_ne!(result.old_did, Some(result.new_did.clone()));
    let backup = result.backup_path.as_deref().expect("backup path");
    let backup_body = std::fs::read_to_string(backup).unwrap();
    assert!(
        backup_body.contains("zOldDevice"),
        "backup keeps old identity"
    );
    let new_body = std::fs::read_to_string(&key_path).unwrap();
    assert!(
        new_body.contains(&result.new_did),
        "key file now holds new identity"
    );
    assert!(!new_body.contains("zOldDevice"));
}

#[test]
fn task9_5_inspect_identities_reports_public_fields_without_private_seed() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("identity.json");
    let body = serde_json::json!({
        "did": "did:key:z6MkInspect",
        "secret_key_hex": hex::encode([9u8; 32]),
        "public_key_hex": hex::encode([8u8; 32]),
    });
    std::fs::write(&key_path, serde_json::to_string_pretty(&body).unwrap()).unwrap();

    let records = cmd::inspect_identities::run(&cmd::inspect_identities::InspectIdentitiesArgs {
        identities: vec![key_path.clone()],
    })
    .expect("inspect must succeed");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.did.as_deref(), Some("did:key:z6MkInspect"));
    assert_eq!(
        record.public_key_hex.as_deref(),
        Some(hex::encode([8u8; 32]).as_str())
    );
    assert!(record.has_private_key);
    assert!(record.error.is_none());

    let rendered = serde_json::to_string(&records).unwrap();
    assert!(
        !rendered.contains(&hex::encode([9u8; 32])),
        "inspect output must never include the private seed"
    );
}
