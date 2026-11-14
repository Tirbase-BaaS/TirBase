// SPDX-License-Identifier: AGPL-3.0-only

//! integration test: first-boot identity generation, replay-safe
//! bootstrap, and scoped token issuance verified by two real `CoreHandle`
//! instances (CLAIM-8.5, CLAIM-8.6, PV-3.11, PV-3.13).
//!
//! The enrollment service is the same one the gateway's admin endpoint uses;
//! the two `CoreHandle`s act as independent relying parties that verify the
//! issued token against the deployment root CA key.

use std::collections::BTreeMap;
use std::sync::Arc;

use tirbase_core::api::types::TrustLevel;
use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::identity::keypair;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::enrollment::{DeviceIdentity, EnrollmentService};
use tirbase_guard::epoch::{EpochError, EpochRegistry, InMemoryEpochStore, InMemoryNonceStore};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_types::CommandRole;

fn trust_root_with_rm(rm: &InMemoryKeyProvider, root_public: [u8; 32]) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: rm.did().to_string(),
                public_key: rm.public_key_bytes(),
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![root_public.to_vec()],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-enrollment-it-{tag}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(storage: &std::path::Path, root_public: [u8; 32]) -> InitConfig {
    InitConfig {
        storage_path: storage.to_string_lossy().into_owned(),
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        deployment: DeploymentConfig {
            root_ca_keys: vec![root_public],
            ..Default::default()
        },
    }
}

fn now_secs() -> i64 {
    tirbase_core::traits::wall_hint_secs().unwrap_or(0)
}

#[tokio::test]
async fn enrolled_token_verifies_on_two_real_core_handles() {
    let (root_seed, root_public) = keypair::generate_keypair().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();

    let nonces = Arc::new(InMemoryNonceStore::new());
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    let service = EnrollmentService::new(
        nonces,
        epochs.clone(),
        Arc::new(trust_root_with_rm(&rm, root_public)),
        root_seed.to_vec(),
        3_600,
    );

 // First-boot identity generation happens on the device.
    let device = DeviceIdentity::generate().unwrap();
    let request = device
        .bootstrap([42u8; 32], CommandRole::CommandIssuer)
        .unwrap();
    let enrolled = service.enroll(&request, now_secs()).unwrap();
    assert_eq!(enrolled.epoch, 0);
    assert_eq!(enrolled.device_id, device.device_id());
    assert_eq!(epochs.current_epoch(&device.device_id()).unwrap(), 0);

 // Replaying the bootstrap nonce is rejected (replay-safe bootstrap).
    assert_eq!(
        service.enroll(&request, now_secs()),
        Err(EpochError::NonceReused)
    );

    let token_hex = hex::encode(&enrolled.token);

 // Two real, independent CoreHandle instances verify the scoped token.
    let dir_a = temp_dir("a");
    let dir_b = temp_dir("b");
    let handle_a = CoreHandle::init(config(&dir_a.join("a.db"), root_public))
        .await
        .expect("init CoreHandle A");
    let handle_b = CoreHandle::init(config(&dir_b.join("b.db"), root_public))
        .await
        .expect("init CoreHandle B");

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
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
