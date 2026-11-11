//! Task 8 integration tests: root CA registry, trust-root rollback protection,
//! and the role registry (CLAIM-8.1, CLAIM-8.2, CLAIM-8.3, CLAIM-8.3a).
//!
//! These drive the same public API the gateway boot path uses:
//! [`RootCaRegistry`] for token verification, [`TrustRootManager`] for
//! version-committed installation/rotation, and [`TrustRootRecord`] for
//! role-threshold lookups.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tirbase_core::auth::biscuit;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::errors::TirBaseError;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::identity::keypair;
use tirbase_core::traits::{AssuranceLevel, KeyProvider, MonotonicCounterTrait};
use tirbase_guard::signed_operation::SignatureEntry;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, ParamFloor, RolePolicy, TrustRootError, TrustRootManager,
    TrustRootRecord, TrustRootSignature,
};
use tirbase_types::{CommandRole, FixedPointValue, UNIT_DEG_C};

#[derive(Debug, Default)]
struct MemoryCounter {
    value: AtomicU64,
}

impl MemoryCounter {
    fn new(value: u64) -> Self {
        MemoryCounter {
            value: AtomicU64::new(value),
        }
    }
}

impl MonotonicCounterTrait for MemoryCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Ok(self.value.load(Ordering::SeqCst))
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        Ok(self.value.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
        let mut current = self.value.load(Ordering::SeqCst);
        loop {
            if value <= current {
                return Ok(current);
            }
            match self
                .value
                .compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(value),
                Err(observed) => current = observed,
            }
        }
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

fn signer(provider: &InMemoryKeyProvider) -> AuthorizedRoleSigner {
    AuthorizedRoleSigner {
        did: provider.did().to_string(),
        public_key: provider.public_key_bytes(),
    }
}

fn sign_record(record: &mut TrustRootRecord, keys: &[&InMemoryKeyProvider]) {
    record.signatures.clear();
    let message = record.signing_bytes();
    for key in keys {
        record.signatures.push(TrustRootSignature {
            signer_did: key.did().to_string(),
            signature: key.sign(&message).unwrap(),
        });
    }
}

fn root_record(
    version: u64,
    root_keys: &[&InMemoryKeyProvider],
    threshold_k: u8,
) -> TrustRootRecord {
    let mut record = TrustRootRecord {
        version,
        root_ca_public_keys: root_keys.iter().map(|key| key.public_key_bytes()).collect(),
        threshold_k,
        role_thresholds: BTreeMap::new(),
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };
    sign_record(&mut record, root_keys);
    record
}

#[test]
fn k_of_n_root_rotation_revokes_old_keys_and_rejects_rollback() {
    let a = InMemoryKeyProvider::generate().unwrap();
    let b = InMemoryKeyProvider::generate().unwrap();
    let c = InMemoryKeyProvider::generate().unwrap();

    let record = root_record(1, &[&a, &b], 2);
    record
        .verify_threshold_signatures()
        .expect("v1 satisfies k=2");
    let counter = Arc::new(MemoryCounter::new(0));
    let mut manager =
        TrustRootManager::install(record, counter.clone(), 1_000).expect("install v1");

    // Rotation v2 keeps b, adds c, revokes a.  It is signed by b and c.
    let mut rotated = root_record(2, &[&b, &c], 2);
    rotated.revoked_root_ca_keys = vec![a.public_key_bytes()];
    sign_record(&mut rotated, &[&b, &c]);
    rotated
        .verify_threshold_signatures()
        .expect("v2 satisfies k=2 among active keys");
    manager
        .rotate(rotated, 1_000)
        .expect("v2 rotates under the counter");

    assert_eq!(manager.committed_version().unwrap(), 2);
    assert!(manager.record().is_root_revoked(&a.public_key_bytes()));
    assert!(!manager.record().is_root_revoked(&b.public_key_bytes()));

    // Restoring v1 must be rejected before anything is committed (CLAIM-8.2).
    let rollback = root_record(1, &[&a, &b], 2);
    assert_eq!(
        manager.rotate(rollback, 1_000),
        Err(TrustRootError::Rollback {
            incoming: 1,
            current: 2
        })
    );
    assert_eq!(counter.read().unwrap(), 2);
}

#[test]
fn revoked_root_key_can_no_longer_verify_a_token() {
    let (old_seed, old_pub) = keypair::generate_keypair().unwrap();
    let (new_seed, new_pub) = keypair::generate_keypair().unwrap();

    let token_from_old = biscuit::create_token(
        "did:key:zOldDevice",
        "CommandIssuer",
        3_600,
        &old_seed,
        false,
    )
    .unwrap();
    let token_from_new = biscuit::create_token(
        "did:key:zNewDevice",
        "CommandIssuer",
        3_600,
        &new_seed,
        false,
    )
    .unwrap();

    // Empty registry: the self-test path must reject before registration.
    let empty = RootCaRegistry::new(Vec::new());
    assert!(empty
        .verify_against_first(|key| biscuit::verify_token(&token_from_new, key, now_secs()))
        .is_err());

    let mut registry = RootCaRegistry::new(vec![old_pub, new_pub]);
    assert!(registry.revoke(&old_pub));
    assert_eq!(registry.active_keys(), vec![new_pub]);
    assert!(!registry.is_registered(&old_pub));

    // A token signed by the revoked key is rejected; the remaining key still
    // verifies its own tokens.
    assert!(registry
        .verify_against_first(|key| biscuit::verify_token(&token_from_old, key, now_secs()))
        .is_err());
    registry
        .verify_against_first(|key| biscuit::verify_token(&token_from_new, key, now_secs()))
        .expect("token verifies against the remaining root key");
}

#[test]
fn role_registry_rejects_a_valid_co_signature_from_an_unregistered_did() {
    let authorised = InMemoryKeyProvider::generate().unwrap();
    let attacker = InMemoryKeyProvider::generate().unwrap();

    let mut record = root_record(1, &[&authorised], 1);
    record.role_thresholds.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(1, vec![signer(&authorised)]),
    );

    let message = b"epoch-bump";
    let entries = vec![SignatureEntry {
        signer_did: attacker.did().to_string(),
        role: CommandRole::PolicyAuthority,
        signature: attacker.sign(message).unwrap(),
    }];

    assert_eq!(
        record.verify_role_signatures(CommandRole::PolicyAuthority, message, &entries),
        Err(TrustRootError::RoleNotAuthorized {
            role: CommandRole::PolicyAuthority,
            signer_did: attacker.did().to_string(),
        }),
        "the DID lookup must happen before signature verification (PV-3.3)"
    );
}

#[test]
fn trust_root_record_carries_role_thresholds_floors_and_expiry() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let mut record = root_record(3, &[&pa], 1);

    record.role_thresholds.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(2, vec![signer(&pa)]),
    );
    record.device_class_floors.insert(
        "cold_room".to_string(),
        vec![ParamFloor {
            param_name: "temperature".to_string(),
            min_floor: FixedPointValue::new(-400, -1, UNIT_DEG_C),
            max_ceiling: FixedPointValue::new(100, -1, UNIT_DEG_C),
        }],
    );

    assert_eq!(
        record.role_threshold(CommandRole::RevocationManager),
        Some(2)
    );
    assert_eq!(
        record
            .device_class_floor("cold_room", "temperature")
            .unwrap()
            .min_floor
            .mantissa,
        -400
    );
    assert!(!record.is_expired(1_000));
    record.expiry_est = 2_000;
    assert!(!record.is_expired(2_000));
    assert!(record.is_expired(2_001));
}

fn now_secs() -> i64 {
    tirbase_core::traits::wall_hint_secs().unwrap_or(0)
}
