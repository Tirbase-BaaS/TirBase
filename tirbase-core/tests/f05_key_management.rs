// SPDX-License-Identifier: AGPL-3.0-only

//! F-05 acceptance tests: key rotation, revocation without fleet re-key, and
//! no private key material in debug/test output.

use tirbase_core::keys::{
    CustodianApproval, KeyCustodian, KeyDomain, KeyError, KeyRegistry, KeyState, QuorumApproval,
    QuorumPolicy, RecoveryOperation, RevocationReason, SoftwareCustodian,
};

fn seed_hex(seed: &[u8; 32]) -> String {
    hex::encode(seed)
}

/// Done when: a rotated key cannot verify new artefacts after expiry.
#[test]
fn f05_rotated_key_cannot_verify_new_artefacts_after_expiry() {
    let custodian = SoftwareCustodian::new();
    let mut registry = KeyRegistry::new();
    registry
        .register(
            custodian
                .generate(KeyDomain::UpdateSigner, "update-1", 1, 1_000, 10_000)
                .expect("generate update-1"),
        )
        .expect("register update-1");

    let old_artefact = registry
        .sign(
            &custodian,
            KeyDomain::UpdateSigner,
            b"release-manifest-v1",
            1_400,
        )
        .expect("sign with update-1");

    // Rotate at 1_500 with a 100 s overlap; the old key's window closes at 1_600.
    let receipt = registry
        .rotate(
            &custodian,
            KeyDomain::UpdateSigner,
            "update-2",
            1_500,
            100,
            10_000,
        )
        .expect("rotate update signer");
    assert_eq!(receipt.previous_key_id.as_deref(), Some("update-1"));
    assert_eq!(receipt.overlap_ends_at, 1_600);

    // During the overlap the old artefact still verifies.
    old_artefact
        .verify(&registry, b"release-manifest-v1", 1_550)
        .expect("old artefact verifies inside the overlap window");

    // A new artefact signed (externally) by the rotated-out key must be
    // rejected once the overlap has expired.
    let new_bytes = b"release-manifest-v2";
    let message = KeyRegistry::signing_bytes(KeyDomain::UpdateSigner, new_bytes);
    let stale_signature = custodian
        .sign(KeyDomain::UpdateSigner, "update-1", &message)
        .expect("the HSM still holds the seed");

    assert_eq!(
        registry.verify_artefact(
            KeyDomain::UpdateSigner,
            "update-1",
            new_bytes,
            &stale_signature,
            1_601
        ),
        Err(KeyError::Expired {
            key_id: "update-1".to_string(),
            not_after: 1_600,
        }),
        "a rotated key must not verify new artefacts after its window closes"
    );

    // The lifecycle itself refuses to let the retired key sign at all.
    assert_eq!(
        registry.sign_with_key(
            &custodian,
            KeyDomain::UpdateSigner,
            "update-1",
            new_bytes,
            1_550
        ),
        Err(KeyError::NotActive {
            key_id: "update-1".to_string(),
            state: KeyState::Retiring,
        })
    );

    // New artefacts are signed by the new key and verify under it.
    let current = registry
        .sign(&custodian, KeyDomain::UpdateSigner, new_bytes, 1_601)
        .expect("sign with the new key");
    assert_eq!(current.key_id, "update-2");
    current
        .verify(&registry, new_bytes, 1_601)
        .expect("new key verifies the new artefact");
}

/// Done when: a compromised key can be revoked without re-keying the fleet.
#[test]
fn f05_compromised_key_revoked_without_rekeying_the_fleet() {
    let authority = SoftwareCustodian::new();
    let mut authority_registry = KeyRegistry::new();
    for (domain, key_id) in [
        (KeyDomain::UpdateSigner, "update-1"),
        (KeyDomain::DeviceIdentity, "device-1"),
        (KeyDomain::TenantWrapping, "tenant-1"),
    ] {
        authority_registry
            .register(
                authority
                    .generate(domain, key_id, 1, 1_000, 100_000)
                    .expect("generate"),
            )
            .expect("register");
    }

    let compromised_artefact = authority_registry
        .sign(
            &authority,
            KeyDomain::UpdateSigner,
            b"malicious-update",
            2_000,
        )
        .expect("sign update");

    // A fleet node holds the same public records and a device credential.
    let mut fleet_registry = authority_registry.clone();
    let device_before = fleet_registry.record("device-1").expect("device").clone();
    let tenant_before = fleet_registry.record("tenant-1").expect("tenant").clone();
    let device_artefact = fleet_registry
        .sign(
            &authority,
            KeyDomain::DeviceIdentity,
            b"device-challenge",
            2_100,
        )
        .expect("device signs");

    // Revoke only the update signer and distribute the list.
    let entry = authority_registry
        .revoke(
            KeyDomain::UpdateSigner,
            "update-1",
            RevocationReason::KeyCompromise,
            2_200,
        )
        .expect("revoke update signer");
    assert_eq!(entry.reason, RevocationReason::KeyCompromise);

    let list = authority_registry.revocation_list();
    assert_eq!(list.apply_to(&mut fleet_registry), 1);
    assert!(list.contains("update-1", 2_200));

    // The compromised key is rejected everywhere...
    assert_eq!(
        fleet_registry.verify_artefact(
            KeyDomain::UpdateSigner,
            "update-1",
            b"malicious-update",
            &compromised_artefact.signature,
            2_200
        ),
        Err(KeyError::Revoked {
            key_id: "update-1".to_string()
        })
    );

    // ...while the device identity and tenant wrapping keys are untouched
    // (same key id, version, public key) and still work.
    assert_eq!(fleet_registry.record("device-1").unwrap(), &device_before);
    assert_eq!(fleet_registry.record("tenant-1").unwrap(), &tenant_before);
    assert_eq!(
        fleet_registry
            .active_key(KeyDomain::DeviceIdentity, 2_200)
            .expect("device key stays active")
            .key_id,
        "device-1"
    );
    device_artefact
        .verify(&fleet_registry, b"device-challenge", 2_200)
        .expect("device credential keeps working across the revocation");

    // No other domain was rotated or re-issued: no fleet re-key happened.
    assert_eq!(fleet_registry.records_in(KeyDomain::DeviceIdentity).len(), 1);
    assert_eq!(fleet_registry.records_in(KeyDomain::TenantWrapping).len(), 1);
    assert_eq!(
        fleet_registry.records_in(KeyDomain::UpdateSigner).len(),
        1,
        "revocation alone must not mint a replacement key"
    );
}

/// Done when: no test or log prints private key material.
#[test]
fn f05_no_private_key_material_in_debug_or_test_output() {
    let custodian = SoftwareCustodian::new();
    let seed = [0x5Au8; 32];
    let record = custodian
        .from_seed(KeyDomain::RootCa, "root-1", 1, 1_000, 200_000, seed)
        .expect("ceremony seed import");

    let mut registry = KeyRegistry::new();
    registry.register(record.clone()).expect("register");
    let signed = registry
        .sign(&custodian, KeyDomain::RootCa, b"root-statement", 1_500)
        .expect("sign");
    let receipt = registry
        .decommission(&custodian, KeyDomain::RootCa, "root-1", 1_600)
        .expect("decommission");

    let rendered = [
        format!("{custodian:?}"),
        format!("{record:?}"),
        format!("{registry:?}"),
        format!("{signed:?}"),
        format!("{receipt:?}"),
    ];

    let hex_seed = seed_hex(&seed);
    let decimal_seed = seed
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    for output in &rendered {
        assert!(
            !output.contains(&hex_seed),
            "private seed leaked into debug output: {output}"
        );
        assert!(
            !output.contains(&decimal_seed),
            "private seed leaked into debug output: {output}"
        );
        assert!(
            !output.contains("5a5a5a5a"),
            "private seed leaked into debug output: {output}"
        );
    }

    // Sanity check: the record is still rendered, so the assertions above are
    // not passing because the output is empty.
    assert!(rendered[1].contains("root-1"));
    assert_eq!(custodian.public_key("root-1").expect("public key").len(), 32);

    // The key cannot be exported through the custodian interface, and after
    // zeroization it cannot sign.
    assert_eq!(
        custodian.sign(KeyDomain::RootCa, "root-1", b"x"),
        Err(KeyError::Destroyed {
            key_id: "root-1".to_string()
        })
    );
}

/// Recovery and disaster re-key require a meeting quorum; the compromised
/// device path revokes and zeroizes only that device.
#[test]
fn f05_quorum_recovery_and_compromised_device_zeroization() {
    let custodian = SoftwareCustodian::new();
    let mut registry = KeyRegistry::new();
    registry
        .register(
            custodian
                .generate(KeyDomain::RootCa, "root-1", 1, 1_000, 100_000)
                .expect("root"),
        )
        .expect("register root");
    registry
        .register(
            custodian
                .generate(KeyDomain::DeviceIdentity, "device-1", 1, 1_000, 100_000)
                .expect("device"),
        )
        .expect("register device");

    let policy = QuorumPolicy::new(2, 3).expect("2-of-3");
    let approval = |operation, domain, count: usize| {
        QuorumApproval::new(
            operation,
            domain,
            None,
            policy,
            (0..count)
                .map(|i| CustodianApproval {
                    custodian_id: format!("custodian-{i}"),
                    share_commitment: vec![i as u8; 32],
                    signed_at: 1_900,
                })
                .collect(),
            1_900,
            5_000,
        )
    };

    assert!(matches!(
        registry.disaster_rekey_root(
            &custodian,
            &approval(RecoveryOperation::DisasterRekey, KeyDomain::RootCa, 1),
            "root-2",
            2_000,
            100_000,
            600
        ),
        Err(KeyError::ApprovalInvalid { .. })
    ));

    let (_rotated, bridge) = registry
        .disaster_rekey_root(
            &custodian,
            &approval(RecoveryOperation::DisasterRekey, KeyDomain::RootCa, 2),
            "root-2",
            2_000,
            100_000,
            600,
        )
        .expect("quorum disaster re-key");
    assert_eq!(bridge.old_root_key_id, "root-1");
    assert_eq!(bridge.not_after, 2_600);

    // Compromised device: revoke with keyCompromise and destroy the key,
    // leaving the root path intact.
    let compromise = registry
        .compromised_device(&custodian, "device-1", "INC-0042", 2_100)
        .expect("compromised device path");
    assert!(!compromise.zeroize.already_destroyed);
    assert_eq!(
        registry.record("device-1").unwrap().state,
        KeyState::Destroyed
    );
    assert_eq!(
        registry.revocations()[0].reason,
        RevocationReason::KeyCompromise
    );
    assert_eq!(
        custodian.sign(KeyDomain::DeviceIdentity, "device-1", b"x"),
        Err(KeyError::Destroyed {
            key_id: "device-1".to_string()
        })
    );
    assert!(
        registry.active_key(KeyDomain::RootCa, 2_100).is_some(),
        "root domain unaffected by device compromise"
    );
}
