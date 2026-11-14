// SPDX-License-Identifier: AGPL-3.0-only

//! Gateway/production integration test: all three command ingress paths
//! converge on `CommandGuard::admit()` before `DriverProxy` dispatch (//! CLAIM-11.3, PV-4.4, INV-6).
//!
//! This test exercises the same convergence contract the gateway ingress
//! handlers implement (mesh/cloud/local admin each call `guard.admit()` with
//! their `IngressSource`). The handlers are thin wrappers; the structural proof
//! is `CommandGuard::admit()` as the only `ActuationPermit` issuer plus the
//! `trybuild` bypass cases in `tirbase-guard`.

use std::sync::Arc;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::{sign_command, single_target_guard, AdmitError, DriverProxy, IngressSource};
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

fn setup() -> (tirbase_guard::CommandGuard, CommandMessage) {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let target = TargetId::new("valve-7");
    let device_id = "did:key:zLocalDevice".to_string();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id, 1_000).unwrap();
    let guard = single_target_guard(registry, target.clone(), device_id);

    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target,
        param: "open_pct".to_string(),
        desired_state: FixedPointValue::new(750, -1, UNIT_PERCENT),
        sequence_number: 1,
        idempotency_key: [1u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::new(),
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };
    sign_command(&mut cmd, &issuer).unwrap();
    (guard, cmd)
}

#[test]
fn mesh_cloud_and_local_admin_all_converge_on_admit_before_driver_proxy() {
    for (ingress, frame) in [
        (IngressSource::Mesh, b"MESH" as &[u8]),
        (IngressSource::CloudApi, b"CLOUD"),
        (IngressSource::LocalAdmin, b"ADMIN"),
    ] {
        let (guard, cmd) = setup();
        let mut wire = Vec::new();
        let mut proxy = DriverProxy::new(&mut wire);
        let admitted = guard
            .admit(&cmd, ingress, &mut proxy, frame)
            .expect("ingress must converge on admit()");
        assert_eq!(admitted.ingress, ingress);
        assert_eq!(wire, frame);
    }
}

#[test]
fn every_ingress_rejects_unsigned_command_before_proxy_dispatch() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let target = TargetId::new("valve-7");
    let device_id = "did:key:zLocalDevice".to_string();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id, 1_000).unwrap();
    let guard = single_target_guard(registry, target.clone(), device_id);
    let unsigned = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target,
        param: "open_pct".to_string(),
        desired_state: FixedPointValue::new(1, 0, UNIT_PERCENT),
        sequence_number: 1,
        idempotency_key: [2u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::new(),
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };

    for ingress in [
        IngressSource::Mesh,
        IngressSource::CloudApi,
        IngressSource::LocalAdmin,
    ] {
        let mut wire = Vec::new();
        let mut proxy = DriverProxy::new(&mut wire);
        let r = guard.admit(&unsigned, ingress, &mut proxy, b"x");
        assert!(
            matches!(r, Err(AdmitError::InvalidSignature(_))),
            "{ingress:?} must reject unsigned command: {r:?}"
        );
        assert!(
            wire.is_empty(),
            "{ingress:?} must not dispatch unsigned command"
        );
    }
}
