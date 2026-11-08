//! Task 11.1 — `CommandMessage` signing/verification (CLAIM-11.1, PV-4.1,
//! PV-4.2, INV-6).
//!
//! Exercises the production callers:
//! * [`tirbase_guard::command::sign_command`] / [`verify_command_signature`]
//! * [`tirbase_guard::CommandGuard::admit`] (the only `ActuationPermit` issuer)
//! * [`tirbase_guard::DriverProxy`] (guard-owned dispatch)
//!
//! A signed command admitted through `CommandGuard::admit()` reaches the driver
//! proxy; an unsigned (default/zero) or otherwise invalid signature is rejected
//! before dispatch.

use std::sync::Arc;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::{
    command_signing_bytes, sign_command, single_target_guard, verify_command_signature, AdmitError,
    DriverProxy, IngressSource,
};
use tirbase_types::command::{CoSignature, CommandMessage};
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

fn fpv(mantissa: i64) -> FixedPointValue {
    FixedPointValue::new(mantissa, -1, UNIT_PERCENT)
}

fn target() -> TargetId {
    TargetId::new("pump-1")
}

fn device_id() -> String {
    "did:key:zDeviceLocal".to_string()
}

fn make_command(issuer: &InMemoryKeyProvider, epoch: u64) -> CommandMessage {
    CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target(),
        param: "speed".to_string(),
        desired_state: fpv(500),
        sequence_number: 1,
        idempotency_key: [7u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: epoch,
        challenge_nonce: None,
        co_signatures: Vec::<CoSignature>::new(),
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

#[test]
fn signed_command_is_accepted_and_dispatched_through_driver_proxy() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id(), 1_000).unwrap();
    let guard = single_target_guard(registry, target(), device_id());

    let mut cmd = make_command(&issuer, 0);
    sign_command(&mut cmd, &issuer).expect("sign");
    verify_command_signature(&cmd).expect("signed command verifies");

    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(&mut wire);
    let frame = b"ACTUATE:pump-1:speed=50.0";
    let admitted = guard
        .admit(&cmd, IngressSource::Mesh, &mut proxy, frame)
        .expect("signed command admitted");

    assert_eq!(admitted.ingress, IngressSource::Mesh);
    assert_eq!(admitted.permit_ref.target_id, target());
    assert_eq!(admitted.permit_ref.param, "speed");
    assert_eq!(wire.as_slice(), frame);
}

#[test]
fn unsigned_command_is_rejected_before_dispatch() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id(), 1_000).unwrap();
    let guard = single_target_guard(registry, target(), device_id());

    let cmd = make_command(&issuer, 0); // signature is zeroed (unsigned)

    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(&mut wire);
    let err = guard
        .admit(&cmd, IngressSource::LocalAdmin, &mut proxy, b"frame")
        .unwrap_err();

    assert!(
        matches!(err, AdmitError::InvalidSignature(_)),
        "unsigned command must be rejected: {err:?}"
    );
    assert!(wire.is_empty(), "unsigned command must not dispatch");
}

#[test]
fn tampered_command_is_rejected() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id(), 1_000).unwrap();
    let guard = single_target_guard(registry, target(), device_id());

    let mut cmd = make_command(&issuer, 0);
    sign_command(&mut cmd, &issuer).unwrap();
    cmd.desired_state = fpv(999); // tamper after signing

    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(&mut wire);
    assert!(
        matches!(
            guard.admit(&cmd, IngressSource::CloudApi, &mut proxy, b"f"),
            Err(AdmitError::InvalidSignature(_))
        ),
        "tampered command must be rejected"
    );
    assert!(wire.is_empty());
}

#[test]
fn wrong_issuer_key_is_rejected() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let other = InMemoryKeyProvider::generate().unwrap();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id(), 1_000).unwrap();
    let guard = single_target_guard(registry, target(), device_id());

    let mut cmd = make_command(&issuer, 0);
    // Sign with a different key than issuer_did claims.
    sign_command(&mut cmd, &other).unwrap();

    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(&mut wire);
    assert!(matches!(
        guard.admit(&cmd, IngressSource::Mesh, &mut proxy, b"f"),
        Err(AdmitError::InvalidSignature(_))
    ));
}

#[test]
fn signature_covers_all_fields_except_signature() {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let mut a = make_command(&issuer, 0);
    let mut b = make_command(&issuer, 0);
    b.sequence_number = 2; // differs only here
    sign_command(&mut a, &issuer).unwrap();
    sign_command(&mut b, &issuer).unwrap();
    assert_ne!(
        command_signing_bytes(&a).unwrap(),
        command_signing_bytes(&b).unwrap(),
        "canonical signing bytes must cover sequence_number"
    );
    // Changing signature alone must not affect signing bytes.
    let mut c = a.clone();
    c.signature = DeviceSignature::Ed25519([9u8; 64]);
    assert_eq!(
        command_signing_bytes(&a).unwrap(),
        command_signing_bytes(&c).unwrap(),
        "signing bytes must exclude the signature field"
    );
}
