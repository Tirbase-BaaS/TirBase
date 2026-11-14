// SPDX-License-Identifier: AGPL-3.0-only

//! epoch integration tests (CLAIM-8.7, CLAIM-8.8 — S22, INV-10).
//!
//! The same `EpochRegistry` / `CommandGuard` pair is wired by the gateway: the
//! registry is backed by the `device_epoch` table and the guard's Stage 8
//! check runs in `CommandGuard::admit`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tirbase_core::events::{install_security_event_sink, ReasonCode, SecurityEvent};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, SecurityEventSink};
use tirbase_guard::epoch::{
    CommandEnvelope, DeviceEpoch, DeviceEpochStore, EpochBump, EpochCommandGuard, EpochError,
    EpochRegistry, InMemoryEpochStore,
};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_types::CommandRole;

#[derive(Debug, Default)]
struct RecordingSink {
    events: Mutex<Vec<SecurityEvent>>,
}

impl SecurityEventSink for RecordingSink {
    fn emit(&self, event: SecurityEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn trust_root(pa: &InMemoryKeyProvider, rm: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes(),
            }],
        ),
    );
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
        root_ca_public_keys: vec![vec![1u8; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

fn signed_bump(
    pa: &InMemoryKeyProvider,
    rm: &InMemoryKeyProvider,
    payload: &EpochBump,
) -> SignedOperation<EpochBump> {
    let mut operation = SignedOperation::new(payload, 1_000, None).unwrap();
    operation
        .sign_with(pa, CommandRole::PolicyAuthority)
        .unwrap();
    operation
        .sign_with(rm, CommandRole::RevocationManager)
        .unwrap();
    operation
}

#[test]
fn epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let trust_root = trust_root(&pa, &rm);

    let store = Arc::new(InMemoryEpochStore::default());
    let registry = Arc::new(EpochRegistry::new(store.clone()));
    let guard = EpochCommandGuard::new(registry.clone());

    let enrolled = registry.ensure_enrolled("did:key:zDevice", 100).unwrap();
    assert_eq!(enrolled.epoch, 0);
    assert!(enrolled.co_sig_pa.is_none());
    assert!(enrolled.co_sig_rm.is_none());

    let command = CommandEnvelope {
        device_id: "did:key:zDevice".to_string(),
        issuer_did: "did:key:zIssuer".to_string(),
        enrollment_epoch: 0,
    };
    guard.admit(&command).expect("epoch-0 command is current");

    let payload = EpochBump {
        device_id: "did:key:zDevice".to_string(),
        previous_epoch: 0,
        new_epoch: 1,
        reason: "snapshot restore".to_string(),
    };
    let operation = signed_bump(&pa, &rm, &payload);
    let bumped = registry
        .apply_bump(&operation, &payload, &trust_root, 200)
        .expect("PA + RM bump applies");
    assert_eq!(bumped.epoch, 1);
    assert!(bumped.co_sig_pa.is_some());
    assert!(bumped.co_sig_rm.is_some());

    assert_eq!(
        guard.admit(&command),
        Err(EpochError::StaleEpoch {
            command_epoch: 0,
            current_epoch: 1
        }),
        "Stage 8 must reject commands produced under the restored epoch (S22)"
    );

    let mut next = command.clone();
    next.enrollment_epoch = 1;
    guard.admit(&next).expect("new-epoch command admitted");

 // The durable row carries the committed epoch, not an in-memory guess.
    let row: DeviceEpoch = store.load("did:key:zDevice").unwrap().unwrap();
    assert_eq!(row.epoch, 1);
}

#[test]
fn bump_without_both_co_signatures_is_rejected() {
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let trust_root = trust_root(&pa, &rm);
    let registry = EpochRegistry::new(Arc::new(InMemoryEpochStore::default()));
    registry.ensure_enrolled("did:key:zDevice", 100).unwrap();

    let payload = EpochBump {
        device_id: "did:key:zDevice".to_string(),
        previous_epoch: 0,
        new_epoch: 1,
        reason: "restore".to_string(),
    };
    let mut operation = SignedOperation::new(&payload, 1_000, None).unwrap();
    operation
        .sign_with(&pa, CommandRole::PolicyAuthority)
        .unwrap();

    assert!(matches!(
        registry.apply_bump(&operation, &payload, &trust_root, 200),
        Err(EpochError::TrustRoot(
            tirbase_guard::trust_root::TrustRootError::ThresholdNotMet { .. }
        ))
    ));
    assert_eq!(registry.current_epoch("did:key:zDevice").unwrap(), 0);
}

#[test]
fn lower_epoch_report_emits_epoch_regression_and_is_rejected() {
    let registry = EpochRegistry::new(Arc::new(InMemoryEpochStore::default()));
    registry.observe_epoch("did:key:zDevice", 5).unwrap();

    let sink = Arc::new(RecordingSink::default());
    let _previous = install_security_event_sink(sink.clone());

    assert_eq!(
        registry.observe_epoch("did:key:zDevice", 4),
        Err(EpochError::EpochRegression {
            device_id: "did:key:zDevice".to_string(),
            witnessed: 5,
            reported: 4,
        })
    );
    assert_eq!(registry.witnessed_epoch("did:key:zDevice"), Some(5));

    let events = sink.events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.reason_code == ReasonCode::EpochRegression),
        "a lower-epoch report must emit EpochRegression: {events:?}"
    );
}
