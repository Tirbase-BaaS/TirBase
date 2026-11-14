// SPDX-License-Identifier: AGPL-3.0-only

//! F-06 acceptance: approval expiry under clock rollback, reboot, and long
//! offline periods, plus verifiable offline time evidence.
//!
//! These tests drive the real `TimeRatchet` with a controllable clock, so
//! "wall clock rolled back", "device rebooted", and "offline for a week" are
//! exact rather than dependent on the host clock.

use std::sync::{Arc, Mutex};

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::timesync::{
    ApprovalRejection, ApprovalExpiry, DriftBound, SignedTimeEvidence, TimeEvidence,
};
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::{
    FreshnessState, TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetError,
    TimeRatchetRecord, TimeRatchetStore,
};
use tirbase_types::CommandRole;

const MICROS_PER_SEC: u64 = 1_000_000;
const BOOT: u64 = 7;
const BASE_WALL: i64 = 1_800_000_000;

#[derive(Debug, Clone, Copy)]
struct ClockState {
    mono_us: u64,
    wall_secs: i64,
    boot: u64,
}

#[derive(Debug)]
struct FakeTimeSource {
    state: Mutex<ClockState>,
}

impl FakeTimeSource {
    fn new(boot: u64, wall_secs: i64) -> Self {
        FakeTimeSource {
            state: Mutex::new(ClockState {
                mono_us: MICROS_PER_SEC,
                wall_secs,
                boot,
            }),
        }
    }

    fn advance_secs(&self, secs: i64) {
        let mut state = self.state.lock().unwrap();
        state.mono_us = state
            .mono_us
            .saturating_add((secs.max(0) as u64).saturating_mul(MICROS_PER_SEC));
    }

    fn reboot(&self, boot: u64) {
        let mut state = self.state.lock().unwrap();
        state.mono_us = MICROS_PER_SEC;
        state.boot = boot;
    }

    fn set_wall_secs(&self, wall_secs: i64) {
        self.state.lock().unwrap().wall_secs = wall_secs;
    }
}

impl TimeSource for FakeTimeSource {
    fn monotonic_now(&self) -> u64 {
        self.state.lock().unwrap().mono_us
    }

    fn wall_hint(&self) -> Option<i64> {
        Some(
            self.state
                .lock()
                .unwrap()
                .wall_secs
                .saturating_mul(MICROS_PER_SEC as i64),
        )
    }

    fn boot_id(&self) -> u64 {
        self.state.lock().unwrap().boot
    }
}

#[derive(Debug, Default)]
struct MemoryStore {
    record: Mutex<Option<TimeRatchetRecord>>,
}

impl TimeRatchetStore for MemoryStore {
    fn load(&self) -> Result<Option<TimeRatchetRecord>, TimeRatchetError> {
        Ok(*self.record.lock().unwrap())
    }

    fn save(&self, record: &TimeRatchetRecord) -> Result<(), TimeRatchetError> {
        *self.record.lock().unwrap() = Some(*record);
        Ok(())
    }
}

fn beacon(wall_time_secs: i64) -> TimeBeacon {
    TimeBeacon {
        wall_time_secs,
        issuer_did: "did:key:z6MktestAnchor".to_string(),
        mono_seq: 1,
        valid_for_secs: 300,
    }
}

fn signed_beacon(
    anchors: &[&InMemoryKeyProvider],
    beacon: &TimeBeacon,
) -> SignedOperation<TimeBeacon> {
    let mut operation =
        SignedOperation::<TimeBeacon>::new(beacon, beacon.wall_time_secs, None).expect("wrap");
    for anchor in anchors {
        operation
            .sign_with(*anchor, CommandRole::TimeAnchor)
            .expect("sign beacon");
    }
    operation
}

fn resolve<'a>(anchors: &'a [&'a InMemoryKeyProvider]) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
    move |did| {
        anchors
            .iter()
            .find(|anchor| anchor.did() == did)
            .map(|anchor| anchor.public_key_bytes())
    }
}

fn open_ratchet() -> TimeRatchet {
    TimeRatchet::open(
        Arc::new(MemoryStore::default()),
        TimeRatchetConfig::default(),
    )
    .expect("open ratchet")
}

fn bootstrap_to(ratchet: &mut TimeRatchet, ts: &FakeTimeSource, wall: i64) {
    let a = InMemoryKeyProvider::generate().expect("anchor a");
    let b = InMemoryKeyProvider::generate().expect("anchor b");
    let bcn = beacon(wall);
    ratchet
        .advance(
            &signed_beacon(&[&a, &b], &bcn),
            &bcn,
            ts,
            resolve(&[&a, &b]),
        )
        .expect("bootstrap beacon accepted with quorum");
}

fn approval(expires_at_est: i64, issued_boot_id: u64) -> ApprovalExpiry {
    ApprovalExpiry {
        approval_id: "APR-42".to_string(),
        expires_at_est,
        issued_boot_id,
    }
}

/// Done when: a clock rollback cannot revive an expired approval.
#[test]
fn f06_clock_rollback_cannot_revive_an_expired_approval() {
    let ts = FakeTimeSource::new(BOOT, BASE_WALL);
    let mut ratchet = open_ratchet();
    bootstrap_to(&mut ratchet, &ts, BASE_WALL);

    let approval = approval(BASE_WALL + 60, BOOT);

    // Move past the expiry on the monotonic domain.
    ts.advance_secs(61);
    assert!(ratchet.is_expired(approval.expires_at_est, &ts));
    let now_before = ratchet.now_est(&ts);
    assert!(matches!(
        approval.check(now_before, ts.boot_id()),
        Err(ApprovalRejection::Expired(_))
    ));

    // Attacker rolls the system clock back a day (and then far forward).
    ts.set_wall_secs(BASE_WALL - 86_400);
    assert_eq!(
        ratchet.now_est(&ts),
        now_before,
        "rolling the wall clock back must not move the authenticated estimate"
    );
    assert!(
        matches!(
            approval.check(ratchet.now_est(&ts), ts.boot_id()),
            Err(ApprovalRejection::Expired(_))
        ),
        "the approval must stay expired after a clock rollback"
    );

    ts.set_wall_secs(BASE_WALL + 86_400 * 365);
    assert_eq!(ratchet.now_est(&ts), now_before);
    assert!(ratchet.is_expired(approval.expires_at_est, &ts));
}

/// Expiry keeps advancing through a long offline period, even though the
/// freshness state degrades to `Unverified`.
#[test]
fn f06_long_offline_period_expires_approval_without_any_beacon() {
    let ts = FakeTimeSource::new(BOOT, BASE_WALL);
    let mut ratchet = open_ratchet();
    bootstrap_to(&mut ratchet, &ts, BASE_WALL);
    let approval = approval(BASE_WALL + 3_600, BOOT);

    // Seven days with no beacon.
    ts.advance_secs(7 * 86_400);
    assert_eq!(ratchet.freshness(&ts), FreshnessState::Unverified);
    assert!(ratchet.now_est(&ts) > approval.expires_at_est);
    assert!(matches!(
        approval.check(ratchet.now_est(&ts), ts.boot_id()),
        Err(ApprovalRejection::Expired(_))
    ));
}

/// After a reboot the ratchet is floored, so time cannot be proven to have
/// advanced. A pre-reboot approval is invalidated instead of being revived.
#[test]
fn f06_reboot_invalidates_pre_reboot_approvals() {
    let ts = FakeTimeSource::new(BOOT, BASE_WALL);
    let mut ratchet = open_ratchet();
    bootstrap_to(&mut ratchet, &ts, BASE_WALL);

    let expired = approval(BASE_WALL + 60, BOOT);
    let pending = approval(BASE_WALL + 3_600, BOOT);

    ts.advance_secs(61);
    assert!(matches!(
        expired.check(ratchet.now_est(&ts), ts.boot_id()),
        Err(ApprovalRejection::Expired(_))
    ));

    // Reboot: the monotonic domain restarts and the boot id changes.
    ts.reboot(BOOT + 1);
    assert_eq!(ratchet.now_est(&ts), ratchet.persisted_floor());
    assert_eq!(ratchet.freshness(&ts), FreshnessState::Unverified);

    assert!(
        matches!(
            expired.check(ratchet.now_est(&ts), ts.boot_id()),
            Err(ApprovalRejection::Expired(_)) | Err(ApprovalRejection::InvalidatedByReboot { .. })
        ),
        "an expired approval must never become usable across a reboot"
    );
    assert!(
        matches!(
            pending.check(ratchet.now_est(&ts), ts.boot_id()),
            Err(ApprovalRejection::InvalidatedByReboot { .. })
        ),
        "a pre-reboot approval must be re-issued, not silently revived"
    );
    assert!(ratchet
        .freshness(&ts)
        .requires_challenge(true));
}

/// A record captured offline carries a signed, verifiable confidence marker.
#[test]
fn f06_offline_records_carry_verifiable_time_confidence() {
    let ts = FakeTimeSource::new(BOOT, BASE_WALL);
    let mut ratchet = open_ratchet();
    bootstrap_to(&mut ratchet, &ts, BASE_WALL);

    ts.advance_secs(3_600);
    let evidence = TimeEvidence::offline(
        ratchet.now_est(&ts),
        ts.monotonic_now() / MICROS_PER_SEC,
        ts.boot_id(),
        ratchet.persisted_floor(),
        3_600,
        DriftBound::default(),
    );
    assert_eq!(evidence.confidence.marker(), "offline");
    assert!(evidence.confidence.is_offline_bounded());
    assert_eq!(evidence.confidence.uncertainty_ms(), Some(430));

    let exporter = InMemoryKeyProvider::generate().expect("exporter key");
    let signed: SignedTimeEvidence = evidence.sign(&exporter).expect("sign evidence");
    signed
        .verify(&exporter.public_key_bytes())
        .expect("offline evidence verifies");

    // The marker is covered by the signature.
    let mut tampered = signed.clone();
    tampered.evidence.ratchet_floor_secs -= 1;
    assert!(tampered.verify(&exporter.public_key_bytes()).is_err());
}
