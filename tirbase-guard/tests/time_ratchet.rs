//! TimeRatchet behaviour tests (7.5 — CLAIM-7.2…7.5, PV-22).
//!
//! These tests drive the real [`TimeRatchet`] with a controllable
//! [`TimeSource`], so "simulated time advance" and "simulated reboot" are exact
//! rather than wall-clock dependent. They cover:
//!
//! * `now_est` arithmetic and its floor (PV-22.1);
//! * wall-clock manipulation not affecting expiry (PV-22.1, S04);
//! * `now_est == persisted_floor` after a reboot (PV-22.4, INV-13);
//! * far-future beacon rejection and the M-of-N quorum (PV-22.5, S23);
//! * freshness / challenge derivation (PV-22.3, INV-9);
//! * durable-before-accepted persistence (PV-22.2).

use std::sync::{Arc, Mutex};

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::{
    FreshnessState, TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetError,
    TimeRatchetRecord, TimeRatchetStore,
};
use tirbase_types::CommandRole;

const MICROS_PER_SEC: u64 = 1_000_000;

// ─── Controllable clock ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct ClockState {
    mono_us: u64,
    wall_secs: i64,
    boot: u64,
}

/// A `TimeSource` whose monotonic, wall and boot domains the test owns.
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

 /// Advance the `CLOCK_BOOTTIME` domain (simulated elapsed time).
    fn advance_secs(&self, secs: i64) {
        let mut state = self.state.lock().unwrap();
        state.mono_us = state
            .mono_us
            .saturating_add((secs.max(0) as u64).saturating_mul(MICROS_PER_SEC));
    }

 /// Simulate a reboot: the monotonic clock restarts and the boot id changes.
    fn reboot(&self, boot: u64) {
        let mut state = self.state.lock().unwrap();
        state.mono_us = MICROS_PER_SEC;
        state.boot = boot;
    }

 /// Simulate a wall-clock jump (which must not affect `now_est`).
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

// ─── Stores ──────────────────────────────────────────────────────────────────

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

/// Store that always fails, modelling an unwritable `primary.db`.
#[derive(Debug)]
struct FailingStore;

impl TimeRatchetStore for FailingStore {
    fn load(&self) -> Result<Option<TimeRatchetRecord>, TimeRatchetError> {
        Ok(None)
    }

    fn save(&self, _record: &TimeRatchetRecord) -> Result<(), TimeRatchetError> {
        Err(TimeRatchetError::Store("disk is read-only".to_string()))
    }
}

// ─── Beacon helpers ──────────────────────────────────────────────────────────

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

fn two_anchors() -> (InMemoryKeyProvider, InMemoryKeyProvider) {
    (
        InMemoryKeyProvider::generate().expect("anchor a"),
        InMemoryKeyProvider::generate().expect("anchor b"),
    )
}

/// Bootstrap a fresh ratchet to `base_wall` using the required M-of-N quorum.
/// The initial jump from floor 0 is always treated as a large jump, so the
/// first beacon is co-signed by two distinct anchors.
fn bootstrap_to(
    ratchet: &mut TimeRatchet,
    ts: &FakeTimeSource,
    base_wall: i64,
) -> (InMemoryKeyProvider, InMemoryKeyProvider) {
    let (a, b) = two_anchors();
    let bcn = beacon(base_wall);
    ratchet
        .advance(
            &signed_beacon(&[&a, &b], &bcn),
            &bcn,
            ts,
            resolve(&[&a, &b]),
        )
        .expect("bootstrap beacon accepted with quorum");
    (a, b)
}

fn open_ratchet(store: Arc<dyn TimeRatchetStore>) -> TimeRatchet {
    TimeRatchet::open(store, TimeRatchetConfig::default()).expect("open ratchet")
}

// ─── now_est (PV-22.1) ───────────────────────────────────────────────────────

#[test]
fn now_est_is_beacon_time_plus_elapsed_monotonic_time() {
    let ts = FakeTimeSource::new(7, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    assert_eq!(ratchet.now_est(&ts), 1_800_000_000);

    ts.advance_secs(90);
    assert_eq!(
        ratchet.now_est(&ts),
        1_800_000_090,
        "now_est must advance with CLOCK_BOOTTIME, not the wall clock"
    );
}

#[test]
fn wall_clock_poisoning_does_not_move_now_est() {
    let ts = FakeTimeSource::new(7, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);

    ts.advance_secs(10);
    let before = ratchet.now_est(&ts);
 // Attacker sets the system clock far into the future.
    ts.set_wall_secs(1_800_000_000 + 86_400 * 365);
    assert_eq!(
        ratchet.now_est(&ts),
        before,
        "now_est must be unaffected by wall-clock manipulation (S04)"
    );
}

#[test]
fn now_est_never_runs_behind_the_persisted_floor() {
    let ts = FakeTimeSource::new(7, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);

 // The monotonic domain goes backwards (should not happen, but the floor is
 // the defensive lower bound).
    let rewind = FakeTimeSource::new(7, 1_800_000_000);
    assert_eq!(ratchet.now_est(&rewind), 1_800_000_000);
    assert!(ratchet.now_est(&rewind) >= ratchet.persisted_floor());
}

// ─── Reboot handling (PV-22.4, INV-13) ───────────────────────────────────────

#[test]
fn now_est_returns_persisted_floor_after_a_reboot() {
    let ts = FakeTimeSource::new(1, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);

    ts.advance_secs(600);
    assert_eq!(ratchet.now_est(&ts), 1_800_000_600);

    ts.reboot(2);
    assert_eq!(
        ratchet.now_est(&ts),
        ratchet.persisted_floor(),
        "after a reboot the monotonic subtraction is invalid; now_est is the floor"
    );
    assert_eq!(ratchet.now_est(&ts), 1_800_000_000);
    assert!(
        ratchet.now_est(&ts) >= 1_800_000_000,
        "now_est must never fall below the pre-reboot floor (INV-13)"
    );
}

// ─── Expiry (PV-22.1, INV-9) ─────────────────────────────────────────────────

#[test]
fn expired_command_is_rejected_after_simulated_time_advance() {
    let ts = FakeTimeSource::new(3, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);

 // A command issued now with a 60-second TTL (Stage 9 evaluates this).
    let command_expiry_est = 1_800_000_000 + 60;
    assert!(!ratchet.is_expired(command_expiry_est, &ts));

    ts.advance_secs(60);
    assert!(
        !ratchet.is_expired(command_expiry_est, &ts),
        "expiry is strict: now_est == expiry_est is still valid"
    );

    ts.advance_secs(1);
    assert!(
        ratchet.is_expired(command_expiry_est, &ts),
        "an expired command must be rejected once now_est passes expiry_est"
    );
}

// ─── advance(): replay, domain, roles (PV-22.5) ──────────────────────────────

#[test]
fn beacon_below_the_persisted_floor_is_rejected_as_a_replay() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    let (anchor, anchor_b) = bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    let anchors = [&anchor, &anchor_b];

    let replay = beacon(1_799_999_000);
    let error = ratchet
        .advance(
            &signed_beacon(&anchors, &replay),
            &replay,
            &ts,
            resolve(&anchors),
        )
        .expect_err("an older beacon must be rejected");
    assert!(matches!(error, TimeRatchetError::BeaconNotAdvancing { .. }));
    assert_eq!(
        ratchet.persisted_floor(),
        1_800_000_000,
        "a rejected beacon must not move the ratchet"
    );
}

#[test]
fn non_anchor_signature_is_rejected_before_the_ratchet_updates() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    let beacon = beacon(1_800_000_000);
    let mut operation = SignedOperation::<TimeBeacon>::new(&beacon, beacon.wall_time_secs, None)
        .expect("wrap beacon");
    operation
        .sign_with(&issuer, CommandRole::CommandIssuer)
        .expect("sign under the wrong role");

    let error = ratchet
        .advance(&operation, &beacon, &ts, resolve(&[&issuer]))
        .expect_err("only TimeAnchor may submit beacons");
    assert!(matches!(error, TimeRatchetError::NonAnchorSignature { .. }));
    assert_eq!(ratchet.persisted_floor(), 0);
    assert_eq!(ratchet.beacon_boot_id(), 0);
}

#[test]
fn beacon_not_bound_to_the_wrapper_payload_is_rejected() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let anchor = InMemoryKeyProvider::generate().unwrap();
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    let signed = beacon(1_800_000_000);
    let operation = signed_beacon(&[&anchor], &signed);
    let tampered = beacon(1_800_000_000 + 5);
    let error = ratchet
        .advance(&operation, &tampered, &ts, resolve(&[&anchor]))
        .expect_err("payload binding must be enforced");
    assert_eq!(error, TimeRatchetError::PayloadMismatch);
    assert_eq!(ratchet.persisted_floor(), 0);
}

#[test]
fn unknown_signer_is_rejected() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let anchor = InMemoryKeyProvider::generate().unwrap();
    let stranger = InMemoryKeyProvider::generate().unwrap();
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    let beacon = beacon(1_800_000_000);
    let operation = signed_beacon(&[&anchor], &beacon);
    let error = ratchet
        .advance(&operation, &beacon, &ts, resolve(&[&stranger]))
        .expect_err("an unknown signer must be rejected");
    assert!(matches!(error, TimeRatchetError::UnknownSigner { .. }));
    assert_eq!(ratchet.persisted_floor(), 0);
}

// ─── advance(): max forward jump and M-of-N quorum (S23) ─────────────────────

#[test]
fn far_future_beacon_is_rejected_without_anchor_quorum() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    let (anchor_a, _anchor_b) = bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    let floor = ratchet.persisted_floor();
    let max_jump = ratchet.max_forward_jump_secs();

    let far_future = beacon(floor + max_jump + 1);
    let error = ratchet
        .advance(
            &signed_beacon(&[&anchor_a], &far_future),
            &far_future,
            &ts,
            resolve(&[&anchor_a]),
        )
        .expect_err("a far-future beacon must be rejected (S23)");

    match error {
        TimeRatchetError::InsufficientAnchorQuorum {
            verified,
            required,
            jump_secs,
        } => {
            assert_eq!(verified, 1);
            assert_eq!(required, 2);
            assert_eq!(jump_secs, max_jump + 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        ratchet.persisted_floor(),
        floor,
        "a rejected far-future beacon must not advance the ratchet"
    );
}

#[test]
fn far_future_beacon_is_accepted_with_two_distinct_time_anchors() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let (anchor_a, anchor_b) = two_anchors();
    let anchors = [&anchor_a, &anchor_b];
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    let far_future = beacon(1_800_000_000 + 86_401);
    let advance = ratchet
        .advance(
            &signed_beacon(&anchors, &far_future),
            &far_future,
            &ts,
            resolve(&anchors),
        )
        .expect("an M-of-N authorized large jump is accepted");

    assert_eq!(advance.anchor_signatures, 2);
    assert_eq!(advance.new_floor, 1_800_086_401);
    assert_eq!(ratchet.persisted_floor(), 1_800_086_401);
}

#[test]
fn duplicate_signatures_from_one_anchor_do_not_satisfy_the_quorum() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let anchor = InMemoryKeyProvider::generate().unwrap();
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    let far_future = beacon(1_800_000_000 + 86_401);
    let mut operation =
        SignedOperation::<TimeBeacon>::new(&far_future, far_future.wall_time_secs, None)
            .expect("wrap beacon");
 // The same anchor signs twice: one distinct signer, so M-of-N is unmet.
    operation
        .sign_with(&anchor, CommandRole::TimeAnchor)
        .expect("sign once");
    operation
        .sign_with(&anchor, CommandRole::TimeAnchor)
        .expect("sign twice");

    let error = ratchet
        .advance(&operation, &far_future, &ts, resolve(&[&anchor]))
        .expect_err("duplicate signers must not satisfy M-of-N");
    assert!(matches!(
        error,
        TimeRatchetError::InsufficientAnchorQuorum { verified: 1, .. }
    ));
}

#[test]
fn a_small_jump_needs_only_one_anchor_signature() {
    let ts = FakeTimeSource::new(5, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    let (anchor, _) = bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    let floor = ratchet.persisted_floor();

    let small = beacon(floor + 86_400);
    let advance = ratchet
        .advance(
            &signed_beacon(&[&anchor], &small),
            &small,
            &ts,
            resolve(&[&anchor]),
        )
        .expect("a jump at the limit is accepted with one anchor");
    assert_eq!(advance.new_floor, floor + 86_400);
}

// ─── Persistence (PV-22.2, CLAIM-7.2) ────────────────────────────────────────

#[test]
fn ratchet_state_survives_reopening_the_store() {
    let ts = FakeTimeSource::new(11, 1_800_000_000);
    let store: Arc<dyn TimeRatchetStore> = Arc::new(MemoryStore::default());

    {
        let mut ratchet = TimeRatchet::open(store.clone(), TimeRatchetConfig::default()).unwrap();
        bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    }

    let reopened = TimeRatchet::open(store, TimeRatchetConfig::default()).expect("reopen");
    assert_eq!(reopened.persisted_floor(), 1_800_000_000);
    assert_eq!(reopened.last_beacon_time(), 1_800_000_000);
    assert_eq!(reopened.beacon_boot_id(), 11);
    assert_eq!(reopened.now_est(&ts), 1_800_000_000);
    assert_eq!(reopened.freshness(&ts), FreshnessState::Verified);
}

#[test]
fn an_advance_that_cannot_be_persisted_does_not_take_effect() {
    let ts = FakeTimeSource::new(11, 1_800_000_000);
    let (anchor_a, anchor_b) = two_anchors();
    let anchors = [&anchor_a, &anchor_b];
    let mut ratchet = open_ratchet(Arc::new(FailingStore));

    let bcn = beacon(1_800_000_000);
    let error = ratchet
        .advance(&signed_beacon(&anchors, &bcn), &bcn, &ts, resolve(&anchors))
        .expect_err("a store failure must reject the beacon");
    assert!(matches!(error, TimeRatchetError::Store(_)));
    assert_eq!(
        ratchet.persisted_floor(),
        0,
        "the ratchet must not advance past what it durably committed"
    );
    assert_eq!(ratchet.beacon_boot_id(), 0);
}

// ─── Freshness (PV-22.3, INV-9) ──────────────────────────────────────────────

#[test]
fn freshness_is_unverified_before_any_beacon_and_after_a_reboot() {
    let ts = FakeTimeSource::new(4, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    assert_eq!(ratchet.freshness(&ts), FreshnessState::Unverified);

    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    assert_eq!(ratchet.freshness(&ts), FreshnessState::Verified);

    ts.reboot(5);
    assert_eq!(
        ratchet.freshness(&ts),
        FreshnessState::Unverified,
        "an unknown post-reboot state is Unverified until a new beacon"
    );
}

#[test]
fn freshness_expires_after_the_staleness_window() {
    let ts = FakeTimeSource::new(4, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));
    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);

    let window = ratchet.staleness_window_secs();
    ts.advance_secs(window);
    assert_eq!(ratchet.freshness(&ts), FreshnessState::Verified);

    ts.advance_secs(1);
    assert_eq!(
        ratchet.freshness(&ts),
        FreshnessState::Unverified,
        "no beacon within the staleness window means UNVERIFIED"
    );
}

#[test]
fn critical_parameter_requires_a_challenge_nonce_when_unverified() {
    let ts = FakeTimeSource::new(4, 1_800_000_000);
    let mut ratchet = open_ratchet(Arc::new(MemoryStore::default()));

    let unverified = ratchet.freshness(&ts);
    assert!(unverified.requires_challenge(true));
    assert!(!unverified.requires_challenge(false));

    bootstrap_to(&mut ratchet, &ts, 1_800_000_000);
    assert!(!ratchet.freshness(&ts).requires_challenge(true));

 // Stale again: the challenge requirement returns for critical parameters.
    ts.advance_secs(ratchet.staleness_window_secs() + 1);
    assert_eq!(ratchet.freshness(&ts), FreshnessState::Unverified);
    assert!(ratchet.freshness(&ts).requires_challenge(true));
}
