//! Property test: the TimeRatchet value is monotonically non-decreasing across
//! any sequence of beacon applications, time advances, and simulated reboots
//! (CLAIM-7.7, PV-22, S23).
//!
//! The property under test is the ratchet *value* (`persisted_floor`): it may
//! never decrease, no matter what beacons arrive (including replayed or hostile
//! ones), and after a simulated reboot `now_est` collapses to that floor without
//! going below it. Removing the `max(persisted_floor, wall_time)` enforcement in
//! `advance()` makes the generated backwards beacons succeed and this test fail.

use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::{
    TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetError, TimeRatchetRecord,
    TimeRatchetStore,
};
use tirbase_types::CommandRole;

const MICROS_PER_SEC: u64 = 1_000_000;

#[derive(Debug)]
struct FakeTimeSource {
    mono_us: Mutex<u64>,
    boot: Mutex<u64>,
}

impl FakeTimeSource {
    fn new(boot: u64) -> Self {
        FakeTimeSource {
            mono_us: Mutex::new(MICROS_PER_SEC),
            boot: Mutex::new(boot),
        }
    }

    fn advance_secs(&self, secs: u64) {
        let mut mono = self.mono_us.lock().unwrap();
        *mono = mono.saturating_add(secs.saturating_mul(MICROS_PER_SEC));
    }

 /// A reboot always changes the boot id and restarts the monotonic domain.
    fn reboot(&self) {
        let mut boot = self.boot.lock().unwrap();
        *boot += 1;
        *self.mono_us.lock().unwrap() = MICROS_PER_SEC;
    }
}

impl TimeSource for FakeTimeSource {
    fn monotonic_now(&self) -> u64 {
        *self.mono_us.lock().unwrap()
    }

    fn wall_hint(&self) -> Option<i64> {
        None
    }

    fn boot_id(&self) -> u64 {
        *self.boot.lock().unwrap()
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

#[derive(Debug, Clone)]
enum Step {
    Beacon { wall_time: i64, anchors: usize },
    Advance { secs: u64 },
    Reboot,
}

fn step_strategy() -> impl Strategy<Value = Step> {
    prop_oneof![
        (0i64..400_000, 1usize..3)
            .prop_map(|(wall_time, anchors)| Step::Beacon { wall_time, anchors }),
        (0u64..200_000).prop_map(|secs| Step::Advance { secs }),
        Just(Step::Reboot),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn ratchet_floor_is_monotonically_non_decreasing_across_beacons_and_reboots(
        steps in prop::collection::vec(step_strategy(), 0..40)
    ) {
        let anchor_a = InMemoryKeyProvider::generate().unwrap();
        let anchor_b = InMemoryKeyProvider::generate().unwrap();
        let anchors = [&anchor_a, &anchor_b];
        let resolve = |did: &str| {
            anchors
                .iter()
                .find(|anchor| anchor.did() == did)
                .map(|anchor| anchor.public_key_bytes())
        };

        let ts = FakeTimeSource::new(1);
        let store = Arc::new(MemoryStore::default());
        let mut ratchet =
            TimeRatchet::open(store.clone(), TimeRatchetConfig::default()).unwrap();

        let mut last_floor = ratchet.persisted_floor();
        let mut seq = 0u64;

        for step in steps {
            match step {
                Step::Advance { secs } => ts.advance_secs(secs),
                Step::Reboot => {
                    let floor_before_reboot = ratchet.persisted_floor();
                    ts.reboot();
                    prop_assert_eq!(ratchet.now_est(&ts), ratchet.persisted_floor());
                    prop_assert!(ratchet.now_est(&ts) >= floor_before_reboot);
                }
                Step::Beacon { wall_time, anchors: signer_count } => {
                    seq += 1;
                    let beacon = TimeBeacon {
                        wall_time_secs: wall_time,
                        issuer_did: anchors[0].did().to_string(),
                        mono_seq: seq,
                        valid_for_secs: 300,
                    };
                    let signers: Vec<&InMemoryKeyProvider> =
                        anchors[..signer_count.min(anchors.len())].to_vec();
                    let mut operation =
                        SignedOperation::<TimeBeacon>::new(&beacon, wall_time, None).unwrap();
                    for signer in &signers {
                        operation
                            .sign_with(*signer, CommandRole::TimeAnchor)
                            .unwrap();
                    }

                    let floor_before = ratchet.persisted_floor();
                    match ratchet.advance(&operation, &beacon, &ts, resolve) {
                        Ok(advance) => {
                            prop_assert!(advance.new_floor >= floor_before);
                            prop_assert!(ratchet.persisted_floor() >= wall_time);
                            prop_assert!(ratchet.last_beacon_time() <= ratchet.persisted_floor());
                        }
                        Err(_) => {
                            prop_assert_eq!(ratchet.persisted_floor(), floor_before);
                        }
                    }
                }
            }

 // The ratchet value never decreases, and it is what was persisted.
            prop_assert!(ratchet.persisted_floor() >= last_floor);
            prop_assert!(ratchet.persisted_floor() >= ratchet.last_beacon_time());
            match store.load().unwrap() {
                Some(persisted) => prop_assert_eq!(persisted, ratchet.record()),
                None => prop_assert_eq!(ratchet.record(), TimeRatchetRecord::default()),
            }
            last_floor = ratchet.persisted_floor();
        }
    }
}
