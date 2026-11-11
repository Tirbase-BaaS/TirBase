//! Gateway-level tests for TimeAnchorService (CLAIM-53.1, CLAIM-53.2, PV-28).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_gateway::time_anchor::{
    select_authenticated_beacon, sign_cose_beacon, verify_cose_beacon, BeaconSink,
    CoseSign1Beacon, PeerBeacon, TimeAnchorService,
};

#[derive(Debug, Default)]
struct FixedWallTimeSource {
    /// CLOCK_REALTIME hint in microseconds since Unix epoch (trait contract).
    wall_micros: i64,
    mono: Mutex<u64>,
}
impl TimeSource for FixedWallTimeSource {
    fn monotonic_now(&self) -> u64 {
        let mut g = self.mono.lock().unwrap();
        *g += 1_000_000;
        *g
    }
    fn wall_hint(&self) -> Option<i64> {
        Some(self.wall_micros)
    }
    fn boot_id(&self) -> u64 {
        1
    }
}

#[derive(Debug, Default)]
struct CollectSink(Mutex<Vec<CoseSign1Beacon>>);
impl BeaconSink for CollectSink {
    fn publish(&self, beacon: &CoseSign1Beacon) {
        self.0.lock().unwrap().push(beacon.clone());
    }
}

#[test]
fn claim_53_1_time_anchor_service_produces_periodic_signed_cose_sign1_beacons() {
    let provider = Arc::new(InMemoryKeyProvider::generate().expect("key"));
    let ts = Arc::new(FixedWallTimeSource {
        wall_micros: 1_800_000_000_i64 * 1_000_000,
        mono: Mutex::new(0),
    });
    let sink = Arc::new(CollectSink::default());
    let svc = Arc::new(TimeAnchorService::new(
        provider.clone(),
        ts,
        Duration::from_millis(5),
        300,
        sink.clone(),
    ));

    // Produce multiple beacons (periodic generation exercised directly and via loop semantics).
    let b1 = svc.produce_beacon().expect("beacon 1");
    let b2 = svc.produce_beacon().expect("beacon 2");
    let b3 = svc.produce_beacon().expect("beacon 3");

    let p1 = verify_cose_beacon(&b1, &provider.public_key_bytes()).expect("verify b1");
    let p2 = verify_cose_beacon(&b2, &provider.public_key_bytes()).expect("verify b2");
    let p3 = verify_cose_beacon(&b3, &provider.public_key_bytes()).expect("verify b3");

    assert_eq!(p1.wall_time_secs, 1_800_000_000);
    assert_eq!(p1.issuer_did, provider.did());
    assert_eq!(p1.valid_for_secs, 300);
    assert!(p2.mono_seq > p1.mono_seq && p3.mono_seq > p2.mono_seq, "mono_seq must increase");

    let published = sink.0.lock().unwrap();
    assert!(published.len() >= 3, "broadcast sink must receive periodic beacons");
    // Signed COSE_Sign1 structure: protected/payload/signature present.
    for b in published.iter() {
        assert!(!b.protected.is_empty());
        assert!(!b.payload.is_empty());
        assert_eq!(b.signature.len(), 64);
    }
}

#[test]
fn claim_53_2_multiple_peers_select_most_recent_valid_beacon_within_max_jump() {
    let peer_a = InMemoryKeyProvider::generate().expect("a");
    let peer_b = InMemoryKeyProvider::generate().expect("b");
    let peer_c = InMemoryKeyProvider::generate().expect("c");
    let floor = 1_700_000_000i64;
    let max_jump = 86_400i64;

    let old = sign_cose_beacon(&peer_a, floor + 100, 10, 300).expect("old");
    let newest_valid = sign_cose_beacon(&peer_b, floor + 500, 11, 300).expect("newest");
    let too_far = sign_cose_beacon(&peer_c, floor + max_jump + 1, 12, 300).expect("too far");
    let below_floor = sign_cose_beacon(&peer_a, floor - 1, 13, 300).expect("below");

    let peers = vec![
        PeerBeacon { beacon: old, anchor_public_key: peer_a.public_key_bytes() },
        PeerBeacon { beacon: newest_valid.clone(), anchor_public_key: peer_b.public_key_bytes() },
        PeerBeacon { beacon: too_far, anchor_public_key: peer_c.public_key_bytes() },
        PeerBeacon { beacon: below_floor, anchor_public_key: peer_a.public_key_bytes() },
    ];

    let (selected_payload, selected_beacon) =
        select_authenticated_beacon(&peers, floor, max_jump).expect("a valid beacon must be selected");
    assert_eq!(selected_payload.wall_time_secs, floor + 500);
    assert_eq!(selected_payload.issuer_did, peer_b.did());
    assert_eq!(selected_beacon.signature, newest_valid.signature);

    // Empty/invalid-only set yields none.
    let bad = PeerBeacon { beacon: newest_valid, anchor_public_key: peer_a.public_key_bytes() };
    assert!(select_authenticated_beacon(&[bad], floor, max_jump).is_none());
}
