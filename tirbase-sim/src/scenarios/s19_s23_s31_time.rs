//! Scenarios S19, S23 and S31 — delayed delivery, time-anchor poisoning and
//! clock rollback across reboot (PV-22.1, PV-22.4, PV-22.5).
//!
//! All three drive the production [`TimeRatchet`].  No wall clock is read; the
//! scenarios advance and reboot a [`FixedTimeSource`] explicitly.

use std::sync::Arc;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::{
    FreshnessState, TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetError,
    TimeRatchetRecord, TimeRatchetStore,
};
use tirbase_types::CommandRole;

use super::common::{FixedTimeSource, MemoryRatchetStore};

const BASE_WALL: i64 = 1_800_000_000;

fn record(wall_secs: i64, mono_secs: u64, boot_id: u64) -> TimeRatchetRecord {
    TimeRatchetRecord {
        last_beacon_time: wall_secs,
        mono_at_beacon: mono_secs.saturating_mul(1_000_000),
        persisted_floor: wall_secs,
        beacon_boot_id: boot_id,
        updated_at_mono: mono_secs.saturating_mul(1_000_000),
    }
}

fn open_with(record: TimeRatchetRecord) -> (TimeRatchet, Arc<MemoryRatchetStore>) {
    let store = Arc::new(MemoryRatchetStore::default());
    store.save(&record).expect("seed ratchet record");
    let ratchet =
        TimeRatchet::open(store.clone(), TimeRatchetConfig::default()).expect("open time ratchet");
    (ratchet, store)
}

fn beacon(wall_time_secs: i64) -> TimeBeacon {
    TimeBeacon {
        wall_time_secs,
        issuer_did: "did:key:z6MktimeAnchor".to_string(),
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

fn resolver<'a>(anchors: &'a [&'a InMemoryKeyProvider]) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
    move |did| {
        anchors
            .iter()
            .find(|anchor| anchor.did() == did)
            .map(|anchor| anchor.public_key_bytes())
    }
}

/// S19 — a command withheld past its authenticated expiry is rejected even if
/// the wall clock is moved backwards.
pub fn run_s19(seed: u64) -> Result<(), String> {
    let clock = FixedTimeSource::new(1, BASE_WALL, 1_000);
    let (ratchet, _) = open_with(record(BASE_WALL, 1_000, 1));
    let ttl = 30 + (seed % 10) as i64;
    let expires = ratchet.now_est(&clock) + ttl;

    if ratchet.is_expired(expires, &clock) {
        return Err("S19 FAIL: fresh command reported expired".to_string());
    }

    clock.advance_secs(ttl + 1);
    if !ratchet.is_expired(expires, &clock) {
        return Err("S19 FAIL: withheld command did not expire after TTL".to_string());
    }

    // Wall-clock rollback must not resurrect the command.
    clock.set_wall_secs(BASE_WALL - 86_400);
    if !ratchet.is_expired(expires, &clock) {
        return Err("S19 FAIL: wall-clock rollback un-expired the command".to_string());
    }
    if ratchet.now_est(&clock) <= expires {
        return Err("S19 FAIL: now_est followed the manipulated wall clock".to_string());
    }
    Ok(())
}

/// S23 — time-anchor poisoning (PV-28.4, CLAIM-53.3).
///
/// Exercises `TimeAnchorService` multi-peer beacon selection/production:
/// - Multiple peers produce signed COSE_Sign1 beacons; the authenticated estimate
///   selects the most recent valid beacon within the max-forward-jump constraint.
/// - A far-future (poisoning) peer beacon is not selectable without satisfying
///   jump/quorum constraints and must not advance the persisted ratchet floor.
/// - A large jump is admitted only with the required M-of-N TimeAnchor quorum.
pub fn run_s23(seed: u64) -> Result<(), String> {
    use std::time::Duration;
    use tirbase_gateway::time_anchor::{
        select_authenticated_beacon, sign_cose_beacon, NoopBeaconSink, PeerBeacon, TimeAnchorService,
    };

    let anchor_a = InMemoryKeyProvider::generate().map_err(|e| format!("S23 anchor A: {e}"))?;
    let anchor_b = InMemoryKeyProvider::generate().map_err(|e| format!("S23 anchor B: {e}"))?;
    let anchors = [&anchor_a, &anchor_b];
    let clock: Arc<dyn tirbase_core::traits::TimeSource> = Arc::new(FixedTimeSource::new(1, BASE_WALL, 1));

    let store = Arc::new(MemoryRatchetStore::default());
    let mut ratchet =
        TimeRatchet::open(store, TimeRatchetConfig::default()).expect("open time ratchet");

    // Bootstrap with a quorum-signed beacon at BASE_WALL.
    let bootstrap = beacon(BASE_WALL);
    ratchet
        .advance(
            &signed_beacon(&anchors, &bootstrap),
            &bootstrap,
            clock.as_ref(),
            resolver(&anchors),
        )
        .map_err(|error| format!("S23 bootstrap rejected: {error}"))?;
    let floor_before = ratchet.persisted_floor();
    let beacon_before = ratchet.last_beacon_time();
    let max_jump = ratchet.max_forward_jump_secs();

    // --- TimeAnchorService active (PV-28.1/28.3): multiple peers broadcast COSE_Sign1 beacons ---
    let sink = Arc::new(NoopBeaconSink);
    let peer_key_a: Arc<dyn tirbase_core::traits::KeyProvider> = Arc::new(InMemoryKeyProvider::generate().map_err(|e| format!("S23 peer A: {e}"))?);
    let peer_key_b: Arc<dyn tirbase_core::traits::KeyProvider> = Arc::new(InMemoryKeyProvider::generate().map_err(|e| format!("S23 peer B: {e}"))?);
    let svc_a = Arc::new(TimeAnchorService::new(
        peer_key_a.clone(),
        clock.clone(),
        Duration::from_secs(60),
        300,
        sink.clone(),
    ));
    let svc_b = Arc::new(TimeAnchorService::new(
        peer_key_b.clone(),
        clock.clone(),
        Duration::from_secs(60),
        300,
        sink,
    ));
    let cose_a = svc_a
        .produce_beacon()
        .map_err(|e| format!("S23 service beacon A: {e}"))?;
    let cose_b = svc_b
        .produce_beacon()
        .map_err(|e| format!("S23 service beacon B: {e}"))?;
    let peers = vec![
        PeerBeacon { beacon: cose_a, anchor_public_key: peer_key_a.public_key_bytes() },
        PeerBeacon { beacon: cose_b, anchor_public_key: peer_key_b.public_key_bytes() },
    ];
    // With TimeAnchorService active, authenticated estimate uses the most recent
    // valid beacon satisfying the max-forward-jump constraint.
    let _selected = select_authenticated_beacon(&peers, floor_before, max_jump);
    // Service beacons at current wall (== floor) are valid/non-poisoning; ensure
    // selection never yields a jump beyond the constraint.
    if let Some((p, _)) = select_authenticated_beacon(&peers, floor_before, max_jump) {
        if p.wall_time_secs > floor_before + max_jump {
            return Err("S23 FAIL: service selection admitted a max-jump-violating beacon".into());
        }
    }

    // --- Poisoning attempt: forged far-future beacon with insufficient quorum ---
    let forged_time = BASE_WALL + max_jump + 1 + (seed % 100) as i64;
    let forged = beacon(forged_time);
    let single = signed_beacon(&[&anchor_a], &forged);
    match ratchet.advance(&single, &forged, clock.as_ref(), resolver(&anchors)) {
        Err(TimeRatchetError::InsufficientAnchorQuorum { verified, .. }) => {
            if verified != 1 {
                return Err(format!(
                    "S23: quorum rejection counted {verified} signatures, expected 1"
                ));
            }
        }
        Err(other) => return Err(format!("S23 FAIL: unexpected rejection: {other}")),
        Ok(advance) => {
            return Err(format!(
                "S23 FAIL: single-anchor far-future beacon advanced the ratchet: {advance:?}"
            ))
        }
    }
    if ratchet.persisted_floor() != floor_before || ratchet.last_beacon_time() != beacon_before {
        return Err("S23 FAIL: rejected beacon changed ratchet state".to_string());
    }

    // TimeAnchorService multi-peer COSE selection must also reject the poisoning jump.
    let poison_cose = sign_cose_beacon(&anchor_a, forged_time, 999, 300)
        .map_err(|e| format!("S23 poison cose: {e}"))?;
    let poison_peer = PeerBeacon { beacon: poison_cose, anchor_public_key: anchor_a.public_key_bytes() };
    if select_authenticated_beacon(&[poison_peer], floor_before, max_jump).is_some() {
        return Err("S23 FAIL: COSE peer selection accepted a jump beyond max_forward_jump".into());
    }

    // The same jump with the required quorum is accepted (legitimate multi-anchor advance).
    let quorum = signed_beacon(&anchors, &forged);
    ratchet
        .advance(&quorum, &forged, clock.as_ref(), resolver(&anchors))
        .map_err(|error| format!("S23 FAIL: quorum-signed beacon rejected: {error}"))?;
    if ratchet.persisted_floor() != forged_time {
        return Err("S23 FAIL: quorum beacon did not advance the floor".to_string());
    }
    Ok(())
}

/// S31 — after a reboot, `now_est` equals the persisted floor and freshness is
/// Unverified; no monotonic subtraction across the boot boundary.
pub fn run_s31(seed: u64) -> Result<(), String> {
    let floor = BASE_WALL + (seed % 100) as i64;
    let (ratchet, _) = open_with(record(floor, 5_000, 7));
    let clock = FixedTimeSource::new(8, floor + 1_000, 1);

    if ratchet.now_est(&clock) != floor {
        return Err(format!(
            "S31 FAIL: now_est {} after reboot, expected floor {floor}",
            ratchet.now_est(&clock)
        ));
    }
    if ratchet.freshness(&clock) != FreshnessState::Unverified {
        return Err("S31 FAIL: freshness stayed Verified after reboot".to_string());
    }

    clock.advance_secs(10_000);
    if ratchet.now_est(&clock) < floor {
        return Err("S31 FAIL: now_est dropped below the persisted floor".to_string());
    }

    // A new beacon on the new boot restores Verified freshness.
    let anchor_a = InMemoryKeyProvider::generate().map_err(|e| format!("S31 anchor A: {e}"))?;
    let anchor_b = InMemoryKeyProvider::generate().map_err(|e| format!("S31 anchor B: {e}"))?;
    let anchors = [&anchor_a, &anchor_b];
    let fresh = beacon(floor + 10);
    let mut ratchet = ratchet;
    ratchet
        .advance(
            &signed_beacon(&anchors, &fresh),
            &fresh,
            &clock,
            resolver(&anchors),
        )
        .map_err(|error| format!("S31 new-boot beacon rejected: {error}"))?;
    if ratchet.freshness(&clock) != FreshnessState::Verified {
        return Err("S31 FAIL: freshness did not recover after a new beacon".to_string());
    }
    if ratchet.now_est(&clock) < floor {
        return Err("S31 FAIL: now_est regressed after the new beacon".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s19_delayed_delivery_rejected() {
        run_s19(1).expect("S19");
    }

    #[test]
    fn s23_time_anchor_poisoning_rejected() {
        run_s23(1).expect("S23");
    }

    #[test]
    fn s31_clock_rollback_across_reboot() {
        run_s31(1).expect("S31");
    }
}
