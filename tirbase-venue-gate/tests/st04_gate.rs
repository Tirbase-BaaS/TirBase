// SPDX-License-Identifier: AGPL-3.0-only

//! ST-04 acceptance tests: the offline decision path, replay/one-shot behaviour,
//! fail-safe vs fail-secure power loss, bounded timeouts, tamper, audit and the
//! event stream.

use std::str::FromStr;

use tirbase_venue::{
    AccessPolicy, AccessPolicyId, AccessPolicyRegistry, EffectiveWindow, Gate, GateId, Reader,
    SpaceModel, TicketClass, TicketType, TimeWindow, TopologyVersion, Venue, Zone,
};
use tirbase_venue_access::{AccessController, CredentialRegistry, CredentialSource, PresentedCredential};
use tirbase_venue_gate::{
    AuditAction, DriveCommand, FailMode, Faults, GateConfig, GateController, GateError, GateEvent,
    GatePosition, GateSim, GateTimings, Presentation, SafeState,
};

const T0: i64 = 1_700_000_000_000_000;
const HOUR_US: i64 = 3_600_000_000;
const DAY_US: i64 = 86_400_000_000;

const CARD: [u8; 4] = [0x04, 0xA1, 0xB2, 0xC3];

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("fixture identifier parses")
}

fn topology() -> TopologyVersion {
    let venue = Venue {
        id: parsed("venue-1"),
        name: "Grand Hall".to_string(),
    };
    let zones = vec![Zone {
        id: parsed("zone-north"),
        venue_id: venue.id.clone(),
        name: "North stand".to_string(),
    }];
    let gates = vec![Gate {
        id: parsed("gate-n1"),
        zone_id: parsed("zone-north"),
        name: "North 1".to_string(),
    }];
    let readers = vec![Reader {
        id: parsed("reader-n1-a"),
        gate_id: parsed("gate-n1"),
        name: "Reader N1 A".to_string(),
    }];
    TopologyVersion::new(
        parsed("topology-1"),
        venue,
        EffectiveWindow::new(T0 - 30 * DAY_US, Some(T0 + 60 * DAY_US)).expect("window"),
        zones,
        gates,
        readers,
        Vec::new(),
    )
    .expect("topology")
}

fn space() -> SpaceModel {
    let mut model = SpaceModel::new();
    model
        .add_ticket_type(TicketType {
            id: parsed("tt-general"),
            name: "General".to_string(),
            class: TicketClass::General,
            section_id: None,
            standing_area_id: None,
        })
        .expect("ticket type");
    model
}

fn policies() -> AccessPolicyRegistry {
    let mut registry = AccessPolicyRegistry::new();
    registry
        .add_policy(AccessPolicy {
            id: AccessPolicyId::new("policy-general-n1").expect("policy id"),
            name: "General entry".to_string(),
            selector: tirbase_venue::TicketSelector::TicketType(parsed("tt-general")),
            gate_id: parsed("gate-n1"),
            zone_id: parsed("zone-north"),
            time_window: TimeWindow::new(T0, T0 + 8 * HOUR_US).expect("window"),
            enabled: true,
        })
        .expect("policy");
    registry
}

fn credentials() -> CredentialRegistry {
    let mut registry = CredentialRegistry::new();
    registry
        .add_holder(parsed("holder-1"), "Ada Lovelace")
        .expect("holder");
    registry
        .register(
            parsed("holder-1"),
            parsed("tt-general"),
            CredentialSource::Osdp,
            &CARD,
        )
        .expect("credential");
    registry
}

fn card() -> PresentedCredential {
    PresentedCredential::new(CredentialSource::Osdp, CARD.to_vec())
}

/// An access controller that has already decided once online, so the gate can
/// operate from its offline cache.
fn offline_access(presented: &PresentedCredential, at_utc_us: i64) -> AccessController {
    let mut access = AccessController::new(
        parsed("reader-n1-a"),
        topology(),
        policies(),
        space(),
        credentials(),
    );
    access
        .authorize(presented, &parsed("gate-n1"), at_utc_us)
        .expect("online grant");
    access.go_offline(at_utc_us + 1_000);
    access
}

fn config(mode: FailMode) -> GateConfig {
    GateConfig::new(parsed("gate-n1"), mode, GateTimings::standard())
        .expect("config")
        .with_audit_capacity(64)
        .expect("audit capacity")
        .with_event_capacity(64)
        .expect("event capacity")
}

fn controller(mode: FailMode, access: AccessController) -> GateController {
    GateController::new(config(mode), access).expect("controller")
}

#[test]
fn offline_valid_ticket_opens_the_gate_once() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );

    let decision = gate
        .present(
            &Presentation::new(presented.clone(), 1),
            &gate_id,
            T0 + HOUR_US + 2_000,
        )
        .expect("offline grant");
    assert!(decision.grant.offline);
    assert!(gate.access().reader().link == tirbase_venue_access::LinkState::Offline);
    assert_eq!(gate.take_commands(), vec![DriveCommand::Unlock]);
    assert_eq!(gate.present(&Presentation::new(presented.clone(), 1), &gate_id, T0 + HOUR_US + 3_000).unwrap_err(),
        GateError::ReplayRejected {
            nonce: 1,
            last_accepted: 1
        });
    assert!(gate.take_commands().is_empty());

    // Mechanism follows the command and the passage consumes the permit.
    let mut sim = GateSim::new(FailMode::FailSafe);
    sim.apply(DriveCommand::Unlock);
    let events = gate.apply_feedback(sim.feedback(), T0 + HOUR_US + 4_000);
    assert!(events.iter().any(|record| matches!(record.event, GateEvent::Unlocked)));
    assert_eq!(gate.position(), GatePosition::Unlocked);

    let permit_id = gate.passage(T0 + HOUR_US + 5_000).expect("passage");
    assert_eq!(Some(permit_id), decision.permit_id.into());
    assert_eq!(gate.position(), GatePosition::Open);
    assert_eq!(gate.permit_id(), None);

    // Exactly one unlock was ever issued.
    let unlocks = gate
        .audit()
        .entries()
        .filter(|entry| entry.action == AuditAction::Granted)
        .count();
    assert_eq!(unlocks, 1);
    assert!(gate.audit().verify().is_ok());
}

#[test]
fn a_replay_does_not_open_the_gate_a_second_time() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    let at = T0 + HOUR_US + 2_000;
    gate.present(&Presentation::new(presented.clone(), 7), &gate_id, at)
        .expect("grant");
    assert_eq!(gate.take_commands(), vec![DriveCommand::Unlock]);
    gate.passage(at + 1_000).expect("passage");
    // The lane is open; the lock command comes when the hold expires.
    assert!(gate.take_commands().is_empty());
    let before = gate.audit().len();

    // Same nonce: a protocol replay.
    assert_eq!(
        gate.present(&Presentation::new(presented.clone(), 7), &gate_id, at + 2_000)
            .unwrap_err(),
        GateError::ReplayRejected {
            nonce: 7,
            last_accepted: 7
        }
    );

    // A fresh nonce inside the local re-use interval is still refused.
    assert_eq!(
        gate.present(&Presentation::new(presented.clone(), 8), &gate_id, at + 3_000)
            .unwrap_err(),
        GateError::ReuseTooSoon {
            last_passage_utc_us: at + 1_000
        }
    );
    assert!(gate.take_commands().is_empty());
    assert_eq!(gate.audit().len(), before + 2);
    assert!(gate
        .audit()
        .entries()
        .rev()
        .take(2)
        .all(|entry| entry.action == AuditAction::Replayed));
}

#[test]
fn power_loss_leaves_the_gate_in_the_configured_safe_state() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let cases = [
        (
            FailMode::FailSafe,
            SafeState::Released,
            GatePosition::Unlocked,
            DriveCommand::Release,
        ),
        (
            FailMode::FailSecure,
            SafeState::Secured,
            GatePosition::Locked,
            DriveCommand::Lock,
        ),
    ];
    for (mode, safe_state, position, command) in cases {
        let mut gate = controller(mode, offline_access(&presented, T0 + HOUR_US));
        // Open the lane first, so power loss has something to interrupt.
        gate.present(
            &Presentation::new(presented.clone(), 1),
            &gate_id,
            T0 + HOUR_US + 2_000,
        )
        .expect("grant");
        gate.take_commands();

        let records = gate.power_loss(T0 + HOUR_US + 3_000);
        assert_eq!(gate.position(), position);
        assert_eq!(gate.take_commands(), vec![command]);
        assert!(!gate.is_powered());
        match &records[0].event {
            GateEvent::PowerLost { safe_state: reported } => {
                assert_eq!(*reported, safe_state);
            }
            other => panic!("expected power loss, got {other:?}"),
        }
        assert_eq!(gate.health().safe_state, safe_state);
        assert_eq!(gate.health().position, position);
        assert!(!gate.health().passage_outstanding);

        // An unpowered gate refuses credentials.
        assert_eq!(
            gate.present(
                &Presentation::new(presented.clone(), 2),
                &gate_id,
                T0 + HOUR_US + 4_000
            )
            .unwrap_err(),
            GateError::PowerOff
        );

        // The simulated lane physically lands in the same state.
        let mut sim = GateSim::new(mode);
        sim.power_cut();
        assert_eq!(sim.position(), position);
        assert_eq!(sim.feedback().position, position);
    }
}

#[test]
fn fail_mode_must_be_explicit_in_configuration() {
    let missing = r#"{"gate_id":"gate-n1","timings":{"permit_timeout_us":10000000,"open_hold_us":5000000,"lock_timeout_us":3000000,"reuse_interval_us":30000000},"audit_capacity":16,"event_capacity":16}"#;
    assert!(matches!(
        GateConfig::from_json(missing),
        Err(GateError::InvalidConfig(_))
    ));

    let explicit = missing.replace(
        "\"gate_id\"",
        "\"fail_mode\":\"fail_secure\",\"gate_id\"",
    );
    let parsed = GateConfig::from_json(&explicit).expect("explicit fail mode");
    assert_eq!(parsed.fail_mode, FailMode::FailSecure);
    assert_eq!(parsed.safe_state(), SafeState::Secured);

    // Timeouts are bounded.
    assert!(matches!(
        GateTimings::new(10_000_000, 5_000_000, 0, 30_000_000),
        Err(GateError::InvalidTimeout(_))
    ));
    assert!(matches!(
        GateTimings::new(10_000_000, 5_000_000, 3_000_000, 999_999_999_999),
        Err(GateError::InvalidTimeout(_))
    ));
}

#[test]
fn fire_alarm_releases_egress_and_refuses_entry() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSecure,
        offline_access(&presented, T0 + HOUR_US),
    );
    gate.engage_fire_alarm(T0 + HOUR_US + 2_000);
    assert_eq!(gate.position(), GatePosition::Open);
    assert_eq!(gate.take_commands(), vec![DriveCommand::Release]);
    assert_eq!(
        gate.present(
            &Presentation::new(presented, 1),
            &gate_id,
            T0 + HOUR_US + 3_000
        )
        .unwrap_err(),
        GateError::FireAlarmActive
    );
    gate.clear_fire_alarm(T0 + HOUR_US + 4_000);
    assert_eq!(gate.take_commands(), vec![DriveCommand::Lock]);
    assert_eq!(gate.position(), GatePosition::Unknown);
    assert!(gate
        .audit()
        .entries()
        .any(|entry| entry.action == AuditAction::FireAlarm));
}

#[test]
fn permit_expires_within_the_bounded_timeout() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    let at = T0 + HOUR_US + 2_000;
    gate.present(&Presentation::new(presented, 1), &gate_id, at)
        .expect("grant");
    gate.take_commands();

    let events = gate.tick(at + 10_000_001);
    assert_eq!(gate.permit_id(), None);
    assert!(events
        .iter()
        .any(|record| matches!(record.event, GateEvent::PermitExpired { .. })));
    assert_eq!(gate.take_commands(), vec![DriveCommand::Lock]);
    assert_eq!(gate.passage(at + 10_000_002).unwrap_err(), GateError::NoActivePermit);
}

#[test]
fn passage_holds_the_lane_open_then_relocks() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    let at = T0 + HOUR_US + 2_000;
    gate.present(&Presentation::new(presented, 1), &gate_id, at)
        .expect("grant");
    gate.take_commands();
    gate.passage(at + 1_000).expect("passage");
    assert_eq!(gate.position(), GatePosition::Open);
    assert_eq!(gate.take_commands(), vec![]);

    let events = gate.tick(at + 1_000 + 5_000_000);
    assert!(events.iter().any(|record| matches!(record.event, GateEvent::Closing)));
    assert_eq!(gate.take_commands(), vec![DriveCommand::Lock]);

    let mut sim = GateSim::new(FailMode::FailSafe);
    sim.apply(DriveCommand::Lock);
    let events = gate.apply_feedback(sim.feedback(), at + 1_000 + 5_000_001);
    assert!(events.iter().any(|record| matches!(record.event, GateEvent::Locked)));
    assert_eq!(gate.position(), GatePosition::Locked);
    assert_eq!(gate.faults(), 0);
}

#[test]
fn lock_that_never_reports_engaged_is_a_fault() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSecure,
        offline_access(&presented, T0 + HOUR_US),
    );
    let mut sim = GateSim::new(FailMode::FailSecure);
    sim.inject(Faults::no_lock_engage());

    let at = T0 + HOUR_US + 2_000;
    gate.present(&Presentation::new(presented, 1), &gate_id, at)
        .expect("grant");
    sim.apply(gate.take_commands()[0]);
    gate.apply_feedback(sim.feedback(), at + 1_000);
    gate.passage(at + 2_000).expect("passage");

    let close_at = at + 2_000 + 5_000_000;
    let events = gate.tick(close_at);
    assert!(events.iter().any(|record| matches!(record.event, GateEvent::Closing)));
    for command in gate.take_commands() {
        sim.apply(command);
    }
    // The lane still reports unlocked although it was told to lock.
    let events = gate.apply_feedback(sim.feedback(), close_at + 1_000);
    assert!(events
        .iter()
        .any(|record| matches!(record.event, GateEvent::PositionFault { .. })));
    assert_eq!(gate.faults(), 1);
    assert_eq!(gate.position(), GatePosition::Unknown);
    assert!(gate.health().degraded);

    let events = gate.tick(close_at + 3_000_001);
    assert!(events.iter().any(|record| matches!(record.event, GateEvent::LockTimeout)));
    assert_eq!(gate.faults(), 2);
}

#[test]
fn stuck_mechanisms_are_detected() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();

    // A lane that will not release cannot satisfy an authorised passage.
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    let mut sim = GateSim::new(FailMode::FailSafe);
    sim.inject(Faults {
        stuck_locked: true,
        ..Faults::none()
    });
    let at = T0 + HOUR_US + 2_000;
    gate.present(&Presentation::new(presented.clone(), 1), &gate_id, at)
        .expect("grant");
    for command in gate.take_commands() {
        sim.apply(command);
    }
    assert_eq!(sim.position(), GatePosition::Locked);
    let events = gate.apply_feedback(sim.feedback(), at + 1_000);
    assert!(events
        .iter()
        .any(|record| matches!(record.event, GateEvent::PositionFault { .. })));

    // A lane that stays open cannot be re-secured.
    let mut gate = controller(
        FailMode::FailSecure,
        offline_access(&presented, T0 + HOUR_US),
    );
    let mut sim = GateSim::new(FailMode::FailSecure);
    sim.inject(Faults::stuck_open());
    gate.present(&Presentation::new(presented, 1), &gate_id, at)
        .expect("grant");
    for command in gate.take_commands() {
        sim.apply(command);
    }
    gate.apply_feedback(sim.feedback(), at + 1_000);
    gate.passage(at + 2_000).expect("passage");
    let close_at = at + 2_000 + 5_000_000;
    gate.tick(close_at);
    for command in gate.take_commands() {
        sim.apply(command);
    }
    let events = gate.apply_feedback(sim.feedback(), close_at + 1_000);
    assert!(events
        .iter()
        .any(|record| matches!(record.event, GateEvent::PositionFault { .. })));
}

#[test]
fn tamper_latches_until_an_authorised_reset() {
    let gate_id: GateId = parsed("gate-n1");
    let presented = card();
    let mut gate = controller(
        FailMode::FailSecure,
        offline_access(&presented, T0 + HOUR_US),
    );
    let mut sim = GateSim::new(FailMode::FailSecure);
    sim.set_tamper(true);
    let events = gate.apply_feedback(sim.feedback(), T0 + HOUR_US + 2_000);
    assert!(events
        .iter()
        .any(|record| matches!(record.event, GateEvent::TamperDetected)));
    assert!(gate.is_tampered());
    assert_eq!(
        gate.present(
            &Presentation::new(presented, 1),
            &gate_id,
            T0 + HOUR_US + 3_000
        )
        .unwrap_err(),
        GateError::TamperLatched
    );
    assert_eq!(
        gate.clear_tamper(false, T0 + HOUR_US + 4_000),
        Err(GateError::TamperLatched)
    );
    assert!(!gate
        .clear_tamper(true, T0 + HOUR_US + 5_000)
        .expect("reset")
        .is_empty());
    assert!(!gate.is_tampered());
}

#[test]
fn unpermitted_passage_is_refused_and_audited() {
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    let at = T0 + HOUR_US + 2_000;
    assert_eq!(gate.passage(at).unwrap_err(), GateError::NoActivePermit);
    assert!(gate
        .audit()
        .entries()
        .any(|entry| entry.action == AuditAction::UnpermittedPassage));
    assert!(gate.events().any(|record| matches!(
        record.event,
        GateEvent::UnpermittedPassage
    )));
}

#[test]
fn presentation_for_another_gate_is_refused() {
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    let error = gate
        .present(
            &Presentation::new(presented, 1),
            &parsed("gate-v1"),
            T0 + HOUR_US + 2_000,
        )
        .unwrap_err();
    assert!(matches!(error, GateError::WrongGate { .. }));
    assert!(gate.audit().is_empty());
}

#[test]
fn local_audit_is_hash_chained_and_survives_restart() {
    let presented = card();
    let mut gate = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    gate.observe_tamper(T0 + HOUR_US + 2_000);
    gate.clear_tamper(true, T0 + HOUR_US + 3_000)
        .expect("reset");
    assert!(gate.audit().verify().is_ok());
    let entries = gate.audit().len();
    let json = gate.audit_json().expect("audit serializes");

    // A restored log verifies and keeps its entries.
    let mut restarted = controller(
        FailMode::FailSafe,
        offline_access(&presented, T0 + HOUR_US),
    );
    restarted.restore_audit(&json).expect("restore");
    assert_eq!(restarted.audit().len(), entries);
    assert!(restarted.audit().verify().is_ok());

    // An edited entry breaks the chain.
    let tampered = json.replace("tamper input asserted", "nothing to see here");
    assert_ne!(tampered, json);
    let error = restarted.restore_audit(&tampered).unwrap_err();
    assert!(matches!(error, GateError::AuditChainBroken(_)));
}

#[test]
fn event_stream_is_bounded() {
    let presented = card();
    let mut bounded = config(FailMode::FailSafe);
    bounded.event_capacity = 4;
    let mut gate = GateController::new(bounded, offline_access(&presented, T0 + HOUR_US))
        .expect("controller");

    for step in 0..10 {
        gate.observe_tamper(T0 + HOUR_US + step * 2);
        gate.clear_tamper(true, T0 + HOUR_US + step * 2 + 1)
            .expect("reset");
    }
    assert_eq!(gate.events().count(), 4);
    let health = gate.health();
    // Two events per step (detect, clear) over ten steps.
    assert_eq!(health.last_event_seq, 20);
    assert!(health.events_dropped >= 6);
    assert!(health.audit_entries > 0);
    let drained = gate.drain_events();
    assert_eq!(drained.len(), 4);
    assert!(gate.events().next().is_none());
}
