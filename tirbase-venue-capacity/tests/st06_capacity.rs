// SPDX-License-Identifier: AGPL-3.0-only

//! ST-06 acceptance tests: limits, idempotent counting, reconciliation,
//! overrides, concurrency and breach behaviour.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tirbase_venue::{GateId, TicketId, TurnstileId, VenueId, ZoneId};
use tirbase_venue_capacity::{
    Alarm, CapacityConfig, CapacityEngine, CapacityError, CapacityLimit, Denial, Direction,
    EventSource, HardPolicy, LimitScope, Observation, ObservationKind, OverrideGrant,
    OverrideState, PresenceEvent, ReconciliationStatus,
};
use tirbase_venue_ticket::{Admission, EventId};

const T0: i64 = 1_700_000_000_000_000;
const HOUR_US: i64 = 3_600_000_000;
const DAY_US: i64 = 86_400_000_000;

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("fixture identifier parses")
}

fn venue() -> VenueId {
    parsed("venue-1")
}

fn zone_north() -> ZoneId {
    parsed("zone-north")
}

fn zone_south() -> ZoneId {
    parsed("zone-south")
}

fn gate_n1() -> GateId {
    parsed("gate-n1")
}

fn gate_n2() -> GateId {
    parsed("gate-n2")
}

fn gate_s1() -> GateId {
    parsed("gate-s1")
}

fn zone_for(gate_id: &GateId) -> ZoneId {
    if gate_id == &gate_s1() {
        zone_south()
    } else {
        zone_north()
    }
}

fn config() -> CapacityConfig {
    CapacityConfig::new(venue(), CapacityLimit::rejecting(12, 15).expect("venue limit"))
        .with_zone(
            zone_north(),
            CapacityLimit::rejecting(8, 10).expect("zone limit"),
            [gate_n1(), gate_n2()],
        )
        .with_zone(
            zone_south(),
            CapacityLimit::rejecting(5, 6).expect("zone limit"),
            [gate_s1()],
        )
        .with_gate_limit(gate_n1(), CapacityLimit::rejecting(4, 5).expect("gate limit"))
}

fn engine() -> CapacityEngine {
    CapacityEngine::new(config()).expect("engine")
}

fn event(
    event_id: &str,
    direction: Direction,
    gate_id: GateId,
    at_utc_us: i64,
) -> PresenceEvent {
    let zone_id = zone_for(&gate_id);
    PresenceEvent::new(
        event_id,
        direction,
        venue(),
        zone_id,
        gate_id,
        at_utc_us,
        EventSource::GateController { gate_id: parsed("gate-controller-1") },
    )
}

fn ingress(event_id: &str, gate_id: GateId) -> PresenceEvent {
    event(event_id, Direction::Ingress, gate_id, T0)
}

fn egress(event_id: &str, gate_id: GateId) -> PresenceEvent {
    event(event_id, Direction::Egress, gate_id, T0)
}

fn grant(scope: LimitScope, at_utc_us: i64, expires_at_utc_us: i64) -> OverrideGrant {
    OverrideGrant {
        override_id: "ovr-1".to_string(),
        scope,
        requested_by: "guard-lead-7".to_string(),
        approved_by: "supervisor-3".to_string(),
        reason: "late surge at the north turnstiles".to_string(),
        granted_at_utc_us: at_utc_us,
        expires_at_utc_us,
        max_headroom: 2,
        max_uses: 2,
    }
}

// --- counting ----------------------------------------------------------

#[test]
fn ingress_and_egress_track_gate_zone_and_venue_occupancy() {
    let mut engine = engine();
    for index in 0..3 {
        let decision = engine
            .record(&ingress(&format!("evt-in-{index}"), gate_n1()))
            .expect("record");
        assert!(decision.is_allowed());
    }
    assert_eq!(engine.venue_occupancy(), 3);
    assert_eq!(engine.zone_occupancy(&zone_north()), 3);
    assert_eq!(engine.gate_occupancy(&gate_n1()), 3);
    assert_eq!(engine.zone_occupancy(&zone_south()), 0);

    let decision = engine
        .record(&egress("evt-out-1", gate_n1()))
        .expect("record");
    assert!(decision.is_allowed());
    assert_eq!(engine.venue_occupancy(), 2);
    assert_eq!(engine.zone_occupancy(&zone_north()), 2);
    assert_eq!(engine.gate_occupancy(&gate_n1()), 2);
}

#[test]
fn a_duplicate_entry_event_does_not_inflate_occupancy() {
    let mut engine = engine();
    let first = engine.record(&ingress("evt-1", gate_n1())).expect("record");
    assert!(first.is_allowed());

    let second = engine.record(&ingress("evt-1", gate_n1())).expect("record");
    assert!(second.is_duplicate(), "duplicate must not count");
    assert_eq!(engine.venue_occupancy(), 1);
    assert_eq!(engine.zone_occupancy(&zone_north()), 1);
    assert_eq!(engine.gate_occupancy(&gate_n1()), 1);

    // A duplicate egress is likewise a no-op.
    engine.record(&egress("evt-out", gate_n1())).expect("record");
    let dup_egress = engine
        .record(&egress("evt-out", gate_n1()))
        .expect("record");
    assert!(dup_egress.is_duplicate());
    assert_eq!(engine.venue_occupancy(), 0);

    // A fresh event still counts.
    engine.record(&ingress("evt-2", gate_n1())).expect("record");
    assert_eq!(engine.venue_occupancy(), 1);
}

#[test]
fn a_denied_event_can_be_retried_and_is_not_a_duplicate() {
    let mut engine = CapacityEngine::new(
        CapacityConfig::new(venue(), CapacityLimit::rejecting(10, 10).expect("limit"))
            .with_zone(
                zone_north(),
                CapacityLimit::rejecting(10, 10).expect("limit"),
                [gate_n1()],
            )
            .with_gate_limit(gate_n1(), CapacityLimit::rejecting(1, 1).expect("limit")),
    )
    .expect("engine");

    engine.record(&ingress("evt-1", gate_n1())).expect("first");
    let denied = engine.record(&ingress("evt-2", gate_n1())).expect("second");
    assert_eq!(
        denied.denial().map(Denial::code),
        Some("hard_limit"),
        "gate limit of one must reject the second"
    );
    assert_eq!(engine.venue_occupancy(), 1);

    // The refused passage left no idempotency record: retrying after an
    // egress can succeed.
    engine.record(&egress("evt-out", gate_n1())).expect("egress");
    let retried = engine.record(&ingress("evt-2", gate_n1())).expect("retry");
    assert!(retried.is_allowed(), "a refused event is not remembered");
}

#[test]
fn egress_below_zero_is_denied_and_never_underflows() {
    let mut engine = engine();
    let decision = engine
        .record(&egress("evt-out", gate_s1()))
        .expect("record");
    assert_eq!(
        decision.denial(),
        Some(&Denial::EgressUnderflow {
            scope: LimitScope::Zone(zone_south()),
            occupancy: 0,
        })
    );
    assert_eq!(engine.venue_occupancy(), 0);

    // An egress at a gate that saw no ingress is counted but flagged.
    engine.record(&ingress("evt-in", gate_n1())).expect("record");
    let decision = engine.record(&egress("evt-out", gate_n2())).expect("record");
    assert!(decision.is_allowed());
    assert!(decision
        .alarms()
        .iter()
        .any(|alarm| matches!(alarm, Alarm::GateUnbalanced { .. })));
    assert_eq!(engine.venue_occupancy(), 0);
    assert_eq!(engine.gate_occupancy(&gate_n1()), 1);
}

// --- limits ------------------------------------------------------------

#[test]
fn hard_limit_rejects_when_configured_to_reject() {
    let mut engine = engine();
    // gate-n1 hard limit is 5, zone-north 10, venue 15.
    for index in 0..5 {
        assert!(engine
            .record(&ingress(&format!("evt-{index}"), gate_n1()))
            .expect("record")
            .is_allowed());
    }
    let decision = engine.record(&ingress("evt-6", gate_n1())).expect("record");
    assert_eq!(
        decision.denial(),
        Some(&Denial::HardLimit {
            scope: LimitScope::Gate(gate_n1()),
            limit: 5,
            occupancy: 5,
            attempted: 6,
        })
    );
    assert_eq!(engine.venue_occupancy(), 5);

    // Another gate in the same zone still admits: only the gate envelope is full.
    assert!(engine
        .record(&ingress("evt-7", gate_n2()))
        .expect("record")
        .is_allowed());
    assert_eq!(engine.gate_occupancy(&gate_n2()), 1);
}

#[test]
fn hard_limit_alarms_and_admits_when_configured_to_alarm() {
    let mut engine = CapacityEngine::new(
        CapacityConfig::new(venue(), CapacityLimit::rejecting(10, 10).expect("venue"))
            .with_zone(
                zone_north(),
                CapacityLimit::rejecting(10, 10).expect("zone"),
                [gate_n1()],
            )
            .with_gate_limit(gate_n1(), CapacityLimit::alarming(2, 3).expect("gate")),
    )
    .expect("engine");

    for index in 0..3 {
        let decision = engine
            .record(&ingress(&format!("evt-{index}"), gate_n1()))
            .expect("record");
        assert!(decision.is_allowed());
    }
    let decision = engine.record(&ingress("evt-4", gate_n1())).expect("record");
    assert!(decision.is_allowed(), "alarm policy admits");
    assert!(decision.alarms().iter().any(|alarm| matches!(
        alarm,
        Alarm::HardLimit {
            scope: LimitScope::Gate(_),
            limit: 3,
            occupancy: 4,
        }
    )));
    assert_eq!(engine.venue_occupancy(), 4);
    assert_eq!(engine.gate_occupancy(&gate_n1()), 4);
}

#[test]
fn soft_limit_alarms_without_refusing() {
    let mut engine = CapacityEngine::new(
        CapacityConfig::new(venue(), CapacityLimit::rejecting(20, 20).expect("venue"))
            .with_zone(
                zone_south(),
                CapacityLimit::rejecting(2, 5).expect("zone"),
                [gate_s1()],
            ),
    )
    .expect("engine");

    for index in 0..2 {
        assert!(engine
            .record(&ingress(&format!("evt-{index}"), gate_s1()))
            .expect("record")
            .alarms()
            .is_empty());
    }
    let decision = engine
        .record(&ingress("evt-3", gate_s1()))
        .expect("record");
    assert!(decision.is_allowed());
    assert_eq!(
        decision.alarms(),
        &[Alarm::SoftLimit {
            scope: LimitScope::Zone(zone_south()),
            limit: 2,
            occupancy: 3,
        }]
    );
}

#[test]
fn the_venue_envelope_applies_across_zones() {
    let mut engine = CapacityEngine::new(
        CapacityConfig::new(venue(), CapacityLimit::rejecting(2, 3).expect("venue"))
            .with_zone(
                zone_north(),
                CapacityLimit::rejecting(10, 10).expect("north"),
                [gate_n2()],
            )
            .with_zone(
                zone_south(),
                CapacityLimit::rejecting(10, 10).expect("south"),
                [gate_s1()],
            ),
    )
    .expect("engine");

    engine.record(&ingress("evt-1", gate_n2())).expect("record");
    engine.record(&ingress("evt-2", gate_s1())).expect("record");
    engine.record(&ingress("evt-3", gate_s1())).expect("record");
    let decision = engine.record(&ingress("evt-4", gate_s1())).expect("record");
    assert_eq!(
        decision.denial(),
        Some(&Denial::HardLimit {
            scope: LimitScope::Venue,
            limit: 3,
            occupancy: 3,
            attempted: 4,
        })
    );
    assert_eq!(engine.venue_occupancy(), 3);
    assert_eq!(engine.zone_occupancy(&zone_south()), 2);
}

// --- overrides ---------------------------------------------------------

#[test]
fn an_override_is_attributable_audited_and_expires() {
    let mut engine = CapacityEngine::new(
        CapacityConfig::new(venue(), CapacityLimit::rejecting(50, 50).expect("venue"))
            .with_zone(
                zone_north(),
                CapacityLimit::rejecting(50, 50).expect("zone"),
                [gate_n1()],
            )
            .with_gate_limit(gate_n1(), CapacityLimit::rejecting(2, 2).expect("gate")),
    )
    .expect("engine");

    for index in 0..2 {
        engine
            .record(&ingress(&format!("evt-{index}"), gate_n1()))
            .expect("record");
    }
    assert!(!engine
        .record(&ingress("evt-3", gate_n1()))
        .expect("record")
        .is_allowed());

    let approved = engine
        .grant_override(grant(LimitScope::Gate(gate_n1()), T0, T0 + HOUR_US))
        .expect("grant");
    assert_eq!(approved.max_headroom, 2);
    assert_eq!(approved.max_uses, 2);
    assert_eq!(approved.state(T0), OverrideState::Active);

    let granted = engine
        .audit()
        .find(|entry| entry.action.code() == "override_granted")
        .expect("grant audited");
    assert_eq!(granted.actor, "supervisor-3");
    assert!(granted.detail.contains("guard-lead-7"), "requester recorded");
    assert!(granted.detail.contains("late surge"));
    assert_eq!(granted.scope, LimitScope::Gate(gate_n1()));

    // Under the override the gate admits above its hard limit, and the use is
    // attributed to the override.
    let decision = engine
        .record(&event("evt-3", Direction::Ingress, gate_n1(), T0 + 60))
        .expect("record");
    assert!(decision.is_allowed());
    assert!(decision.alarms().iter().any(|alarm| matches!(
        alarm,
        Alarm::OverrideUsed { override_id, .. } if override_id == "ovr-1"
    )));
    assert_eq!(engine.override_by_id("ovr-1").expect("override").uses, 1);
    let used = engine
        .audit()
        .find(|entry| entry.action.code() == "override_used")
        .expect("use audited");
    assert_eq!(used.reference, "ovr-1");

    // Second use exhausts the two permitted passages past the limit.
    assert!(engine
        .record(&event("evt-4", Direction::Ingress, gate_n1(), T0 + 120))
        .expect("record")
        .is_allowed());
    assert_eq!(
        engine.override_by_id("ovr-1").expect("override").state(T0 + 120),
        OverrideState::Exhausted
    );
    let decision = engine
        .record(&event("evt-5", Direction::Ingress, gate_n1(), T0 + 180))
        .expect("record");
    assert!(decision.denial().is_some(), "exhausted override admits nothing");

    // A different override with a later deadline expires even if unused.
    let mut later = grant(LimitScope::Gate(gate_n1()), T0 + 200, T0 + 300);
    later.override_id = "ovr-2".to_string();
    later.max_uses = 5;
    engine.grant_override(later).expect("second grant");
    assert_eq!(engine.sweep(T0 + 299), Vec::<String>::new());
    assert_eq!(engine.sweep(T0 + 300), vec!["ovr-2".to_string()]);
    assert_eq!(
        engine.override_by_id("ovr-2").expect("override").state(T0 + 300),
        OverrideState::Expired
    );
    assert!(engine
        .audit()
        .any(|entry| entry.action.code() == "override_expired" && entry.reference == "ovr-2"));
    assert_eq!(engine.venue_occupancy(), 4);
}

#[test]
fn overrides_need_separation_of_duties_and_a_valid_scope() {
    let mut engine = engine();
    let mut self_approved = grant(LimitScope::Gate(gate_n1()), T0, T0 + HOUR_US);
    self_approved.approved_by = "guard-lead-7".to_string();
    assert_eq!(
        engine.grant_override(self_approved),
        Err(CapacityError::InvalidOverride(
            "requester cannot approve their own override"
        ))
    );

    let mut empty_reason = grant(LimitScope::Gate(gate_n1()), T0, T0 + HOUR_US);
    empty_reason.reason = "  ".to_string();
    assert!(matches!(
        engine.grant_override(empty_reason),
        Err(CapacityError::InvalidOverride(_))
    ));

    let mut past = grant(LimitScope::Gate(gate_n1()), T0, T0);
    past.override_id = "ovr-past".to_string();
    assert!(matches!(
        engine.grant_override(past),
        Err(CapacityError::InvalidOverride(_))
    ));

    let mut unknown = grant(LimitScope::Zone(parsed("zone-nowhere")), T0, T0 + HOUR_US);
    unknown.override_id = "ovr-unknown".to_string();
    assert!(matches!(
        engine.grant_override(unknown),
        Err(CapacityError::InvalidOverride(_))
    ));

    engine
        .grant_override(grant(LimitScope::Gate(gate_n1()), T0, T0 + HOUR_US))
        .expect("first grant");
    let mut second = grant(LimitScope::Gate(gate_n1()), T0 + 1, T0 + 2 * HOUR_US);
    second.override_id = "ovr-dup".to_string();
    assert_eq!(
        engine.grant_override(second),
        Err(CapacityError::OverrideAlreadyActive(LimitScope::Gate(
            gate_n1()
        )))
    );

    let revoked = engine
        .revoke_override("ovr-1", "supervisor-9", "crowd cleared", T0 + 60)
        .expect("revoke");
    assert_eq!(revoked.state(T0 + 61), OverrideState::Revoked);
    assert!(engine
        .audit()
        .any(|entry| entry.action.code() == "override_revoked" && entry.actor == "supervisor-9"));
}

// --- reconciliation ----------------------------------------------------

#[test]
fn sensor_disagreement_is_reported_and_can_be_adopted_with_audit() {
    let mut engine = CapacityEngine::new(
        CapacityConfig::new(venue(), CapacityLimit::rejecting(30, 40).expect("venue"))
            .with_zone(
                zone_north(),
                CapacityLimit::rejecting(8, 10).expect("zone"),
                [gate_n2()],
            ),
    )
    .expect("engine");

    for index in 0..10 {
        assert!(engine
            .record(&ingress(&format!("evt-{index}"), gate_n2()))
            .expect("record")
            .is_allowed());
    }
    assert_eq!(engine.zone_occupancy(&zone_north()), 10);

    let turnstiles = Observation::new(
        "obs-turnstile-1",
        zone_north(),
        "turnstile-bank-n",
        T0,
        ObservationKind::Turnstile {
            ingress_total: 10,
            egress_total: 0,
        },
    );
    let report = engine.reconcile(&turnstiles).expect("reconcile");
    assert_eq!(report.status, ReconciliationStatus::Agree);
    assert_eq!((report.tracked, report.observed, report.delta), (10, 10, 0));

    let sensor = Observation::new(
        "obs-sensor-1",
        zone_north(),
        "sensor-n1",
        T0,
        ObservationKind::Occupancy { occupancy: 15 },
    );
    let report = engine.reconcile(&sensor).expect("reconcile");
    assert_eq!(report.status, ReconciliationStatus::ObservedHigher);
    assert_eq!((report.tracked, report.observed, report.delta), (10, 15, 5));
    assert_eq!(report.source_kind.code(), "occupancy_sensor");

    let adoption = engine
        .adopt_observation(&sensor, "guard-lead-7", "sensor recount after gate jam")
        .expect("adopt");
    assert_eq!((adoption.previous, adoption.adopted), (10, 15));
    assert_eq!(engine.zone_occupancy(&zone_north()), 15);
    assert_eq!(engine.venue_occupancy(), 15);
    assert!(adoption
        .alarms
        .iter()
        .any(|alarm| matches!(alarm, Alarm::SensorDisagreement { observed: 15, .. })));
    assert!(adoption
        .alarms
        .iter()
        .any(|alarm| matches!(alarm, Alarm::HardLimit { .. })));
    let entry = engine
        .audit()
        .find(|entry| entry.action.code() == "reconciliation_adopted")
        .expect("adoption audited");
    assert_eq!(entry.actor, "guard-lead-7");
    assert!(entry.detail.contains("gate jam"));
    assert_eq!(entry.reference, "obs-sensor-1");

    // A low reading adopts downwards.
    let low = Observation::new(
        "obs-sensor-2",
        zone_north(),
        "sensor-n1",
        T0 + 60,
        ObservationKind::Occupancy { occupancy: 7 },
    );
    let adoption = engine
        .adopt_observation(&low, "guard-lead-7", "recount")
        .expect("adopt");
    assert_eq!((adoption.previous, adoption.adopted), (15, 7));
    assert_eq!(engine.venue_occupancy(), 7);

    // Turnstile totals disagree when they lag the sensor.
    let lagging = Observation::new(
        "obs-turnstile-2",
        zone_north(),
        "turnstile-bank-n",
        T0 + 120,
        ObservationKind::Turnstile {
            ingress_total: 30,
            egress_total: 10,
        },
    );
    let report = engine.reconcile(&lagging).expect("reconcile");
    assert_eq!(report.status, ReconciliationStatus::ObservedHigher);
    assert_eq!((report.tracked, report.observed, report.delta), (7, 20, 13));

    // Adoption needs both an actor and a reason, and a known zone.
    assert!(matches!(
        engine.adopt_observation(&sensor, "", "reason"),
        Err(CapacityError::EmptyAttribution(_))
    ));
    assert!(matches!(
        engine.adopt_observation(&sensor, "guard-lead-7", " "),
        Err(CapacityError::EmptyAttribution(_))
    ));
    let unknown_zone = Observation::new(
        "obs-unknown",
        parsed("zone-nowhere"),
        "sensor-x",
        T0,
        ObservationKind::Occupancy { occupancy: 1 },
    );
    assert!(matches!(
        engine.reconcile(&unknown_zone),
        Err(CapacityError::UnknownZone(_))
    ));
}

// --- concurrent entries and config ------------------------------------

#[test]
fn concurrent_entries_do_not_lose_counts_or_double_count_duplicates() {
    let config = CapacityConfig::new(venue(), CapacityLimit::rejecting(5_000, 6_000).expect("venue"))
        .with_zone(
            zone_north(),
            CapacityLimit::rejecting(5_000, 6_000).expect("zone"),
            [gate_n1()],
        );
    let engine = Arc::new(Mutex::new(
        CapacityEngine::new(config).expect("engine"),
    ));

    let mut handles = Vec::new();
    for worker in 0..8 {
        let engine = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            for index in 0..250 {
                let event = ingress(&format!("evt-{worker}-{index}"), gate_n1());
                let decision = engine.lock().expect("lock").record(&event).expect("record");
                assert!(decision.is_allowed());
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }
    {
        let engine = engine.lock().expect("lock");
        assert_eq!(engine.venue_occupancy(), 2_000);
        assert_eq!(engine.zone_occupancy(&zone_north()), 2_000);
        assert_eq!(engine.gate_occupancy(&gate_n1()), 2_000);
    }

    // Every worker presents the same retried event: exactly one is counted.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let engine = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            engine
                .lock()
                .expect("lock")
                .record(&ingress("evt-duplicate", gate_n1()))
                .expect("record")
                .is_allowed()
        }));
    }
    let admitted = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .filter(|allowed| *allowed)
        .count();
    assert_eq!(admitted, 1, "a duplicate event counts exactly once");
    assert_eq!(engine.lock().expect("lock").venue_occupancy(), 2_001);
}

#[test]
fn envelope_configuration_and_attribution_are_validated() {
    assert_eq!(
        CapacityLimit::rejecting(5, 4),
        Err(CapacityError::InvalidConfig(
            "soft limit must not exceed the hard limit"
        ))
    );

    let duplicated_gate = CapacityConfig::new(venue(), CapacityLimit::rejecting(10, 10).unwrap())
        .with_zone(
            zone_north(),
            CapacityLimit::rejecting(5, 5).unwrap(),
            [gate_n1()],
        )
        .with_zone(
            zone_south(),
            CapacityLimit::rejecting(5, 5).unwrap(),
            [gate_n1()],
        );
    assert!(matches!(
        CapacityEngine::new(duplicated_gate),
        Err(CapacityError::InvalidConfig(
            "a gate belongs to more than one zone"
        ))
    ));

    let stray_gate_limit = CapacityConfig::new(venue(), CapacityLimit::rejecting(10, 10).unwrap())
        .with_zone(
            zone_north(),
            CapacityLimit::rejecting(5, 5).unwrap(),
            [gate_n1()],
        )
        .with_gate_limit(gate_s1(), CapacityLimit::rejecting(1, 1).unwrap());
    assert!(matches!(
        CapacityEngine::new(stray_gate_limit),
        Err(CapacityError::InvalidConfig(
            "a gate limit names a gate in no zone"
        ))
    ));

    let mut engine = engine();
    assert_eq!(
        engine.record(&PresenceEvent::new(
            "evt-wrong-venue",
            Direction::Ingress,
            parsed("venue-2"),
            zone_north(),
            gate_n1(),
            T0,
            EventSource::Manual { operator: "guard-lead-7".to_string() },
        )),
        Err(CapacityError::VenueMismatch {
            expected: venue(),
            presented: parsed("venue-2"),
        })
    );
    assert_eq!(
        engine.record(&PresenceEvent::new(
            "",
            Direction::Ingress,
            venue(),
            zone_north(),
            gate_n1(),
            T0,
            EventSource::Manual { operator: "guard-lead-7".to_string() },
        )),
        Err(CapacityError::EmptyEventId)
    );
    let mut misplaced = event("evt-wrong-gate-zone", Direction::Ingress, gate_s1(), T0);
    misplaced.zone_id = zone_north();
    assert_eq!(
        engine.record(&misplaced),
        Err(CapacityError::GateNotInZone {
            gate_id: gate_s1(),
            zone_id: zone_north(),
        })
    );
    assert!(engine.clone().with_dedupe(0, DAY_US).is_err());
    assert!(engine.clone().with_dedupe(1, 0).is_err());
    assert!(engine.with_dedupe(1, 31 * DAY_US).is_err());
    assert!(CapacityLimit::alarming(0, 1).is_ok());
    assert_eq!(HardPolicy::Reject.code(), "reject");
    assert_eq!(HardPolicy::Alarm.code(), "alarm");
}

#[test]
fn admission_events_are_idempotent_across_retries() {
    let mut engine = engine();
    let admission = Admission {
        ticket_id: TicketId::new("ticket-1").expect("ticket"),
        event_id: EventId::new("event-1").expect("event"),
        venue_id: venue(),
        gate_id: gate_n1(),
        zone_id: zone_north(),
        nonce: 42,
        holder_bound: false,
    };
    let source = EventSource::Turnstile {
        turnstile_id: TurnstileId::new("turnstile-n1-a").expect("turnstile"),
    };

    let first = engine
        .record_admission(&admission, Direction::Ingress, T0, source.clone())
        .expect("record");
    assert!(first.is_allowed());
    let retry = engine
        .record_admission(&admission, Direction::Ingress, T0 + 1_000, source)
        .expect("record");
    assert!(retry.is_duplicate());
    assert_eq!(engine.venue_occupancy(), 1);

    // A new nonce is a new passage.
    let next = Admission { nonce: 43, ..admission.clone() };
    assert!(engine
        .record_admission(
            &next,
            Direction::Ingress,
            T0 + 2_000,
            EventSource::Manual { operator: "guard-lead-7".to_string() },
        )
        .expect("record")
        .is_allowed());
    assert_eq!(engine.venue_occupancy(), 2);

    // Holder-bound admissions are counted the same way; the capacity layer
    // relies on ST-05 having checked the binding.
    let bound = Admission {
        nonce: 44,
        holder_bound: true,
        ..admission
    };
    engine
        .record_admission(
            &bound,
            Direction::Ingress,
            T0 + 3_000,
            EventSource::Manual { operator: "guard-lead-7".to_string() },
        )
        .expect("record");
    assert_eq!(engine.venue_occupancy(), 3);
}

#[test]
fn duplicate_detection_is_bounded_by_retention() {
    let mut engine = engine().with_dedupe(4, HOUR_US).expect("dedupe");
    engine.record(&ingress("evt-1", gate_n1())).expect("record");
    assert!(engine
        .record(&ingress("evt-1", gate_n1()))
        .expect("record")
        .is_duplicate());

    // Past the retention window the id is forgotten, so a replay after hand-off
    // counts again; the store stays bounded and says how much it dropped.
    engine.sweep(T0 + 2 * HOUR_US);
    assert_eq!(engine.venue_occupancy(), 1);
    assert!(engine
        .record(&event("evt-1", Direction::Ingress, gate_n1(), T0 + 2 * HOUR_US))
        .expect("record")
        .is_allowed());
    assert_eq!(engine.venue_occupancy(), 2);
}
