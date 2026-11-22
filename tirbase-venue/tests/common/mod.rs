// SPDX-License-Identifier: AGPL-3.0-only

//! Shared ST-01 fixtures.

#![allow(dead_code)]

use std::str::FromStr;

use tirbase_venue::{
    AccessPolicy, AccessPolicyId, AccessPolicyRegistry, EffectiveWindow, Gate, GateId, Reader,
    Seat, Section, SectionKind, SpaceModel, StandingArea, TicketClass, TicketType, TimeWindow,
    TopologyVersion, Turnstile, Venue, Zone, ZoneId,
};

/// Base event timestamp, UTC microseconds.
pub const T0: i64 = 1_700_000_000_000_000;
/// One hour in UTC microseconds.
pub const HOUR_US: i64 = 3_600_000_000;
/// One day in UTC microseconds.
pub const DAY_US: i64 = 86_400_000_000;

pub fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("fixture identifier parses")
}

pub fn venue() -> Venue {
    Venue {
        id: parsed("venue-1"),
        name: "Grand Hall".to_string(),
    }
}

pub fn topology() -> TopologyVersion {
    let venue = venue();
    let zones = vec![
        Zone {
            id: parsed("zone-north"),
            venue_id: venue.id.clone(),
            name: "North stand".to_string(),
        },
        Zone {
            id: parsed("zone-vip"),
            venue_id: venue.id.clone(),
            name: "VIP lounge".to_string(),
        },
    ];
    let gates = vec![
        Gate {
            id: parsed("gate-n1"),
            zone_id: parsed("zone-north"),
            name: "North 1".to_string(),
        },
        Gate {
            id: parsed("gate-n2"),
            zone_id: parsed("zone-north"),
            name: "North 2".to_string(),
        },
        Gate {
            id: parsed("gate-v1"),
            zone_id: parsed("zone-vip"),
            name: "VIP".to_string(),
        },
    ];
    let readers = vec![
        Reader {
            id: parsed("reader-n1-a"),
            gate_id: parsed("gate-n1"),
            name: "Reader N1 A".to_string(),
        },
        Reader {
            id: parsed("reader-v1-a"),
            gate_id: parsed("gate-v1"),
            name: "Reader V1 A".to_string(),
        },
    ];
    let turnstiles = vec![
        Turnstile {
            id: parsed("turnstile-n1-a"),
            gate_id: parsed("gate-n1"),
            name: "Turnstile N1 A".to_string(),
        },
        Turnstile {
            id: parsed("turnstile-v1-a"),
            gate_id: parsed("gate-v1"),
            name: "Turnstile V1 A".to_string(),
        },
    ];

    TopologyVersion::new(
        parsed("topology-1"),
        venue,
        EffectiveWindow::new(T0 - 30 * DAY_US, Some(T0 + 60 * DAY_US)).expect("window"),
        zones,
        gates,
        readers,
        turnstiles,
    )
    .expect("fixture topology is valid")
}

pub fn sections() -> Vec<Section> {
    vec![
        Section {
            id: parsed("section-north-a"),
            zone_id: parsed("zone-north"),
            name: "North A".to_string(),
            kind: SectionKind::Seated,
        },
        Section {
            id: parsed("section-vip"),
            zone_id: parsed("zone-vip"),
            name: "VIP".to_string(),
            kind: SectionKind::Seated,
        },
    ]
}

pub fn seats() -> Vec<Seat> {
    vec![
        Seat {
            id: parsed("seat-n1"),
            section_id: parsed("section-north-a"),
            label: "A1".to_string(),
        },
        Seat {
            id: parsed("seat-n2"),
            section_id: parsed("section-north-a"),
            label: "A2".to_string(),
        },
        Seat {
            id: parsed("seat-v1"),
            section_id: parsed("section-vip"),
            label: "V1".to_string(),
        },
    ]
}

pub fn standing_areas() -> Vec<StandingArea> {
    vec![StandingArea {
        id: parsed("standing-north"),
        zone_id: parsed("zone-north"),
        name: "North terrace".to_string(),
        capacity: 100,
    }]
}

pub fn ticket_types() -> Vec<TicketType> {
    vec![
        TicketType {
            id: parsed("tt-general"),
            name: "General".to_string(),
            class: TicketClass::General,
            section_id: Some(parsed("section-north-a")),
            standing_area_id: None,
        },
        TicketType {
            id: parsed("tt-vip"),
            name: "VIP".to_string(),
            class: TicketClass::Vip,
            section_id: Some(parsed("section-vip")),
            standing_area_id: None,
        },
        TicketType {
            id: parsed("tt-staff"),
            name: "Staff".to_string(),
            class: TicketClass::Staff,
            section_id: None,
            standing_area_id: None,
        },
        TicketType {
            id: parsed("tt-ada"),
            name: "Accessible".to_string(),
            class: TicketClass::Ada,
            section_id: Some(parsed("section-north-a")),
            standing_area_id: None,
        },
    ]
}

pub fn space_from_parts(
    sections: Vec<Section>,
    seats: Vec<Seat>,
    standing_areas: Vec<StandingArea>,
    ticket_types: Vec<TicketType>,
) -> SpaceModel {
    let mut model = SpaceModel::new();
    for section in sections {
        model.add_section(section).expect("section");
    }
    for seat in seats {
        model.add_seat(seat).expect("seat");
    }
    for area in standing_areas {
        model.add_standing_area(area).expect("standing area");
    }
    for ticket_type in ticket_types {
        model.add_ticket_type(ticket_type).expect("ticket type");
    }
    model
}

pub fn space() -> SpaceModel {
    space_from_parts(sections(), seats(), standing_areas(), ticket_types())
}

fn policy(
    id: &str,
    name: &str,
    selector: tirbase_venue::TicketSelector,
    gate: &str,
    zone: &str,
    from_utc_us: i64,
    until_utc_us: i64,
) -> AccessPolicy {
    AccessPolicy {
        id: AccessPolicyId::new(id).expect("policy id"),
        name: name.to_string(),
        selector,
        gate_id: GateId::new(gate).expect("gate id"),
        zone_id: ZoneId::new(zone).expect("zone id"),
        time_window: TimeWindow::new(from_utc_us, until_utc_us).expect("time window"),
        enabled: true,
    }
}

/// Policies granting one deterministic route per ticket class/gate.
pub fn policies() -> AccessPolicyRegistry {
    let mut registry = AccessPolicyRegistry::new();
    let window = (T0, T0 + 8 * HOUR_US);
    for (id, gate) in [
        ("policy-general-n1", "gate-n1"),
        ("policy-general-n2", "gate-n2"),
    ] {
        registry
            .add_policy(policy(
                id,
                "General entry",
                tirbase_venue::TicketSelector::TicketType(parsed("tt-general")),
                gate,
                "zone-north",
                window.0,
                window.1,
            ))
            .expect("policy");
    }
    registry
        .add_policy(policy(
            "policy-vip",
            "VIP entry",
            tirbase_venue::TicketSelector::TicketClass(TicketClass::Vip),
            "gate-v1",
            "zone-vip",
            window.0,
            window.1,
        ))
        .expect("policy");
    registry
        .add_policy(policy(
            "policy-staff",
            "Staff early entry",
            tirbase_venue::TicketSelector::TicketClass(TicketClass::Staff),
            "gate-n1",
            "zone-north",
            T0,
            T0 + 2 * HOUR_US,
        ))
        .expect("policy");
    registry
        .add_policy(policy(
            "policy-ada",
            "Accessible entry",
            tirbase_venue::TicketSelector::TicketClass(TicketClass::Ada),
            "gate-n1",
            "zone-north",
            window.0,
            window.1,
        ))
        .expect("policy");
    registry
}

pub struct Fixture {
    pub topology: TopologyVersion,
    pub space: SpaceModel,
    pub policies: AccessPolicyRegistry,
}

pub fn fixture() -> Fixture {
    Fixture {
        topology: topology(),
        space: space(),
        policies: policies(),
    }
}

/// Convenience for building a scan record.
pub fn scan(
    ticket: &str,
    gate: &str,
    zone: &str,
    direction: tirbase_venue::ScanDirection,
    ts_utc_us: i64,
) -> tirbase_venue::ScanRecord {
    tirbase_venue::ScanRecord {
        ticket_id: parsed(ticket),
        gate_id: parsed(gate),
        zone_id: parsed(zone),
        direction,
        ts_utc_us,
    }
}
