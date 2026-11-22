// SPDX-License-Identifier: AGPL-3.0-only

//! ST-01: deterministic capacity attribution per zone and gate.

mod common;

use tirbase_venue::{
    CapacityAttribution, EffectiveWindow, Gate, Section, SectionKind, SpaceModel, TopologyVersion,
    VenueError, Zone,
};

use common::{
    fixture, parsed, seats, sections, space_from_parts, standing_areas, ticket_types, topology,
    venue, T0,
};

#[test]
fn zone_capacity_is_seats_plus_standing_areas() {
    let fixture = fixture();
    let attribution =
        CapacityAttribution::compute(&fixture.topology, &fixture.space).expect("attribution");

    let north = attribution.zone(&parsed("zone-north")).expect("north zone");
    assert_eq!(north.seated, 2);
    assert_eq!(north.standing, 100);
    assert_eq!(north.total, 102);

    let vip = attribution.zone(&parsed("zone-vip")).expect("vip zone");
    assert_eq!(vip.seated, 1);
    assert_eq!(vip.standing, 0);
    assert_eq!(vip.total, 1);

    assert_eq!(attribution.total(), 103);
    assert!(attribution.zone(&parsed("zone-missing")).is_none());
}

#[test]
fn gate_contributions_sum_to_zone_capacity() {
    let fixture = fixture();
    let attribution =
        CapacityAttribution::compute(&fixture.topology, &fixture.space).expect("attribution");

    assert_eq!(
        attribution
            .gate(&parsed("gate-n1"))
            .expect("north 1")
            .capacity,
        51
    );
    assert_eq!(
        attribution
            .gate(&parsed("gate-n2"))
            .expect("north 2")
            .capacity,
        51
    );
    assert_eq!(
        attribution.gate(&parsed("gate-v1")).expect("vip").capacity,
        1
    );

    for zone in attribution.zones() {
        assert_eq!(
            attribution.gate_total_for_zone(&zone.zone_id),
            zone.total,
            "gate shares must equal zone total for {}",
            zone.zone_id
        );
    }

    let gate_total: u32 = attribution.gates().map(|gate| gate.capacity).sum();
    assert_eq!(gate_total, attribution.total());
}

#[test]
fn attribution_is_independent_of_insertion_order() {
    let mut reversed_sections = sections();
    reversed_sections.reverse();
    let mut reversed_seats = seats();
    reversed_seats.reverse();
    let mut reversed_standing = standing_areas();
    reversed_standing.reverse();
    let mut reversed_types = ticket_types();
    reversed_types.reverse();

    let forward = space_from_parts(sections(), seats(), standing_areas(), ticket_types());
    let reversed = space_from_parts(
        reversed_sections,
        reversed_seats,
        reversed_standing,
        reversed_types,
    );

    let topology = topology();
    let a = CapacityAttribution::compute(&topology, &forward).expect("forward attribution");
    let b = CapacityAttribution::compute(&topology, &reversed).expect("reversed attribution");
    assert_eq!(a, b);

    // Recomputing from the same inputs yields byte-identical contributions.
    let c = CapacityAttribution::compute(&topology, &forward).expect("repeat attribution");
    assert_eq!(a, c);
}

#[test]
fn remainder_seats_go_to_the_first_gates_in_id_order() {
    let venue = venue();
    let topology = TopologyVersion::new(
        parsed("topology-remainder"),
        venue.clone(),
        EffectiveWindow::new(T0, None).unwrap(),
        vec![Zone {
            id: parsed("zone-odd"),
            venue_id: venue.id.clone(),
            name: "Odd".to_string(),
        }],
        vec![
            Gate {
                id: parsed("gate-b"),
                zone_id: parsed("zone-odd"),
                name: "B".to_string(),
            },
            Gate {
                id: parsed("gate-a"),
                zone_id: parsed("zone-odd"),
                name: "A".to_string(),
            },
        ],
        vec![],
        vec![],
    )
    .unwrap();

    let mut space = SpaceModel::new();
    space
        .add_section(Section {
            id: parsed("section-odd"),
            zone_id: parsed("zone-odd"),
            name: "Odd".to_string(),
            kind: SectionKind::Mixed,
        })
        .unwrap();
    space
        .add_standing_area(tirbase_venue::StandingArea {
            id: parsed("standing-odd"),
            zone_id: parsed("zone-odd"),
            name: "Odd terrace".to_string(),
            capacity: 3,
        })
        .unwrap();

    let attribution = CapacityAttribution::compute(&topology, &space).unwrap();
    assert_eq!(attribution.zone(&parsed("zone-odd")).unwrap().total, 3);
    assert_eq!(attribution.gate(&parsed("gate-a")).unwrap().capacity, 2);
    assert_eq!(attribution.gate(&parsed("gate-b")).unwrap().capacity, 1);
}

#[test]
fn zone_with_capacity_but_no_gate_is_rejected() {
    let venue = venue();
    let topology = TopologyVersion::new(
        parsed("topology-gateless"),
        venue.clone(),
        EffectiveWindow::new(T0, None).unwrap(),
        vec![Zone {
            id: parsed("zone-enclosed"),
            venue_id: venue.id.clone(),
            name: "Enclosed".to_string(),
        }],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();

    let mut space = SpaceModel::new();
    space
        .add_standing_area(tirbase_venue::StandingArea {
            id: parsed("standing-enclosed"),
            zone_id: parsed("zone-enclosed"),
            name: "Enclosed terrace".to_string(),
            capacity: 10,
        })
        .unwrap();

    let error = CapacityAttribution::compute(&topology, &space)
        .expect_err("capacity cannot be attributed without a gate");
    assert!(matches!(error, VenueError::InvalidCapacity(_)));
}

#[test]
fn space_referencing_unknown_zone_is_rejected() {
    let topology = topology();
    let mut space = SpaceModel::new();
    space
        .add_section(Section {
            id: parsed("section-orphan"),
            zone_id: parsed("zone-orphan"),
            name: "Orphan".to_string(),
            kind: SectionKind::Seated,
        })
        .unwrap();

    let error = CapacityAttribution::compute(&topology, &space)
        .expect_err("section zone is not in the topology");
    assert!(matches!(error, VenueError::UnknownZone(_)));
}

#[test]
fn empty_topology_attributes_no_capacity() {
    let venue = venue();
    let topology = TopologyVersion::new(
        parsed("topology-empty"),
        venue,
        EffectiveWindow::new(T0, None).unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let attribution = CapacityAttribution::compute(&topology, &SpaceModel::new()).unwrap();
    assert_eq!(attribution.total(), 0);
    assert_eq!(attribution.zones().count(), 0);
    assert_eq!(attribution.gates().count(), 0);
}
