// SPDX-License-Identifier: AGPL-3.0-only

//! ST-01: venue/zone/gate/reader/turnstile hierarchy and versioned topology.

mod common;

use tirbase_venue::{
    AccessPolicyId, EffectiveWindow, Gate, Reader, TopologyRegistry, TopologyVersion, Zone,
};

use common::{parsed, topology, venue, DAY_US, T0};

#[test]
fn hierarchy_links_every_level() {
    let topology = topology();

    assert_eq!(tirbase_venue::topology::zone_ids(&topology).len(), 2);
    assert_eq!(topology.gates().count(), 3);
    assert_eq!(topology.readers().count(), 2);
    assert_eq!(topology.turnstiles().count(), 2);

    let north = parsed("zone-north");
    let gates: Vec<_> = topology
        .gates_in_zone(&north)
        .into_iter()
        .map(|gate| gate.id.as_str().to_string())
        .collect();
    assert_eq!(gates, vec!["gate-n1", "gate-n2"]);

    let n1 = parsed("gate-n1");
    assert_eq!(
        topology.zone_for_gate(&n1).map(|zone| zone.as_str()),
        Some("zone-north")
    );
    assert!(topology.gate_in_zone(&n1, &north));
    assert!(!topology.gate_in_zone(&n1, &parsed("zone-vip")));

    let readers = topology.readers_in_gate(&n1);
    assert_eq!(readers.len(), 1);
    assert_eq!(readers[0].id.as_str(), "reader-n1-a");
    let turnstiles = topology.turnstiles_in_gate(&n1);
    assert_eq!(turnstiles.len(), 1);
    assert_eq!(turnstiles[0].id.as_str(), "turnstile-n1-a");
}

#[test]
fn gate_must_reference_a_zone_in_the_same_venue() {
    let venue = venue();
    let result = TopologyVersion::new(
        parsed("topology-bad"),
        venue.clone(),
        EffectiveWindow::new(T0, None).unwrap(),
        vec![],
        vec![Gate {
            id: parsed("gate-orphan"),
            zone_id: parsed("zone-missing"),
            name: "Orphan".to_string(),
        }],
        vec![Reader {
            id: parsed("reader-orphan"),
            gate_id: parsed("gate-missing"),
            name: "Reader orphan".to_string(),
        }],
        vec![],
    );
    assert!(result.is_err(), "unknown zone gate must be rejected");
}

#[test]
fn zone_from_another_venue_is_rejected() {
    let venue = venue();
    let result = TopologyVersion::new(
        parsed("topology-bad"),
        venue,
        EffectiveWindow::new(T0, None).unwrap(),
        vec![Zone {
            id: parsed("zone-foreign"),
            venue_id: parsed("venue-other"),
            name: "Foreign".to_string(),
        }],
        vec![],
        vec![],
        vec![],
    );
    assert!(result.is_err(), "zone venue mismatch must be rejected");
}

#[test]
fn duplicate_zone_ids_are_rejected() {
    let venue = venue();
    let zone = Zone {
        id: parsed("zone-dup"),
        venue_id: venue.id.clone(),
        name: "Dup".to_string(),
    };
    let result = TopologyVersion::new(
        parsed("topology-dup"),
        venue,
        EffectiveWindow::new(T0, None).unwrap(),
        vec![zone.clone(), zone],
        vec![],
        vec![],
        vec![],
    );
    assert!(result.is_err(), "duplicate zone ids must be rejected");
}

#[test]
fn registry_selects_the_effective_version() {
    let mut registry = TopologyRegistry::new();
    let first = topology();
    registry.insert(first).expect("first version");

    let venue = venue();
    let second_start = T0 + 60 * DAY_US;
    let second = TopologyVersion::new(
        parsed("topology-2"),
        venue.clone(),
        EffectiveWindow::new(second_start, None).unwrap(),
        vec![Zone {
            id: parsed("zone-south"),
            venue_id: venue.id.clone(),
            name: "South stand".to_string(),
        }],
        vec![],
        vec![],
        vec![],
    )
    .expect("second version");
    registry.insert(second).expect("second version");

    let at_first = registry
        .effective_for(&venue.id, T0)
        .expect("version in force");
    assert_eq!(at_first.id.as_str(), "topology-1");
    let at_second = registry
        .effective_for(&venue.id, second_start)
        .expect("version in force");
    assert_eq!(at_second.id.as_str(), "topology-2");

    assert_eq!(registry.versions_for_venue(&venue.id).len(), 2);
    assert!(registry.get(&parsed("topology-1")).is_some());
}

#[test]
fn overlapping_versions_for_one_venue_are_rejected() {
    let mut registry = TopologyRegistry::new();
    registry.insert(topology()).expect("first version");

    let overlapping = TopologyVersion::new(
        parsed("topology-overlap"),
        venue(),
        EffectiveWindow::new(T0 + 10 * DAY_US, None).unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .expect("valid window");
    assert!(registry.insert(overlapping).is_err());
}

#[test]
fn effective_window_end_is_exclusive() {
    let window = EffectiveWindow::new(T0, Some(T0 + 1000)).unwrap();
    assert!(window.contains(T0));
    assert!(window.contains(T0 + 999));
    assert!(!window.contains(T0 + 1000));
    assert!(!window.contains(T0 - 1));
}

#[test]
fn topology_round_trips_through_json() {
    let topology = topology();
    let json = serde_json::to_string(&topology).expect("serialize");
    let restored: TopologyVersion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, topology);
}

#[test]
fn policy_ids_are_validated() {
    assert!(AccessPolicyId::new("").is_err());
    assert!(AccessPolicyId::new("bad\nid").is_err());
}
