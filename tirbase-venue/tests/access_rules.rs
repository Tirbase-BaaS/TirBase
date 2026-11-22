// SPDX-License-Identifier: AGPL-3.0-only

//! ST-01: access rules resolve a ticket to exactly one gate/zone policy.

mod common;

use tirbase_venue::{
    AccessDecision, AccessPolicy, AccessPolicyId, GateId, Ticket, TicketClass, TicketSelector,
    TimeWindow, VenueError, ZoneId,
};

use common::{fixture, parsed, HOUR_US, T0};

fn ticket(id: &str, ticket_type: &str) -> Ticket {
    Ticket::new(parsed(id), parsed(ticket_type))
}

#[test]
fn general_ticket_resolves_to_one_policy_at_its_gate() {
    let fixture = fixture();
    let ticket = ticket("ticket-1", "tt-general");

    let decision = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket,
            &parsed("gate-n1"),
            T0,
        )
        .expect("general ticket enters at North 1");
    assert_eq!(
        decision,
        AccessDecision {
            ticket_id: parsed("ticket-1"),
            gate_id: parsed("gate-n1"),
            zone_id: parsed("zone-north"),
            policy_id: parsed("policy-general-n1"),
        }
    );

    let other_gate = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket,
            &parsed("gate-n2"),
            T0,
        )
        .expect("general ticket enters at North 2");
    assert_eq!(other_gate.policy_id.as_str(), "policy-general-n2");
    assert_eq!(other_gate.zone_id.as_str(), "zone-north");
}

#[test]
fn general_ticket_is_denied_at_the_vip_gate() {
    let fixture = fixture();
    let ticket = ticket("ticket-1", "tt-general");
    let error = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket,
            &parsed("gate-v1"),
            T0,
        )
        .expect_err("general ticket cannot use the VIP gate");
    assert!(matches!(error, VenueError::AccessDenied(_)));
}

#[test]
fn vip_staff_and_ada_classes_are_selected_by_class_rules() {
    let fixture = fixture();

    let vip = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-vip", "tt-vip"),
            &parsed("gate-v1"),
            T0,
        )
        .expect("VIP entry");
    assert_eq!(vip.policy_id.as_str(), "policy-vip");
    assert_eq!(vip.zone_id.as_str(), "zone-vip");

    let staff = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-staff", "tt-staff"),
            &parsed("gate-n1"),
            T0 + HOUR_US,
        )
        .expect("staff entry inside its window");
    assert_eq!(staff.policy_id.as_str(), "policy-staff");

    let ada = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-ada", "tt-ada"),
            &parsed("gate-n1"),
            T0,
        )
        .expect("accessible entry");
    assert_eq!(ada.policy_id.as_str(), "policy-ada");
}

#[test]
fn staff_rule_is_limited_by_time_window_and_gate() {
    let fixture = fixture();
    let staff = ticket("ticket-staff", "tt-staff");

    let late = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &staff,
            &parsed("gate-n1"),
            T0 + 3 * HOUR_US,
        )
        .expect_err("staff window closed");
    assert!(matches!(late, VenueError::AccessDenied(_)));

    let wrong_gate = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &staff,
            &parsed("gate-n2"),
            T0,
        )
        .expect_err("staff rule only covers North 1");
    assert!(matches!(wrong_gate, VenueError::AccessDenied(_)));
}

#[test]
fn time_window_boundaries_are_inclusive_start_exclusive_end() {
    let fixture = fixture();
    let staff = ticket("ticket-staff", "tt-staff");

    assert!(fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &staff,
            &parsed("gate-n1"),
            T0
        )
        .is_ok());
    assert!(fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &staff,
            &parsed("gate-n1"),
            T0 + 2 * HOUR_US,
        )
        .is_err());
}

#[test]
fn unknown_gate_and_unknown_ticket_type_are_reported() {
    let fixture = fixture();

    let unknown_gate = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-1", "tt-general"),
            &parsed("gate-missing"),
            T0,
        )
        .expect_err("unknown gate");
    assert!(matches!(unknown_gate, VenueError::UnknownGate(_)));

    let unknown_type = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-1", "tt-missing"),
            &parsed("gate-n1"),
            T0,
        )
        .expect_err("unknown ticket type");
    assert!(matches!(unknown_type, VenueError::UnknownTicketType(_)));
}

#[test]
fn overlapping_policies_are_rejected_as_ambiguous() {
    let mut fixture = fixture();
    fixture
        .policies
        .add_policy(AccessPolicy {
            id: AccessPolicyId::new("policy-general-duplicate").unwrap(),
            name: "Duplicate general rule".to_string(),
            selector: TicketSelector::TicketClass(TicketClass::General),
            gate_id: GateId::new("gate-n1").unwrap(),
            zone_id: ZoneId::new("zone-north").unwrap(),
            time_window: TimeWindow::new(T0, T0 + 8 * HOUR_US).unwrap(),
            enabled: true,
        })
        .unwrap();

    let error = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-1", "tt-general"),
            &parsed("gate-n1"),
            T0 + HOUR_US,
        )
        .expect_err("two matching policies must be ambiguous");
    match error {
        VenueError::AmbiguousPolicy { policy_ids, .. } => {
            assert_eq!(
                policy_ids.iter().map(|id| id.as_str()).collect::<Vec<_>>(),
                vec!["policy-general-duplicate", "policy-general-n1"]
            );
        }
        other => panic!("expected AmbiguousPolicy, got {other:?}"),
    }
}

#[test]
fn disabled_policy_never_matches() {
    let mut fixture = fixture();
    let mut policy = fixture
        .policies
        .get(&parsed("policy-general-n1"))
        .expect("policy exists")
        .clone();
    policy.id = AccessPolicyId::new("policy-general-n1-disabled").unwrap();
    policy.enabled = false;
    fixture.policies.add_policy(policy).unwrap();

    // The original enabled policy still resolves; the added one is inert.
    let decision = fixture
        .policies
        .resolve_in_space(
            &fixture.topology,
            &fixture.space,
            &ticket("ticket-1", "tt-general"),
            &parsed("gate-n1"),
            T0,
        )
        .expect("enabled policy still matches");
    assert_eq!(decision.policy_id.as_str(), "policy-general-n1");
}

#[test]
fn explicit_zone_must_match_the_gate_zone() {
    let fixture = fixture();
    let error = fixture
        .policies
        .resolve_for_zone(
            &fixture.topology,
            fixture.space.ticket_types_map(),
            &ticket("ticket-1", "tt-general"),
            &parsed("gate-n1"),
            &parsed("zone-vip"),
            T0,
        )
        .expect_err("gate is not in the VIP zone");
    assert!(matches!(error, VenueError::HierarchyMismatch(_)));
}
