// SPDX-License-Identifier: AGPL-3.0-only

//! ST-11 command-center acceptance tests.

use tirbase_venue_command_center::{CommandCenter, IncidentActionKind, LockCommand, Mode, Role};

const T0: i64 = 1_700_000_000_000_000;
const APPROVERS: [&str; 2] = ["custodian-1", "custodian-2"];

fn center() -> CommandCenter {
    CommandCenter::new(T0).expect("command center builds")
}

fn approvers() -> Vec<String> {
    APPROVERS.iter().map(|value| (*value).to_string()).collect()
}

#[test]
fn lockdown_is_initiated_and_released_with_the_configured_approvals() {
    let mut center = center();
    let live_before = center.snapshot("ops-1", Role::Operator, T0);
    assert!(live_before
        .venue
        .zones
        .iter()
        .flat_map(|zone| zone.gates.iter())
        .all(|gate| gate.posture == "normal"));
    assert!(live_before.active_lockdowns.is_empty());

    let outcome = center
        .lockdown(
            "sup-1",
            Role::Supervisor,
            LockCommand::Lockdown,
            "venue",
            "Smoke reported in the north service corridor",
            &approvers(),
            T0 + 1_000_000,
        )
        .expect("two approvals engage the lockdown");
    assert_eq!(outcome.status, "executed");
    assert_eq!(outcome.mode, Mode::Live);

    let locked = center.snapshot("sup-1", Role::Supervisor, T0 + 1_000_000);
    assert_eq!(locked.active_lockdowns.len(), 1);
    assert_eq!(locked.active_lockdowns[0].requested_by, "sup-1");
    assert_eq!(locked.active_lockdowns[0].approvers, approvers());
    assert!(locked
        .venue
        .zones
        .iter()
        .flat_map(|zone| zone.gates.iter())
        .all(|gate| gate.posture == "locked" && !gate.ingress_allowed && gate.egress_allowed));
    let audit = locked
        .audit
        .iter()
        .find(|entry| entry.action == "lockdown.engaged")
        .expect("lockdown audit row");
    assert_eq!(audit.actor, "sup-1");
    assert_eq!(audit.role, Role::Supervisor);

    let released = center
        .lockdown(
            "sup-1",
            Role::Supervisor,
            LockCommand::Release,
            "venue",
            "Fire service declared the venue safe",
            &approvers(),
            T0 + 2_000_000,
        )
        .expect("release with approvals");
    assert_eq!(released.status, "executed");
    let live_after = center.snapshot("sup-1", Role::Supervisor, T0 + 2_000_000);
    assert!(live_after.active_lockdowns.is_empty());
    assert!(live_after
        .venue
        .zones
        .iter()
        .flat_map(|zone| zone.gates.iter())
        .all(|gate| gate.posture == "normal" && gate.ingress_allowed));
    assert!(live_after
        .audit
        .iter()
        .any(|entry| entry.action == "lockdown.released" && entry.actor == "sup-1"));
}

#[test]
fn a_single_approval_or_self_approval_is_refused_without_mutating_gate_state() {
    let mut center = center();
    let error = center
        .lockdown(
            "sup-1",
            Role::Supervisor,
            LockCommand::Lockdown,
            "venue",
            "Test",
            &["custodian-1".to_string()],
            T0 + 1_000_000,
        )
        .expect_err("one approval is not enough");
    assert_eq!(error.code, "insufficient_approvals");

    let error = center
        .lockdown(
            "custodian-1",
            Role::Supervisor,
            LockCommand::Lockdown,
            "venue",
            "Test",
            &["custodian-1".to_string(), "custodian-2".to_string()],
            T0 + 1_000_000,
        )
        .expect_err("requester cannot approve their own command");
    assert_eq!(error.code, "self_approval");

    let snapshot = center.snapshot("sup-1", Role::Supervisor, T0 + 1_000_000);
    assert!(snapshot.active_lockdowns.is_empty());
    assert!(snapshot
        .venue
        .zones
        .iter()
        .flat_map(|zone| zone.gates.iter())
        .all(|gate| gate.posture == "normal"));
}

#[test]
fn every_incident_action_is_attributable_and_transitions_in_order() {
    let mut center = center();
    let acknowledged = center
        .incident_action(
            "ops-2",
            Role::Operator,
            "inc-1",
            IncidentActionKind::Acknowledge,
            Some("On it"),
            T0 + 1_000_000,
        )
        .expect("operator acknowledges");
    assert_eq!(
        acknowledged.status,
        tirbase_venue_command_center::IncidentStatus::Acknowledged
    );
    assert_eq!(acknowledged.actions.last().unwrap().actor, "ops-2");
    assert_eq!(acknowledged.actions.last().unwrap().role, Role::Operator);

    let dispatched = center
        .incident_action(
            "ops-2",
            Role::Operator,
            "inc-1",
            IncidentActionKind::Dispatch,
            Some("North response team, two stewards"),
            T0 + 2_000_000,
        )
        .expect("operator dispatches");
    assert_eq!(
        dispatched.status,
        tirbase_venue_command_center::IncidentStatus::Dispatched
    );

    let escalated = center
        .incident_action(
            "sup-1",
            Role::Supervisor,
            "inc-1",
            IncidentActionKind::Escalate,
            Some("Crowd pressure rising; requesting police support"),
            T0 + 3_000_000,
        )
        .expect("supervisor escalates");
    assert_eq!(
        escalated.status,
        tirbase_venue_command_center::IncidentStatus::Escalated
    );

    let resolved = center
        .incident_action(
            "safety-1",
            Role::SafetyOfficer,
            "inc-1",
            IncidentActionKind::Resolve,
            Some("Crowd redistributed to south concourse"),
            T0 + 4_000_000,
        )
        .expect("safety officer resolves");
    assert_eq!(
        resolved.status,
        tirbase_venue_command_center::IncidentStatus::Resolved
    );

    center
        .incident_action(
            "safety-1",
            Role::SafetyOfficer,
            "inc-1",
            IncidentActionKind::Report,
            None,
            T0 + 5_000_000,
        )
        .expect("safety officer reports");

    let snapshot = center.snapshot("auditor-1", Role::Auditor, T0 + 5_000_000);
    let incident = snapshot
        .incidents
        .iter()
        .find(|incident| incident.id == "inc-1")
        .expect("incident exists");
    assert_eq!(incident.actions.len(), 5);
    assert!(incident
        .actions
        .iter()
        .all(|action| !action.actor.is_empty() && action.action_id.starts_with("act-")));
    assert!(snapshot
        .audit
        .iter()
        .filter(|entry| entry.subject == "inc-1")
        .all(|entry| entry.actor == "ops-2"
            || entry.actor == "sup-1"
            || entry.actor == "safety-1"));
    let report = snapshot
        .after_action_reports
        .iter()
        .find(|report| report.incident_id.as_deref() == Some("inc-1"))
        .expect("incident after-action report");
    assert_eq!(report.generated_by, "safety-1");
    assert!(report.participants.contains(&"ops-2".to_string()));
}

#[test]
fn role_permissions_are_enforced() {
    let mut center = center();
    assert_eq!(
        center
            .incident_action(
                "auditor-1",
                Role::Auditor,
                "inc-1",
                IncidentActionKind::Acknowledge,
                None,
                T0 + 1_000_000,
            )
            .expect_err("auditor is read-only")
            .code,
        "forbidden"
    );
    assert_eq!(
        center
            .incident_action(
                "ops-1",
                Role::Operator,
                "inc-1",
                IncidentActionKind::Resolve,
                Some("done"),
                T0 + 1_000_000,
            )
            .expect_err("operator cannot resolve")
            .code,
        "forbidden"
    );
    assert_eq!(
        center
            .lockdown(
                "ops-1",
                Role::Operator,
                LockCommand::Lockdown,
                "venue",
                "Test",
                &approvers(),
                T0 + 1_000_000,
            )
            .expect_err("operator cannot lock down")
            .code,
        "forbidden"
    );
    assert_eq!(
        center
            .start_drill("auditor-1", Role::Auditor, T0 + 1_000_000)
            .expect_err("auditor cannot drill")
            .code,
        "forbidden"
    );
    let snapshot = center.snapshot("auditor-1", Role::Auditor, T0 + 1_000_000);
    assert!(snapshot.capabilities.contains(&"audit.view".to_string()));
    assert!(!snapshot
        .capabilities
        .contains(&"lockdown.request".to_string()));
    assert!(snapshot
        .roles
        .iter()
        .find(|view| view.role == Role::Operator)
        .unwrap()
        .capabilities
        .contains(&"incident.acknowledge".to_string()));
}

#[test]
fn drill_mode_cannot_affect_live_gate_state() {
    let mut center = center();
    let before = center.live_fingerprint(T0 + 1_000_000);

    let drill = center
        .start_drill("safety-1", Role::SafetyOfficer, T0 + 1_000_000)
        .expect("safety officer starts drill");
    assert_eq!(drill.mode, Mode::Drill);

    center
        .lockdown(
            "safety-1",
            Role::SafetyOfficer,
            LockCommand::Lockdown,
            "venue",
            "Drill: simulated smoke event",
            &approvers(),
            T0 + 2_000_000,
        )
        .expect("drill lockdown uses drill approvals");
    center
        .incident_action(
            "ops-1",
            Role::Operator,
            "inc-1",
            IncidentActionKind::Acknowledge,
            Some("Drill acknowledgement"),
            T0 + 2_000_000,
        )
        .expect("drill incident action");

    let during = center.snapshot("safety-1", Role::SafetyOfficer, T0 + 2_000_000);
    assert_eq!(during.mode, Mode::Drill);
    assert!(during
        .active_lockdowns
        .iter()
        .any(|lock| lock.scope == "venue:venue-1"));
    assert!(during
        .venue
        .zones
        .iter()
        .flat_map(|zone| zone.gates.iter())
        .all(|gate| gate.posture == "locked"));

    // The live state is untouched while the drill runs.
    assert_eq!(before, center.live_fingerprint(T0 + 2_000_000));

    let report = center
        .end_drill("safety-1", Role::SafetyOfficer, T0 + 3_000_000)
        .expect("drill ends");
    assert!(report.drill);
    assert!(report.live_gate_state_unchanged);
    assert!(report.summary.contains("unchanged"));
    assert_eq!(before, center.live_fingerprint(T0 + 3_000_000));

    let after = center.snapshot("safety-1", Role::SafetyOfficer, T0 + 3_000_000);
    assert_eq!(after.mode, Mode::Live);
    assert!(after.active_lockdowns.is_empty());
    assert!(after
        .venue
        .zones
        .iter()
        .flat_map(|zone| zone.gates.iter())
        .all(|gate| gate.posture == "normal"));
    assert!(after
        .after_action_reports
        .iter()
        .any(|report| report.drill && report.live_gate_state_unchanged));
    assert!(after
        .audit
        .iter()
        .any(|entry| entry.action == "drill.report" && entry.actor == "safety-1"));
}

#[test]
fn drill_can_run_after_an_incident_report_and_live_lockdown_stays_live() {
    let mut center = center();
    center
        .lockdown(
            "sup-1",
            Role::Supervisor,
            LockCommand::Lockdown,
            "zone:zone-south",
            "Live south closure for a gas smell",
            &approvers(),
            T0 + 1_000_000,
        )
        .expect("live zone lockdown");

    center
        .start_drill("sup-1", Role::Supervisor, T0 + 2_000_000)
        .expect("drill starts");
    let drill = center.snapshot("sup-1", Role::Supervisor, T0 + 2_000_000);
    assert_eq!(drill.mode, Mode::Drill);
    assert!(
        drill.active_lockdowns.is_empty(),
        "drill starts without live locks"
    );
    center
        .end_drill("sup-1", Role::Supervisor, T0 + 3_000_000)
        .expect("drill ends");

    let live = center.snapshot("sup-1", Role::Supervisor, T0 + 3_000_000);
    assert_eq!(live.active_lockdowns.len(), 1);
    assert_eq!(live.active_lockdowns[0].scope, "zone:zone-south");
}
