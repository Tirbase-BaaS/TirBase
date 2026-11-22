// SPDX-License-Identifier: AGPL-3.0-only

//! ST-08 acceptance tests: M-of-N lockdown approval, release with fresh
//! approvals, fail-safe posture and break-glass, capacity overrides, expiry,
//! attribution/audit and concurrent commands.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tirbase_venue::{GateId, VenueId, ZoneId};
use tirbase_venue_capacity::{CapacityConfig, CapacityLimit, LimitScope};
use tirbase_venue_lockdown::{
    ApprovalPolicy, CommandAction, CommandRequest, LockScope, LockdownEngine, LockdownError,
    SecurityEventKind, SignedCommand,
};
use tirbase_venue_ticket::{Ed25519Signer, IssuerKey, IssuerKeyRing, IssuerKeyState, TicketSigner};

const T0: i64 = 1_700_000_000_000_000;
const HOUR_US: i64 = 3_600_000_000;

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

fn venue_scope() -> LockScope {
    LockScope::Venue { venue_id: venue() }
}

fn zone_scope(zone_id: &str) -> LockScope {
    LockScope::Zone {
        zone_id: parsed(zone_id),
    }
}

fn config() -> CapacityConfig {
    CapacityConfig::new(venue(), CapacityLimit::rejecting(10_000, 10_000).expect("venue"))
        .with_zone(
            zone_north(),
            CapacityLimit::rejecting(10_000, 10_000).expect("zone"),
            [gate_n1(), gate_n2()],
        )
        .with_zone(
            zone_south(),
            CapacityLimit::rejecting(10_000, 10_000).expect("zone"),
            [gate_s1()],
        )
}

fn many_gate_config() -> CapacityConfig {
    let gates: Vec<GateId> = (1..=8)
        .map(|index| parsed(&format!("gate-n{index}")))
        .collect();
    CapacityConfig::new(venue(), CapacityLimit::rejecting(10_000, 10_000).expect("venue"))
        .with_zone(
            zone_north(),
            CapacityLimit::rejecting(10_000, 10_000).expect("zone"),
            gates,
        )
}

fn custodian(index: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(
        format!("custodian-{index}"),
        [30u8.wrapping_add(index); 32],
    )
}

fn approval_ring() -> IssuerKeyRing {
    let signers: [&dyn TicketSigner; 3] = [&custodian(1), &custodian(2), &custodian(3)];
    let mut ring = IssuerKeyRing::new();
    for (index, signer) in signers.iter().enumerate() {
        ring.add_key(IssuerKey {
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key(),
            not_before_utc_us: T0 - 86_400_000_000,
            not_after_utc_us: T0 + 365 * 86_400_000_000,
            state: if index == 0 {
                IssuerKeyState::Active
            } else {
                IssuerKeyState::Retiring
            },
        })
        .expect("approval key");
    }
    ring
}

fn request(
    request_id: &str,
    action: CommandAction,
    approvals_required: u32,
    window_us: i64,
) -> CommandRequest {
    CommandRequest::new(
        request_id,
        action,
        "suspicious crowd movement",
        "duty-manager",
        T0,
        T0 + window_us,
        approvals_required,
    )
    .expect("command request")
}

fn sign(request: CommandRequest, approvers: &[(&str, &dyn TicketSigner)]) -> SignedCommand {
    SignedCommand::sign(request, approvers, T0).expect("signed command")
}

fn engine() -> LockdownEngine {
    LockdownEngine::new(config(), ApprovalPolicy::standard()).expect("engine")
}

// --- lockdown approvals ------------------------------------------------

#[test]
fn lockdown_requires_the_configured_approvals() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();

    // The request asks for one approval, but policy requires two.
    let req = request(
        "req-lock",
        CommandAction::Lockdown {
            scope: venue_scope(),
        },
        1,
        HOUR_US,
    );
    let one = sign(req.clone(), &[("alice", &c1)]);
    assert_eq!(
        engine.execute(&one, &ring, T0),
        Err(LockdownError::InsufficientApprovals {
            provided: 1,
            required: 2,
        })
    );
    assert!(engine.venue_lockdown(T0).is_none());
    assert!(engine.ingress_allowed(&gate_n1(), T0));

    let two = sign(req, &[("alice", &c1), ("bob", &c2)]);
    let outcome = engine.execute(&two, &ring, T0).expect("execute");
    assert!(outcome.is_executed());
    let lock = engine.venue_lockdown(T0).expect("locked");
    assert_eq!(lock.request_id, "req-lock");
    assert_eq!(lock.requested_by, "duty-manager");
    assert_eq!(lock.approvers, vec!["alice", "bob"]);
    assert_eq!(lock.reason, "suspicious crowd movement");
    assert!(!engine.ingress_allowed(&gate_n1(), T0));
    assert!(!engine.ingress_allowed(&gate_s1(), T0));
    assert!(engine.egress_allowed());
    assert_eq!(engine.gate_posture(&gate_n1(), T0).code(), "locked");
}

#[test]
fn a_zone_lockdown_blocks_only_its_zone() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();

    let cmd = sign(
        request(
            "req-zone",
            CommandAction::Lockdown {
                scope: zone_scope("zone-north"),
            },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    engine.execute(&cmd, &ring, T0).expect("execute");
    assert!(engine.zone_lockdown(&zone_north(), T0).is_some());
    assert!(!engine.ingress_allowed(&gate_n1(), T0));
    assert!(!engine.ingress_allowed(&gate_n2(), T0));
    assert!(engine.ingress_allowed(&gate_s1(), T0));
    assert_eq!(engine.gate_posture(&gate_s1(), T0).code(), "normal");
    assert_eq!(engine.active_lockdowns(T0).len(), 1);
}

// --- release and approval binding -------------------------------------

#[test]
fn release_cannot_reuse_lockdown_approvals() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let c3 = custodian(3);
    let ring = approval_ring();
    let mut engine = engine();

    let lockdown = sign(
        request(
            "req-lock",
            CommandAction::Lockdown {
                scope: venue_scope(),
            },
            2,
            2 * HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    engine.execute(&lockdown, &ring, T0).expect("lockdown");

    // Reusing the lockdown signatures on a release request fails verification:
    // the signatures are bound to the lockdown action bytes.
    let release_req = request(
        "req-release",
        CommandAction::ReleaseLockdown {
            scope: venue_scope(),
        },
        2,
        2 * HOUR_US,
    );
    let reused = SignedCommand {
        request: release_req.clone(),
        approvals: lockdown.approvals.clone(),
    };
    assert_eq!(
        engine.execute(&reused, &ring, T0 + HOUR_US),
        Err(LockdownError::Signature {
            key_id: "custodian-1".to_string(),
        })
    );
    assert!(engine.venue_lockdown(T0 + HOUR_US).is_some());

    // Tampering a correctly signed lockdown into a release also fails.
    let mut tampered = lockdown;
    tampered.request.action = CommandAction::ReleaseLockdown {
        scope: venue_scope(),
    };
    assert!(matches!(
        engine.execute(&tampered, &ring, T0 + HOUR_US),
        Err(LockdownError::Signature { .. })
    ));
    assert!(engine.venue_lockdown(T0 + HOUR_US).is_some());

    // A fresh release with its own approvals works.
    let release = sign(release_req, &[("carol", &c3), ("bob", &c2)]);
    let outcome = engine.execute(&release, &ring, T0 + HOUR_US);
    assert!(outcome.expect("release").is_executed());
    assert!(engine.venue_lockdown(T0 + HOUR_US).is_none());
    assert!(engine.ingress_allowed(&gate_n1(), T0 + HOUR_US));
    let event = engine
        .events()
        .find(|event| event.kind == SecurityEventKind::LockdownReleased)
        .expect("release event");
    assert!(event.detail.contains("req-lock"), "names the released lockdown");
    assert_eq!(event.actor, "duty-manager");
    assert_eq!(event.approvers, vec!["carol", "bob"]);
}

#[test]
fn approvers_must_be_distinct_and_never_the_requester() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();
    let action = CommandAction::Lockdown {
        scope: venue_scope(),
    };

    let self_approved = sign(
        request("req-self", action.clone(), 2, HOUR_US),
        &[("duty-manager", &c1), ("bob", &c2)],
    );
    assert_eq!(
        engine.execute(&self_approved, &ring, T0),
        Err(LockdownError::SelfApproval {
            approver: "duty-manager".to_string()
        })
    );

    let duplicate_approver = sign(
        request("req-dup", action.clone(), 2, HOUR_US),
        &[("alice", &c1), ("alice", &c2)],
    );
    assert_eq!(
        engine.execute(&duplicate_approver, &ring, T0),
        Err(LockdownError::DuplicateApprover {
            approver: "alice".to_string()
        })
    );

    let duplicate_key = sign(
        request("req-key", action, 2, HOUR_US),
        &[("alice", &c1), ("bob", &c1)],
    );
    assert_eq!(
        engine.execute(&duplicate_key, &ring, T0),
        Err(LockdownError::DuplicateSigner {
            key_id: "custodian-1".to_string()
        })
    );
    assert!(engine.venue_lockdown(T0).is_none());
}

#[test]
fn approvals_are_bound_to_the_exact_action() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();

    let cmd = sign(
        request(
            "req-cap",
            CommandAction::CapacityOverride {
                scope: LimitScope::Gate(gate_n1()),
                headroom: 50,
            },
            2,
            2 * HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    engine.execute(&cmd, &ring, T0).expect("grant");
    assert_eq!(
        engine
            .capacity_override(&LimitScope::Gate(gate_n1()), T0)
            .expect("grant")
            .headroom,
        50
    );

    let mut wider = cmd;
    wider.request.action = CommandAction::CapacityOverride {
        scope: LimitScope::Gate(gate_n1()),
        headroom: 5_000,
    };
    assert_eq!(
        engine.execute(&wider, &ring, T0 + HOUR_US),
        Err(LockdownError::Signature {
            key_id: "custodian-1".to_string(),
        })
    );
    assert_eq!(
        engine
            .capacity_override(&LimitScope::Gate(gate_n1()), T0 + HOUR_US)
            .expect("grant")
            .headroom,
        50
    );
}

// --- expiry ------------------------------------------------------------

#[test]
fn commands_and_approvals_expire() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();

    let req = request(
        "req-lock",
        CommandAction::Lockdown {
            scope: venue_scope(),
        },
        2,
        HOUR_US,
    );
    let cmd = sign(req.clone(), &[("alice", &c1), ("bob", &c2)]);
    assert_eq!(
        engine.execute(&cmd, &ring, T0 + 2 * HOUR_US),
        Err(LockdownError::Expired {
            expires_at_utc_us: T0 + HOUR_US,
        })
    );

    let late = SignedCommand::sign(req, &[("alice", &c1), ("bob", &c2)], T0 + 2 * HOUR_US)
        .expect("sign");
    assert_eq!(
        engine.execute(&late, &ring, T0),
        Err(LockdownError::ApprovalAfterExpiry {
            approved_at_utc_us: T0 + 2 * HOUR_US,
            expires_at_utc_us: T0 + HOUR_US,
        })
    );

    // Break-glass closes at its expiry and the sweep records it.
    let glass = sign(
        request(
            "req-glass",
            CommandAction::EmergencyGateOpen { gate_id: gate_n1() },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    engine.execute(&glass, &ring, T0).expect("open");
    assert!(engine.egress_allowed());
    assert!(engine
        .gate_posture(&gate_n1(), T0 + HOUR_US - 1)
        .is_break_glass());
    assert_eq!(
        engine.gate_posture(&gate_n1(), T0 + HOUR_US).code(),
        "normal"
    );
    let expired = engine.sweep(T0 + HOUR_US);
    assert!(expired.iter().any(|expiry| {
        expiry.kind == SecurityEventKind::BreakGlassExpired && expiry.request_id == "req-glass"
    }));
}

#[test]
fn capacity_override_and_break_glass_need_their_own_approvals() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();

    engine
        .execute(
            &sign(
                request(
                    "req-lock",
                    CommandAction::Lockdown {
                        scope: venue_scope(),
                    },
                    2,
                    3 * HOUR_US,
                ),
                &[("alice", &c1), ("bob", &c2)],
            ),
            &ring,
            T0,
        )
        .expect("lockdown");

    // One approval is not enough for a capacity override.
    let cap_req = request(
        "req-cap",
        CommandAction::CapacityOverride {
            scope: LimitScope::Zone(zone_north()),
            headroom: 100,
        },
        2,
        2 * HOUR_US,
    );
    assert_eq!(
        engine.execute(
            &sign(cap_req.clone(), &[("alice", &c1)]),
            &ring,
            T0 + HOUR_US
        ),
        Err(LockdownError::InsufficientApprovals {
            provided: 1,
            required: 2,
        })
    );
    let grant = engine
        .execute(
            &sign(cap_req, &[("alice", &c1), ("bob", &c2)]),
            &ring,
            T0 + HOUR_US,
        )
        .expect("grant");
    assert!(grant.is_executed());
    let override_grant = engine
        .capacity_override(&LimitScope::Zone(zone_north()), T0 + HOUR_US)
        .expect("grant");
    assert_eq!(override_grant.headroom, 100);
    assert_eq!(override_grant.approvers, vec!["alice", "bob"]);

    // Break-glass opens one gate only, and expires with its own window.
    assert!(engine.gate_posture(&gate_s1(), T0 + HOUR_US).is_locked());
    let glass_req = request(
        "req-glass",
        CommandAction::EmergencyGateOpen { gate_id: gate_s1() },
        2,
        2 * HOUR_US,
    );
    assert_eq!(
        engine.execute(
            &sign(glass_req.clone(), &[("alice", &c1)]),
            &ring,
            T0 + HOUR_US
        ),
        Err(LockdownError::InsufficientApprovals {
            provided: 1,
            required: 2,
        })
    );
    engine
        .execute(
            &sign(glass_req, &[("alice", &c1), ("bob", &c2)]),
            &ring,
            T0 + HOUR_US,
        )
        .expect("break glass");
    assert!(engine.gate_posture(&gate_s1(), T0 + HOUR_US).is_break_glass());
    assert!(engine.ingress_allowed(&gate_s1(), T0 + HOUR_US));
    assert!(!engine.ingress_allowed(&gate_n1(), T0 + HOUR_US));

    // At the shared expiry the override and break-glass are gone; the
    // lockdown (three hours) is still engaged.
    let expired = engine.sweep(T0 + 2 * HOUR_US);
    assert_eq!(expired.len(), 2);
    assert!(engine
        .capacity_override(&LimitScope::Zone(zone_north()), T0 + 2 * HOUR_US)
        .is_none());
    assert!(engine.gate_posture(&gate_s1(), T0 + 2 * HOUR_US).is_locked());
    assert!(engine.venue_lockdown(T0 + 2 * HOUR_US).is_some());
}

// --- attribution and audit --------------------------------------------

#[test]
fn every_override_is_attributable_and_auditable() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let c3 = custodian(3);
    let ring = approval_ring();
    let mut engine = engine();

    let commands = [
        sign(
            request(
                "req-lock",
                CommandAction::Lockdown {
                    scope: venue_scope(),
                },
                2,
                4 * HOUR_US,
            ),
            &[("alice", &c1), ("bob", &c2)],
        ),
        sign(
            request(
                "req-cap",
                CommandAction::CapacityOverride {
                    scope: LimitScope::Gate(gate_n1()),
                    headroom: 20,
                },
                2,
                3 * HOUR_US,
            ),
            &[("alice", &c1), ("carol", &c3)],
        ),
        sign(
            request(
                "req-glass",
                CommandAction::EmergencyGateOpen { gate_id: gate_n2() },
                2,
                2 * HOUR_US,
            ),
            &[("bob", &c2), ("carol", &c3)],
        ),
        sign(
            request(
                "req-release",
                CommandAction::ReleaseLockdown {
                    scope: venue_scope(),
                },
                2,
                3 * HOUR_US,
            ),
            &[("carol", &c3), ("bob", &c2)],
        ),
    ];
    for command in &commands {
        engine
            .execute(command, &ring, T0)
            .expect("command executes");
    }

    let events: Vec<_> = engine.events().collect();
    assert_eq!(events.len(), 4);
    assert!(events
        .windows(2)
        .all(|pair| pair[0].seq < pair[1].seq));

    let engaged = events
        .iter()
        .find(|event| event.kind == SecurityEventKind::LockdownEngaged)
        .expect("lockdown event");
    assert_eq!(engaged.request_id, "req-lock");
    assert_eq!(engaged.action, "lockdown");
    assert_eq!(engaged.scope, "venue:venue-1");
    assert_eq!(engaged.actor, "duty-manager");
    assert_eq!(engaged.approvers, vec!["alice", "bob"]);
    assert!(engaged.detail.contains("crowd movement"));

    let granted = events
        .iter()
        .find(|event| event.kind == SecurityEventKind::CapacityOverrideGranted)
        .expect("capacity event");
    assert_eq!(granted.request_id, "req-cap");
    assert_eq!(granted.scope, "capacity:gate:gate-n1");
    assert_eq!(granted.actor, "duty-manager");
    assert_eq!(granted.approvers, vec!["alice", "carol"]);

    let glass = events
        .iter()
        .find(|event| event.kind == SecurityEventKind::BreakGlassOpened)
        .expect("break-glass event");
    assert_eq!(glass.scope, "gate:gate-n2");
    assert_eq!(glass.approvers, vec!["bob", "carol"]);

    let released = events
        .iter()
        .find(|event| event.kind == SecurityEventKind::LockdownReleased)
        .expect("release event");
    assert_eq!(released.request_id, "req-release");
    assert!(released.detail.contains("req-lock"));

    // The records themselves keep the same attribution.
    assert_eq!(
        engine
            .capacity_override(&LimitScope::Gate(gate_n1()), T0)
            .expect("grant")
            .requested_by,
        "duty-manager"
    );
}

#[test]
fn thresholds_are_per_command_family() {
    let c1 = custodian(1);
    let c2 = custodian(2);
    let c3 = custodian(3);
    let ring = approval_ring();
    let mut engine =
        LockdownEngine::new(config(), ApprovalPolicy::new(2, 3, 2, 2).expect("policy"))
            .expect("engine");

    engine
        .execute(
            &sign(
                request(
                    "req-lock",
                    CommandAction::Lockdown {
                        scope: venue_scope(),
                    },
                    2,
                    2 * HOUR_US,
                ),
                &[("alice", &c1), ("bob", &c2)],
            ),
            &ring,
            T0,
        )
        .expect("lockdown with two");

    let release = request(
        "req-release",
        CommandAction::ReleaseLockdown {
            scope: venue_scope(),
        },
        2,
        2 * HOUR_US,
    );
    assert_eq!(
        engine.execute(
            &sign(release.clone(), &[("alice", &c1), ("bob", &c2)]),
            &ring,
            T0
        ),
        Err(LockdownError::InsufficientApprovals {
            provided: 2,
            required: 3,
        })
    );
    engine
        .execute(
            &sign(
                release,
                &[("alice", &c1), ("bob", &c2), ("carol", &c3)],
            ),
            &ring,
            T0,
        )
        .expect("release with three");
    assert!(engine.venue_lockdown(T0).is_none());
}

// --- concurrency -------------------------------------------------------

#[test]
fn concurrent_execution_of_one_command_happens_once() {
    let gate = Arc::new(Mutex::new(engine()));
    let ring = approval_ring();
    let c1 = custodian(1);
    let c2 = custodian(2);
    let command = sign(
        request(
            "req-lock",
            CommandAction::Lockdown {
                scope: venue_scope(),
            },
            2,
            2 * HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );

    let mut handles = Vec::new();
    for _ in 0..8 {
        let gate = Arc::clone(&gate);
        let command = command.clone();
        let ring = ring.clone();
        handles.push(std::thread::spawn(move || {
            gate.lock()
                .expect("lock")
                .execute(&command, &ring, T0)
                .expect("execute")
                .code()
        }));
    }
    let codes: Vec<&'static str> = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .collect();
    assert_eq!(codes.iter().filter(|code| **code == "executed").count(), 1);
    assert_eq!(
        codes
            .iter()
            .filter(|code| **code == "already_executed")
            .count(),
        7
    );

    let gate = gate.lock().expect("lock");
    assert!(gate.venue_lockdown(T0).is_some());
    assert_eq!(
        gate.events()
            .filter(|event| event.kind == SecurityEventKind::LockdownEngaged)
            .count(),
        1
    );
}

#[test]
fn concurrent_distinct_break_glass_commands_all_execute() {
    let gate = Arc::new(Mutex::new(
        LockdownEngine::new(many_gate_config(), ApprovalPolicy::standard()).expect("engine"),
    ));
    let ring = approval_ring();

    let mut handles = Vec::new();
    for index in 1..=8 {
        let gate = Arc::clone(&gate);
        let ring = ring.clone();
        let gate_id: GateId = parsed(&format!("gate-n{index}"));
        handles.push(std::thread::spawn(move || {
            let c1 = custodian(1);
            let c2 = custodian(2);
            let command = sign(
                request(
                    &format!("req-{index}"),
                    CommandAction::EmergencyGateOpen {
                        gate_id: gate_id.clone(),
                    },
                    2,
                    HOUR_US,
                ),
                &[("alice", &c1), ("bob", &c2)],
            );
            gate.lock()
                .expect("lock")
                .execute(&command, &ring, T0)
                .expect("execute")
                .is_executed()
        }));
    }
    assert!(handles
        .into_iter()
        .all(|handle| handle.join().expect("worker")));

    let gate = gate.lock().expect("lock");
    assert_eq!(
        gate.events()
            .filter(|event| event.kind == SecurityEventKind::BreakGlassOpened)
            .count(),
        8
    );
    for index in 1..=8 {
        let gate_id: GateId = parsed(&format!("gate-n{index}"));
        assert!(gate.gate_posture(&gate_id, T0).is_break_glass());
    }
}

// --- validation --------------------------------------------------------

#[test]
fn invalid_commands_and_scopes_are_refused() {
    assert!(CommandRequest::new(
        "",
        CommandAction::Lockdown {
            scope: venue_scope()
        },
        "reason",
        "duty-manager",
        T0,
        T0 + HOUR_US,
        2
    )
    .is_err());
    assert!(CommandRequest::new(
        "req",
        CommandAction::Lockdown {
            scope: venue_scope()
        },
        "  ",
        "duty-manager",
        T0,
        T0 + HOUR_US,
        2
    )
    .is_err());
    assert!(CommandRequest::new(
        "req",
        CommandAction::Lockdown {
            scope: venue_scope()
        },
        "reason",
        "duty-manager",
        T0,
        T0,
        2
    )
    .is_err());
    assert!(CommandRequest::new(
        "req",
        CommandAction::Lockdown {
            scope: venue_scope()
        },
        "reason",
        "duty-manager",
        T0,
        T0 + HOUR_US,
        0
    )
    .is_err());
    assert!(ApprovalPolicy::new(0, 2, 2, 2).is_err());

    let c1 = custodian(1);
    let c2 = custodian(2);
    let ring = approval_ring();
    let mut engine = engine();

    let unknown_zone = sign(
        request(
            "req-zone",
            CommandAction::Lockdown {
                scope: zone_scope("zone-nowhere"),
            },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    assert_eq!(
        engine.execute(&unknown_zone, &ring, T0),
        Err(LockdownError::UnknownZone(parsed("zone-nowhere")))
    );

    let wrong_venue = sign(
        request(
            "req-venue",
            CommandAction::Lockdown {
                scope: LockScope::Venue {
                    venue_id: parsed("venue-2"),
                },
            },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    assert_eq!(
        engine.execute(&wrong_venue, &ring, T0),
        Err(LockdownError::VenueMismatch {
            expected: venue(),
            presented: parsed("venue-2"),
        })
    );

    let unknown_gate = sign(
        request(
            "req-gate",
            CommandAction::EmergencyGateOpen {
                gate_id: parsed("gate-nowhere"),
            },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    assert_eq!(
        engine.execute(&unknown_gate, &ring, T0),
        Err(LockdownError::UnknownGate(parsed("gate-nowhere")))
    );

    // A release with nothing locked is refused.
    let release = sign(
        request(
            "req-release",
            CommandAction::ReleaseLockdown {
                scope: venue_scope(),
            },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    assert_eq!(
        engine.execute(&release, &ring, T0),
        Err(LockdownError::NotLocked {
            scope: venue_scope()
        })
    );

    // The same command executes once; a second lockdown for the same scope
    // while one is active is a conflict.
    let lockdown = sign(
        request(
            "req-lock",
            CommandAction::Lockdown {
                scope: venue_scope(),
            },
            2,
            2 * HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    assert!(engine
        .execute(&lockdown, &ring, T0)
        .expect("execute")
        .is_executed());
    assert_eq!(
        engine
            .execute(&lockdown, &ring, T0)
            .expect("idempotent")
            .code(),
        "already_executed"
    );
    let second = sign(
        request(
            "req-lock-2",
            CommandAction::Lockdown {
                scope: venue_scope(),
            },
            2,
            HOUR_US,
        ),
        &[("alice", &c1), ("bob", &c2)],
    );
    assert_eq!(
        engine.execute(&second, &ring, T0),
        Err(LockdownError::LockdownActive {
            scope: venue_scope()
        })
    );
}
