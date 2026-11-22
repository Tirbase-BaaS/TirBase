// SPDX-License-Identifier: AGPL-3.0-only

//! ST-07 acceptance tests: cross-gate replay, window refusal, revocation
//! deltas and propagation, M-of-N emergency approvals, stale-list policy,
//! bounded replay storage and concurrency.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tirbase_venue::{GateId, TicketId};
use tirbase_venue_admission::{
    DeltaPolicy, EpochPolicy, GateAdmission, GateDeny, GateReplayGuard, RevocationAccumulator,
    RevocationDelta, RevocationError, SignedRevocationDelta, StalePolicy, StaleReason,
    SubmitOutcome,
};
use tirbase_venue_ticket::{
    Denial, Ed25519Signer, EventId, IssuerKey, IssuerKeyRing, IssuerKeyState, SignedTicket,
    TicketPayload, TicketSigner, VenueScope,
};

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

fn ticket_id() -> TicketId {
    parsed("ticket-1")
}

fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed("issuer-1", [7u8; 32])
}

fn ticket_ring() -> IssuerKeyRing {
    let mut ring = IssuerKeyRing::new();
    ring.add_public_key(
        "issuer-1",
        issuer().public_key(),
        T0 - DAY_US,
        T0 + 365 * DAY_US,
    )
    .expect("issuer key");
    ring
}

fn rev_signer(index: u8) -> Ed25519Signer {
    let seed = [10u8.wrapping_add(index); 32];
    Ed25519Signer::from_seed(format!("rev-{index}"), seed)
}

fn rev_ring(signers: &[&dyn TicketSigner]) -> IssuerKeyRing {
    let mut ring = IssuerKeyRing::new();
    for (index, signer) in signers.iter().enumerate() {
        ring.add_key(IssuerKey {
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key(),
            not_before_utc_us: T0 - DAY_US,
            not_after_utc_us: T0 + 365 * DAY_US,
            state: if index == 0 {
                IssuerKeyState::Active
            } else {
                IssuerKeyState::Retiring
            },
        })
        .expect("delta key");
    }
    ring
}

fn payload(nonce: u64, gate: &str) -> TicketPayload {
    TicketPayload::new(
        ticket_id(),
        VenueScope::new(
            EventId::new("event-1").expect("event"),
            parsed("venue-1"),
            parsed(gate),
            parsed("zone-north"),
        ),
        T0,
        T0 + 8 * HOUR_US,
        nonce,
    )
    .expect("payload")
}

fn issue_ticket(nonce: u64, gate: &str) -> SignedTicket {
    SignedTicket::sign(payload(nonce, gate), &issuer()).expect("signed ticket")
}

fn delta(
    base_version: u64,
    version: u64,
    issued_at_utc_us: i64,
    expires_at_utc_us: i64,
    added: Vec<TicketId>,
) -> RevocationDelta {
    RevocationDelta::new(
        base_version,
        version,
        issued_at_utc_us,
        expires_at_utc_us,
        added,
        Vec::new(),
    )
    .expect("delta")
}

fn signed(delta: RevocationDelta, signers: &[&dyn TicketSigner]) -> SignedRevocationDelta {
    SignedRevocationDelta::sign(delta, signers).expect("signed delta")
}

fn baseline_delta() -> RevocationDelta {
    delta(0, 1, T0, T0 + 30 * DAY_US, Vec::new())
}

fn guard_with_capacity(capacity: usize) -> GateAdmission {
    let mut gate = GateAdmission::new(
        GateReplayGuard::new(EpochPolicy::default(), capacity).expect("replay guard"),
        StalePolicy::FailClosed,
    );
    gate.apply_delta(
        &signed(baseline_delta(), &[&rev_signer(1)]),
        &rev_ring(&[&rev_signer(1)]),
        &DeltaPolicy::standard(),
        T0,
    )
    .expect("baseline revocation list");
    gate
}

fn guard() -> GateAdmission {
    guard_with_capacity(64)
}

fn admit(
    gate: &mut GateAdmission,
    ticket: &SignedTicket,
    gate_id: &str,
    at_utc_us: i64,
) -> tirbase_venue_admission::GateDecision {
    gate.admit(ticket, &parsed(gate_id), at_utc_us, &ticket_ring())
}

// --- cross-gate single use --------------------------------------------

#[test]
fn a_ticket_cannot_be_used_at_two_gates() {
    let mut gate = guard();
    let ticket = issue_ticket(1, "gate-n1");

    let first = admit(&mut gate, &ticket, "gate-n1", T0 + HOUR_US);
    assert!(first.is_admitted());
    assert_eq!(first.code(), "admitted");

    let other = admit(&mut gate, &ticket, "gate-n2", T0 + HOUR_US + 1_000);
    assert!(other.denial().is_some());
    assert_eq!(other.code(), "cross_gate");
    match other.denial().expect("denied") {
        GateDeny::CrossGate { claimed_by, .. } => {
            assert_eq!(claimed_by, &parsed("gate-n1"));
        }
        other => panic!("expected a cross-gate denial, got {other:?}"),
    }

    let again = admit(&mut gate, &ticket, "gate-n1", T0 + HOUR_US + 2_000);
    assert_eq!(again.code(), "duplicate");
    match again.denial().expect("denied") {
        GateDeny::Duplicate { replay_key } => {
            assert_eq!(replay_key.gate_id, parsed("gate-n1"));
            assert_eq!(replay_key.nonce, 1);
            assert_eq!(
                replay_key.epoch,
                EpochPolicy::default().epoch_of(T0 + HOUR_US + 2_000)
            );
        }
        other => panic!("expected a duplicate denial, got {other:?}"),
    }

    // A different ticket (new nonce) is a new passage.
    let next = admit(&mut gate, &issue_ticket(2, "gate-n1"), "gate-n2", T0 + HOUR_US);
    assert!(next.is_admitted());
}

#[test]
fn reuse_after_the_validity_window_is_denied() {
    let mut gate = guard();
    let ticket = issue_ticket(1, "gate-n1");
    assert!(admit(&mut gate, &ticket, "gate-n1", T0 + HOUR_US).is_admitted());

    let late = admit(&mut gate, &ticket, "gate-n2", T0 + 8 * HOUR_US);
    assert_eq!(late.code(), "expired");
    match late.denial().expect("denied") {
        GateDeny::Ticket(Denial::Expired { valid_until_utc_us }) => {
            assert_eq!(*valid_until_utc_us, T0 + 8 * HOUR_US);
        }
        other => panic!("expected an expired denial, got {other:?}"),
    }

    let early = admit(&mut gate, &issue_ticket(3, "gate-n1"), "gate-n1", T0 - 1);
    assert_eq!(early.code(), "not_yet_valid");
}

#[test]
fn the_replay_key_includes_the_gate_and_the_epoch() {
    let epoch = EpochPolicy::new(60_000_000).expect("one-minute epochs");
    let mut replay = GateReplayGuard::new(epoch, 8).expect("guard");
    let payload = payload(1, "gate-n1");

    match replay.admit(&payload, &parsed("gate-n1"), T0 + HOUR_US) {
        tirbase_venue_admission::ReplayVerdict::Fresh { key, .. } => {
            assert_eq!(key.ticket_id, ticket_id());
            assert_eq!(key.nonce, 1);
            assert_eq!(key.gate_id, parsed("gate-n1"));
            assert_eq!(key.epoch, epoch.epoch_of(T0 + HOUR_US));
        }
        other => panic!("expected a fresh use, got {other:?}"),
    }

    // Same gate, two minutes later: a new epoch, still the same ticket use.
    let later = replay.admit(&payload, &parsed("gate-n1"), T0 + HOUR_US + 120_000_000);
    assert_eq!(later.code(), "already_used");
    match later {
        tirbase_venue_admission::ReplayVerdict::AlreadyUsed { claimed_epoch, .. } => {
            assert_eq!(claimed_epoch, epoch.epoch_of(T0 + HOUR_US));
        }
        other => panic!("expected already-used, got {other:?}"),
    }

    let other_gate = replay.admit(&payload, &parsed("gate-n2"), T0 + HOUR_US + 120_000_000);
    assert_eq!(other_gate.code(), "cross_gate");

    let before_window = replay.admit(&payload, &parsed("gate-n1"), T0 - HOUR_US);
    assert_eq!(before_window.code(), "not_yet_valid");
    let after_window = replay.admit(&payload, &parsed("gate-n1"), T0 + 8 * HOUR_US);
    assert_eq!(after_window.code(), "window_closed");
}

// --- revocation --------------------------------------------------------

#[test]
fn a_revoked_ticket_is_denied_after_sync() {
    let mut gate = guard();
    let first = issue_ticket(1, "gate-n1");
    assert!(admit(&mut gate, &first, "gate-n1", T0 + HOUR_US).is_admitted());

    let revoke = signed(
        delta(1, 2, T0 + HOUR_US, T0 + 30 * DAY_US, vec![ticket_id()]),
        &[&rev_signer(1)],
    );
    let outcome = gate
        .apply_delta(
            &revoke,
            &rev_ring(&[&rev_signer(1)]),
            &DeltaPolicy::standard(),
            T0 + HOUR_US,
        )
        .expect("delta applies");
    assert_eq!(outcome, SubmitOutcome::Applied { version: 2 });
    assert_eq!(gate.ledger().version(), 2);
    assert!(gate.ledger().is_revoked(&ticket_id()));

    // Even a fresh nonce for the revoked ticket id is refused after sync,
    // and the replay check never gets a chance to run.
    let denied = admit(&mut gate, &issue_ticket(2, "gate-n1"), "gate-n3", T0 + 2 * HOUR_US);
    assert_eq!(denied.code(), "revoked_ticket");
    match denied.denial().expect("denied") {
        GateDeny::Revoked { ticket_id: id } => assert_eq!(id, &ticket_id()),
        other => panic!("expected a revocation denial, got {other:?}"),
    }
}

#[test]
fn revocation_deltas_accumulate_offline_across_gateways() {
    let r1 = rev_signer(1);
    let ring = rev_ring(&[&r1]);
    let signer_refs: [&dyn TicketSigner; 1] = [&r1];
    let v1 = signed(baseline_delta(), &signer_refs);
    let v2 = signed(
        delta(1, 2, T0, T0 + 30 * DAY_US, vec![parsed("ticket-9")]),
        &signer_refs,
    );
    let v3 = signed(delta(2, 3, T0, T0 + 30 * DAY_US, Vec::new()), &signer_refs);

    // A gateway that receives v2 and v3 before v1 queues them, then applies
    // the whole chain when the base arrives.
    let mut offline = RevocationAccumulator::new();
    assert_eq!(
        offline
            .submit(&v2, &ring, &DeltaPolicy::standard(), T0)
            .expect("queue"),
        SubmitOutcome::Queued { waiting_for: 1 }
    );
    assert_eq!(
        offline
            .submit(&v3, &ring, &DeltaPolicy::standard(), T0)
            .expect("queue"),
        SubmitOutcome::Queued { waiting_for: 1 }
    );
    assert_eq!(offline.pending_len(), 2);
    assert_eq!(
        offline
            .submit(&v1, &ring, &DeltaPolicy::standard(), T0)
            .expect("apply"),
        SubmitOutcome::Applied { version: 3 }
    );
    assert_eq!(offline.pending_len(), 0);
    assert_eq!(offline.ledger().version(), 3);
    assert!(offline.ledger().is_revoked(&parsed("ticket-9")));

    // A peer applies the same bundle in reverse order.
    let mut peer = RevocationAccumulator::new();
    let applied = peer
        .apply_bundle(
            &[v3.clone(), v2.clone(), v1.clone()],
            &ring,
            &DeltaPolicy::standard(),
            T0,
        )
        .expect("bundle");
    assert_eq!(applied, 3);
    assert_eq!(peer.ledger().version(), 3);
    assert_eq!(
        peer.submit(&v2, &ring, &DeltaPolicy::standard(), T0)
            .expect("resubmit"),
        SubmitOutcome::AlreadyApplied { version: 3 }
    );

    // A delta forking below the applied version is a gap, not a queue entry.
    let fork = signed(delta(0, 9, T0, T0 + 30 * DAY_US, Vec::new()), &signer_refs);
    assert_eq!(
        peer.submit(&fork, &ring, &DeltaPolicy::standard(), T0),
        Err(RevocationError::Gap {
            expected: 3,
            offered: 0,
        })
    );

    // Two different deltas claiming the same version are refused while one
    // waits in the queue.
    let mut queued = RevocationAccumulator::new();
    let a = signed(delta(1, 2, T0, T0 + 30 * DAY_US, Vec::new()), &signer_refs);
    let b = signed(
        delta(1, 2, T0, T0 + 30 * DAY_US, vec![parsed("ticket-x")]),
        &signer_refs,
    );
    assert!(matches!(
        queued.submit(&a, &ring, &DeltaPolicy::standard(), T0),
        Ok(SubmitOutcome::Queued { .. })
    ));
    assert_eq!(
        queued.submit(&b, &ring, &DeltaPolicy::standard(), T0),
        Err(RevocationError::ConflictingVersion { version: 2 })
    );

    // The offline queue itself is bounded.
    let mut small = RevocationAccumulator::with_pending_capacity(1).expect("small queue");
    assert!(matches!(
        small.submit(&v2, &ring, &DeltaPolicy::standard(), T0),
        Ok(SubmitOutcome::Queued { .. })
    ));
    assert_eq!(
        small.submit(&v3, &ring, &DeltaPolicy::standard(), T0),
        Err(RevocationError::PendingFull { capacity: 1 })
    );
}

#[test]
fn a_stale_revocation_list_follows_the_fail_safe_policy() {
    let missing = issue_ticket(1, "gate-n1");

    // Missing list, fail closed: refused, silent.
    let mut gate = GateAdmission::new(
        GateReplayGuard::new(EpochPolicy::default(), 8).expect("guard"),
        StalePolicy::FailClosed,
    );
    assert_eq!(
        admit(&mut gate, &missing, "gate-n1", T0 + HOUR_US).code(),
        "revocation_list_missing"
    );
    assert!(gate.alarm().is_none());

    // Missing list, alarm policy: refused and alarmed.
    let mut gate = GateAdmission::new(
        GateReplayGuard::new(EpochPolicy::default(), 8).expect("guard"),
        StalePolicy::Alarm,
    );
    assert_eq!(
        admit(&mut gate, &missing, "gate-n1", T0 + HOUR_US).code(),
        "revocation_list_missing"
    );
    let alarm = gate.take_alarm().expect("alarm");
    assert_eq!(alarm.reason, StaleReason::Missing);
    assert_eq!(alarm.version, 0);
    assert!(gate.take_alarm().is_none());

    // Expired list: refused under both policies, alarmed only under Alarm.
    for policy in [StalePolicy::FailClosed, StalePolicy::Alarm] {
        let mut gate = GateAdmission::new(
            GateReplayGuard::new(EpochPolicy::default(), 8).expect("guard"),
            policy,
        );
        gate.apply_delta(
            &signed(delta(0, 1, T0, T0 + 2 * HOUR_US, Vec::new()), &[&rev_signer(1)]),
            &rev_ring(&[&rev_signer(1)]),
            &DeltaPolicy::standard(),
            T0,
        )
        .expect("short list");
        let decision = admit(&mut gate, &missing, "gate-n1", T0 + 3 * HOUR_US);
        assert_eq!(decision.code(), "revocation_list_expired");
        match decision.denial().expect("denied") {
            GateDeny::RevocationListExpired {
                version,
                expires_at_utc_us,
            } => {
                assert_eq!(*version, 1);
                assert_eq!(*expires_at_utc_us, T0 + 2 * HOUR_US);
            }
            other => panic!("expected an expired list denial, got {other:?}"),
        }
        match policy {
            StalePolicy::FailClosed => assert!(gate.alarm().is_none()),
            StalePolicy::Alarm => {
                let alarm = gate.alarm().expect("alarm");
                assert_eq!(alarm.reason, StaleReason::Expired);
                assert_eq!(alarm.expires_at_utc_us, T0 + 2 * HOUR_US);
            }
        }
    }

    // An already-expired delta is never applied.
    let mut gate = GateAdmission::new(
        GateReplayGuard::new(EpochPolicy::default(), 8).expect("guard"),
        StalePolicy::FailClosed,
    );
    let stale = signed(delta(0, 1, T0, T0 + HOUR_US, Vec::new()), &[&rev_signer(1)]);
    assert!(matches!(
        gate.apply_delta(
            &stale,
            &rev_ring(&[&rev_signer(1)]),
            &DeltaPolicy::standard(),
            T0 + 2 * HOUR_US
        ),
        Err(RevocationError::Expired { .. })
    ));
    assert_eq!(gate.ledger().version(), 0);
}

#[test]
fn an_emergency_delta_needs_m_of_n_approval() {
    let r1 = rev_signer(1);
    let r2 = rev_signer(2);
    let r3 = rev_signer(3);
    let ring = rev_ring(&[&r1, &r2, &r3]);
    let policy = DeltaPolicy::standard();
    let emergency = delta(0, 1, T0, T0 + 2 * HOUR_US, vec![ticket_id()])
        .with_emergency(2)
        .expect("emergency delta");

    let one_refs: [&dyn TicketSigner; 1] = [&r1];
    let one = SignedRevocationDelta::sign(emergency.clone(), &one_refs).expect("sign");
    assert_eq!(
        one.verify(&ring, &policy, T0),
        Err(RevocationError::InsufficientApprovals {
            provided: 1,
            required: 2,
        })
    );

    let two_refs: [&dyn TicketSigner; 2] = [&r1, &r2];
    let two = SignedRevocationDelta::sign(emergency.clone(), &two_refs).expect("sign");
    assert_eq!(two.verify(&ring, &policy, T0).expect("verify"), 2);

    let mut gate = GateAdmission::new(
        GateReplayGuard::new(EpochPolicy::default(), 8).expect("guard"),
        StalePolicy::FailClosed,
    );
    assert_eq!(
        gate.apply_delta(&one, &ring, &policy, T0),
        Err(RevocationError::InsufficientApprovals {
            provided: 1,
            required: 2,
        })
    );
    assert_eq!(gate.ledger().version(), 0);
    assert_eq!(
        gate.apply_delta(&two, &ring, &policy, T0).expect("apply"),
        SubmitOutcome::Applied { version: 1 }
    );
    assert_eq!(
        admit(&mut gate, &issue_ticket(1, "gate-n1"), "gate-n1", T0 + HOUR_US).code(),
        "revoked_ticket"
    );

    // The same key cannot count twice, and an emergency cannot live too long.
    let duplicate_refs: [&dyn TicketSigner; 2] = [&r1, &r1];
    let duplicate = SignedRevocationDelta::sign(emergency.clone(), &duplicate_refs).expect("sign");
    assert_eq!(
        duplicate.verify(&ring, &policy, T0),
        Err(RevocationError::DuplicateSigner {
            key_id: "rev-1".to_string()
        })
    );

    let long = delta(0, 1, T0, T0 + 12 * HOUR_US, Vec::new())
        .with_emergency(2)
        .expect("emergency delta");
    let long = SignedRevocationDelta::sign(long, &two_refs).expect("sign");
    assert!(matches!(
        long.verify(&ring, &policy, T0),
        Err(RevocationError::EmergencyTtlTooLong { .. })
    ));

    // A routine delta still obeys its own threshold.
    let routine = delta(0, 1, T0, T0 + 2 * HOUR_US, Vec::new())
        .with_approvals(2)
        .expect("threshold");
    let single = SignedRevocationDelta::sign(routine.clone(), &one_refs).expect("sign");
    assert!(matches!(
        single.verify(&ring, &policy, T0),
        Err(RevocationError::InsufficientApprovals {
            provided: 1,
            required: 2
        })
    ));
    let both = SignedRevocationDelta::sign(routine, &two_refs).expect("sign");
    assert_eq!(both.verify(&ring, &policy, T0).expect("verify"), 2);

    // The configured policy can raise the routine threshold above the delta's.
    let strict = DeltaPolicy::new(2, 2, 6 * HOUR_US).expect("policy");
    let single = SignedRevocationDelta::sign(
        delta(0, 1, T0, T0 + 2 * HOUR_US, Vec::new()),
        &one_refs,
    )
    .expect("sign");
    assert!(matches!(
        single.verify(&ring, &strict, T0),
        Err(RevocationError::InsufficientApprovals { .. })
    ));
}

#[test]
fn a_tampered_delta_or_ticket_is_rejected() {
    let r1 = rev_signer(1);
    let ring = rev_ring(&[&r1]);
    let policy = DeltaPolicy::standard();
    let mut tampered = signed(
        delta(0, 1, T0, T0 + 2 * HOUR_US, Vec::new()),
        &[&r1],
    );
    tampered.delta.added.push(parsed("ticket-77"));
    assert_eq!(
        tampered.verify(&ring, &policy, T0),
        Err(RevocationError::Signature {
            key_id: "rev-1".to_string()
        })
    );

    let mut gate = guard();
    let mut bad_ticket = issue_ticket(1, "gate-n1");
    bad_ticket.signature = "00".repeat(64);
    assert_eq!(
        admit(&mut gate, &bad_ticket, "gate-n1", T0 + HOUR_US).code(),
        "bad_signature"
    );

    let mut unknown = issue_ticket(1, "gate-n1");
    unknown.key_id = "issuer-404".to_string();
    assert_eq!(
        admit(&mut gate, &unknown, "gate-n1", T0 + HOUR_US).code(),
        "unknown_issuer_key"
    );
}

// --- replay storage ----------------------------------------------------

#[test]
fn the_replay_store_is_bounded_and_cleans_up() {
    let epoch = EpochPolicy::default();
    let mut replay = GateReplayGuard::new(epoch, 1).expect("guard");
    let a = payload(1, "gate-n1");
    let b = payload(2, "gate-n1");

    assert!(replay.admit(&a, &parsed("gate-n1"), T0 + HOUR_US).is_admitted());
    assert!(replay.admit(&b, &parsed("gate-n1"), T0 + HOUR_US).is_admitted());
    assert_eq!(replay.len(), 1);
    assert_eq!(replay.claims_len(), 1);
    assert!(replay.evicted() > 0);

    // The bounded store dropped the oldest use; re-admitting it counts again.
    // Deployments size the bound so this cannot happen inside one event.
    assert!(replay.admit(&a, &parsed("gate-n1"), T0 + HOUR_US).is_admitted());

    // Window cleanup reclaims everything after the tickets expire.
    replay.prune(T0 + 8 * HOUR_US);
    assert!(replay.is_empty());
    assert_eq!(replay.claims_len(), 0);

    // Persistence keeps duplicate detection across a restart.
    let mut replay = GateReplayGuard::new(epoch, 8).expect("guard");
    assert!(replay.admit(&a, &parsed("gate-n1"), T0 + HOUR_US).is_admitted());
    let json = replay.to_json().expect("json");
    let mut restored = GateReplayGuard::from_json(&json).expect("restore");
    assert_eq!(
        restored
            .admit(&a, &parsed("gate-n1"), T0 + HOUR_US)
            .code(),
        "duplicate"
    );
    assert!(GateReplayGuard::from_json("not json").is_err());
    assert!(GateReplayGuard::new(epoch, 0).is_err());
    assert!(EpochPolicy::new(0).is_err());
    assert!(EpochPolicy::new(DAY_US + 1).is_err());
}

// --- concurrency -------------------------------------------------------

#[test]
fn concurrent_presentations_of_one_ticket_admit_exactly_once() {
    let gate = Arc::new(Mutex::new(guard()));
    let ticket = issue_ticket(11, "gate-n1");

    let mut handles = Vec::new();
    for worker in 0..8 {
        let gate = Arc::clone(&gate);
        let ticket = ticket.clone();
        handles.push(std::thread::spawn(move || {
            let gate_id = parsed::<GateId>(&format!("gate-{worker}"));
            gate.lock()
                .expect("lock")
                .admit(&ticket, &gate_id, T0 + HOUR_US, &ticket_ring())
                .is_admitted()
        }));
    }
    let admitted = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(admitted, 1, "one ticket is one passage");
    assert_eq!(gate.lock().expect("lock").guard().claims_len(), 1);
}

#[test]
fn concurrent_distinct_tickets_all_count_once() {
    let gate = Arc::new(Mutex::new(guard_with_capacity(2_048)));

    let mut handles = Vec::new();
    for worker in 0..8u64 {
        let gate = Arc::clone(&gate);
        handles.push(std::thread::spawn(move || {
            let mut admitted = 0;
            for index in 0..50u64 {
                let ticket = issue_ticket(1_000 + worker * 50 + index, "gate-n1");
                if gate
                    .lock()
                    .expect("lock")
                    .admit(&ticket, &parsed("gate-n1"), T0 + HOUR_US, &ticket_ring())
                    .is_admitted()
                {
                    admitted += 1;
                }
            }
            admitted
        }));
    }
    let admitted: u64 = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .sum();
    assert_eq!(admitted, 400);
    let gate = gate.lock().expect("lock");
    assert_eq!(gate.guard().len(), 400);
    assert_eq!(gate.guard().claims_len(), 400);
}
