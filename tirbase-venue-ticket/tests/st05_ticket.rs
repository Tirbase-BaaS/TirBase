// SPDX-License-Identifier: AGPL-3.0-only

//! ST-05 acceptance tests and property tests for the offline ticket kernel.

use std::str::FromStr;

use proptest::prelude::*;
use tirbase_venue::{GateId, TicketId, VenueId, ZoneId};
use tirbase_venue_ticket::{
    Denial, Ed25519Signer, EventId, HolderBinding, HolderKind, HolderPolicy, IssuerKeyRing,
    OfflineValidator, ReplayStore, SignedRevocationList, SignedTicket, StaleRevocationPolicy,
    TicketPayload, TicketRevocationList, ValidationRequest, ValidatorPolicy, VenueScope,
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

fn scope() -> VenueScope {
    VenueScope::new(
        EventId::new("event-1").expect("event id"),
        parsed("venue-1"),
        parsed("gate-n1"),
        parsed("zone-north"),
    )
}

fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed("issuer-1", [7u8; 32])
}

fn other_issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed("issuer-2", [8u8; 32])
}

fn ring() -> IssuerKeyRing {
    let mut ring = IssuerKeyRing::new();
    ring.add_public_key(
        "issuer-1",
        issuer().verifying_key(),
        T0 - DAY_US,
        T0 + 365 * DAY_US,
    )
    .expect("issuer key");
    ring
}

fn payload(nonce: u64) -> TicketPayload {
    TicketPayload::new(parsed("ticket-1"), scope(), T0, T0 + 8 * HOUR_US, nonce)
        .expect("payload")
}

fn ticket(nonce: u64) -> SignedTicket {
    SignedTicket::sign(payload(nonce), &issuer()).expect("signed ticket")
}

fn request_at(at_utc_us: i64) -> ValidationRequest {
    ValidationRequest::new(scope(), at_utc_us)
}

fn list(version: u64, expires_at_utc_us: i64, revoked: Vec<TicketId>) -> SignedRevocationList {
    SignedRevocationList::sign(
        TicketRevocationList::new(version, T0 - HOUR_US, expires_at_utc_us, revoked)
            .expect("list"),
        &issuer(),
    )
    .expect("signed list")
}

fn standard_validator() -> OfflineValidator {
    let mut validator = OfflineValidator::new(
        ring(),
        ReplayStore::new(64, DAY_US).expect("replay store"),
        ValidatorPolicy::standard(),
    );
    validator
        .refresh_revocation(&list(1, T0 + 30 * DAY_US, Vec::new()), T0)
        .expect("list applies");
    validator
}

fn validator_with_policy(policy: ValidatorPolicy) -> OfflineValidator {
    let mut validator = OfflineValidator::new(
        ring(),
        ReplayStore::new(64, DAY_US).expect("replay store"),
        policy,
    );
    validator
        .refresh_revocation(&list(1, T0 + 30 * DAY_US, Vec::new()), T0)
        .expect("list applies");
    validator
}

// --- done-when ---------------------------------------------------------

#[test]
fn a_valid_ticket_validates_offline() {
    let mut validator = standard_validator();
    let admission = validator
        .validate(&ticket(1), &request_at(T0 + HOUR_US))
        .expect("valid ticket");
    assert_eq!(admission.ticket_id, parsed("ticket-1"));
    assert_eq!(admission.event_id, EventId::new("event-1").unwrap());
    assert_eq!(admission.venue_id, parsed("venue-1"));
    assert_eq!(admission.gate_id, parsed("gate-n1"));
    assert_eq!(admission.zone_id, parsed("zone-north"));
    assert_eq!(admission.nonce, 1);
    assert!(!admission.holder_bound);
    assert!(validator.replay_store().contains("ticket-1#1"));
    assert_eq!(validator.revocation_version(), 1);
}

#[test]
fn a_replayed_ticket_is_denied() {
    let mut validator = standard_validator();
    validator
        .validate(&ticket(9), &request_at(T0 + HOUR_US))
        .expect("first admission");
    let denial = validator
        .validate(&ticket(9), &request_at(T0 + HOUR_US + 1_000))
        .expect_err("second presentation is a replay");
    assert_eq!(
        denial,
        Denial::Replayed {
            ticket_id: parsed("ticket-1"),
            nonce: 9,
        }
    );
    assert_eq!(denial.code(), "replayed");

    // A re-issued ticket (new nonce) is a different presentation.
    let mut validator = standard_validator();
    validator
        .validate(&ticket(1), &request_at(T0 + HOUR_US))
        .expect("first");
    validator
        .validate(&ticket(2), &request_at(T0 + HOUR_US))
        .expect("new nonce admits");
}

#[test]
fn a_revoked_ticket_is_denied() {
    let mut validator = OfflineValidator::new(
        ring(),
        ReplayStore::new(64, DAY_US).expect("store"),
        ValidatorPolicy::standard(),
    );
    validator
        .refresh_revocation(
            &list(1, T0 + 30 * DAY_US, vec![parsed("ticket-1")]),
            T0,
        )
        .expect("revocation list");
    let denial = validator
        .validate(&ticket(1), &request_at(T0 + HOUR_US))
        .expect_err("revoked");
    assert_eq!(
        denial,
        Denial::RevokedTicket {
            ticket_id: parsed("ticket-1")
        }
    );
    assert_eq!(denial.code(), "revoked_ticket");
}

#[test]
fn an_expired_revocation_list_fails_closed_or_alarms_per_policy() {
    let fail_closed = ValidatorPolicy {
        stale_list: StaleRevocationPolicy::FailClosed,
        ..ValidatorPolicy::standard()
    };
    let mut validator = validator_with_policy(fail_closed);
    // Replace the fresh list with one that expires before the scan.
    validator
        .refresh_revocation(&list(2, T0 + 2 * HOUR_US, Vec::new()), T0)
        .expect("shorter list");
    let denial = validator
        .validate(&ticket(1), &request_at(T0 + 3 * HOUR_US))
        .expect_err("stale list fails closed");
    assert!(matches!(
        denial,
        Denial::RevocationListExpired { version: 2, .. }
    ));
    assert!(validator.alarm().is_none());

    let alarm_policy = ValidatorPolicy {
        stale_list: StaleRevocationPolicy::Alarm,
        ..ValidatorPolicy::standard()
    };
    let mut validator = validator_with_policy(alarm_policy);
    validator
        .refresh_revocation(&list(2, T0 + 2 * HOUR_US, Vec::new()), T0)
        .expect("shorter list");
    let denial = validator
        .validate(&ticket(1), &request_at(T0 + 3 * HOUR_US))
        .expect_err("stale list refuses");
    assert!(matches!(
        denial,
        Denial::RevocationListExpired { version: 2, .. }
    ));
    let alarm = validator.take_alarm().expect("alarm raised");
    assert_eq!(alarm.version, 2);
    assert_eq!(alarm.expired_at_utc_us, T0 + 2 * HOUR_US);
    assert!(validator.take_alarm().is_none());

    // No list at all is refused too.
    let mut bare = OfflineValidator::new(
        ring(),
        ReplayStore::new(64, DAY_US).expect("store"),
        ValidatorPolicy::standard(),
    );
    assert_eq!(
        bare.validate(&ticket(1), &request_at(T0 + HOUR_US)).unwrap_err(),
        Denial::RevocationListMissing
    );

    // Refreshing with an already-expired list is refused.
    let mut bare = OfflineValidator::new(
        ring(),
        ReplayStore::new(64, DAY_US).expect("store"),
        alarm_policy,
    );
    assert!(matches!(
        bare.refresh_revocation(&list(1, T0 + HOUR_US, Vec::new()), T0 + 2 * HOUR_US),
        Err(Denial::RevocationListExpired { .. })
    ));
    assert!(bare.alarm().is_some());
    assert_eq!(bare.revocation_version(), 0);
}

// --- key rotation and revocation refresh -------------------------------

#[test]
fn key_rotation_keeps_old_tickets_valid_only_for_the_overlap() {
    let mut ring = ring();
    let old_ticket = ticket(1);
    let rotation = ring
        .rotate(
            "issuer-2",
            other_issuer().verifying_key(),
            T0 + 2 * HOUR_US,
            HOUR_US,
            30 * DAY_US,
        )
        .expect("rotate");
    assert_eq!(rotation.previous_key_id.as_deref(), Some("issuer-1"));
    assert_eq!(rotation.overlap_ends_at_utc_us, T0 + 3 * HOUR_US);
    assert_eq!(ring.active_key_id(), Some("issuer-2"));

    let mut validator = OfflineValidator::new(
        ring.clone(),
        ReplayStore::new(64, DAY_US).expect("store"),
        ValidatorPolicy::standard(),
    );
    validator
        .refresh_revocation(&list(1, T0 + 30 * DAY_US, Vec::new()), T0)
        .expect("list");

    // Old ticket still verifies inside the overlap.
    validator
        .validate(&old_ticket, &request_at(T0 + 2 * HOUR_US + 30 * 60 * 1_000_000))
        .expect("overlap");

    // And fails once the overlap closes.
    let denial = validator
        .validate(&ticket(2), &request_at(T0 + 3 * HOUR_US + 1))
        .expect_err("retired key");
    assert!(matches!(denial, Denial::KeyExpired { .. }));

    // A ticket signed by the new key verifies.
    let new_ticket = SignedTicket::sign(payload(3), &other_issuer()).expect("sign");
    let mut validator = OfflineValidator::new(
        ring,
        ReplayStore::new(64, DAY_US).expect("store"),
        ValidatorPolicy::standard(),
    );
    validator
        .refresh_revocation(&list(1, T0 + 30 * DAY_US, Vec::new()), T0)
        .expect("list");
    validator
        .validate(&new_ticket, &request_at(T0 + 4 * HOUR_US))
        .expect("new key");
}

#[test]
fn a_revoked_issuer_key_verifies_nothing_even_inside_its_window() {
    let mut ring = ring();
    // A second key must vouch for the revocation list, so add it before the
    // first key is revoked.
    ring.rotate(
        "issuer-2",
        other_issuer().verifying_key(),
        T0 + 2 * HOUR_US,
        HOUR_US,
        30 * DAY_US,
    )
    .expect("second key");
    let ticket = ticket(1);
    ring.revoke("issuer-1", T0 + HOUR_US).expect("revoke");
    let mut validator = OfflineValidator::new(
        ring,
        ReplayStore::new(64, DAY_US).expect("store"),
        ValidatorPolicy::standard(),
    );
    let signed_list = SignedRevocationList::sign(
        TicketRevocationList::new(1, T0 - HOUR_US, T0 + 30 * DAY_US, Vec::new()).expect("list"),
        &other_issuer(),
    )
    .expect("sign");
    validator
        .refresh_revocation(&signed_list, T0 + 2 * HOUR_US + 1)
        .expect("list");
    assert_eq!(
        validator
            .validate(&ticket, &request_at(T0 + 2 * HOUR_US + 1))
            .unwrap_err()
            .code(),
        "key_revoked"
    );
}

#[test]
fn revocation_refresh_is_monotonic_and_signed() {
    let mut validator = standard_validator();
    let status = validator
        .refresh_revocation(&list(2, T0 + 31 * DAY_US, Vec::new()), T0 + HOUR_US)
        .expect("v2 applies");
    assert_eq!(status.version, 2);
    assert_eq!(status.revoked, 0);
    assert_eq!(validator.revocation_version(), 2);

    assert_eq!(
        validator.refresh_revocation(&list(1, T0 + 32 * DAY_US, Vec::new()), T0 + HOUR_US),
        Err(Denial::RevocationListRollback {
            applied: 2,
            offered: 1
        })
    );

    // Signed by a key the ring does not hold.
    let forged = SignedRevocationList::sign(
        TicketRevocationList::new(3, T0, T0 + 30 * DAY_US, Vec::new()).expect("list"),
        &Ed25519Signer::from_seed("issuer-x", [9u8; 32]),
    )
    .expect("sign");
    assert_eq!(
        validator.refresh_revocation(&forged, T0 + HOUR_US),
        Err(Denial::RevocationListSignature)
    );

    // JSON round trip.
    let json = validator
        .revocation_list()
        .expect("list")
        .signing_bytes("issuer-1")
        .expect("bytes");
    assert!(!json.is_empty());
    let encoded = signed_list_json(&list(2, T0 + 31 * DAY_US, Vec::new()));
    assert!(SignedRevocationList::from_json(&encoded).is_ok());
}

fn signed_list_json(list: &SignedRevocationList) -> String {
    list.to_json().expect("json")
}

// --- scope, time, holder, signature ------------------------------------

#[test]
fn wrong_scope_and_time_are_typed_denials() {
    let mut validator = standard_validator();
    let mut wrong = request_at(T0 + HOUR_US);
    wrong.scope.venue_id = VenueId::new("venue-2").expect("venue");
    assert!(matches!(
        validator.validate(&ticket(1), &wrong).unwrap_err(),
        Denial::WrongVenue { .. }
    ));

    let mut wrong = request_at(T0 + HOUR_US);
    wrong.scope.gate_id = GateId::new("gate-v1").expect("gate");
    assert!(matches!(
        validator.validate(&ticket(1), &wrong).unwrap_err(),
        Denial::WrongGate { .. }
    ));

    let mut wrong = request_at(T0 + HOUR_US);
    wrong.scope.zone_id = ZoneId::new("zone-vip").expect("zone");
    assert!(matches!(
        validator.validate(&ticket(1), &wrong).unwrap_err(),
        Denial::WrongZone { .. }
    ));

    let mut wrong = request_at(T0 + HOUR_US);
    wrong.scope.event_id = EventId::new("event-2").expect("event");
    assert!(matches!(
        validator.validate(&ticket(1), &wrong).unwrap_err(),
        Denial::WrongEvent { .. }
    ));

    assert_eq!(
        validator
            .validate(&ticket(1), &request_at(T0 - 1))
            .unwrap_err(),
        Denial::NotYetValid {
            valid_from_utc_us: T0
        }
    );
    assert_eq!(
        validator
            .validate(&ticket(1), &request_at(T0 + 8 * HOUR_US))
            .unwrap_err(),
        Denial::Expired {
            valid_until_utc_us: T0 + 8 * HOUR_US
        }
    );
}

#[test]
fn holder_binding_is_enforced_when_required() {
    let binding = HolderBinding::new(HolderKind::CredentialFingerprint, "aa11bb22")
        .expect("binding");
    let bound = SignedTicket::sign(payload(1).with_holder(binding.clone()), &issuer())
        .expect("signed");

    let mut validator = standard_validator();
    validator
        .validate(&bound, &request_at(T0 + HOUR_US).with_holder(binding.clone()))
        .expect("matching holder");

    let mut validator = standard_validator();
    assert_eq!(
        validator
            .validate(&bound, &request_at(T0 + HOUR_US))
            .unwrap_err(),
        Denial::HolderMismatch
    );

    let mut validator = standard_validator();
    let wrong = HolderBinding::new(HolderKind::CredentialFingerprint, "cc33dd44").expect("binding");
    assert_eq!(
        validator
            .validate(&bound, &request_at(T0 + HOUR_US).with_holder(wrong))
            .unwrap_err(),
        Denial::HolderMismatch
    );

    // Required policy refuses a ticket with no binding at all.
    let required = ValidatorPolicy {
        holder: HolderPolicy::Required,
        ..ValidatorPolicy::standard()
    };
    let mut validator = validator_with_policy(required);
    assert_eq!(
        validator
            .validate(&ticket(1), &request_at(T0 + HOUR_US))
            .unwrap_err(),
        Denial::HolderBindingRequired
    );

    // Ignore policy does not compare bindings.
    let ignore = ValidatorPolicy {
        holder: HolderPolicy::Ignore,
        ..ValidatorPolicy::standard()
    };
    let mut validator = validator_with_policy(ignore);
    validator
        .validate(&bound, &request_at(T0 + HOUR_US))
        .expect("ignored binding");
}

#[test]
fn signature_and_encoding_failures_are_typed() {
    let mut validator = standard_validator();

    let mut tampered = ticket(1);
    tampered.signature = "00".repeat(64);
    assert!(matches!(
        validator.validate(&tampered, &request_at(T0 + HOUR_US)).unwrap_err(),
        Denial::BadSignature { .. }
    ));

    let mut unknown = ticket(1);
    unknown.key_id = "issuer-404".to_string();
    assert!(matches!(
        validator.validate(&unknown, &request_at(T0 + HOUR_US)).unwrap_err(),
        Denial::UnknownIssuerKey { .. }
    ));

    let mut malformed = ticket(1);
    malformed.signature = "zz".to_string();
    assert!(matches!(
        validator.validate(&malformed, &request_at(T0 + HOUR_US)).unwrap_err(),
        Denial::BadSignature { .. }
    ));

    let mut wrong_payload = ticket(1);
    wrong_payload.payload.nonce = 2;
    assert!(matches!(
        validator
            .validate(&wrong_payload, &request_at(T0 + HOUR_US))
            .unwrap_err(),
        Denial::BadSignature { .. }
    ));
}

#[test]
fn payloads_are_deterministically_encoded_and_round_trip() {
    let first = payload(5);
    let second = payload(5);
    assert_eq!(
        first.canonical_bytes().expect("bytes"),
        second.canonical_bytes().expect("bytes")
    );
    assert_eq!(
        first.signing_bytes("issuer-1").expect("bytes"),
        second.signing_bytes("issuer-1").expect("bytes")
    );
    assert_ne!(
        first.canonical_bytes().expect("bytes"),
        payload(6).canonical_bytes().expect("bytes")
    );
    assert_ne!(
        first.signing_bytes("issuer-1").expect("bytes"),
        first.signing_bytes("issuer-2").expect("bytes")
    );

    let signed = SignedTicket::sign(first, &issuer()).expect("sign");
    let json = signed.to_json().expect("json");
    let restored = SignedTicket::from_json(&json).expect("parse");
    assert_eq!(restored, signed);
    assert!(TicketPayload::new(parsed("ticket-1"), scope(), T0, T0, 1).is_err());
    assert!(SignedTicket::from_json("not a ticket").is_err());
}

#[test]
fn replay_store_is_bounded_and_persists() {
    let mut store = ReplayStore::new(2, HOUR_US).expect("store");
    assert!(store.record("a".to_string(), T0));
    assert!(store.record("b".to_string(), T0 + 1));
    assert!(!store.record("a".to_string(), T0 + 2));
    // Capacity 2: admitting a third evicts the oldest.
    assert!(store.record("c".to_string(), T0 + 3));
    assert_eq!(store.len(), 2);
    assert_eq!(store.evicted(), 1);
    assert!(!store.contains("a"));

    // Retention prunes.
    store.prune(T0 + 2 * HOUR_US);
    assert!(store.is_empty());

    let json = store.to_json().expect("json");
    let restored = ReplayStore::from_json(&json).expect("parse");
    assert_eq!(restored, store);

    assert!(ReplayStore::new(0, HOUR_US).is_err());
    assert!(ReplayStore::new(1, 0).is_err());
    assert!(ReplayStore::new(1, i64::MAX).is_err());
}

// --- property tests ----------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn property_a_replay_is_always_denied(nonce in any::<u64>()) {
        let mut validator = standard_validator();
        let ticket = ticket(nonce);
        prop_assert!(validator.validate(&ticket, &request_at(T0 + HOUR_US)).is_ok());
        let denial = validator.validate(&ticket, &request_at(T0 + HOUR_US + 1)).unwrap_err();
        prop_assert_eq!(denial.code(), "replayed");
    }

    #[test]
    fn property_tickets_outside_their_window_are_denied(
        before in 1i64..10_000_000,
        after in 0i64..10_000_000,
    ) {
        let mut validator = standard_validator();
        let denial = validator.validate(&ticket(1), &request_at(T0 - before)).unwrap_err();
        prop_assert_eq!(denial.code(), "not_yet_valid");
        let mut validator = standard_validator();
        let denial = validator
            .validate(&ticket(1), &request_at(T0 + 8 * HOUR_US + after))
            .unwrap_err();
        prop_assert_eq!(denial.code(), "expired");
    }

    #[test]
    fn property_wrong_venue_or_gate_is_denied(suffix in 2u32..10_000) {
        let mut request = request_at(T0 + HOUR_US);
        request.scope.venue_id = VenueId::new(format!("venue-{suffix}")).expect("venue");
        let mut validator = standard_validator();
        prop_assert_eq!(
            validator.validate(&ticket(1), &request).unwrap_err().code(),
            "wrong_venue"
        );

        let mut request = request_at(T0 + HOUR_US);
        request.scope.gate_id = GateId::new(format!("gate-{suffix}")).expect("gate");
        let mut validator = standard_validator();
        prop_assert_eq!(
            validator.validate(&ticket(1), &request).unwrap_err().code(),
            "wrong_gate"
        );
    }

    #[test]
    fn property_any_corrupted_signature_is_denied(index in 0usize..128, step in 1u32..15) {
        let mut ticket = ticket(1);
        let index = index % 128;
        let mut chars: Vec<char> = ticket.signature.chars().collect();
        let current = chars[index].to_digit(16).expect("hex digit");
        chars[index] = char::from_digit((current + step) % 16, 16).expect("hex digit");
        ticket.signature = chars.into_iter().collect();
        let mut validator = standard_validator();
        let denial = validator.validate(&ticket, &request_at(T0 + HOUR_US)).unwrap_err();
        prop_assert_eq!(denial.code(), "bad_signature");
    }

    #[test]
    fn property_unknown_issuer_keys_are_denied(id in 1u32..1_000) {
        let mut ticket = ticket(1);
        ticket.key_id = format!("issuer-{id}");
        let mut validator = standard_validator();
        let denial = validator.validate(&ticket, &request_at(T0 + HOUR_US)).unwrap_err();
        prop_assert_eq!(denial.code(), "unknown_issuer_key");
    }
}
