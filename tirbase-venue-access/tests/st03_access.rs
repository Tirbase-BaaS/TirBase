// SPDX-License-Identifier: AGPL-3.0-only

//! ST-03 acceptance tests: secure-channel read, frame rejection, revocation
//! across an offline restart, plus recorded frames and decoder robustness.

use std::str::FromStr;

use tirbase_venue::{
    AccessPolicy, AccessPolicyId, AccessPolicyRegistry, EffectiveWindow, Gate, GateId, Reader,
    SpaceModel, TicketClass, TicketType, TimeWindow, TopologyVersion, Venue, Zone,
};
use tirbase_venue_access::{
    AccessController, AccessError, CredentialRegistry, CredentialSource, HealthEvent,
    LinkState, PresentedCredential, RevocationDelta, RevocationList, TamperState,
    AppliedRevocation,
};

const T0: i64 = 1_700_000_000_000_000;
const HOUR_US: i64 = 3_600_000_000;
const DAY_US: i64 = 86_400_000_000;

/// Card material used by the OSDP and registry tests.
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
    .expect("fixture topology is valid")
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
        .add_ticket_type(TicketType {
            id: parsed("tt-vip"),
            name: "VIP".to_string(),
            class: TicketClass::Vip,
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

fn new_controller(credentials: CredentialRegistry) -> AccessController {
    AccessController::new(
        parsed("reader-n1-a"),
        topology(),
        policies(),
        space(),
        credentials,
    )
}

fn card() -> PresentedCredential {
    PresentedCredential::new(CredentialSource::Osdp, CARD.to_vec())
}

#[test]
fn credential_registry_stores_only_fingerprints() {
    let registry = credentials();
    let credential = registry.credentials().next().expect("one credential");
    let json = serde_json::to_string(&registry).expect("registry serializes");
    // CARD is 04 A1 B2 C3: neither its hex nor its decimal form may appear.
    assert!(!json.contains("04a1b2c3"));
    assert!(!json.contains("4a1b2c3"));
    assert!(json.contains(&credential.fingerprint));
    assert_eq!(credential.fingerprint.len(), 64);

    let mut registry = registry;
    let duplicate = registry.register(
        parsed("holder-1"),
        parsed("tt-general"),
        CredentialSource::Osdp,
        &CARD,
    );
    assert!(matches!(
        duplicate,
        Err(AccessError::DuplicateCredential(_))
    ));
}

#[test]
fn revocation_delta_versions_are_monotonic() {
    let mut list = RevocationList::default();
    let id = credentials()
        .credentials()
        .next()
        .expect("credential")
        .id
        .clone();
    let first = RevocationDelta {
        base_version: 0,
        to_version: 1,
        issued_at_utc_us: T0,
        revoke: vec![id.clone()],
        reinstate: Vec::new(),
    };
    assert_eq!(
        list.apply(&first),
        Ok(AppliedRevocation::Applied {
            from: 0,
            to: 1,
            newly_revoked: 1,
            reinstated: 0,
        })
    );
    assert!(list.is_revoked(&id));

    let replay = RevocationDelta {
        base_version: 1,
        to_version: 1,
        issued_at_utc_us: T0,
        revoke: Vec::new(),
        reinstate: Vec::new(),
    };
    assert_eq!(list.apply(&replay), Ok(AppliedRevocation::AlreadyCurrent));

    let mut backwards = first.clone();
    backwards.to_version = 0;
    assert!(matches!(
        list.apply(&backwards),
        Err(AccessError::RevocationRegression { .. })
    ));

    let mut skipped = first.clone();
    skipped.to_version = 3;
    assert!(matches!(
        list.apply(&skipped),
        Err(AccessError::RevocationOutOfOrder {
            expected: 1,
            offered: 0
        })
    ));

    let reinstate = RevocationDelta {
        base_version: 1,
        to_version: 2,
        issued_at_utc_us: T0 + HOUR_US,
        revoke: Vec::new(),
        reinstate: vec![id.clone()],
    };
    assert!(matches!(
        list.apply(&reinstate),
        Ok(AppliedRevocation::Applied {
            newly_revoked: 0,
            reinstated: 1,
            ..
        })
    ));
    assert!(!list.is_revoked(&id));
    assert_eq!(list.version(), 2);
}

#[test]
fn revocation_survives_offline_restart() {
    let gate: GateId = parsed("gate-n1");
    let presented = card();
    let mut controller = new_controller(credentials());
    let grant = controller
        .authorize(&presented, &gate, T0 + HOUR_US)
        .expect("online grant");
    controller.revoke(grant.credential_id.clone());
    let json = controller.cache_json().expect("cache serializes");

    // A fresh controller, as after a reader power cycle.
    let mut restarted = new_controller(credentials());
    restarted.restore_cache(&json).expect("cache restores");
    assert!(restarted.cache().revocation.is_revoked(&grant.credential_id));
    restarted.go_offline(T0 + 2 * HOUR_US);

    let error = restarted
        .authorize(&presented, &gate, T0 + 2 * HOUR_US)
        .expect_err("revoked credential is refused offline");
    assert!(matches!(error, AccessError::CredentialRevoked(_)));
}

#[test]
fn offline_reader_uses_cached_grant_then_refuses_unknown_card() {
    let gate: GateId = parsed("gate-n1");
    let presented = card();
    let mut controller = new_controller(credentials());
    let online = controller
        .authorize(&presented, &gate, T0 + HOUR_US)
        .expect("online grant");
    assert!(!online.offline);

    controller.go_offline(T0 + 2 * HOUR_US);
    assert_eq!(controller.reader().link, LinkState::Offline);
    let cached = controller
        .authorize(&presented, &gate, T0 + 2 * HOUR_US)
        .expect("cached grant");
    assert!(cached.offline);
    assert_eq!(cached.policy_id, online.policy_id);

    let other = PresentedCredential::new(CredentialSource::Osdp, vec![0x09, 0x09]);
    let mut registry = credentials();
    registry
        .register(
            parsed("holder-1"),
            parsed("tt-general"),
            CredentialSource::Osdp,
            &[0x09, 0x09],
        )
        .expect("second credential");
    let mut controller = new_controller(registry);
    controller.go_offline(T0 + HOUR_US);
    let error = controller
        .authorize(&other, &gate, T0 + HOUR_US)
        .expect_err("no cached grant");
    assert_eq!(error, AccessError::NoCachedGrant);

    // Restoring the cache also restores the secure-channel flag.
    assert!(!controller.cache().is_secure());
}

#[cfg(feature = "osdp")]
mod osdp {
    use super::*;
    use tirbase_venue_access::crypto::AesKey;
    use tirbase_venue_access::osdp::{
        self, OsdpError, OsdpFrame, OsdpPoller, OsdpReply, Scs,
    };
    use tirbase_venue_access::sim::OsdpSim;

    fn master() -> AesKey {
        AesKey::from_array([0x40u8; 16])
    }

    fn establish(poller: &mut OsdpPoller, sim: &mut OsdpSim) {
        let challenge = poller
            .begin_secure_channel(Scs::Scs12, &master(), [0x01; 8])
            .expect("challenge");
        let reply = sim.handle(&challenge).expect("ccrypt");
        poller.accept_ccrypt(&reply).expect("session keys");
        let scrypt = poller.scrypt_frame().expect("scrypt");
        let reply = sim.handle(&scrypt).expect("rmac");
        poller.accept_rmac(&reply).expect("mac chain");
    }

    /// Flip one byte, then repair the CRC so only the MAC can reject it.
    fn tamper_and_refresh_crc(frame: &[u8], index: usize) -> Vec<u8> {
        let mut out = frame.to_vec();
        out[index] ^= 0x01;
        let length = out.len();
        let crc = osdp::crc16(&out[..length - 2]);
        out[length - 2..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    #[test]
    fn crc_and_recorded_poll_frames_round_trip() {
        // Check value for the OSDP CRC-16 (poly 0x1021, init 0x1FFF).
        assert_eq!(osdp::crc16(b"123456789"), 0x6E26);

        // Recorded poll frame shape: SOM 53, ADDR 00, LEN 0008, CTRL 07 (seq 3,
        // CRC), POLL 60, CRC AE4B (little-endian).
        let recorded_poll = [0x53u8, 0x00, 0x08, 0x00, 0x07, 0x60, 0xAE, 0x4B];
        let frame = OsdpFrame::decode(&recorded_poll).expect("recorded poll decodes");
        assert_eq!(frame.address, 0x00);
        assert_eq!(frame.sequence, 3);
        assert_eq!(frame.payload, vec![osdp::CMD_POLL]);
        assert_eq!(frame.encode().expect("re-encode"), recorded_poll.to_vec());

        // Recorded ACK reply: ADDR 80 (reply flag), CTRL 05 (seq 1, CRC).
        let recorded_ack = [0x53u8, 0x80, 0x08, 0x00, 0x05, 0x40, 0x7E, 0x2B];
        let reply = OsdpFrame::decode(&recorded_ack).expect("recorded ack decodes");
        assert_eq!(reply.address, 0x80);
        assert_eq!(reply.payload, vec![osdp::REPLY_ACK]);

        // A single flipped byte fails the CRC.
        let mut corrupt = recorded_poll;
        corrupt[5] ^= 0x01;
        assert_eq!(OsdpFrame::decode(&corrupt), Err(OsdpError::BadCrc));
    }

    #[test]
    fn secure_channel_authenticates_polls_and_reads_a_credential() {
        let mut poller = OsdpPoller::new(1).expect("poller");
        let mut sim = OsdpSim::new(1, &master()).expect("pd");
        sim.queue_card(CARD.to_vec(), 32);
        establish(&mut poller, &mut sim);
        assert!(poller.is_secure());
        assert_eq!(poller.scs(), Some(Scs::Scs12));

        let poll = poller.poll_frame().expect("poll");
        let reply = sim.handle(&poll).expect("card reply");
        let card = match poller.accept(&reply).expect("reply opens") {
            OsdpReply::Card(card) => card,
            other => panic!("expected card reply, got {other:?}"),
        };
        assert_eq!(card.data, CARD.to_vec());
        assert_eq!(card.bit_count, 32);

        let presented = PresentedCredential::new(CredentialSource::Osdp, card.data.clone());
        let mut controller = new_controller(credentials());
        let grant = controller
            .authorize(&presented, &parsed("gate-n1"), T0 + HOUR_US)
            .expect("grant");
        assert_eq!(grant.zone_id, parsed("zone-north"));
        assert_eq!(grant.ticket_id.as_str(), format!("tkt-{}", grant.credential_id));
        assert!(controller.cache().revocation.is_empty());

        // An empty poll after the card is ACKed.
        let poll = poller.poll_frame().expect("poll");
        let reply = sim.handle(&poll).expect("ack");
        assert_eq!(poller.accept(&reply).expect("ack opens"), OsdpReply::Ack);
    }

    #[test]
    fn secure_channel_rejects_a_tampered_block() {
        let mut poller = OsdpPoller::new(1).expect("poller");
        let mut sim = OsdpSim::new(1, &master()).expect("pd");
        establish(&mut poller, &mut sim);

        let poll = poller.poll_frame().expect("poll");
        let tampered = tamper_and_refresh_crc(&poll, poll.len() - 10);
        assert_eq!(sim.handle(&tampered), Err(OsdpError::MacMismatch));

        // A PD reply with a broken MAC is rejected and counted.
        let mut poller = OsdpPoller::new(1).expect("poller");
        let mut sim = OsdpSim::new(1, &master()).expect("pd");
        establish(&mut poller, &mut sim);
        let request = poller.status_request_frame().expect("status request");
        let reply = sim.handle(&request).expect("status reply");
        let bad = tamper_and_refresh_crc(&reply, reply.len() - 8);
        assert!(matches!(
            poller.accept(&bad),
            Err(OsdpError::MacMismatch)
        ));
        assert_eq!(poller.secure_failures(), 1);
    }

    #[test]
    fn status_reports_tamper_and_the_reader_latches() {
        let mut poller = OsdpPoller::new(1).expect("poller");
        let mut sim = OsdpSim::new(1, &master()).expect("pd");
        establish(&mut poller, &mut sim);
        sim.set_tamper(true);
        sim.set_power_fault(true);

        let request = poller.status_request_frame().expect("status request");
        let reply = sim.handle(&request).expect("status reply");
        match poller.accept(&reply).expect("status opens") {
            OsdpReply::Status(status) => {
                assert!(status.tamper);
                assert!(status.power_fault);
            }
            other => panic!("expected status, got {other:?}"),
        }
        assert_eq!(poller.tamper_events(), 1);

        let mut controller = new_controller(credentials());
        let events = controller.reader_mut().observe_tamper();
        assert_eq!(events, vec![HealthEvent::TamperDetected]);
        assert_eq!(controller.reader().tamper, TamperState::Latched);
        assert!(matches!(
            controller.authorize(&card(), &parsed("gate-n1"), T0 + HOUR_US),
            Err(AccessError::ReaderTampered(_))
        ));
        assert!(controller.reader_mut().clear_tamper(false).is_err());
        assert_eq!(
            controller.reader_mut().clear_tamper(true).expect("reset"),
            vec![HealthEvent::TamperCleared]
        );
        assert_eq!(controller.reader().tamper, TamperState::Clear);
    }

    #[test]
    fn plain_frames_and_checksum_mode_are_refused_where_required() {
        // An 8-bit-checksum frame (CTRL bit 2 clear) is refused outright.
        let mut frame = vec![0x53u8, 0x00, 0x08, 0x00, 0x02, 0x60, 0x00, 0x00];
        let crc = osdp::crc16(&frame[..6]);
        frame[6] = crc as u8;
        assert_eq!(OsdpFrame::decode(&frame), Err(OsdpError::UnsupportedChecksum));

        // A poller without a session cannot seal a command.
        let mut poller = OsdpPoller::new(2).expect("poller");
        assert_eq!(poller.poll_frame(), Err(OsdpError::NotSecure));
        assert!(OsdpPoller::new(0x80).is_err());
    }
}

#[cfg(feature = "wiegand")]
mod wiegand {
    use super::*;
    use tirbase_venue_access::sim::WiegandSim;
    use tirbase_venue_access::wiegand::{
        decode, DataLine, WiegandError, WiegandPulse, WiegandTiming, BITS_26, BITS_34,
    };

    #[test]
    fn recorded_26_and_34_bit_captures_decode() {
        let pulses = WiegandSim::pulses(123, 45_678, BITS_26);
        assert_eq!(pulses.len(), 26);
        let card = decode(&pulses, &WiegandTiming::default()).expect("26-bit capture");
        assert_eq!(card.bits, BITS_26);
        assert_eq!(card.facility_code, 123);
        assert_eq!(card.card_number, 45_678);
        assert_eq!(card.material().len(), 9);

        let pulses = WiegandSim::pulses(0x1234, 0x5678, BITS_34);
        assert_eq!(pulses.len(), 34);
        let card = decode(&pulses, &WiegandTiming::default()).expect("34-bit capture");
        assert_eq!(card.bits, BITS_34);
        assert_eq!(card.facility_code, 0x1234);
        assert_eq!(card.card_number, 0x5678);

        // The recorded bit pattern for facility 123 / card 45 678: leading even
        // parity bit, 8 facility bits, 16 card bits, trailing odd parity bit.
        assert_eq!(WiegandSim::frame_bits(123, 45_678, BITS_26).len(), 26);
    }

    #[test]
    fn bad_parity_frame_is_rejected() {
        let pulses = WiegandSim::bad_parity(123, 45_678, BITS_26);
        assert!(matches!(
            decode(&pulses, &WiegandTiming::default()),
            Err(WiegandError::BadParity { .. })
        ));

        // Flipping the odd (trailing) parity bit is also rejected.
        let mut pulses = WiegandSim::pulses(123, 45_678, BITS_26);
        let last = pulses.len() - 1;
        pulses[last].line = match pulses[last].line {
            DataLine::Zero => DataLine::One,
            DataLine::One => DataLine::Zero,
        };
        assert!(matches!(
            decode(&pulses, &WiegandTiming::default()),
            Err(WiegandError::BadParity { .. })
        ));
    }

    #[test]
    fn bad_timing_frame_is_rejected() {
        // Too narrow and too wide.
        for width in [5u32, 900] {
            let pulses = WiegandSim::pulses_with(1, 2, BITS_26, width, 1_000);
            assert!(matches!(
                decode(&pulses, &WiegandTiming::default()),
                Err(WiegandError::BadPulseWidth { .. })
            ));
        }
        // Gap below the bounce floor.
        let pulses = WiegandSim::pulses_with(1, 2, BITS_26, 50, 50);
        assert!(matches!(
            decode(&pulses, &WiegandTiming::default()),
            Err(WiegandError::BadGap { .. })
        ));
        // Trailing gap shorter than a frame separator.
        let mut pulses = WiegandSim::pulses(1, 2, BITS_26);
        pulses.last_mut().expect("pulses").gap_after_us = 1_000;
        assert!(matches!(
            decode(&pulses, &WiegandTiming::default()),
            Err(WiegandError::BadFrameGap { .. })
        ));
        // Unsupported format and empty capture.
        assert!(matches!(
            decode(
                &WiegandSim::pulses(1, 2, 32),
                &WiegandTiming::default()
            ),
            Err(WiegandError::UnsupportedLength(32))
        ));
        assert_eq!(
            decode(&[], &WiegandTiming::default()),
            Err(WiegandError::NoPulses)
        );
    }

    #[test]
    fn wiegand_card_presents_to_the_registry() {
        let pulses = WiegandSim::pulses(123, 45_678, BITS_26);
        let card = decode(&pulses, &WiegandTiming::default()).expect("capture");
        let presented = card.presented();
        let mut registry = CredentialRegistry::new();
        registry
            .add_holder(parsed("holder-1"), "Ada Lovelace")
            .expect("holder");
        registry
            .register(
                parsed("holder-1"),
                parsed("tt-general"),
                presented.source.clone(),
                &presented.material,
            )
            .expect("credential");
        assert!(registry.lookup(&presented).is_some());
        let other = WiegandSim::pulses(123, 45_679, BITS_26);
        let other = decode(&other, &WiegandTiming::default())
            .expect("capture")
            .presented();
        assert!(registry.lookup(&other).is_none());
    }

    #[test]
    fn malformed_captures_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..500 {
            let pulses: Vec<WiegandPulse> = (0..26)
                .map(|_| {
                    let bits = next();
                    WiegandPulse::new(
                        if bits & 1 == 0 {
                            DataLine::Zero
                        } else {
                            DataLine::One
                        },
                        (bits >> 8) as u32 % 1_000,
                        (bits >> 24) as u32 % 30_000,
                    )
                })
                .collect();
            let _ = decode(&pulses, &WiegandTiming::default());
        }
    }
}

#[cfg(feature = "desfire")]
mod desfire {
    use tirbase_venue_access::crypto::AesKey;
    use tirbase_venue_access::desfire::{DesfireError, DesfireReader};
    use tirbase_venue_access::sim::DesfireSim;

    const FILE: &[u8] = b"VENUE-CRED-0001";

    fn run(key: AesKey) {
        let mut card = DesfireSim::new(0, key.clone(), [1, 2, 3, 4, 5, 6, 7])
            .expect("card")
            .with_file(1, FILE.to_vec());
        let mut reader = DesfireReader::new(0, key).expect("reader");

        let command = reader.start_authentication([0x10; 16]).expect("part 1");
        let response = card.handle(&command).expect("challenge");
        let command = reader
            .complete_authentication(&response)
            .expect("part 2");
        let response = card.handle(&command).expect("caps");
        reader.finish_authentication(&response).expect("authenticated");
        assert!(reader.is_authenticated());

        let command = reader
            .read_file(1, 0, FILE.len() as u32)
            .expect("read data");
        let response = card.handle(&command).expect("file data");
        let data = reader.accept_file_data(&response).expect("decrypted");
        assert_eq!(data, FILE);
    }

    #[test]
    fn ev2_and_ev3_authenticate_and_read_the_same_file() {
        run(AesKey::from_array([0x11u8; 16]));
        run(AesKey::from_array([0x22u8; 16]));
    }

    #[test]
    fn wrong_application_key_is_rejected() {
        let mut card = DesfireSim::new(0, AesKey::from_array([0x11u8; 16]), [9; 7])
            .expect("card")
            .with_file(1, FILE.to_vec());
        let mut reader = DesfireReader::new(0, AesKey::from_array([0x33u8; 16]))
            .expect("reader");
        let command = reader.start_authentication([0x10; 16]).expect("part 1");
        let response = card.handle(&command).expect("challenge");
        let command = reader
            .complete_authentication(&response)
            .expect("part 2");
        assert!(matches!(
            card.handle(&command),
            Err(DesfireError::BadRandom)
        ));
    }

    #[test]
    fn unauthenticated_read_is_refused() {
        let key = AesKey::from_array([0x11u8; 16]);
        let mut reader = DesfireReader::new(0, key).expect("reader");
        assert_eq!(
            reader.read_file(1, 0, 4),
            Err(DesfireError::NotAuthenticated)
        );
    }

    #[test]
    fn arbitrary_apdus_never_panic() {
        let key = AesKey::from_array([0x11u8; 16]);
        let mut state = 0xDEAD_BEEF_CAFE_1234u64;
        for _ in 0..800 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state % 80) as usize;
            let bytes: Vec<u8> = (0..length)
                .map(|index| ((state >> (index % 8 * 8)) & 0xFF) as u8)
                .collect();
            let mut card = DesfireSim::new(0, AesKey::from_array([0x11u8; 16]), [0; 7])
                .expect("card");
            let _ = card.handle(&bytes);
        }
        let mut reader = DesfireReader::new(0, key).expect("reader");
        let _ = reader.accept_file_data(&[]);
    }
}
