// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for POS-08: arbitrary device input never panics, decoded
//! frames re-encode canonically, and every endpoint stays inside its bounds.

use proptest::prelude::*;
use tirbase_pos::{
    CheckId, Gs1Data, HidKey, HidScanner, KdsCodec, KdsLine, KdsTicket, KdsTicketId, LineItemId,
    LineStatus, OrderId, Quantity, ScaleCodec, ScaleProtocol, ScannedCode, ScannerCodec,
    ScannerFraming, SimulatedScanner, Station, Symbology,
};

fn framing(choice: u8) -> ScannerFraming {
    match choice % 3 {
        0 => ScannerFraming {
            prefix: 0x02,
            suffix: 0x03,
            checksum: tirbase_pos::ScannerChecksum::None,
        },
        1 => ScannerFraming::stx_etx_xor(),
        _ => ScannerFraming {
            prefix: 0x02,
            suffix: 0x03,
            checksum: tirbase_pos::ScannerChecksum::Sum8,
        },
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_scale_frames_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..80),
    ) {
        for protocol in [ScaleProtocol::MettlerToledo, ScaleProtocol::CasBinary] {
            if let Ok(reading) = ScaleCodec::decode(protocol, &bytes) {
                let encoded = ScaleCodec::encode(protocol, &reading).unwrap();
                prop_assert!(encoded.len() <= tirbase_pos::MAX_SCALE_FRAME_BYTES);
                let again = ScaleCodec::decode(protocol, &encoded).unwrap();
                prop_assert_eq!(reading, again);
            }
        }
    }

    #[test]
    fn arbitrary_scanner_input_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..400),
        checksum in 0_u8..3,
        payload in proptest::collection::vec(0x20_u8..=0x7E, 1..200),
    ) {
        let frame = framing(checksum);
        let _ = ScannerCodec::decode_serial(&bytes, frame);
        let _ = ScannerCodec::decode_payload(&bytes, Symbology::Gs1);
        let _ = Gs1Data::parse(&bytes);

        let encoded = ScannerCodec::encode_serial(&payload, frame).unwrap();
        prop_assert!(encoded.len() <= frame.max_frame_bytes());
        let decoded = ScannerCodec::decode_serial(&encoded, frame).unwrap();
        prop_assert_eq!(decoded, payload.as_slice());
        let code: ScannedCode = ScannerCodec::decode_payload(decoded, Symbology::Plain).unwrap();
        prop_assert_eq!(code.raw(), payload.as_slice());
    }

    #[test]
    fn arbitrary_hid_key_streams_never_panic(
        keys in proptest::collection::vec(
            prop_oneof![
                any::<char>().prop_map(HidKey::Character),
                Just(HidKey::Enter),
                Just(HidKey::Tab)
            ],
            0..80,
        ),
        max_bytes in 1_usize..64,
    ) {
        let scanner = SimulatedScanner::hid(keys);
        let mut scanner = HidScanner::new(scanner, Symbology::Plain, max_bytes).unwrap();
        if let Ok(code) = scanner.scan() {
            prop_assert!(code.raw().len() <= max_bytes);
            prop_assert!(code.raw().iter().all(|byte| (0x20..=0x7E).contains(byte)));
        }
    }

    #[test]
    fn arbitrary_kds_frames_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let _ = KdsCodec::decode_ticket(&bytes);
        let _ = KdsCodec::decode_ack(&bytes);
    }

    #[test]
    fn kds_tickets_round_trip_within_the_bound(
        name in "[A-Za-z0-9 %|._:@/-]{1,40}",
        sequence in any::<u64>(),
        thousandths in 1_i64..1_000_000,
    ) {
        let line = KdsLine::new(
            LineItemId::new("line-1").unwrap(),
            name,
            Quantity::from_thousandths(thousandths).unwrap(),
            Station::Grill,
            LineStatus::Queued,
        ).unwrap();
        let ticket = KdsTicket::new(
            KdsTicketId::new("ticket-1").unwrap(),
            OrderId::new("order-1").unwrap(),
            CheckId::new("check-1").unwrap(),
            sequence,
            vec![line],
        ).unwrap();
        let encoded = KdsCodec::encode_ticket(&ticket).unwrap();
        prop_assert!(encoded.len() <= tirbase_pos::MAX_KDS_TICKET_BYTES);
        let decoded = KdsCodec::decode_ticket(&encoded).unwrap();
        prop_assert_eq!(KdsCodec::encode_ticket(&decoded).unwrap(), encoded);
        prop_assert_eq!(decoded, ticket);
    }
}
