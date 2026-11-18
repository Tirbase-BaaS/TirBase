// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for POS-07: arbitrary device bytes never panic, arbitrary
//! text never exceeds the codec capacity, and a receipt job is either fully
//! encoded inside its bound or rejected before any write.

use proptest::prelude::*;
use tirbase_pos::{
    decode_status_response, Currency, EscPosCodec, EscPosError, Money, QrOptions, Receipt,
    ReceiptLine, ReceiptPrinter, SimulatedPrinter, StatusKind,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_status_responses_never_panic(
        kind in 1_u8..=4,
        response in proptest::collection::vec(any::<u8>(), 0..24),
    ) {
        let kind = StatusKind::try_from(kind).unwrap();
        let decoded = decode_status_response(kind, &response);
        match decoded {
            Ok(status) => {
                prop_assert!(!response.is_empty());
                prop_assert_eq!(status.raw(), response[0]);
                prop_assert_eq!(status.kind(), kind);
            }
            Err(error) => {
                prop_assert!(
                    matches!(
                        error,
                        EscPosError::EmptyStatusResponse | EscPosError::OversizedStatusResponse
                    ),
                    "unexpected decode error: {error:?}"
                );
            }
        }
    }

    #[test]
    fn arbitrary_text_is_bounded_or_rejected(
        text in ".{0,300}",
        capacity in 1_usize..2048,
    ) {
        let mut codec = EscPosCodec::new(capacity).unwrap();
        match codec.text(&text) {
            Ok(()) => prop_assert!(codec.len() <= capacity),
            Err(EscPosError::BufferFull { capacity: reported }) => {
                prop_assert_eq!(reported, capacity);
                prop_assert!(codec.len() <= capacity);
            }
            Err(EscPosError::InvalidTextLength)
            | Err(EscPosError::ControlCharacter)
            | Err(EscPosError::UnencodableCharacter(_)) => {
                prop_assert!(codec.len() <= capacity);
            }
            Err(other) => prop_assert!(false, "unexpected text error: {other:?}"),
        }
    }

    #[test]
    fn arbitrary_qr_payloads_are_bounded_or_rejected(
        data in ".{0,1200}",
        capacity in 1_usize..4096,
    ) {
        let mut codec = EscPosCodec::new(capacity).unwrap();
        match codec.qr_code(&data, QrOptions::default()) {
            Ok(()) => prop_assert!(codec.len() <= capacity),
            Err(EscPosError::BufferFull { capacity: reported }) => {
                prop_assert_eq!(reported, capacity);
                prop_assert!(codec.len() <= capacity);
            }
            Err(EscPosError::InvalidQrData) => prop_assert!(codec.len() <= capacity),
            Err(other) => prop_assert!(false, "unexpected QR error: {other:?}"),
        }
    }

    #[test]
    fn a_receipt_job_never_exceeds_its_capacity(
        title in "[A-Za-z ]{1,24}",
        description in "[A-Za-z ]{1,24}",
        amount in 0_i64..100_000,
        capacity in 1_usize..4096,
    ) {
        let receipt = Receipt::new(
            title,
            money(amount),
            money(0),
            money(0),
            money(0),
            money(amount),
        );
        let receipt = match receipt {
            Ok(receipt) => receipt,
            // A whitespace-only title is rejected by receipt validation.
            Err(_) => return Ok(()),
        };
        let mut receipt = receipt;
        let line = match ReceiptLine::new(description, "1", money(amount)) {
            Ok(line) => line,
            Err(_) => return Ok(()),
        };
        receipt.push_line(line).unwrap();

        let mut printer = ReceiptPrinter::new(SimulatedPrinter::ready(), capacity).unwrap();
        match printer.print_receipt(&receipt) {
            Ok(outcome) => prop_assert!(outcome.bytes_written <= capacity),
            Err(_) => {
                // Rejection must happen before a receipt job is written; the
                // only permitted bytes are the fixed three-byte status query.
                let sim = printer.into_transport();
                let query = EscPosCodec::status_query_bytes(StatusKind::Printer);
                prop_assert!(sim.writes().iter().all(|write| write == &query));
            }
        }
    }
}
