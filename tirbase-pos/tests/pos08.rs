// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;

use tirbase_pos::{
    CheckId, Currency, DeviceTransport, Employee, EmployeeId, EmployeeRole, Gs1Data, Gs1Error,
    HidKey, HidScanner, KdsCodec, KdsCodecError, KdsEndpoint, KdsError, KdsLine, KdsSubmitOutcome,
    KdsTicket, KdsTicketId, LineItem, LineItemId, LineStatus, Money, OperationId, Order,
    OrderCommand, OrderId, Organization, Ownership, Quantity, RoundingMode, ScaleCodec,
    ScaleConfig, ScaleEndpoint, ScaleError, ScaleFault, ScaleFrameError, ScaleMode, ScaleProtocol,
    ScannedCode, ScannerChecksum, ScannerCodec, ScannerError, ScannerFrameError, ScannerFraming,
    SerialScanner, SimulatedKds, SimulatedScale, SimulatedScanner, Station, Store, StoreId,
    Symbology, Terminal, TerminalId, Timestamp, TransportError, Weight, WeightUnit,
};

#[derive(Default)]
struct ScriptedIo {
    chunks: VecDeque<Vec<u8>>,
    writes: Vec<Vec<u8>>,
}

impl ScriptedIo {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into(),
            writes: Vec::new(),
        }
    }
}

impl DeviceTransport for ScriptedIo {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.writes.push(bytes.to_vec());
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let Some(chunk) = self.chunks.pop_front() else {
            return Ok(0);
        };
        if chunk.len() > buf.len() {
            return Err(TransportError::ReadFailed);
        }
        buf[..chunk.len()].copy_from_slice(&chunk);
        Ok(chunk.len())
    }
}

struct TimeoutHid;

impl tirbase_pos::HidTransport for TimeoutHid {
    fn read_key(&mut self) -> Result<Option<HidKey>, TransportError> {
        Err(TransportError::Timeout)
    }
}

struct MisackedKds;

impl tirbase_pos::KdsTransport for MisackedKds {
    fn send(&mut self, _frame: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let ack = b"ACK other-ticket 7\n";
        if ack.len() > buf.len() {
            return Err(TransportError::ReadFailed);
        }
        buf[..ack.len()].copy_from_slice(ack);
        Ok(ack.len())
    }
}

fn kg(thousandths: i64) -> Weight {
    Weight::new(WeightUnit::Kilogram, thousandths).unwrap()
}

fn binary_frame(status: u8, sign: u8, digits: &[u8; 6], unit: u8) -> Vec<u8> {
    let mut frame = vec![0x02, status, sign];
    frame.extend_from_slice(digits);
    frame.push(unit);
    frame.push(0x03);
    let checksum = frame[1..].iter().fold(0_u8, |acc, byte| acc ^ byte);
    frame.push(checksum);
    frame
}

fn gs1_serial_frame(payload: &[u8]) -> Vec<u8> {
    ScannerCodec::encode_serial(payload, ScannerFraming::stx_etx_xor()).unwrap()
}

fn hid_keys(text: &str) -> Vec<HidKey> {
    let mut keys: Vec<HidKey> = text.chars().map(HidKey::Character).collect();
    keys.push(HidKey::Enter);
    keys
}

fn kds_line(id: &str, name: &str, thousandths: i64, station: Station) -> KdsLine {
    KdsLine::new(
        LineItemId::new(id).unwrap(),
        name,
        Quantity::from_thousandths(thousandths).unwrap(),
        station,
        LineStatus::Queued,
    )
    .unwrap()
}

fn ticket(sequence: u64) -> KdsTicket {
    KdsTicket::new(
        KdsTicketId::new("ticket-1").unwrap(),
        OrderId::new("order-1").unwrap(),
        CheckId::new("check-1").unwrap(),
        sequence,
        vec![
            kds_line("line-1", "Burger one", 2000, Station::Grill),
            kds_line("line-2", "Salad", 1000, Station::Cold),
        ],
    )
    .unwrap()
}

#[test]
fn recorded_scale_vectors_decode_and_encode_exactly() {
    let text = ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"ST,GS,+001.234,kg\r\n").unwrap();
    assert_eq!(text.weight, kg(1234));
    assert_eq!(text.weight.to_string(), "1.234 kg");
    assert!(text.stable);
    assert_eq!(text.mode, ScaleMode::Gross);
    assert_eq!(text.fault, None);
    assert_eq!(
        ScaleCodec::encode(ScaleProtocol::MettlerToledo, &text).unwrap(),
        b"ST,GS,+001.234,kg\r\n".to_vec()
    );

    let binary_frame = [
        0x02, 0x03, b'+', b'0', b'0', b'1', b'2', b'3', b'4', b'0', 0x03, 0x1F,
    ];
    let binary = ScaleCodec::decode(ScaleProtocol::CasBinary, &binary_frame).unwrap();
    assert_eq!(binary.weight, kg(1234));
    assert!(binary.stable);
    assert_eq!(binary.mode, ScaleMode::Net);
    assert_eq!(binary.fault, None);
    assert_eq!(
        ScaleCodec::encode(ScaleProtocol::CasBinary, &binary).unwrap(),
        binary_frame.to_vec()
    );

    let unstable =
        ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"US,NT,+000.000,g\r\n").unwrap();
    assert!(!unstable.stable);
    assert_eq!(unstable.mode, ScaleMode::Net);
    assert_eq!(unstable.weight, Weight::zero(WeightUnit::Gram));

    let overflow =
        ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"OL,GS,+999.999,kg\r\n").unwrap();
    assert_eq!(overflow.fault, Some(ScaleFault::Overflow));
    let underload =
        ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"UL,GS,+000.000,kg\r\n").unwrap();
    assert_eq!(underload.fault, Some(ScaleFault::Underload));
}

#[test]
fn malformed_scale_frames_are_rejected_without_panicking() {
    assert_eq!(
        ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"ST,GS,+001.234,kg").unwrap_err(),
        ScaleError::Frame(ScaleFrameError::Truncated)
    );
    assert_eq!(
        ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"ST,GS,+001.23,kg\r\n").unwrap_err(),
        ScaleError::Frame(ScaleFrameError::InvalidWeight)
    );
    assert_eq!(
        ScaleCodec::decode(ScaleProtocol::MettlerToledo, b"ST,GS,+001.234,st\r\n").unwrap_err(),
        ScaleError::Frame(ScaleFrameError::UnknownUnit)
    );
    let mut bad_checksum = binary_frame(0x01, b'+', b"001234", b'0');
    bad_checksum[11] ^= 0xFF;
    assert_eq!(
        ScaleCodec::decode(ScaleProtocol::CasBinary, &bad_checksum).unwrap_err(),
        ScaleError::Frame(ScaleFrameError::Checksum)
    );
    assert_eq!(
        ScaleCodec::decode(ScaleProtocol::CasBinary, &[0x02, 0x01]).unwrap_err(),
        ScaleError::Frame(ScaleFrameError::Truncated)
    );
    for byte in 0_u8..=255 {
        let _ = ScaleCodec::decode(ScaleProtocol::MettlerToledo, &[byte]);
        let _ = ScaleCodec::decode(ScaleProtocol::CasBinary, &[byte]);
    }
}

#[test]
fn stable_weight_requires_consecutive_identical_samples() {
    let mut scale = SimulatedScale::new(ScaleProtocol::MettlerToledo);
    scale.set_weight(kg(1500), true);
    let config = ScaleConfig {
        stable_samples: 2,
        stall_timeout_ms: 1_000,
    };
    let mut endpoint = ScaleEndpoint::new(scale, ScaleProtocol::MettlerToledo, config).unwrap();

    let first = endpoint.poll(0).unwrap().unwrap();
    assert_eq!(first.reading.weight, kg(1500));
    assert_eq!(first.stable_weight, None);

    let second = endpoint.poll(10).unwrap().unwrap();
    assert_eq!(second.stable_weight, Some(kg(1500)));
    assert_eq!(endpoint.stable_readings(), 1);
}

#[test]
fn an_unstable_frame_resets_stability() {
    let io = ScriptedIo::new(vec![
        b"ST,GS,+001.500,kg\r\n".to_vec(),
        b"US,GS,+001.500,kg\r\n".to_vec(),
        b"ST,GS,+001.500,kg\r\n".to_vec(),
        b"ST,GS,+001.500,kg\r\n".to_vec(),
    ]);
    let config = ScaleConfig {
        stable_samples: 2,
        stall_timeout_ms: 1_000,
    };
    let mut endpoint = ScaleEndpoint::new(io, ScaleProtocol::MettlerToledo, config).unwrap();
    assert!(endpoint.poll(0).unwrap().unwrap().stable_weight.is_none());
    assert!(endpoint.poll(10).unwrap().unwrap().stable_weight.is_none());
    assert!(endpoint.poll(20).unwrap().unwrap().stable_weight.is_none());
    assert_eq!(
        endpoint.poll(30).unwrap().unwrap().stable_weight,
        Some(kg(1500))
    );
    assert_eq!(endpoint.stable_readings(), 1);
}

#[test]
fn tare_reports_net_weight_after_a_command() {
    let mut scale = SimulatedScale::new(ScaleProtocol::CasBinary);
    scale.set_weight(kg(1500), true);
    let config = ScaleConfig {
        stable_samples: 1,
        stall_timeout_ms: 1_000,
    };
    let mut endpoint = ScaleEndpoint::new(scale, ScaleProtocol::CasBinary, config).unwrap();
    endpoint.tare(0).unwrap();
    assert_eq!(endpoint.tare_commands(), 1);
    let mut scale = endpoint.into_transport();
    assert_eq!(scale.tare_count(), 1);
    assert_eq!(scale.net_weight(), kg(0));
    assert_eq!(scale.writes(), [b"\x05".to_vec()]);

    // Placing another 0.25 kg leaves 0.25 kg net over the 1.5 kg tare.
    scale.set_weight(kg(1750), true);
    let mut endpoint = ScaleEndpoint::new(scale, ScaleProtocol::CasBinary, config).unwrap();
    let update = endpoint.poll(1).unwrap().unwrap();
    assert_eq!(update.reading.mode, ScaleMode::Net);
    assert_eq!(update.reading.weight, kg(250));
    assert_eq!(update.stable_weight, Some(kg(250)));
}

#[test]
fn scale_faults_are_surfaced_and_do_not_become_stable_weight() {
    let mut scale = SimulatedScale::new(ScaleProtocol::MettlerToledo);
    scale.set_weight(kg(100), true);
    scale.set_fault(Some(ScaleFault::Overflow));
    let config = ScaleConfig {
        stable_samples: 1,
        stall_timeout_ms: 1_000,
    };
    let mut endpoint = ScaleEndpoint::new(scale, ScaleProtocol::MettlerToledo, config).unwrap();
    let update = endpoint.poll(0).unwrap().unwrap();
    assert_eq!(update.reading.fault, Some(ScaleFault::Overflow));
    assert_eq!(update.stable_weight, None);
    assert_eq!(endpoint.stable_readings(), 0);

    endpoint
        .into_transport()
        .set_fault(Some(ScaleFault::Underload));
    let mut scale = SimulatedScale::new(ScaleProtocol::MettlerToledo);
    scale.set_fault(Some(ScaleFault::Underload));
    let mut endpoint = ScaleEndpoint::new(scale, ScaleProtocol::MettlerToledo, config).unwrap();
    let update = endpoint.poll(0).unwrap().unwrap();
    assert_eq!(update.reading.fault, Some(ScaleFault::Underload));
}

#[test]
fn a_stalled_scale_reports_a_timeout() {
    let mut scale = SimulatedScale::new(ScaleProtocol::MettlerToledo);
    scale.set_weight(kg(500), true);
    let config = ScaleConfig {
        stable_samples: 1,
        stall_timeout_ms: 100,
    };
    let mut endpoint = ScaleEndpoint::new(scale, ScaleProtocol::MettlerToledo, config).unwrap();
    endpoint.poll(0).unwrap().unwrap();
    assert_eq!(endpoint.poll(101).unwrap_err(), ScaleError::Timeout);
}

#[test]
fn a_partial_scale_frame_is_buffered_and_never_decoded() {
    let io = ScriptedIo::new(vec![b"ST,GS,+001.234,kg".to_vec()]);
    let mut endpoint =
        ScaleEndpoint::new(io, ScaleProtocol::MettlerToledo, ScaleConfig::default()).unwrap();
    assert!(endpoint.poll(0).unwrap().is_none());
    assert_eq!(endpoint.frames(), 0);
    assert!(endpoint.buffered_bytes() > 0);
}

#[test]
fn weights_convert_units_and_become_exact_quantities() {
    assert_eq!(kg(1234).to_quantity().unwrap().thousandths(), 1234);
    assert_eq!(
        Weight::new(WeightUnit::Gram, 1_234_000)
            .unwrap()
            .to_unit(WeightUnit::Kilogram)
            .unwrap(),
        kg(1234)
    );
    assert_eq!(
        Weight::new(WeightUnit::Pound, 1000)
            .unwrap()
            .to_unit(WeightUnit::Ounce)
            .unwrap()
            .thousandths(),
        16_000
    );
    assert_eq!(
        Weight::new(WeightUnit::Kilogram, 0).unwrap().to_quantity(),
        Err(ScaleError::InvalidWeight)
    );
}

#[test]
fn recorded_scanner_vectors_frame_exactly() {
    let payload = b"ABC123";
    let frame = ScannerCodec::encode_serial(payload, ScannerFraming::stx_etx_xor()).unwrap();
    assert_eq!(
        frame,
        vec![0x02, 0x41, 0x42, 0x43, 0x31, 0x32, 0x33, 0x70, 0x03]
    );
    assert_eq!(
        ScannerCodec::decode_serial(&frame, ScannerFraming::stx_etx_xor()).unwrap(),
        payload
    );

    let sum_frame = ScannerCodec::encode_serial(
        b"123",
        ScannerFraming {
            prefix: 0x02,
            suffix: 0x03,
            checksum: ScannerChecksum::Sum8,
        },
    )
    .unwrap();
    assert_eq!(sum_frame, vec![0x02, b'1', b'2', b'3', 150, 0x03]);
}

#[test]
fn truncated_and_corrupt_scanner_frames_are_rejected() {
    assert_eq!(
        ScannerCodec::decode_serial(&[0x02, b'A'], ScannerFraming::stx_etx_xor()).unwrap_err(),
        ScannerError::Frame(ScannerFrameError::Truncated)
    );
    let mut corrupt = gs1_serial_frame(b"0109501101530003");
    let checksum_index = corrupt.len() - 2;
    corrupt[checksum_index] ^= 0xFF;
    assert_eq!(
        ScannerCodec::decode_serial(&corrupt, ScannerFraming::stx_etx_xor()).unwrap_err(),
        ScannerError::Frame(ScannerFrameError::Checksum)
    );
    assert_eq!(
        ScannerCodec::decode_serial(
            &[0x02, 0x03],
            ScannerFraming {
                prefix: 0x02,
                suffix: 0x03,
                checksum: ScannerChecksum::None,
            }
        )
        .unwrap_err(),
        ScannerError::Frame(ScannerFrameError::EmptyPayload)
    );
}

#[test]
fn a_hid_wedge_scan_and_its_bounds_are_enforced() {
    let scanner = SimulatedScanner::hid(hid_keys("0123456789012"));
    let mut scanner = HidScanner::new(scanner, Symbology::Plain, 32).unwrap();
    let code = scanner.scan().unwrap();
    assert_eq!(code.text(), Some("0123456789012"));
    assert_eq!(scanner.scans(), 1);

    let scanner = SimulatedScanner::hid(hid_keys("ABCD"));
    let mut scanner = HidScanner::new(scanner, Symbology::Plain, 3).unwrap();
    assert!(matches!(
        scanner.scan(),
        Err(ScannerError::PayloadTooLong { .. })
    ));

    let mut scanner = HidScanner::new(TimeoutHid, Symbology::Plain, 8).unwrap();
    assert_eq!(scanner.scan().unwrap_err(), ScannerError::Timeout);
}

#[test]
fn a_serial_scan_reassembles_split_frames() {
    let frame = gs1_serial_frame(b"0109501101530003");
    let split = frame.len() / 2;
    let scanner = SimulatedScanner::serial(vec![frame[..split].to_vec(), frame[split..].to_vec()]);
    let mut scanner =
        SerialScanner::with_default_reads(scanner, ScannerFraming::stx_etx_xor(), Symbology::Gs1)
            .unwrap();
    let code = scanner.scan().unwrap();
    assert_eq!(code.gtin(), Some("09501101530003"));
    assert_eq!(scanner.scans(), 1);
}

#[test]
fn a_serial_scanner_times_out_on_an_unterminated_frame() {
    let io = ScriptedIo::new(vec![b"\x02ABC".to_vec(), b"DEF".to_vec()]);
    let mut scanner =
        SerialScanner::new(io, ScannerFraming::stx_etx_xor(), Symbology::Plain, 2).unwrap();
    assert_eq!(scanner.scan().unwrap_err(), ScannerError::Timeout);
}

#[test]
fn gs1_element_strings_parse_to_typed_values() {
    let data = Gs1Data::parse(b"0109501101530003310300123410LOT-7\x1D17251231").unwrap();
    assert_eq!(data.gtin(), Some("09501101530003"));
    assert_eq!(data.get("10"), Some("LOT-7"));
    assert_eq!(data.get("17"), Some("251231"));
    let weight = data.net_weight().unwrap();
    assert_eq!(weight, kg(1234));
    assert_eq!(data.elements().len(), 4);

    let code = ScannerCodec::decode_payload(b"01095011015300033103001234", Symbology::Gs1).unwrap();
    assert_eq!(code.gtin(), Some("09501101530003"));
    assert_eq!(code.net_weight(), Some(kg(1234)));
}

#[test]
fn malformed_gs1_data_is_rejected() {
    // Wrong check digit.
    assert_eq!(
        Gs1Data::parse(b"0109501101530004").unwrap_err(),
        Gs1Error::InvalidGtinCheckDigit
    );
    // Unsupported AI.
    assert_eq!(Gs1Data::parse(b"7001001").unwrap_err(), Gs1Error::UnknownAi);
    // Truncated fixed-length field.
    assert_eq!(
        Gs1Data::parse(b"01095011015300").unwrap_err(),
        Gs1Error::Truncated
    );
    // Empty variable-length field.
    assert_eq!(
        Gs1Data::parse(b"10\x1D0109501101530003").unwrap_err(),
        Gs1Error::InvalidLength
    );
    // Impossible date.
    assert_eq!(
        Gs1Data::parse(b"17250230").unwrap_err(),
        Gs1Error::InvalidDate
    );
    // A plain payload cannot contain GS.
    assert!(matches!(
        ScannerCodec::decode_payload(b"A\x1DB", Symbology::Plain),
        Err(ScannerError::NonPrintable)
    ));
}

#[test]
fn kds_ticket_codec_round_trips_exactly() {
    let ticket = ticket(7);
    let encoded = KdsCodec::encode_ticket(&ticket).unwrap();
    assert_eq!(
        std::str::from_utf8(&encoded).unwrap(),
        "KDS1\nI ticket-1\nO order-1\nC check-1\nS 7\nL line-1 2000 grill queued Burger%20one\nL line-2 1000 cold queued Salad\nEND\n"
    );
    let decoded = KdsCodec::decode_ticket(&encoded).unwrap();
    assert_eq!(decoded, ticket);
    assert_eq!(decoded.status(), tirbase_pos::TicketStatus::Queued);
    assert_eq!(decoded.lines()[0].name(), "Burger one");
}

#[test]
fn truncated_kds_frames_are_rejected() {
    let encoded = KdsCodec::encode_ticket(&ticket(7)).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    let without_end = text.trim_end_matches("END\n");
    assert_eq!(
        KdsCodec::decode_ticket(without_end.as_bytes()).unwrap_err(),
        KdsError::Codec(KdsCodecError::Truncated)
    );
    let cut = &encoded[..encoded.len() / 2];
    assert!(KdsCodec::decode_ticket(cut).is_err());
    let ack = KdsCodec::encode_ack(&tirbase_pos::KdsAck::new(
        KdsTicketId::new("ticket-1").unwrap(),
        7,
    ))
    .unwrap();
    assert_eq!(ack, b"ACK ticket-1 7\n");
    assert_eq!(
        KdsCodec::decode_ack(&ack[..ack.len() - 1]).unwrap_err(),
        KdsError::Codec(KdsCodecError::Truncated)
    );
}

#[test]
fn duplicate_kds_tickets_are_deduplicated() {
    let sim = SimulatedKds::new();
    let mut endpoint = KdsEndpoint::with_defaults(sim).unwrap();
    assert_eq!(
        endpoint.submit(&ticket(7)).unwrap(),
        KdsSubmitOutcome::Created { attempts: 1 }
    );
    assert_eq!(
        endpoint.submit(&ticket(7)).unwrap(),
        KdsSubmitOutcome::Duplicate
    );
    assert_eq!(endpoint.sends(), 1);
    assert_eq!(
        endpoint.acknowledged(&KdsTicketId::new("ticket-1").unwrap()),
        Some(7)
    );
    let sim = endpoint.into_transport();
    assert_eq!(sim.tickets().len(), 1);
    assert_eq!(sim.frames().len(), 1);

    let sim = SimulatedKds::new();
    let mut endpoint = KdsEndpoint::new(sim, 3).unwrap();
    endpoint.submit(&ticket(7)).unwrap();
    assert_eq!(
        endpoint.submit(&ticket(8)).unwrap_err(),
        KdsError::TicketConflict
    );
}

#[test]
fn kds_delivery_retries_a_lost_ack_and_exhausts_its_budget() {
    let mut sim = SimulatedKds::new();
    sim.drop_next_acks(1);
    let mut endpoint = KdsEndpoint::new(sim, 3).unwrap();
    assert_eq!(
        endpoint.submit(&ticket(7)).unwrap(),
        KdsSubmitOutcome::Created { attempts: 2 }
    );
    assert_eq!(endpoint.retries(), 1);
    assert_eq!(endpoint.into_transport().duplicate_frames(), 1);

    let mut sim = SimulatedKds::new();
    sim.fail_next_sends(2);
    let mut endpoint = KdsEndpoint::new(sim, 2).unwrap();
    assert_eq!(
        endpoint.submit(&ticket(7)).unwrap_err(),
        KdsError::RetryExhausted { attempts: 2 }
    );
    assert_eq!(endpoint.sends(), 0);
}

#[test]
fn a_mismatched_kds_ack_is_rejected() {
    let mut endpoint = KdsEndpoint::new(MisackedKds, 1).unwrap();
    assert_eq!(
        endpoint.submit(&ticket(7)).unwrap_err(),
        KdsError::AckMismatch
    );
}

#[test]
fn a_weighed_item_a_scanned_barcode_and_a_kds_ticket_complete_a_flow() {
    let store_id = StoreId::new("store-1").unwrap();
    let mut org = Organization::new();
    org.add_store(Store::new(store_id.clone(), "Store One").unwrap())
        .unwrap();
    org.add_terminal(
        Terminal::new(
            TerminalId::new("till-1").unwrap(),
            store_id.clone(),
            "Till 1",
        )
        .unwrap(),
    )
    .unwrap();
    org.add_employee(
        Employee::new(
            EmployeeId::new("emp-1").unwrap(),
            store_id.clone(),
            "Ada",
            vec![EmployeeRole::Cashier],
        )
        .unwrap(),
    )
    .unwrap();
    let ownership = Ownership::new(
        store_id,
        TerminalId::new("till-1").unwrap(),
        EmployeeId::new("emp-1").unwrap(),
        None,
    );

    // 1. Scan a GS1 barcode through the serial guard.
    let payload = b"01095011015300033103001234";
    let frame = gs1_serial_frame(payload);
    let split = frame.len() / 2;
    let scanner = SimulatedScanner::serial(vec![frame[..split].to_vec(), frame[split..].to_vec()]);
    let mut scanner =
        SerialScanner::new(scanner, ScannerFraming::stx_etx_xor(), Symbology::Gs1, 4).unwrap();
    let scanned = scanner.scan().unwrap();
    assert_eq!(scanned.gtin(), Some("09501101530003"));

    // 2. Weigh an item through the scale guard, requiring two stable frames.
    let mut scale = SimulatedScale::new(ScaleProtocol::MettlerToledo);
    scale.set_weight(kg(1234), true);
    let mut scale = ScaleEndpoint::new(
        scale,
        ScaleProtocol::MettlerToledo,
        ScaleConfig {
            stable_samples: 2,
            stall_timeout_ms: 1_000,
        },
    )
    .unwrap();
    assert!(scale.poll(0).unwrap().unwrap().stable_weight.is_none());
    let weighed = scale
        .poll(10)
        .unwrap()
        .unwrap()
        .stable_weight
        .expect("stable weight");
    let weighed_quantity = weighed.to_quantity().unwrap();
    assert_eq!(weighed_quantity.thousandths(), 1234);

    // 3. Build exact POS-01 lines from the two device readings.
    let mut order = Order::open(
        OrderId::new("order-1").unwrap(),
        ownership,
        &org,
        Timestamp::from_millis(1_000),
    )
    .unwrap();
    let check_id = CheckId::new("check-1").unwrap();
    let usd = Currency::from_code("USD").unwrap();
    order
        .apply(OrderCommand::CreateCheck {
            operation_id: OperationId::new("op-1").unwrap(),
            check_id: check_id.clone(),
            currency: usd,
            rounding: RoundingMode::HalfAwayFromZero,
            at: Timestamp::from_millis(1_001),
        })
        .unwrap();
    let weighed_line = LineItem::new(
        LineItemId::new("weighed-1").unwrap(),
        "Apples",
        weighed_quantity,
        Money::new(usd, 250),
    )
    .unwrap();
    assert_eq!(
        weighed_line
            .compute(RoundingMode::HalfAwayFromZero)
            .unwrap()
            .base,
        Money::new(usd, 309)
    );
    order
        .apply(OrderCommand::AddLineItem {
            operation_id: OperationId::new("op-2").unwrap(),
            check_id: check_id.clone(),
            line: weighed_line,
            at: Timestamp::from_millis(1_002),
        })
        .unwrap();
    let scanned_line = LineItem::new(
        LineItemId::new("scanned-1").unwrap(),
        "Imported cheese",
        Quantity::from_units(1).unwrap(),
        Money::new(usd, 199),
    )
    .unwrap();
    order
        .apply(OrderCommand::AddLineItem {
            operation_id: OperationId::new("op-3").unwrap(),
            check_id: check_id.clone(),
            line: scanned_line,
            at: Timestamp::from_millis(1_003),
        })
        .unwrap();
    let check = order.check(&check_id).unwrap();
    assert_eq!(check.totals().unwrap().subtotal, Money::new(usd, 508));

    // 4. Send the check to the kitchen display; retry once if the ack is lost.
    let kds_lines = check
        .line_items()
        .map(|line| {
            KdsLine::new(
                line.id().clone(),
                line.name(),
                line.quantity(),
                Station::Expo,
                LineStatus::Queued,
            )
            .unwrap()
        })
        .collect();
    let kds_ticket = KdsTicket::new(
        KdsTicketId::new("check-1-ticket").unwrap(),
        OrderId::new("order-1").unwrap(),
        check_id.clone(),
        1,
        kds_lines,
    )
    .unwrap();
    let mut sim = SimulatedKds::new();
    sim.drop_next_acks(1);
    let mut kds = KdsEndpoint::new(sim, 2).unwrap();
    assert_eq!(
        kds.submit(&kds_ticket).unwrap(),
        KdsSubmitOutcome::Created { attempts: 2 }
    );
    assert_eq!(
        kds.submit(&kds_ticket).unwrap(),
        KdsSubmitOutcome::Duplicate
    );
    let sim = kds.into_transport();
    assert_eq!(sim.tickets().len(), 1);
    assert_eq!(sim.tickets()[0].lines().len(), 2);
    assert_eq!(sim.tickets()[0].status(), tirbase_pos::TicketStatus::Queued);
}

#[test]
fn arbitrary_device_bytes_never_panic() {
    let samples: Vec<Vec<u8>> = vec![
        vec![0x02],
        vec![0x03, 0x02],
        b"ST,GS,+001.234,kg\r\n".to_vec(),
        vec![0xFF; 64],
        b"KDS1\nI ".to_vec(),
        b"ACK ".to_vec(),
        b"0109501101530003".to_vec(),
        (0_u8..=255).collect(),
    ];
    for sample in samples {
        let _ = ScaleCodec::decode(ScaleProtocol::MettlerToledo, &sample);
        let _ = ScaleCodec::decode(ScaleProtocol::CasBinary, &sample);
        let _ = ScannerCodec::decode_serial(&sample, ScannerFraming::stx_etx_xor());
        let _ = ScannerCodec::decode_payload(&sample, Symbology::Gs1);
        let _ = Gs1Data::parse(&sample);
        let _ = KdsCodec::decode_ticket(&sample);
        let _ = KdsCodec::decode_ack(&sample);
    }
    let code: ScannedCode = ScannerCodec::decode_payload(b"PLAIN-1", Symbology::Plain).unwrap();
    assert_eq!(code.raw(), b"PLAIN-1");
}
