// SPDX-License-Identifier: AGPL-3.0-only

//! POS-07 behavioural tests: recorded ESC/POS byte vectors, code pages,
//! barcode/QR commands, cash-drawer pulses, bounded buffers, status decoding,
//! malformed device input and the simulated sale flow.

use std::collections::VecDeque;

use tirbase_pos::{
    barcode_bytes, Alignment, BarcodeType, CheckId, CodePage, Currency, CutMode, DrawerPin,
    Employee, EmployeeId, EmployeeRole, EscPosCodec, EscPosError, LineItem, LineItemId, Money,
    OperationId, Order, OrderCommand, Organization, Ownership, PaymentId, PaymentLink,
    PaymentMethod, PrinterError, PrinterErrorCode, PrinterStatus, PrinterTransport, QrEcc,
    QrOptions, Quantity, Rate, Receipt, ReceiptLine, ReceiptPrinter, RoundingMode,
    SimulatedPrinter, StatusKind, Store, StoreId, Terminal, TerminalId, Timestamp, TransportError,
    MAX_QR_DATA_BYTES, MAX_RECEIPT_LINES, MAX_STATUS_RESPONSE_BYTES, MAX_TEXT_BYTES,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn money(minor: i64) -> Money {
    Money::new(usd(), minor)
}

fn ts(value: i64) -> Timestamp {
    Timestamp::from_millis(value)
}

fn store_id() -> StoreId {
    StoreId::new("store-1").unwrap()
}

fn terminal_id() -> TerminalId {
    TerminalId::new("till-1").unwrap()
}

fn employee_id() -> EmployeeId {
    EmployeeId::new("emp-1").unwrap()
}

fn organization() -> Organization {
    let mut org = Organization::new();
    org.add_store(Store::new(store_id(), "Store One").unwrap())
        .unwrap();
    org.add_terminal(Terminal::new(terminal_id(), store_id(), "Till 1").unwrap())
        .unwrap();
    org.add_employee(
        Employee::new(
            employee_id(),
            store_id(),
            "Ada",
            vec![EmployeeRole::Cashier],
        )
        .unwrap(),
    )
    .unwrap();
    org
}

/// A closed, fully paid POS-01 check: 2 x Coffee at 4.50, 10% tax, 1.00 tip.
fn closed_check() -> tirbase_pos::Check {
    let mut order = Order::open(
        tirbase_pos::OrderId::new("order-1").unwrap(),
        Ownership::new(store_id(), terminal_id(), employee_id(), None),
        &organization(),
        ts(1_000),
    )
    .unwrap();
    let check_id = CheckId::new("check-1").unwrap();
    order
        .apply(OrderCommand::CreateCheck {
            operation_id: OperationId::new("op-1").unwrap(),
            check_id: check_id.clone(),
            currency: usd(),
            rounding: RoundingMode::HalfAwayFromZero,
            at: ts(1_001),
        })
        .unwrap();
    order
        .apply(OrderCommand::AddLineItem {
            operation_id: OperationId::new("op-2").unwrap(),
            check_id: check_id.clone(),
            line: LineItem::new(
                LineItemId::new("line-1").unwrap(),
                "Coffee",
                Quantity::from_units(2).unwrap(),
                money(450),
            )
            .unwrap()
            .with_tax_rate(Rate::from_percent(10).unwrap()),
            at: ts(1_002),
        })
        .unwrap();
    order
        .apply(OrderCommand::SetTip {
            operation_id: OperationId::new("op-3").unwrap(),
            check_id: check_id.clone(),
            tip: money(100),
            at: ts(1_003),
        })
        .unwrap();
    order
        .apply(OrderCommand::LinkPayment {
            operation_id: OperationId::new("op-4").unwrap(),
            check_id: check_id.clone(),
            payment: PaymentLink::captured(
                PaymentId::new("pay-1").unwrap(),
                PaymentMethod::Cash,
                money(1_090),
            )
            .unwrap(),
            at: ts(1_004),
        })
        .unwrap();
    order
        .apply(OrderCommand::CloseCheck {
            operation_id: OperationId::new("op-5").unwrap(),
            check_id: check_id.clone(),
            at: ts(1_005),
        })
        .unwrap();
    order.check(&check_id).unwrap().clone()
}

fn sale_receipt() -> Receipt {
    Receipt::from_check(&closed_check(), "TIRBASE CAFE")
        .unwrap()
        .with_footer("Thank you")
        .unwrap()
}

#[test]
fn recorded_command_vectors_are_exact() {
    let mut codec = EscPosCodec::new(64).unwrap();
    codec.initialize().unwrap();
    codec.code_page(CodePage::Cp437).unwrap();
    codec.align(Alignment::Center).unwrap();
    codec.bold(true).unwrap();
    codec.text("Café").unwrap();
    codec.bold(false).unwrap();
    codec.feed(2).unwrap();
    codec.cut(CutMode::Partial).unwrap();
    assert_eq!(
        codec.as_bytes(),
        &[
            0x1B, 0x40, // ESC @
            0x1B, 0x74, 0x00, // ESC t 0 (CP437)
            0x1B, 0x61, 0x01, // ESC a 1 (centre)
            0x1B, 0x45, 0x01, // ESC E 1
            b'C', b'a', b'f', 0x82, // CP437 é
            0x1B, 0x45, 0x00, // ESC E 0
            0x1B, 0x64, 0x02, // ESC d 2
            0x1D, 0x56, 0x01, // GS V 1 (partial cut)
        ]
    );
}

#[test]
fn code_page_selection_and_encoding_are_exact() {
    assert_eq!(CodePage::Cp437.number(), 0);
    assert_eq!(CodePage::Cp850.number(), 2);
    assert_eq!(CodePage::Cp1252.number(), 16);

    let mut codec = EscPosCodec::new(32).unwrap();
    codec.code_page(CodePage::Cp1252).unwrap();
    codec.text("€5").unwrap();
    assert_eq!(codec.as_bytes(), &[0x1B, 0x74, 0x10, 0x80, b'5']);

    // A character outside the page is rejected, never replaced.
    let mut codec = EscPosCodec::new(32).unwrap();
    codec.code_page(CodePage::Cp1252).unwrap();
    assert_eq!(
        codec.text("→").unwrap_err(),
        EscPosError::UnencodableCharacter('→')
    );
    // Only the page-selection command is buffered; no text byte was appended.
    assert_eq!(codec.as_bytes(), &[0x1B, 0x74, 0x10]);
}

#[test]
fn barcode_and_qr_vectors_are_exact() {
    assert_eq!(
        barcode_bytes("ABC", BarcodeType::Code128, 32).unwrap(),
        &[0x1D, 0x6B, 0x49, 3, b'A', b'B', b'C']
    );
    assert_eq!(
        barcode_bytes("400638133393", BarcodeType::Ean13, 32).unwrap(),
        &[
            0x1D, 0x6B, 0x43, b'4', b'0', b'0', b'6', b'3', b'8', b'1', b'3', b'3', b'3', b'9',
            b'3'
        ]
    );

    let mut codec = EscPosCodec::new(64).unwrap();
    codec
        .qr_code(
            "hi",
            QrOptions {
                model: 2,
                module_size: 6,
                ecc: QrEcc::Medium,
            },
        )
        .unwrap();
    assert_eq!(
        codec.as_bytes(),
        &[
            0x1D, 0x28, 0x6B, 0x04, 0x00, 0x31, 0x41, 0x02, 0x00, // model 2
            0x1D, 0x28, 0x6B, 0x03, 0x00, 0x31, 0x43, 0x06, // module size 6
            0x1D, 0x28, 0x6B, 0x03, 0x00, 0x31, 0x45, 0x31, // ECC M
            0x1D, 0x28, 0x6B, 0x05, 0x00, 0x31, 0x50, 0x30, b'h', b'i', // store
            0x1D, 0x28, 0x6B, 0x03, 0x00, 0x31, 0x51, 0x30, // print
        ]
    );
}

#[test]
fn drawer_and_status_vectors_are_exact() {
    let mut codec = EscPosCodec::new(32).unwrap();
    codec.drawer_kick(DrawerPin::Pin2).unwrap();
    codec.status_query(StatusKind::Printer).unwrap();
    codec.status_query(StatusKind::Offline).unwrap();
    codec.status_query(StatusKind::Error).unwrap();
    codec.status_query(StatusKind::Paper).unwrap();
    assert_eq!(
        codec.as_bytes(),
        &[
            0x1B, 0x70, 0x00, 25, 250, // ESC p 0 25 250
            0x10, 0x04, 1, // DLE EOT 1
            0x10, 0x04, 2, // DLE EOT 2
            0x10, 0x04, 3, // DLE EOT 3
            0x10, 0x04, 4, // DLE EOT 4
        ]
    );
    assert_eq!(
        EscPosCodec::status_query_bytes(StatusKind::Error),
        [0x10, 0x04, 3]
    );
}

#[test]
fn oversized_input_is_rejected_without_allocating_a_job() {
    let mut codec = EscPosCodec::new(MAX_TEXT_BYTES * 2).unwrap();
    let long_text = "x".repeat(MAX_TEXT_BYTES + 1);
    assert_eq!(
        codec.text(&long_text).unwrap_err(),
        EscPosError::InvalidTextLength
    );
    assert!(codec.is_empty());

    let long_qr = "q".repeat(MAX_QR_DATA_BYTES + 1);
    assert_eq!(
        codec.qr_code(&long_qr, QrOptions::default()).unwrap_err(),
        EscPosError::InvalidQrData
    );
    assert!(codec.is_empty());

    let long_barcode = "b".repeat(256);
    assert_eq!(
        codec
            .barcode(&long_barcode, BarcodeType::Code128)
            .unwrap_err(),
        EscPosError::InvalidBarcodeLength
    );
    assert!(codec.is_empty());

    // A fixed-capacity codec stops at the boundary instead of growing.
    let mut small = EscPosCodec::new(6).unwrap();
    assert!(small.initialize().is_ok());
    assert_eq!(
        small.drawer_kick(DrawerPin::Pin2).unwrap_err(),
        EscPosError::BufferFull { capacity: 6 }
    );
    assert_eq!(small.as_bytes().len(), 2);
}

#[test]
fn malformed_status_bytes_never_panic_and_decode_deterministically() {
    // Every byte value for every register is safe to decode.
    for kind in [
        StatusKind::Printer,
        StatusKind::Offline,
        StatusKind::Error,
        StatusKind::Paper,
    ] {
        for byte in 0..=u8::MAX {
            let status: PrinterStatus = tirbase_pos::decode_status(kind, byte);
            assert_eq!(status.raw(), byte);
            assert_eq!(status.kind(), kind);
        }
    }

    // Arbitrary lengths and content: only a bounded, non-empty response decodes.
    for length in 0..24_usize {
        let response = vec![0xA5_u8; length];
        let decoded = tirbase_pos::decode_status_response(StatusKind::Error, &response);
        if length == 0 {
            assert_eq!(decoded, Err(EscPosError::EmptyStatusResponse));
        } else if length > MAX_STATUS_RESPONSE_BYTES {
            assert_eq!(decoded, Err(EscPosError::OversizedStatusResponse));
        } else {
            assert_eq!(decoded.unwrap().raw(), 0xA5);
        }
    }

    // A malformed status kind is a typed error, not a panic.
    assert_eq!(
        StatusKind::try_from(0),
        Err(EscPosError::InvalidStatusKind(0))
    );
    assert_eq!(
        StatusKind::try_from(5),
        Err(EscPosError::InvalidStatusKind(5))
    );

    let error = tirbase_pos::decode_status(StatusKind::Error, 0b0000_1000);
    assert_eq!(
        error.error_code(),
        Some(PrinterErrorCode::UnrecoverableError)
    );
    assert!(!error.is_ready());
}

#[test]
fn a_sale_prints_a_receipt_and_opens_the_drawer_in_simulation() {
    let receipt = sale_receipt();
    let mut printer = ReceiptPrinter::new(SimulatedPrinter::ready(), 4096).unwrap();

    let outcome = printer.print_sale(&receipt, PaymentMethod::Cash).unwrap();
    assert!(outcome.cash_drawer_opened);
    assert_eq!(outcome.receipts_printed, 1);
    assert_eq!(printer.receipts_printed(), 1);
    assert_eq!(printer.drawer_kicks(), 1);

    let sim = printer.into_transport();
    let text = sim.receipt_text();
    assert!(text.contains("TIRBASE CAFE"), "receipt text: {text}");
    assert!(text.contains("Coffee"), "receipt text: {text}");
    assert!(text.contains("TOTAL"), "receipt text: {text}");
    assert!(text.contains("10.90 USD"), "receipt text: {text}");
    assert!(text.contains("CASH"), "receipt text: {text}");
    assert!(text.contains("Thank you"), "receipt text: {text}");
    assert!(sim.cut_issued());
    assert_eq!(sim.drawer_pulse_count(), 1);
    assert_eq!(sim.status_queries(), &[StatusKind::Printer]);
    // The journal holds the status query and then the receipt job.
    assert_eq!(sim.writes().len(), 2);
    assert_eq!(sim.writes()[1].len(), outcome.bytes_written);
}

#[test]
fn a_card_sale_prints_but_does_not_open_the_drawer() {
    let receipt = sale_receipt();
    let mut printer = ReceiptPrinter::new(SimulatedPrinter::ready(), 4096).unwrap();
    let outcome = printer.print_sale(&receipt, PaymentMethod::Card).unwrap();
    assert!(!outcome.cash_drawer_opened);
    assert_eq!(printer.drawer_kicks(), 0);
    let sim = printer.into_transport();
    assert!(!sim.drawer_pulsed());
    assert!(sim.receipt_text().contains("CARD"));
    assert!(sim.cut_issued());
}

#[test]
fn a_ready_check_is_required_before_any_receipt_bytes_are_written() {
    let receipt = sale_receipt();
    let mut sim = SimulatedPrinter::ready();
    // Offline status register bit 3 set.
    sim.push_status_byte(0b0000_1000);
    let mut printer = ReceiptPrinter::new(sim, 4096).unwrap();

    let error = printer
        .print_sale(&receipt, PaymentMethod::Card)
        .unwrap_err();
    assert_eq!(error.device_error(), Some(PrinterErrorCode::Offline));
    assert_eq!(printer.receipts_printed(), 0);

    let sim = printer.into_transport();
    assert!(
        sim.receipt_text().is_empty(),
        "no receipt bytes may be written after a failed status check"
    );
    assert!(!sim.cut_issued());
}

#[test]
fn an_encoding_failure_writes_nothing() {
    let receipt = sale_receipt();
    let mut printer = ReceiptPrinter::new(SimulatedPrinter::ready(), 16).unwrap();
    let error = printer
        .print_sale(&receipt, PaymentMethod::Cash)
        .unwrap_err();
    assert!(matches!(
        error,
        PrinterError::Codec(EscPosError::BufferFull { capacity: 16 })
    ));
    let sim = printer.into_transport();
    assert!(sim.writes().is_empty());
    assert!(!sim.drawer_pulsed());
}

#[test]
fn status_reads_use_a_fixed_size_buffer() {
    struct RecordingTransport {
        buffers: Vec<usize>,
        responses: VecDeque<Vec<u8>>,
    }

    impl PrinterTransport for RecordingTransport {
        fn write_all(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }

        fn read_status(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
            self.buffers.push(buffer.len());
            let response = self.responses.pop_front().unwrap_or_else(|| vec![0x00]);
            let copied = response.len().min(buffer.len());
            buffer[..copied].copy_from_slice(&response[..copied]);
            Ok(copied)
        }
    }

    let transport = RecordingTransport {
        buffers: Vec::new(),
        // A 100-byte burst from the device must be truncated, not allocated.
        responses: VecDeque::from([vec![0xAA_u8; 100], vec![]]),
    };
    let mut printer = ReceiptPrinter::new(transport, 4096).unwrap();

    assert_eq!(printer.query_status(StatusKind::Error).unwrap().raw(), 0xAA);
    assert!(matches!(
        printer.query_status(StatusKind::Printer),
        Err(PrinterError::EmptyStatusResponse)
    ));

    let transport = printer.into_transport();
    assert_eq!(
        transport.buffers,
        vec![MAX_STATUS_RESPONSE_BYTES, MAX_STATUS_RESPONSE_BYTES]
    );
}

#[test]
fn receipt_validation_preserves_exact_money() {
    // Wrong total is rejected at construction.
    assert_eq!(
        Receipt::new(
            "Cafe",
            money(900),
            money(0),
            money(90),
            money(100),
            money(1_089)
        )
        .unwrap_err(),
        PrinterError::InvalidTotals
    );

    // Empty receipt.
    let empty = Receipt::new("Cafe", money(0), money(0), money(0), money(0), money(0)).unwrap();
    assert_eq!(empty.validate(), Err(PrinterError::EmptyReceipt));

    // Mixed currencies.
    let mut receipt = Receipt::new(
        "Cafe",
        money(900),
        money(0),
        money(90),
        money(0),
        money(990),
    )
    .unwrap();
    receipt
        .push_line(
            ReceiptLine::new(
                "Coffee",
                "1",
                Money::new(Currency::from_code("EUR").unwrap(), 990),
            )
            .unwrap(),
        )
        .unwrap_err();
    // push_line itself rejects the mixed currency.
    assert!(receipt.lines().is_empty());

    // A receipt cannot exceed the line bound.
    let mut receipt =
        Receipt::new("Cafe", money(0), money(0), money(0), money(0), money(0)).unwrap();
    for index in 0..MAX_RECEIPT_LINES {
        receipt
            .push_line(ReceiptLine::new(format!("Item {index}"), "1", money(0)).unwrap())
            .unwrap();
    }
    assert!(matches!(
        receipt.push_line(ReceiptLine::new("One too many", "1", money(0)).unwrap()),
        Err(PrinterError::TooManyLines { .. })
    ));
}

#[test]
fn pulse_drawer_is_a_guarded_standalone_operation() {
    let mut printer = ReceiptPrinter::new(SimulatedPrinter::ready(), 64).unwrap();
    printer.pulse_drawer().unwrap();
    assert_eq!(printer.drawer_kicks(), 1);
    assert_eq!(printer.receipts_printed(), 0);
    let sim = printer.into_transport();
    assert_eq!(sim.drawer_pulse_count(), 1);
    assert!(!sim.cut_issued());
}

#[test]
fn receipt_text_is_extracted_without_parsing_commands() {
    let mut receipt =
        Receipt::new("Cafe", money(100), money(0), money(0), money(0), money(100)).unwrap();
    receipt
        .push_line(ReceiptLine::new("Tea", "1", money(100)).unwrap())
        .unwrap();
    let mut printer = ReceiptPrinter::new(SimulatedPrinter::ready(), 4096).unwrap();
    printer.print_sale(&receipt, PaymentMethod::Card).unwrap();
    let sim = printer.into_transport();
    let text = sim.receipt_text();
    assert!(text.contains("Tea"));
    assert!(text.contains("1.00 USD"));
}
