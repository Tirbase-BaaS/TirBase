// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

//! Fuzz target for POS-07 device input (status bytes) and bounded encoding.
//!
//! The POS printer path treats everything the device sends as untrusted. This
//! target decodes arbitrary status responses for every register, feeds
//! arbitrary text and QR payloads through the fixed-capacity codec, and runs a
//! scripted simulated sale so a malformed status byte cannot panic the guard.

use libfuzzer_sys::fuzz_target;
use tirbase_pos::{
    decode_status_response, Currency, EscPosCodec, Money, QrOptions, Receipt, ReceiptLine,
    ReceiptPrinter, SimulatedPrinter, StatusKind,
};

fuzz_target!(|data: &[u8]| {
    // 1. Every status register with arbitrary (empty, short or oversized) bytes.
    for kind in [
        StatusKind::Printer,
        StatusKind::Offline,
        StatusKind::Error,
        StatusKind::Paper,
    ] {
        let _ = decode_status_response(kind, data);
    }

    // 2. Arbitrary text and QR payload into a fixed-capacity codec. Errors are
    //    expected; only panics or over-capacity output are failures.
    let text = String::from_utf8_lossy(data);
    let mut codec = EscPosCodec::new(256).unwrap();
    let _ = codec.text(&text);
    let _ = codec.line(&text);
    let _ = codec.qr_code(&text, QrOptions::default());
    assert!(codec.len() <= codec.capacity());

    // 3. Drive the guard-owned printer with a simulated device whose status
    //    response is attacker-controlled. The receipt itself is bounded and
    //    well formed so the fuzzer focuses on device input.
    let currency = Currency::from_code("USD").unwrap();
    let amount = Money::new(currency, 100);
    if let Ok(mut receipt) = Receipt::new(
        "Fuzz",
        amount,
        Money::zero(currency),
        Money::zero(currency),
        Money::zero(currency),
        amount,
    ) {
        let description = if text.is_empty() {
            "item".to_string()
        } else {
            text.chars().take(32).collect()
        };
        if let Ok(line) = ReceiptLine::new(description, "1", amount) {
            if receipt.push_line(line).is_ok() {
                let mut sim = SimulatedPrinter::ready();
                sim.push_status(data.iter().copied().take(16).collect::<Vec<u8>>());
                sim.push_status(data.to_vec());
                if let Ok(mut printer) = ReceiptPrinter::new(sim, 512) {
                    let _ = printer.print_sale(&receipt, tirbase_pos::PaymentMethod::Cash);
                }
            }
        }
    }
});
