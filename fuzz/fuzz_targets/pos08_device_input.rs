// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

//! Fuzz target for POS-08 device input.
//!
//! Arbitrary bytes are treated as scale frames, framed/unframed scanner
//! payloads, keyboard-wedge key streams, KDS tickets and acknowledgements.
//! Every codec must reject or decode them without panicking, and every
//! endpoint must keep its fixed buffer.

use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use tirbase_pos::{
    DeviceTransport, Gs1Data, HidKey, HidScanner, KdsCodec, KdsEndpoint, KdsTransport, ScaleCodec,
    ScaleProtocol, ScannerCodec, ScannerFraming, SerialScanner, SimulatedScanner, Symbology,
    TransportError,
};

struct BytesIo {
    chunks: VecDeque<Vec<u8>>,
}

impl BytesIo {
    fn new(data: &[u8]) -> Self {
        let mut chunks = VecDeque::new();
        for chunk in data.chunks(16) {
            chunks.push_back(chunk.to_vec());
        }
        Self { chunks }
    }
}

impl DeviceTransport for BytesIo {
    fn write_all(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
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

struct KdsIo {
    response: Vec<u8>,
    sent: bool,
}

impl KdsTransport for KdsIo {
    fn send(&mut self, _frame: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if self.sent {
            return Ok(0);
        }
        self.sent = true;
        let len = self.response.len().min(buf.len());
        buf[..len].copy_from_slice(&self.response[..len]);
        Ok(len)
    }
}

fuzz_target!(|data: &[u8]| {
    for protocol in [ScaleProtocol::MettlerToledo, ScaleProtocol::CasBinary] {
        let _ = ScaleCodec::decode(protocol, data);
    }

    for framing in [
        ScannerFraming::stx_etx(),
        ScannerFraming::stx_etx_xor(),
        ScannerFraming {
            prefix: b'[',
            suffix: b']',
            checksum: tirbase_pos::ScannerChecksum::Sum8,
        },
    ] {
        let _ = ScannerCodec::decode_serial(data, framing);
    }
    let _ = ScannerCodec::decode_payload(data, Symbology::Gs1);
    let _ = Gs1Data::parse(data);
    let _ = KdsCodec::decode_ticket(data);
    let _ = KdsCodec::decode_ack(data);

    // Keyboard-wedge input: bound key count, expect rejection or a bounded scan.
    let mut keys: Vec<HidKey> = data
        .iter()
        .take(64)
        .map(|byte| HidKey::Character(char::from(*byte)))
        .collect();
    keys.push(HidKey::Enter);
    let scanner = SimulatedScanner::hid(keys);
    if let Ok(mut scanner) = HidScanner::new(scanner, Symbology::Plain, 32) {
        if let Ok(code) = scanner.scan() {
            assert!(code.raw().len() <= 32);
        }
    }

    // Serial scanner endpoint over the same bytes, with a read budget.
    let scanner = SimulatedScanner::serial(vec![data.to_vec()]);
    if let Ok(mut scanner) =
        SerialScanner::new(scanner, ScannerFraming::stx_etx_xor(), Symbology::Gs1, 8)
    {
        if let Ok(code) = scanner.scan() {
            assert!(code.raw().len() <= tirbase_pos::MAX_SCAN_PAYLOAD_BYTES);
        }
    }

    // Guard-owned scale and KDS endpoints over arbitrary bytes.
    if let Ok(mut endpoint) = tirbase_pos::ScaleEndpoint::new(
        BytesIo::new(data),
        ScaleProtocol::MettlerToledo,
        tirbase_pos::ScaleConfig::default(),
    ) {
        for now in 0..4 {
            let _ = endpoint.poll(now);
        }
    }

    if let Ok(mut endpoint) = KdsEndpoint::new(
        KdsIo {
            response: data.to_vec(),
            sent: false,
        },
        2,
    ) {
        // A ticket built from fixed, valid data exercises the ack path.
        let line = tirbase_pos::KdsLine::new(
            tirbase_pos::LineItemId::new("line").unwrap(),
            "item",
            tirbase_pos::Quantity::from_units(1).unwrap(),
            tirbase_pos::Station::Expo,
            tirbase_pos::LineStatus::Queued,
        )
        .unwrap();
        let ticket = tirbase_pos::KdsTicket::new(
            tirbase_pos::KdsTicketId::new("ticket").unwrap(),
            tirbase_pos::OrderId::new("order").unwrap(),
            tirbase_pos::CheckId::new("check").unwrap(),
            1,
            vec![line],
        )
        .unwrap();
        let _ = endpoint.submit(&ticket);
    }
});
