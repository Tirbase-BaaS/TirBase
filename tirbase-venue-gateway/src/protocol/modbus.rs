// SPDX-License-Identifier: AGPL-3.0-only

//! Modbus TCP/RTU register ingest (feature `modbus`).
//!
//! Only FC03 (Read Holding Registers) and FC04 (Read Input Registers) response
//! PDUs are decoded. FC06 and FC16 response frames are rejected as write paths.

use tirbase_driver_api::modbus_codec::{
    decode_read_registers_response, parse_rtu_frame, parse_tcp_adu,
};

use crate::point::{DecodedPoint, PointAddress, PointValue};
use crate::protocol::ProtocolError;

/// Decode a Modbus TCP FC03/FC04 response into register readings.
///
/// `start_register` is the first register address requested; each returned
/// register is mapped to `start_register + index`.
pub fn decode_tcp_read_response(
    unit_id: u8,
    start_register: u16,
    frame: &[u8],
) -> Result<Vec<DecodedPoint>, ProtocolError> {
    let adu = parse_tcp_adu(frame).map_err(|error| ProtocolError::Codec(error.to_string()))?;
    if adu.unit_id != unit_id {
        return Err(ProtocolError::UnitMismatch {
            expected: unit_id,
            actual: adu.unit_id,
        });
    }
    decode_read_pdu(unit_id, start_register, &adu.pdu)
}

/// Decode a Modbus RTU FC03/FC04 response into register readings.
pub fn decode_rtu_read_response(
    unit_id: u8,
    start_register: u16,
    frame: &[u8],
) -> Result<Vec<DecodedPoint>, ProtocolError> {
    let (actual_unit, pdu) =
        parse_rtu_frame(frame).map_err(|error| ProtocolError::Codec(error.to_string()))?;
    if actual_unit != unit_id {
        return Err(ProtocolError::UnitMismatch {
            expected: unit_id,
            actual: actual_unit,
        });
    }
    decode_read_pdu(unit_id, start_register, &pdu)
}

fn decode_read_pdu(
    unit_id: u8,
    start_register: u16,
    pdu: &[u8],
) -> Result<Vec<DecodedPoint>, ProtocolError> {
    let Some(&function) = pdu.first() else {
        return Err(ProtocolError::InvalidFrame("empty Modbus PDU"));
    };
    match function {
        0x03 | 0x04 => {}
        0x06 | 0x10 => {
            return Err(ProtocolError::WritePathRejected(
                "Modbus write-function response is not ingested",
            ));
        }
        _ => {
            return Err(ProtocolError::Unsupported(
                "only Modbus FC03/FC04 read responses are supported",
            ));
        }
    }
    let registers = decode_read_registers_response(pdu, function)
        .map_err(|error| ProtocolError::Codec(error.to_string()))?;

    let mut readings = Vec::with_capacity(registers.len());
    for (index, raw) in registers.into_iter().enumerate() {
        let offset = u16::try_from(index)
            .map_err(|_| ProtocolError::InvalidFrame("too many Modbus registers"))?;
        let register = start_register
            .checked_add(offset)
            .ok_or(ProtocolError::InvalidFrame("register address overflow"))?;
        readings.push(DecodedPoint::new(
            PointAddress::Modbus {
                unit_id,
                function,
                register,
            },
            PointValue::number(i64::from(raw), 0),
        ));
    }
    Ok(readings)
}
