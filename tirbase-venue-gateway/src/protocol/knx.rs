// SPDX-License-Identifier: AGPL-3.0-only

//! KNX/IP group-value ingest (feature `knx`).
//!
//! This is a compact, read-only decode of KNXnet/IP TUNNELING_REQUEST frames
//! carrying a cEMI `L_Data.ind` group-value write/response. The supported data
//! lengths are DPT1 (1 bit) and DPT9 (16-bit float, hundredths precision), which
//! cover the gateway's gate/discrete and temperature/environment points.
//!
//! `L_Data.req` (a request that would write to the bus) is rejected, as are
//! GroupValueRead requests, which carry no value.

use crate::point::{DecodedPoint, PointAddress, PointValue};
use crate::protocol::ProtocolError;

/// KNXnet/IP service type for a tunneling request.
pub const KNXNET_IP_TUNNELING_REQUEST: u16 = 0x0420;

const CEMI_L_DATA_IND: u8 = 0x29;
const CEMI_L_DATA_REQ: u8 = 0x11;
const APCI_GROUP_VALUE_READ: u16 = 0x000;
const APCI_GROUP_VALUE_RESPONSE: u16 = 0x040;
const APCI_GROUP_VALUE_WRITE: u16 = 0x080;

/// Decode one KNXnet/IP tunneling frame into a group-address reading.
pub fn decode_group_value_indication(frame: &[u8]) -> Result<DecodedPoint, ProtocolError> {
    if frame.len() < 12 {
        return Err(ProtocolError::InvalidFrame("truncated KNXnet/IP frame"));
    }
    if frame[0] != 0x06 || frame[1] != 0x10 {
        return Err(ProtocolError::InvalidFrame("not a KNXnet/IP v1 frame"));
    }
    let service = u16::from_be_bytes([frame[2], frame[3]]);
    if service != KNXNET_IP_TUNNELING_REQUEST {
        return Err(ProtocolError::Unsupported(
            "only KNXnet/IP TUNNELING_REQUEST frames are ingested",
        ));
    }
    let total_length = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if total_length != frame.len() {
        return Err(ProtocolError::InvalidFrame(
            "KNXnet/IP total length does not match the frame",
        ));
    }
    let connection_length = frame[6] as usize;
    if connection_length != 4 {
        return Err(ProtocolError::InvalidFrame(
            "unexpected KNXnet/IP connection header length",
        ));
    }
    let cemi = 6 + connection_length;
    if frame.len() < cemi + 2 {
        return Err(ProtocolError::InvalidFrame("truncated cEMI frame"));
    }
    match frame[cemi] {
        CEMI_L_DATA_IND => {}
        CEMI_L_DATA_REQ => {
            return Err(ProtocolError::WritePathRejected(
                "KNX cEMI L_Data.req is a bus write",
            ));
        }
        _ => {
            return Err(ProtocolError::Unsupported(
                "only KNX cEMI L_Data.ind is ingested",
            ));
        }
    }

    let additional_info = frame[cemi + 1] as usize;
    let control = cemi + 2 + additional_info;
    if frame.len() < control + 9 {
        return Err(ProtocolError::InvalidFrame("truncated KNX group value"));
    }
    let group_address = u16::from_be_bytes([frame[control + 4], frame[control + 5]]);
    let data_length = frame[control + 6] & 0x3F;
    let apci_high = frame[control + 7];
    let apci_low = frame[control + 8];
    let apci = ((u16::from(apci_high) & 0x03) << 8) | (u16::from(apci_low) & 0xC0);
    match apci {
        APCI_GROUP_VALUE_WRITE | APCI_GROUP_VALUE_RESPONSE => {}
        APCI_GROUP_VALUE_READ => {
            return Err(ProtocolError::Unsupported(
                "KNX GroupValueRead carries no value",
            ));
        }
        _ => {
            return Err(ProtocolError::Unsupported(
                "only KNX group-value write/response frames are ingested",
            ));
        }
    }

    let value = match data_length {
        1 => PointValue::Boolean(apci_low & 0x01 != 0),
        16 => {
            if frame.len() < control + 10 {
                return Err(ProtocolError::InvalidFrame("truncated DPT9 value"));
            }
            let raw = ((u16::from(apci_low) & 0x3F) << 8) | u16::from(frame[control + 9]);
            decode_dpt9(raw)
        }
        _ => {
            return Err(ProtocolError::Unsupported(
                "KNX data length outside the DPT1/DPT9 subset",
            ));
        }
    };
    Ok(DecodedPoint::new(
        PointAddress::Knx { group_address },
        value,
    ))
}

/// Decode a DPT9 16-bit float into hundredths of the engineering unit.
fn decode_dpt9(raw: u16) -> PointValue {
    let negative = raw & 0x8000 != 0;
    let exponent = u32::from((raw >> 11) & 0x0F);
    let mantissa = i64::from(raw & 0x07FF);
    let scaled = mantissa.saturating_mul(1i64 << exponent);
    PointValue::number(if negative { -scaled } else { scaled }, -2)
}
