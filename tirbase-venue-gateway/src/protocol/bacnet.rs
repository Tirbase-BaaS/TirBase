// SPDX-License-Identifier: AGPL-3.0-only

//! BACnet/IP ingest (feature `bacnet`).
//!
//! Uses the Apache-2.0 read-only BACnet codec. Only ReadProperty-ACK frames are
//! accepted; SimpleACK (a write acknowledgement) is rejected explicitly, and the
//! codec itself refuses to encode WriteProperty.

use tirbase_driver_api::{
    encode_read_property, parse_message, BacnetMessage, BacnetValue, ObjectIdentifier, PropertyId,
};

use crate::point::{DecodedPoint, PointAddress, PointValue};
use crate::protocol::ProtocolError;

/// Build a read-only Present-Value ReadProperty request for polling.
pub fn read_property_request(
    object: ObjectIdentifier,
    invoke_id: u8,
) -> Result<Vec<u8>, ProtocolError> {
    encode_read_property(invoke_id, object, PropertyId::PRESENT_VALUE)
        .map_err(|error| ProtocolError::Codec(error.to_string()))
}

/// Decode a ReadProperty-ACK for a known object into a venue point reading.
pub fn decode_read_property_ack(
    object: ObjectIdentifier,
    frame: &[u8],
) -> Result<DecodedPoint, ProtocolError> {
    match parse_message(frame).map_err(|error| ProtocolError::Codec(error.to_string()))? {
        BacnetMessage::ReadPropertyAck { value, .. } => Ok(DecodedPoint::new(
            PointAddress::Bacnet {
                object_type: object.object_type.code(),
                instance: object.instance,
                property: PropertyId::PRESENT_VALUE.as_u32(),
            },
            value_to_point(object, value)?,
        )),
        BacnetMessage::SimpleAck { .. } => Err(ProtocolError::WritePathRejected(
            "BACnet SimpleACK acknowledges a write service",
        )),
        _ => Err(ProtocolError::InvalidFrame(
            "expected a BACnet ReadProperty-ACK",
        )),
    }
}

fn value_to_point(
    object: ObjectIdentifier,
    value: BacnetValue,
) -> Result<PointValue, ProtocolError> {
    if object.object_type.is_binary() {
        return value
            .as_bool()
            .map(PointValue::Boolean)
            .ok_or(ProtocolError::InvalidValue(
                "binary object has no boolean value",
            ));
    }
    match value {
        BacnetValue::Boolean(flag) => Ok(PointValue::Boolean(flag)),
        BacnetValue::Null => Err(ProtocolError::InvalidValue("null BACnet value")),
        BacnetValue::Real(number) => PointValue::from_scaled(f64::from(number), -1).ok_or(
            ProtocolError::InvalidValue("BACnet real is not representable"),
        ),
        BacnetValue::Double(number) => PointValue::from_scaled(number, -1).ok_or(
            ProtocolError::InvalidValue("BACnet double is not representable"),
        ),
        BacnetValue::Unsigned(number) => i64::try_from(number)
            .map(|mantissa| PointValue::number(mantissa, 0))
            .map_err(|_| ProtocolError::InvalidValue("BACnet unsigned exceeds i64")),
        BacnetValue::Signed(number) => Ok(PointValue::number(number, 0)),
        BacnetValue::Enumerated(number) => Ok(PointValue::number(i64::from(number), 0)),
    }
}
