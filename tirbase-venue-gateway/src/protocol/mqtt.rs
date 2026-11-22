// SPDX-License-Identifier: AGPL-3.0-only

//! MQTT 3.1.1 PUBLISH ingest (feature `mqtt`).
//!
//! Uses the Apache-2.0 MQTT packet codec to decode inbound PUBLISH frames. The
//! gateway never publishes: there is no outbound packet builder in this module.

use tirbase_driver_api::mqtt_codec::MqttBridgeCodec;

use crate::point::{DecodedPoint, PointAddress, PointValue};
use crate::protocol::ProtocolError;

/// Decode one MQTT PUBLISH frame into a topic reading.
///
/// Payload typing: `true`/`false` become booleans, integer payloads become
/// decimal numbers with exponent 0, and everything else is text.
pub fn decode_publish(frame: &[u8]) -> Result<DecodedPoint, ProtocolError> {
    let codec = MqttBridgeCodec::new();
    let (topic, payload, _qos, _packet_id) = codec
        .decode_publish(frame)
        .map_err(|error| ProtocolError::Codec(error.to_string()))?;
    let text = std::str::from_utf8(&payload)
        .map_err(|_| ProtocolError::InvalidValue("MQTT payload is not UTF-8"))?;
    let value = match text.trim() {
        "true" | "TRUE" | "True" => PointValue::Boolean(true),
        "false" | "FALSE" | "False" => PointValue::Boolean(false),
        other => match other.parse::<i64>() {
            Ok(number) => PointValue::number(number, 0),
            Err(_) => PointValue::Text(text.to_string()),
        },
    };
    Ok(DecodedPoint::new(PointAddress::Mqtt { topic }, value))
}
