// SPDX-License-Identifier: Apache-2.0

//! MQTT connector.
//!
//! The broker connection is injected as [`MqttTransport`]; this crate supplies
//! the publish encoding (MQTT 3.1.1 fixed header, remaining length varint,
//! topic, packet id) so a host can bind any client library without this crate
//! depending on one.

use std::sync::atomic::{AtomicU16, Ordering};

use crate::connector::{
    validate_connector_common, AuthKind, Connector, ConnectorBuildError, ConnectorCapabilities,
    ConnectorHealth, ConnectorKind, DeliveryRequest, DeliveryResult, DEFAULT_MAX_PAYLOAD_BYTES,
};

/// MQTT publish ceiling.
pub const MQTT_MAX_REMAINING_LENGTH: usize = 268_435_455;

/// Result of one publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqttPublish {
    /// Whether the broker already had this event.
    pub duplicate: bool,
    /// Packet identifier used.
    pub packet_id: u16,
}

/// Transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttTransportError {
    /// Whether a retry could succeed.
    pub retryable: bool,
    /// Secret-free detail.
    pub detail: String,
}

impl MqttTransportError {
    /// A transient failure.
    pub fn retryable(detail: impl Into<String>) -> Self {
        Self {
            retryable: true,
            detail: detail.into(),
        }
    }

    /// A permanent failure.
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            retryable: false,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for MqttTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for MqttTransportError {}

/// A broker connection.
pub trait MqttTransport: Send + Sync {
    /// Publish one message and await the broker's acknowledgement.
    fn publish(
        &self,
        topic: &str,
        payload: &[u8],
        qos: u8,
        retain: bool,
    ) -> Result<MqttPublish, MqttTransportError>;
}

/// Packet identifier allocation.
#[derive(Debug, Default)]
pub struct PacketIds {
    next: AtomicU16,
}

impl PacketIds {
    /// Allocate the next non-zero packet id.
    pub fn next(&self) -> u16 {
        let id = self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if id == 0 {
            self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
        } else {
            id
        }
    }
}

/// Encode an MQTT 3.1.1 PUBLISH packet.
///
/// Returns `None` when the topic is empty, longer than 65,535 bytes, contains a
/// wildcard, or the payload would exceed the protocol's remaining-length limit.
pub fn encode_publish(
    topic: &str,
    payload: &[u8],
    qos: u8,
    packet_id: u16,
    retain: bool,
) -> Option<Vec<u8>> {
    if qos > 1 || topic.is_empty() || topic.len() > u16::MAX as usize {
        return None;
    }
    if topic.contains(['+', '#']) {
        return None;
    }
    if qos == 1 && packet_id == 0 {
        return None;
    }
    let mut remaining = 2 + topic.len() + payload.len();
    if qos > 0 {
        remaining += 2;
    }
    if remaining > MQTT_MAX_REMAINING_LENGTH {
        return None;
    }
    let mut packet = Vec::with_capacity(remaining + 5);
    let flags = 0b0011_0000 | (qos << 1) | u8::from(retain);
    packet.push(flags);
    let mut length = remaining;
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        packet.push(byte);
        if length == 0 {
            break;
        }
    }
    packet.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    packet.extend_from_slice(topic.as_bytes());
    if qos > 0 {
        packet.extend_from_slice(&packet_id.to_be_bytes());
    }
    packet.extend_from_slice(payload);
    Some(packet)
}

/// An MQTT connector.
pub struct MqttConnector<T: MqttTransport> {
    name: String,
    topic: String,
    qos: u8,
    retain: bool,
    transport: T,
    packet_ids: PacketIds,
    max_payload_bytes: usize,
}

impl<T: MqttTransport> MqttConnector<T> {
    /// Build a connector publishing to `topic`.
    pub fn new(
        name: impl Into<String>,
        topic: impl Into<String>,
        qos: u8,
        transport: T,
    ) -> Result<Self, ConnectorBuildError> {
        let name = name.into();
        validate_connector_common(&name, DEFAULT_MAX_PAYLOAD_BYTES)?;
        let topic = topic.into();
        if topic.is_empty() || topic.contains(['+', '#']) {
            return Err(ConnectorBuildError::new(
                "topic",
                "must be a concrete topic without wildcards",
            ));
        }
        if qos > 1 {
            return Err(ConnectorBuildError::new("qos", "must be 0 or 1"));
        }
        Ok(Self {
            name,
            topic,
            qos,
            retain: false,
            transport,
            packet_ids: PacketIds::default(),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        })
    }

    /// Retain published messages.
    pub fn with_retain(mut self, retain: bool) -> Self {
        self.retain = retain;
        self
    }

    /// Restrict the accepted payload size.
    pub fn with_max_payload_bytes(mut self, max_payload_bytes: usize) -> Self {
        self.max_payload_bytes = max_payload_bytes.max(1);
        self
    }

    /// The topic.
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

impl<T: MqttTransport> Connector for MqttConnector<T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Mqtt
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            idempotent: true,
            auth: vec![AuthKind::None],
            max_payload_bytes: self.max_payload_bytes,
        }
    }

    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult {
        let message = serde_json::json!({
            "event_id": request.event_id,
            "event_type": request.event_type,
            "tenant": request.tenant,
            "idempotency_key": request.idempotency_key,
            "attempt": request.attempt,
            "data": request.payload,
        });
        let payload = match serde_json::to_vec(&message) {
            Ok(payload) => payload,
            Err(error) => return DeliveryResult::permanent(format!("payload: {error}")),
        };
        if payload.len() > self.max_payload_bytes {
            return DeliveryResult::permanent(format!(
                "{} bytes exceeds the {}-byte ceiling",
                payload.len(),
                self.max_payload_bytes
            ));
        }
        let packet_id = self.packet_ids.next();
        if encode_publish(&self.topic, &payload, self.qos, packet_id, self.retain).is_none() {
            return DeliveryResult::permanent("message cannot be encoded as MQTT PUBLISH");
        }
        match self
            .transport
            .publish(&self.topic, &payload, self.qos, self.retain)
        {
            Ok(publish) if publish.duplicate => {
                DeliveryResult::duplicate(format!("broker had packet {}", publish.packet_id))
            }
            Ok(publish) => {
                DeliveryResult::delivered(format!("published packet {}", publish.packet_id))
            }
            Err(error) if error.retryable => DeliveryResult::retryable(error.detail, None),
            Err(error) => DeliveryResult::permanent(error.detail),
        }
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy(format!("publishing to {} at QoS {}", self.topic, self.qos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_encoding_matches_mqtt_3_1_1() {
        let packet = encode_publish("plant/a", b"hi", 0, 0, false).expect("packet");
        assert_eq!(packet[0], 0x30);
        assert_eq!(packet[1], 2 + 7 + 2);
        assert_eq!(&packet[2..4], &[0, 7]);
        assert_eq!(&packet[4..11], b"plant/a");
        assert_eq!(&packet[11..], b"hi");

        let qos1 = encode_publish("a/b", b"x", 1, 7, true).expect("packet");
        assert_eq!(qos1[0], 0b0011_0011);
        assert_eq!(&qos1[2..4], &[0, 3]);
        assert_eq!(&qos1[4..7], b"a/b");
        assert_eq!(&qos1[7..9], &[0, 7]);
        assert_eq!(&qos1[9..], b"x");

        assert!(encode_publish("", b"x", 0, 0, false).is_none());
        assert!(encode_publish("a/+", b"x", 0, 0, false).is_none());
        assert!(encode_publish("a/b", b"x", 2, 1, false).is_none());
        assert!(encode_publish("a/b", b"x", 1, 0, false).is_none());
    }

    #[test]
    fn remaining_length_varint_encodes_large_payloads() {
        let payload = vec![0u8; 200];
        let packet = encode_publish("t", &payload, 0, 0, false).expect("packet");
        assert_eq!(packet[0], 0x30);
        assert_eq!(packet[1], 0xCB);
        assert_eq!(packet[2], 0x01);
    }
}
