// SPDX-License-Identifier: Apache-2.0

//! Pure MQTT 3.1.1 packet codec (CONNECT/CONNACK/PUBLISH/PUBACK).
//!
//! These helpers build and parse MQTT packet bytes. The TLS transport lives in
//! the AGPL `tirbase-drivers` crate; this module performs no I/O.

use crate::driver_trait::{DriverError, Frame};

/// Maximum length of an MQTT topic filter or name accepted by the codec.
pub const MAX_TOPIC_LEN: usize = 512;

/// MQTT QoS levels supported by the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttQoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
}

impl TryFrom<u8> for MqttQoS {
    type Error = DriverError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::AtMostOnce),
            1 => Ok(Self::AtLeastOnce),
            _ => Err(DriverError::UnsupportedParam(format!(
                "MQTT QoS {v} not supported; only 0 and 1 are allowed"
            ))),
        }
    }
}

/// Pure MQTT packet codec helpers (3.1.1 subset: CONNECT/CONNACK/PUBLISH/PUBACK).
#[derive(Debug, Clone, Default)]
pub struct MqttBridgeCodec;

impl MqttBridgeCodec {
    pub fn new() -> Self {
        Self
    }

    pub fn encode_remaining_length(mut len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (len % 128) as u8;
            len /= 128;
            if len > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if len == 0 {
                break;
            }
        }
        out
    }

    pub fn decode_remaining_length(data: &[u8]) -> Result<(usize, usize), DriverError> {
        let mut multiplier = 1usize;
        let mut value = 0usize;
        let mut i = 0usize;
        loop {
            if i >= data.len() || i >= 4 {
                return Err(DriverError::InvalidFrame(
                    "invalid MQTT remaining length".into(),
                ));
            }
            let encoded = data[i];
            value = value
                .checked_add(((encoded & 127) as usize).saturating_mul(multiplier))
                .ok_or_else(|| DriverError::InvalidFrame("MQTT length overflow".into()))?;
            multiplier = multiplier.saturating_mul(128);
            i += 1;
            if (encoded & 128) == 0 {
                break;
            }
        }
        Ok((value, i))
    }

    /// Encode an MQTT UTF-8 string field (length-prefixed).
    ///
    /// Rejects empty values, values longer than 65,535 bytes, and values that
    /// contain control characters or the null character, per the MQTT 3.1.1
    /// UTF-8 string rules.
    pub fn encode_utf8_string(out: &mut Vec<u8>, value: &str) -> Result<(), DriverError> {
        if value.is_empty() {
            return Err(DriverError::Codec("empty MQTT string field".into()));
        }
        if value.len() > u16::MAX as usize {
            return Err(DriverError::Codec(
                "MQTT string field exceeds 65535 bytes".into(),
            ));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(DriverError::Codec(
                "MQTT string field contains control characters".into(),
            ));
        }
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn validate_topic(topic: &str) -> Result<(), DriverError> {
        if topic.is_empty() || topic.len() > MAX_TOPIC_LEN {
            return Err(DriverError::Codec(format!(
                "MQTT topic must be 1..={MAX_TOPIC_LEN} bytes"
            )));
        }
        if topic.chars().any(char::is_control) {
            return Err(DriverError::Codec(
                "MQTT topic contains control characters".into(),
            ));
        }
        Ok(())
    }

    pub fn encode_connect(&self, client_id: &str) -> Result<Frame, DriverError> {
        self.encode_connect_inner(client_id, None, None)
    }

    /// Encode a CONNECT carrying per-device username and password credentials.
    ///
    /// The password is placed in this frame and nowhere else; callers must not
    /// log the returned bytes. Both values are validated as MQTT UTF-8 strings
    /// and must be non-empty.
    pub fn encode_connect_with_credentials(
        &self,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> Result<Frame, DriverError> {
        if username.is_empty() || password.is_empty() {
            return Err(DriverError::Codec(
                "MQTT credentials must be non-empty".into(),
            ));
        }
        self.encode_connect_inner(client_id, Some(username), Some(password))
    }

    fn encode_connect_inner(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Frame, DriverError> {
        let mut vh = Vec::new();
        vh.extend_from_slice(&[0, 4]);
        vh.extend_from_slice(b"MQTT");
        vh.push(4); // protocol level 3.1.1
        let mut flags = 0x02u8; // clean session
        if password.is_some() {
            flags |= 0x40;
        }
        if username.is_some() {
            flags |= 0x80;
        }
        vh.push(flags);
        vh.extend_from_slice(&30u16.to_be_bytes()); // keepalive
        let mut payload = Vec::new();
        Self::encode_utf8_string(&mut payload, client_id)?;
        if let Some(username) = username {
            Self::encode_utf8_string(&mut payload, username)?;
        }
        if let Some(password) = password {
            Self::encode_utf8_string(&mut payload, password)?;
        }
        let mut pkt = vec![0x10];
        pkt.extend(Self::encode_remaining_length(vh.len() + payload.len()));
        pkt.extend_from_slice(&vh);
        pkt.extend_from_slice(&payload);
        Ok(pkt)
    }

    /// Encode a SUBSCRIBE packet for exactly one topic filter.
    pub fn encode_subscribe(
        &self,
        topic: &str,
        qos: MqttQoS,
        packet_id: u16,
    ) -> Result<Frame, DriverError> {
        if packet_id == 0 {
            return Err(DriverError::Codec(
                "SUBSCRIBE packet id must be non-zero".into(),
            ));
        }
        Self::validate_topic(topic)?;
        let mut body = Vec::new();
        body.extend_from_slice(&packet_id.to_be_bytes());
        Self::encode_utf8_string(&mut body, topic)?;
        body.push(qos as u8);
        let mut pkt = vec![0x82];
        pkt.extend(Self::encode_remaining_length(body.len()));
        pkt.extend_from_slice(&body);
        Ok(pkt)
    }

    /// Decode a SUBACK and confirm it grants the expected subscription.
    ///
    /// A return code of `0x80` (failure) and a packet-identifier mismatch are
    /// typed errors: a broker must not silently leave the bridge unsubscribed.
    pub fn decode_suback(&self, frame: &[u8], expected_packet_id: u16) -> Result<(), DriverError> {
        if frame.len() < 5 || frame[0] != 0x90 {
            return Err(DriverError::InvalidFrame("expected MQTT SUBACK".into()));
        }
        let (remaining, rl_len) = Self::decode_remaining_length(&frame[1..])?;
        let start = 1 + rl_len;
        if remaining < 3 || frame.len() < start + remaining {
            return Err(DriverError::InvalidFrame("truncated MQTT SUBACK".into()));
        }
        let packet_id = u16::from_be_bytes([frame[start], frame[start + 1]]);
        if packet_id != expected_packet_id {
            return Err(DriverError::Codec(format!(
                "SUBACK packet id mismatch: expected {expected_packet_id}, got {packet_id}"
            )));
        }
        let granted = frame[start + 2];
        if granted == 0x80 {
            return Err(DriverError::Codec(
                "MQTT SUBACK rejected subscription".into(),
            ));
        }
        MqttQoS::try_from(granted)?;
        Ok(())
    }

    /// Encode a DISCONNECT packet.
    pub fn encode_disconnect(&self) -> Frame {
        vec![0xE0, 0x00]
    }

    pub fn encode_connack(&self, session_present: bool, return_code: u8) -> Frame {
        vec![0x20, 0x02, if session_present { 1 } else { 0 }, return_code]
    }

    pub fn decode_connack(&self, frame: &[u8]) -> Result<(), DriverError> {
        if frame.len() < 4 || frame[0] != 0x20 {
            return Err(DriverError::InvalidFrame("expected MQTT CONNACK".into()));
        }
        if frame[3] != 0 {
            return Err(DriverError::Codec(format!(
                "MQTT CONNACK return code {}",
                frame[3]
            )));
        }
        Ok(())
    }

    /// Encode a PUBLISH packet (QoS 0 or 1). QoS 1 requires a packet identifier.
    pub fn encode_publish(
        &self,
        topic: &str,
        payload: &[u8],
        qos: MqttQoS,
        packet_id: Option<u16>,
    ) -> Result<Frame, DriverError> {
        if qos == MqttQoS::AtLeastOnce && packet_id.is_none() {
            return Err(DriverError::Codec(
                "QoS 1 PUBLISH requires packet id".into(),
            ));
        }
        Self::validate_topic(topic)?;
        let mut vh = Vec::new();
        let topic_bytes = topic.as_bytes();
        vh.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        vh.extend_from_slice(topic_bytes);
        if qos == MqttQoS::AtLeastOnce {
            vh.extend_from_slice(&packet_id.unwrap().to_be_bytes());
        }
        let mut pkt = Vec::new();
        let fixed = 0x30u8 | ((qos as u8) << 1);
        pkt.push(fixed);
        pkt.extend(Self::encode_remaining_length(vh.len() + payload.len()));
        pkt.extend_from_slice(&vh);
        pkt.extend_from_slice(payload);
        Ok(pkt)
    }

    /// Decode a PUBLISH packet. Returns (topic, payload, qos, packet_id).
    pub fn decode_publish(
        &self,
        frame: &[u8],
    ) -> Result<(String, Vec<u8>, MqttQoS, Option<u16>), DriverError> {
        if frame.len() < 2 || (frame[0] & 0xF0) != 0x30 {
            return Err(DriverError::InvalidFrame("expected MQTT PUBLISH".into()));
        }
        let qos = MqttQoS::try_from((frame[0] >> 1) & 0x03)?;
        let (remaining, rl_len) = Self::decode_remaining_length(&frame[1..])?;
        let start = 1 + rl_len;
        let end = start
            .checked_add(remaining)
            .ok_or_else(|| DriverError::InvalidFrame("MQTT length overflow".into()))?;
        if frame.len() < end {
            return Err(DriverError::InvalidFrame("truncated MQTT PUBLISH".into()));
        }
        let body = &frame[start..end];
        if body.len() < 2 {
            return Err(DriverError::InvalidFrame("short MQTT topic".into()));
        }
        let tlen = u16::from_be_bytes([body[0], body[1]]) as usize;
        let mut idx = 2 + tlen;
        if body.len() < idx {
            return Err(DriverError::InvalidFrame("truncated MQTT topic".into()));
        }
        let topic = String::from_utf8(body[2..idx].to_vec())
            .map_err(|e| DriverError::InvalidFrame(format!("invalid MQTT topic utf8: {e}")))?;
        let packet_id = if qos == MqttQoS::AtLeastOnce {
            if body.len() < idx + 2 {
                return Err(DriverError::InvalidFrame("missing QoS1 packet id".into()));
            }
            let pid = u16::from_be_bytes([body[idx], body[idx + 1]]);
            idx += 2;
            Some(pid)
        } else {
            None
        };
        Ok((topic, body[idx..].to_vec(), qos, packet_id))
    }

    pub fn encode_puback(&self, packet_id: u16) -> Frame {
        vec![0x40, 0x02, (packet_id >> 8) as u8, packet_id as u8]
    }

    pub fn decode_puback(&self, frame: &[u8]) -> Result<u16, DriverError> {
        if frame.len() < 4 || frame[0] != 0x40 {
            return Err(DriverError::InvalidFrame("expected MQTT PUBACK".into()));
        }
        Ok(u16::from_be_bytes([frame[2], frame[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qos0_publish_roundtrip() {
        let c = MqttBridgeCodec::new();
        let pkt = c
            .encode_publish("t/a", b"hello", MqttQoS::AtMostOnce, None)
            .unwrap();
        let (topic, payload, qos, pid) = c.decode_publish(&pkt).unwrap();
        assert_eq!(topic, "t/a");
        assert_eq!(payload, b"hello");
        assert_eq!(qos, MqttQoS::AtMostOnce);
        assert_eq!(pid, None);
    }

    #[test]
    fn qos1_publish_puback_roundtrip() {
        let c = MqttBridgeCodec::new();
        let pkt = c
            .encode_publish("t/b", b"data", MqttQoS::AtLeastOnce, Some(42))
            .unwrap();
        let (topic, payload, qos, pid) = c.decode_publish(&pkt).unwrap();
        assert_eq!(topic, "t/b");
        assert_eq!(payload, b"data");
        assert_eq!(qos, MqttQoS::AtLeastOnce);
        assert_eq!(pid, Some(42));
        let ack = c.encode_puback(42);
        assert_eq!(c.decode_puback(&ack).unwrap(), 42);
    }

    #[test]
    fn connect_puback_codec() {
        let c = MqttBridgeCodec::new();
        let connect = c.encode_connect("client-1").unwrap();
        assert_eq!(connect[0], 0x10);
        let connack = c.encode_connack(false, 0);
        c.decode_connack(&connack).unwrap();
    }

    #[test]
    fn unsupported_qos_is_a_typed_error() {
        assert!(matches!(
            MqttQoS::try_from(2),
            Err(DriverError::UnsupportedParam(_))
        ));
    }

    #[test]
    fn connect_with_credentials_sets_flags_and_carries_values() {
        let c = MqttBridgeCodec::new();
        let frame = c
            .encode_connect_with_credentials("coldroom-1", "device-coldroom-1", "s3cret")
            .expect("connect frame");
        assert_eq!(frame[0], 0x10);
        // Protocol name, level, flags, keepalive.
        assert_eq!(&frame[2..8], b"\x00\x04MQTT");
        assert_eq!(frame[8], 4, "MQTT 3.1.1 protocol level");
        assert_eq!(frame[9], 0xC2, "clean session + username + password");
        let body = &frame[12..];
        assert!(body.windows(10).any(|w| w == b"coldroom-1"));
        assert!(body.windows(17).any(|w| w == b"device-coldroom-1"));
        assert!(body.windows(6).any(|w| w == b"s3cret"));
    }

    #[test]
    fn connect_rejects_empty_credentials() {
        let c = MqttBridgeCodec::new();
        assert!(c.encode_connect_with_credentials("c", "user", "").is_err());
        assert!(c.encode_connect_with_credentials("c", "", "pass").is_err());
        assert!(c
            .encode_connect_with_credentials("c", "us\ner", "pass")
            .is_err());
    }

    #[test]
    fn subscribe_suback_roundtrip() {
        let c = MqttBridgeCodec::new();
        let sub = c
            .encode_subscribe(
                "tirbase/devices/coldroom-1/reading",
                MqttQoS::AtLeastOnce,
                7,
            )
            .expect("subscribe frame");
        assert_eq!(sub[0], 0x82);
        let suback = vec![0x90, 0x03, 0x00, 0x07, 0x01];
        c.decode_suback(&suback, 7).expect("granted QoS 1");
        assert!(c.decode_suback(&suback, 8).is_err(), "packet id mismatch");
        assert!(
            c.decode_suback(&[0x90, 0x03, 0x00, 0x07, 0x80], 7).is_err(),
            "broker rejection must be typed"
        );
    }

    #[test]
    fn subscribe_rejects_wildcard_free_validation_of_empty_topics() {
        let c = MqttBridgeCodec::new();
        assert!(c.encode_subscribe("", MqttQoS::AtMostOnce, 1).is_err());
        assert!(c
            .encode_subscribe(&"a".repeat(MAX_TOPIC_LEN + 1), MqttQoS::AtMostOnce, 1)
            .is_err());
        assert!(c
            .encode_subscribe("a/b\u{0}", MqttQoS::AtMostOnce, 1)
            .is_err());
        assert!(c.encode_subscribe("a/b", MqttQoS::AtMostOnce, 0).is_err());
    }

    #[test]
    fn publish_rejects_bad_topics() {
        let c = MqttBridgeCodec::new();
        assert!(c
            .encode_publish("", b"x", MqttQoS::AtMostOnce, None)
            .is_err());
        assert!(c
            .encode_publish("a\u{7f}/b", b"x", MqttQoS::AtMostOnce, None)
            .is_err());
    }

    #[test]
    fn disconnect_is_empty_packet() {
        assert_eq!(MqttBridgeCodec::new().encode_disconnect(), vec![0xE0, 0x00]);
    }
}
