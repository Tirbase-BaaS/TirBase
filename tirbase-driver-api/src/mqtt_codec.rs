// SPDX-License-Identifier: Apache-2.0

//! Pure MQTT 3.1.1 packet codec (CONNECT/CONNACK/PUBLISH/PUBACK).
//!
//! These helpers build and parse MQTT packet bytes. The TLS transport lives in
//! the AGPL `tirbase-drivers` crate; this module performs no I/O.

use crate::driver_trait::{DriverError, Frame};

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

    pub fn encode_connect(&self, client_id: &str) -> Result<Frame, DriverError> {
        let mut vh = Vec::new();
        vh.extend_from_slice(&[0, 4]);
        vh.extend_from_slice(b"MQTT");
        vh.push(4); // protocol level 3.1.1
        vh.push(0x02); // clean session
        vh.extend_from_slice(&30u16.to_be_bytes()); // keepalive
        let mut payload = Vec::new();
        let id = client_id.as_bytes();
        payload.extend_from_slice(&(id.len() as u16).to_be_bytes());
        payload.extend_from_slice(id);
        let mut pkt = vec![0x10];
        pkt.extend(Self::encode_remaining_length(vh.len() + payload.len()));
        pkt.extend_from_slice(&vh);
        pkt.extend_from_slice(&payload);
        Ok(pkt)
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
}
