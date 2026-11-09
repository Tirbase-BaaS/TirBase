//! MQTT bridge driver codec and TLS-only connection policy (CLAIM-34.2, PV-10.7).
//!
//! Supports QoS 0 and 1 packet encoding/decoding helpers. Plain-text connections
//! are rejected by [`MqttConnectConfig::validate_tls_required`] / [`connect_tls_only`].

use std::fmt;

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

/// Connection security error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttSecurityError {
    PlainTextRejected { uri: String },
    MissingTlsConfig,
}

impl fmt::Display for MqttSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttSecurityError::PlainTextRejected { uri } => {
                write!(
                    f,
                    "plain-text MQTT connection rejected for '{uri}'; TLS is required"
                )
            }
            MqttSecurityError::MissingTlsConfig => {
                write!(f, "MQTT TLS configuration is required")
            }
        }
    }
}

impl std::error::Error for MqttSecurityError {}

/// Configuration for an MQTT bridge endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttConnectConfig {
    /// Broker URI. `mqtt://` / unencrypted endpoints are rejected; `mqtts://` or
    /// an explicit TLS transport is required.
    pub uri: String,
    pub client_id: String,
    pub tls_configured: bool,
}

impl MqttConnectConfig {
    /// Validate that this config uses TLS and does not permit plain-text MQTT.
    pub fn validate_tls_required(&self) -> Result<(), MqttSecurityError> {
        let lower = self.uri.trim().to_ascii_lowercase();
        if lower.starts_with("mqtt://") || lower.starts_with("tcp://") || lower.starts_with("ws://")
        {
            return Err(MqttSecurityError::PlainTextRejected {
                uri: self.uri.clone(),
            });
        }
        if !self.tls_configured
            && !(lower.starts_with("mqtts://")
                || lower.starts_with("ssl://")
                || lower.starts_with("tcps://")
                || lower.starts_with("wss://"))
        {
            return Err(MqttSecurityError::MissingTlsConfig);
        }
        Ok(())
    }
}

/// Connect helper that enforces TLS-only policy before any network I/O.
///
/// The returned value is a marker proving validation passed; production wiring
/// passes it to the TLS transport.
pub fn connect_tls_only(
    config: &MqttConnectConfig,
) -> Result<TlsValidatedEndpoint, MqttSecurityError> {
    config.validate_tls_required()?;
    Ok(TlsValidatedEndpoint {
        uri: config.uri.clone(),
        client_id: config.client_id.clone(),
    })
}

/// Marker proving the endpoint passed TLS-only validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsValidatedEndpoint {
    pub uri: String,
    pub client_id: String,
}

/// Pure MQTT packet codec helpers (QoS 0/1 focus for PV-10.7).
#[derive(Debug, Clone, Default)]
pub struct MqttBridgeCodec;

impl MqttBridgeCodec {
    pub fn new() -> Self {
        Self
    }

    fn encode_remaining_length(mut len: usize) -> Vec<u8> {
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

    fn decode_remaining_length(data: &[u8]) -> Result<(usize, usize), DriverError> {
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
                .checked_add(
                    ((encoded & 127) as usize)
                        .checked_mul(multiplier)
                        .ok_or_else(|| {
                            DriverError::InvalidFrame("MQTT remaining length overflow".into())
                        })?,
                )
                .ok_or_else(|| {
                    DriverError::InvalidFrame("MQTT remaining length overflow".into())
                })?;
            multiplier = multiplier.saturating_mul(128);
            i += 1;
            if (encoded & 128) == 0 {
                break;
            }
        }
        Ok((value, i))
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

    /// Encode a PUBACK for QoS 1.
    pub fn encode_puback(&self, packet_id: u16) -> Frame {
        vec![0x40, 0x02, (packet_id >> 8) as u8, packet_id as u8]
    }

    /// Decode PUBACK packet id.
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
    fn plain_text_mqtt_is_rejected() {
        let cfg = MqttConnectConfig {
            uri: "mqtt://broker.local:1883".into(),
            client_id: "c1".into(),
            tls_configured: false,
        };
        let err = connect_tls_only(&cfg).unwrap_err();
        assert!(matches!(err, MqttSecurityError::PlainTextRejected { .. }));
    }

    #[test]
    fn tcp_plain_text_is_rejected() {
        let cfg = MqttConnectConfig {
            uri: "tcp://127.0.0.1:1883".into(),
            client_id: "c1".into(),
            tls_configured: false,
        };
        assert!(connect_tls_only(&cfg).is_err());
    }

    #[test]
    fn mqtts_with_tls_is_accepted() {
        let cfg = MqttConnectConfig {
            uri: "mqtts://broker.local:8883".into(),
            client_id: "c1".into(),
            tls_configured: true,
        };
        let ok = connect_tls_only(&cfg).unwrap();
        assert_eq!(ok.client_id, "c1");
    }

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
}
