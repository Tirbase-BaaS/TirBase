//! MQTT 3.1.1 bridge driver and TLS-only transport (CLAIM-34.2, PV-10.7).
//!
//! Public API enforces TLS: [`connect_mqtts`] performs a real `rustls` handshake
//! and speaks MQTT 3.1.1 packets over the resulting TLS stream. There is no
//! public plaintext connect path, and a plaintext TCP server is rejected because
//! the TLS handshake fails.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

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

/// Connection security / protocol error.
#[derive(Debug)]
pub enum MqttError {
    PlainTextRejected { uri: String },
    InvalidUri(String),
    Io(io::Error),
    Tls(String),
    Protocol(String),
}

impl fmt::Display for MqttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttError::PlainTextRejected { uri } => write!(
                f,
                "plain-text MQTT connection rejected for '{uri}'; use mqtts:// and TLS"
            ),
            MqttError::InvalidUri(m) => write!(f, "invalid MQTT URI: {m}"),
            MqttError::Io(e) => write!(f, "mqtt io error: {e}"),
            MqttError::Tls(m) => write!(f, "mqtt TLS error: {m}"),
            MqttError::Protocol(m) => write!(f, "mqtt protocol error: {m}"),
        }
    }
}

impl std::error::Error for MqttError {}

impl From<io::Error> for MqttError {
    fn from(e: io::Error) -> Self {
        MqttError::Io(e)
    }
}

impl From<DriverError> for MqttError {
    fn from(e: DriverError) -> Self {
        MqttError::Protocol(e.to_string())
    }
}

/// Public marker kept for compatibility with existing tests/callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttSecurityError;
impl fmt::Display for MqttSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "plain-text MQTT/TLS validation failed")
    }
}
impl std::error::Error for MqttSecurityError {}

/// Configuration for an MQTT bridge endpoint. Only TLS endpoints are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttConnectConfig {
    pub uri: String,
    pub client_id: String,
    pub tls_configured: bool,
}

impl MqttConnectConfig {
 /// Validates URI/TLS intent. Does not replace a real handshake.
    pub fn validate_tls_required(&self) -> Result<(), MqttError> {
        let lower = self.uri.trim().to_ascii_lowercase();
        if lower.starts_with("mqtt://") || lower.starts_with("tcp://") || lower.starts_with("ws://")
        {
            return Err(MqttError::PlainTextRejected {
                uri: self.uri.clone(),
            });
        }
        if !self.tls_configured
            && !(lower.starts_with("mqtts://")
                || lower.starts_with("ssl://")
                || lower.starts_with("tcps://")
                || lower.starts_with("wss://"))
        {
            return Err(MqttError::Tls(
                "MQTT TLS configuration is required (use mqtts://)".into(),
            ));
        }
        Ok(())
    }
}

/// Marker proving the endpoint passed TLS-only validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsValidatedEndpoint {
    pub uri: String,
    pub client_id: String,
}

pub fn connect_tls_only(config: &MqttConnectConfig) -> Result<TlsValidatedEndpoint, MqttError> {
    config.validate_tls_required()?;
    Ok(TlsValidatedEndpoint {
        uri: config.uri.clone(),
        client_id: config.client_id.clone(),
    })
}

/// Parse `mqtts://host:port` (or `ssl://`/`tcps://`) into host/port.
pub fn parse_mqtts_uri(uri: &str) -> Result<(String, u16), MqttError> {
    let lower = uri.trim().to_ascii_lowercase();
    if lower.starts_with("mqtt://") || lower.starts_with("tcp://") || lower.starts_with("ws://") {
        return Err(MqttError::PlainTextRejected {
            uri: uri.to_string(),
        });
    }
    let rest = uri
        .trim()
        .strip_prefix("mqtts://")
        .or_else(|| uri.trim().strip_prefix("ssl://"))
        .or_else(|| uri.trim().strip_prefix("tcps://"))
        .ok_or_else(|| MqttError::InvalidUri("expected mqtts://, ssl://, or tcps://".into()))?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| MqttError::InvalidUri(format!("invalid port '{p}'")))?,
        ),
        None => (rest.to_string(), 8883),
    };
    if host.is_empty() {
        return Err(MqttError::InvalidUri("missing host".into()));
    }
    Ok((host, port))
}

/// Install rustls ring crypto provider if not already installed (test/CLI helper).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a rustls client config that trusts `roots` (for tests/custom CAs) plus
/// webpki roots when `include_webpki` is true.
pub fn client_config_with_roots(
    extra_roots: impl IntoIterator<Item = rustls::pki_types::CertificateDer<'static>>,
    include_webpki: bool,
) -> Result<Arc<ClientConfig>, MqttError> {
    let mut roots = RootCertStore::empty();
    if include_webpki {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for cert in extra_roots {
        roots
            .add(cert)
            .map_err(|e| MqttError::Tls(format!("add root: {e}")))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub type TlsTcpStream = StreamOwned<ClientConnection, TcpStream>;

/// Real MQTT 3.1.1 client over TLS. No public plaintext connect path exists.
#[derive(Debug)]
pub struct MqttTlsClient {
    stream: TlsTcpStream,
    codec: MqttBridgeCodec,
    next_packet_id: u16,
}

impl MqttTlsClient {
 /// Connect to an `mqtts://` endpoint and perform TLS handshake + MQTT CONNECT.
 /// Connecting to a plaintext TCP server fails at TLS handshake (CLAIM-34.2).
    pub fn connect_mqtts(
        uri: &str,
        client_id: &str,
        tls_config: Arc<ClientConfig>,
        io_timeout: Duration,
    ) -> Result<Self, MqttError> {
        let (host, port) = parse_mqtts_uri(uri)?;
        let addr = (host.as_str(), port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| MqttError::InvalidUri(format!("no address for {host}:{port}")))?;
        let tcp = TcpStream::connect_timeout(&addr, io_timeout)?;
        tcp.set_read_timeout(Some(io_timeout))?;
        tcp.set_write_timeout(Some(io_timeout))?;
        tcp.set_nodelay(true)?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| MqttError::Tls(format!("invalid server name '{host}': {e}")))?;
        let conn = ClientConnection::new(tls_config, server_name)
            .map_err(|e| MqttError::Tls(format!("tls client: {e}")))?;
        let mut stream = StreamOwned::new(conn, tcp);
 // Completing handshake by writing/flushing if needed happens on first I/O.
        let connect = MqttBridgeCodec::new().encode_connect(client_id)?;
        stream.write_all(&connect)?;
        stream.flush()?;
        let ack = read_packet(&mut stream, io_timeout)?;
        MqttBridgeCodec::new().decode_connack(&ack)?;
        Ok(Self {
            stream,
            codec: MqttBridgeCodec::new(),
            next_packet_id: 1,
        })
    }

    pub fn publish_qos0(&mut self, topic: &str, payload: &[u8]) -> Result<(), MqttError> {
        let pkt = self
            .codec
            .encode_publish(topic, payload, MqttQoS::AtMostOnce, None)
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        self.stream.write_all(&pkt)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn publish_qos1(
        &mut self,
        topic: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<u16, MqttError> {
        let pid = self.alloc_packet_id();
        let pkt = self
            .codec
            .encode_publish(topic, payload, MqttQoS::AtLeastOnce, Some(pid))
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        self.stream.write_all(&pkt)?;
        self.stream.flush()?;
        let ack = read_packet(&mut self.stream, timeout)?;
        let ack_pid = self
            .codec
            .decode_puback(&ack)
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        if ack_pid != pid {
            return Err(MqttError::Protocol(format!(
                "PUBACK packet id mismatch: expected {pid}, got {ack_pid}"
            )));
        }
        Ok(pid)
    }

    fn alloc_packet_id(&mut self) -> u16 {
        let pid = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
        pid
    }
}

fn read_packet<R: Read>(r: &mut R, _timeout: Duration) -> Result<Vec<u8>, MqttError> {
    let mut head = [0u8; 1];
    r.read_exact(&mut head)?;
    let mut rem = Vec::new();
    let mut multiplier = 1usize;
    let mut value = 0usize;
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        rem.push(b[0]);
        value += ((b[0] & 127) as usize) * multiplier;
        if (b[0] & 128) == 0 {
            break;
        }
        multiplier *= 128;
        if rem.len() > 4 {
            return Err(MqttError::Protocol("remaining length too large".into()));
        }
    }
    let mut body = vec![0u8; value];
    r.read_exact(&mut body)?;
    let mut out = Vec::with_capacity(1 + rem.len() + body.len());
    out.push(head[0]);
    out.extend_from_slice(&rem);
    out.extend_from_slice(&body);
    Ok(out)
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
    fn plain_text_mqtt_uri_is_rejected() {
        let cfg = MqttConnectConfig {
            uri: "mqtt://broker.local:1883".into(),
            client_id: "c1".into(),
            tls_configured: false,
        };
        assert!(matches!(
            connect_tls_only(&cfg),
            Err(MqttError::PlainTextRejected { .. })
        ));
    }

    #[test]
    fn tcp_plain_text_is_rejected() {
        let err = parse_mqtts_uri("tcp://127.0.0.1:1883").unwrap_err();
        assert!(matches!(err, MqttError::PlainTextRejected { .. }));
    }

    #[test]
    fn mqtts_uri_parses() {
        let (h, p) = parse_mqtts_uri("mqtts://localhost:8883").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 8883);
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

    #[test]
    fn connect_puback_codec() {
        let c = MqttBridgeCodec::new();
        let connect = c.encode_connect("client-1").unwrap();
        assert_eq!(connect[0], 0x10);
        let connack = c.encode_connack(false, 0);
        c.decode_connack(&connack).unwrap();
    }
}
