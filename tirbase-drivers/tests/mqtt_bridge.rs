// SPDX-License-Identifier: AGPL-3.0-only

//! CC-07 MQTT sensor bridge: loopback broker over the crate's rustls test
//! harness.
//!
//! The broker answers CONNECT (recording the per-device credentials),
//! SUBSCRIBE (recording the exact topic and QoS), publishes a scripted message
//! sequence, and records PUBACKs. The tests prove the bridge's end-to-end
//! contract: valid readings decode, invalid/oversized/replayed payloads are
//! rejected, TLS verification cannot be bypassed through the bridge API, and a
//! silent broker fails a read within its deadline.
#![allow(clippy::disallowed_methods)] // tests measure real elapsed time

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

use tirbase_drivers::mqtt::{
    MqttBridgeClient, MqttBridgeCodec, MqttBridgeConfig, MqttBridgeError, MqttClockFn,
    MqttDeviceCredentials, MqttQoS, MqttTlsTrust, MqttTopicAllowlist, PayloadError, ReplayError,
};

const TOPIC: &str = "tirbase/devices/coldroom-1/reading";

/// Monotonic millisecond clock supplied by the caller (PV-3.12: no direct
/// clock reads inside driver code).
fn monotonic_clock() -> MqttClockFn {
    let start = Instant::now();
    Arc::new(move || start.elapsed().as_millis() as u64)
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let certified =
        generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).expect("rcgen");
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .expect("key")
        .clone_key();
    (cert, key)
}

fn server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config"),
    )
}

fn read_packet(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut head = [0u8; 1];
    stream.read_exact(&mut head).map_err(|e| e.to_string())?;
    let mut remaining = 0usize;
    let mut multiplier = 1usize;
    let mut length_bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("length: {e}"))?;
        length_bytes.push(byte[0]);
        remaining += ((byte[0] & 127) as usize) * multiplier;
        if (byte[0] & 128) == 0 {
            break;
        }
        multiplier *= 128;
        if length_bytes.len() > 4 {
            return Err("remaining length too large".into());
        }
    }
    if remaining > 65_536 {
        return Err(format!("packet too large: {remaining}"));
    }
    let mut body = vec![0u8; remaining];
    stream.read_exact(&mut body).map_err(|e| e.to_string())?;
    let mut out = vec![head[0]];
    out.extend(length_bytes);
    out.extend(body);
    Ok(out)
}

#[derive(Debug, Default)]
struct ConnectFields {
    client_id: String,
    username: String,
    password: String,
    flags: u8,
}

fn connect_fields(packet: &[u8]) -> Option<ConnectFields> {
    let (_, rl_len) = MqttBridgeCodec::decode_remaining_length(packet.get(1..)?).ok()?;
    let body = packet.get(1 + rl_len..)?;
    let name_len = u16::from_be_bytes([*body.first()?, *body.get(1)?]) as usize;
    let mut index = 2 + name_len;
    let _level = *body.get(index)?;
    index += 1;
    let flags = *body.get(index)?;
    index += 3; // flags byte + two-byte keepalive
    let take = |index: &mut usize| -> Option<String> {
        let len = u16::from_be_bytes([*body.get(*index)?, *body.get(*index + 1)?]) as usize;
        *index += 2;
        let value = body.get(*index..*index + len)?.to_vec();
        *index += len;
        String::from_utf8(value).ok()
    };
    let client_id = take(&mut index)?;
    let username = if flags & 0x80 != 0 {
        take(&mut index)?
    } else {
        String::new()
    };
    let password = if flags & 0x40 != 0 {
        take(&mut index)?
    } else {
        String::new()
    };
    Some(ConnectFields {
        client_id,
        username,
        password,
        flags,
    })
}

#[derive(Debug, Default)]
struct BrokerOutcome {
    connected: bool,
    client_id: String,
    username: String,
    password: String,
    connect_flags: u8,
    subscribe_topic: String,
    subscribe_qos: u8,
    pubacks: Vec<u16>,
    errors: Vec<String>,
}

enum ScriptStep {
    Publish {
        topic: &'static str,
        payload: Vec<u8>,
        qos: MqttQoS,
        packet_id: Option<u16>,
    },
    ExpectPubacks(usize),
    Sleep(Duration),
}

/// Start a loopback TLS MQTT broker that performs CONNECT/CONNACK and one
/// SUBSCRIBE/SUBACK, then executes the script. Errors are recorded in the
/// outcome instead of panicking so a refused TLS handshake is observable.
fn spawn_broker(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    steps: Vec<ScriptStep>,
) -> (u16, JoinHandle<BrokerOutcome>) {
    let config = server_config(cert, key);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind broker");
    let address = listener.local_addr().expect("broker addr");
    let handle = thread::spawn(move || {
        let mut outcome = BrokerOutcome::default();
        let (tcp, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(error) => {
                outcome.errors.push(format!("accept: {error}"));
                return outcome;
            }
        };
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let connection = match ServerConnection::new(config) {
            Ok(connection) => connection,
            Err(error) => {
                outcome.errors.push(format!("server conn: {error}"));
                return outcome;
            }
        };
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        let codec = MqttBridgeCodec::new();

        let connect = match read_packet(&mut stream) {
            Ok(packet) => packet,
            Err(error) => {
                outcome.errors.push(format!("connect: {error}"));
                return outcome;
            }
        };
        if connect.first().copied() != Some(0x10) {
            outcome.errors.push("expected CONNECT".into());
            return outcome;
        }
        if let Some(fields) = connect_fields(&connect) {
            outcome.client_id = fields.client_id;
            outcome.username = fields.username;
            outcome.password = fields.password;
            outcome.connect_flags = fields.flags;
        } else {
            outcome.errors.push("malformed CONNECT".into());
        }
        if let Err(error) = stream.write_all(&codec.encode_connack(false, 0)) {
            outcome.errors.push(format!("connack: {error}"));
            return outcome;
        }
        let _ = stream.flush();

        let subscribe = match read_packet(&mut stream) {
            Ok(packet) => packet,
            Err(error) => {
                outcome.errors.push(format!("subscribe: {error}"));
                return outcome;
            }
        };
        if subscribe.first().copied() != Some(0x82) {
            outcome.errors.push("expected SUBSCRIBE".into());
            return outcome;
        }
        let (_, rl_len) =
            MqttBridgeCodec::decode_remaining_length(&subscribe[1..]).expect("subscribe length");
        let body = &subscribe[1 + rl_len..];
        let packet_id = u16::from_be_bytes([body[0], body[1]]);
        let topic_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        outcome.subscribe_topic = String::from_utf8_lossy(&body[4..4 + topic_len]).into_owned();
        outcome.subscribe_qos = body[4 + topic_len];
        let suback = vec![
            0x90,
            0x03,
            (packet_id >> 8) as u8,
            packet_id as u8,
            outcome.subscribe_qos,
        ];
        if let Err(error) = stream.write_all(&suback) {
            outcome.errors.push(format!("suback: {error}"));
            return outcome;
        }
        let _ = stream.flush();
        outcome.connected = true;

        for step in steps {
            match step {
                ScriptStep::Publish {
                    topic,
                    payload,
                    qos,
                    packet_id,
                } => match codec.encode_publish(topic, &payload, qos, packet_id) {
                    Ok(packet) => {
                        if let Err(error) = stream.write_all(&packet) {
                            outcome.errors.push(format!("publish: {error}"));
                            return outcome;
                        }
                        let _ = stream.flush();
                    }
                    Err(error) => outcome.errors.push(format!("encode publish: {error}")),
                },
                ScriptStep::ExpectPubacks(count) => {
                    for _ in 0..count {
                        match read_packet(&mut stream) {
                            Ok(packet) => match codec.decode_puback(&packet) {
                                Ok(packet_id) => outcome.pubacks.push(packet_id),
                                Err(error) => {
                                    outcome.errors.push(format!("puback decode: {error}"));
                                }
                            },
                            Err(error) => {
                                outcome.errors.push(format!("puback read: {error}"));
                                break;
                            }
                        }
                    }
                }
                ScriptStep::Sleep(duration) => thread::sleep(duration),
            }
        }
        outcome
    });
    (address.port(), handle)
}

/// A broker that completes the TLS handshake but never answers CONNECT.
fn spawn_silent_before_connack(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
    let config = server_config(cert, key);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent broker");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        if let Ok((tcp, _)) = listener.accept() {
            // Complete the handshake by reading the CONNECT flight, then stall.
            let _ = tcp.set_read_timeout(Some(Duration::from_millis(200)));
            let connection = ServerConnection::new(config).expect("server conn");
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            let _ = read_packet(&mut stream);
            thread::sleep(Duration::from_secs(1));
        }
    });
    port
}

fn payload(seq: u64, timestamp_ms: u64) -> Vec<u8> {
    format!("v=1;device=coldroom-1;seq={seq};ts={timestamp_ms};temp_mc=4512;rh_cp=5560")
        .into_bytes()
}

fn bridge_config(port: u16, max_payload_bytes: usize) -> MqttBridgeConfig {
    let mut config = MqttBridgeConfig::new(
        format!("mqtts://127.0.0.1:{port}"),
        "bridge-coldroom-1",
        MqttDeviceCredentials::new("device-coldroom-1", "s3cret").expect("credentials"),
        MqttTopicAllowlist::exact([TOPIC]).expect("allowlist"),
    );
    config.max_payload_bytes = max_payload_bytes;
    config.replay_window_ms = 60_000;
    config.connect_timeout = Duration::from_secs(2);
    config.io_timeout = Duration::from_secs(2);
    config
}

#[test]
fn valid_qos1_reading_is_accepted_and_acknowledged() {
    let (cert, key) = self_signed();
    let (port, broker) = spawn_broker(
        cert.clone(),
        key,
        vec![
            ScriptStep::Publish {
                topic: TOPIC,
                payload: payload(1, 5),
                qos: MqttQoS::AtLeastOnce,
                packet_id: Some(9),
            },
            ScriptStep::ExpectPubacks(1),
        ],
    );

    let mut bridge = MqttBridgeClient::connect(
        &bridge_config(port, 512),
        &MqttTlsTrust::with_roots([cert]),
        monotonic_clock(),
    )
    .expect("TLS bridge connect with per-device credentials");

    let reading = bridge.read_reading().expect("valid reading accepted");
    assert_eq!(reading.device_id, "coldroom-1");
    assert_eq!(reading.schema_version, 1);
    assert_eq!(reading.sequence, 1);
    assert_eq!(reading.temperature.mantissa, 4512);
    assert_eq!(reading.temperature.exponent, -3);
    assert_eq!(reading.humidity.mantissa, 5560);
    assert_eq!(reading.humidity.exponent, -2);
    assert_eq!(reading.qos, MqttQoS::AtLeastOnce);

    let outcome = broker.join().expect("broker thread");
    assert!(outcome.connected, "errors: {:?}", outcome.errors);
    assert_eq!(outcome.client_id, "bridge-coldroom-1");
    assert_eq!(outcome.username, "device-coldroom-1");
    assert_eq!(outcome.password, "s3cret");
    assert_eq!(outcome.connect_flags & 0xC0, 0xC0, "username + password");
    assert_eq!(outcome.subscribe_topic, TOPIC);
    assert_eq!(outcome.subscribe_qos, 1, "SUBSCRIBE must request QoS 1");
    assert_eq!(outcome.pubacks, vec![9], "QoS 1 PUBLISH must be PUBACKed");
}

#[test]
fn repeated_invalid_and_oversized_payloads_are_rejected() {
    let (cert, key) = self_signed();
    let (port, broker) = spawn_broker(
        cert.clone(),
        key,
        vec![
            // 1. baseline reading
            ScriptStep::Publish {
                topic: TOPIC,
                payload: payload(1, 5),
                qos: MqttQoS::AtMostOnce,
                packet_id: None,
            },
            // 2. byte-identical replay of sequence 1
            ScriptStep::Publish {
                topic: TOPIC,
                payload: payload(1, 5),
                qos: MqttQoS::AtMostOnce,
                packet_id: None,
            },
            // 3. schema violation: rh_cp missing
            ScriptStep::Publish {
                topic: TOPIC,
                payload: b"v=1;device=coldroom-1;seq=2;ts=5;temp_mc=0".to_vec(),
                qos: MqttQoS::AtMostOnce,
                packet_id: None,
            },
            // 4. oversized for a 128-byte payload budget
            ScriptStep::Publish {
                topic: TOPIC,
                payload: vec![b'x'; 300],
                qos: MqttQoS::AtMostOnce,
                packet_id: None,
            },
            // 5. not in the allowlist
            ScriptStep::Publish {
                topic: "tirbase/devices/coldroom-2/reading",
                payload: payload(3, 5),
                qos: MqttQoS::AtMostOnce,
                packet_id: None,
            },
            ScriptStep::Sleep(Duration::from_millis(300)),
        ],
    );

    let mut bridge = MqttBridgeClient::connect(
        &bridge_config(port, 128),
        &MqttTlsTrust::with_roots([cert]),
        monotonic_clock(),
    )
    .expect("bridge connect");

    assert_eq!(bridge.read_reading().expect("baseline").sequence, 1);

    match bridge.read_reading().expect_err("replay must be rejected") {
        MqttBridgeError::Replay(ReplayError::DuplicateSequence { sequence, .. }) => {
            assert_eq!(sequence, 1);
        }
        other => panic!("expected replay rejection, got {other:?}"),
    }

    match bridge
        .read_reading()
        .expect_err("invalid payload must be rejected")
    {
        MqttBridgeError::InvalidPayload(PayloadError::MissingField(field)) => {
            assert_eq!(field, "rh_cp");
        }
        other => panic!("expected schema rejection, got {other:?}"),
    }

    match bridge
        .read_reading()
        .expect_err("oversized payload must be rejected")
    {
        MqttBridgeError::PayloadTooLarge { len, max } => {
            assert_eq!(len, 300);
            assert_eq!(max, 128);
        }
        other => panic!("expected size rejection, got {other:?}"),
    }

    match bridge
        .read_reading()
        .expect_err("non-allowlisted topic must be rejected")
    {
        MqttBridgeError::TopicNotAllowed(topic) => {
            assert_eq!(topic, "tirbase/devices/coldroom-2/reading");
        }
        other => panic!("expected topic rejection, got {other:?}"),
    }

    let outcome = broker.join().expect("broker thread");
    assert!(outcome.connected, "errors: {:?}", outcome.errors);
    assert_eq!(outcome.subscribe_topic, TOPIC);
}

#[test]
fn wildcard_allowlist_requires_opt_in_and_is_enforced_on_read() {
    let (cert, key) = self_signed();
    let (port, broker) = spawn_broker(
        cert.clone(),
        key,
        vec![
            ScriptStep::Publish {
                topic: "tirbase/devices/coldroom-9/reading",
                payload: payload(1, 5),
                qos: MqttQoS::AtMostOnce,
                packet_id: None,
            },
            ScriptStep::Sleep(Duration::from_millis(200)),
        ],
    );

    let mut config = MqttBridgeConfig::new(
        format!("mqtts://127.0.0.1:{port}"),
        "bridge-coldroom-1",
        MqttDeviceCredentials::new("device-coldroom-1", "s3cret").expect("credentials"),
        // Explicit opt-in: the bridge must accept topics matching the pattern.
        MqttTopicAllowlist::with_wildcards(["tirbase/devices/+/reading"]).expect("wildcards"),
    );
    config.connect_timeout = Duration::from_secs(2);
    config.io_timeout = Duration::from_secs(2);

    let mut bridge = MqttBridgeClient::connect(
        &config,
        &MqttTlsTrust::with_roots([cert]),
        monotonic_clock(),
    )
    .expect("bridge connect");
    assert_eq!(bridge.subscribed_topics(), ["tirbase/devices/+/reading"]);
    let reading = bridge
        .read_reading()
        .expect("wildcard-matched topic accepted after opt-in");
    assert_eq!(reading.device_id, "coldroom-1");

    let outcome = broker.join().expect("broker thread");
    assert_eq!(outcome.subscribe_topic, "tirbase/devices/+/reading");
}

#[test]
fn tls_verification_cannot_be_disabled_through_the_bridge_api() {
    let (cert, key) = self_signed();
    let (port, broker) = spawn_broker(
        cert,
        key,
        vec![ScriptStep::Sleep(Duration::from_millis(100))],
    );

    // The bridge only accepts a CA-root set, so an untrusted self-signed server
    // must fail the handshake instead of being accepted.
    let error = MqttBridgeClient::connect(
        &bridge_config(port, 512),
        &MqttTlsTrust::webpki(),
        monotonic_clock(),
    )
    .expect_err("self-signed broker must not be trusted by webpki roots");
    assert!(
        matches!(
            error,
            MqttBridgeError::Tls(_) | MqttBridgeError::Io(_) | MqttBridgeError::Protocol(_)
        ),
        "expected TLS failure, got {error:?}"
    );
    let _ = broker.join();

    // Wildcards are not subscribed to unless the caller opts in explicitly.
    assert!(MqttTopicAllowlist::exact(["tirbase/#"]).is_err());
    assert!(MqttTopicAllowlist::exact(["tirbase/+/reading"]).is_err());
}

#[test]
fn broker_outage_fails_reads_within_the_deadline() {
    // 1. Broker accepts TCP/TLS but never answers CONNECT.
    let (cert, key) = self_signed();
    let port = spawn_silent_before_connack(cert, key);
    let mut config = bridge_config(port, 512);
    config.connect_timeout = Duration::from_millis(250);
    let started = Instant::now();
    let error = MqttBridgeClient::connect(&config, &MqttTlsTrust::webpki(), monotonic_clock())
        .expect_err("silent broker must not complete connect");
    let elapsed = started.elapsed();
    assert!(
        matches!(error, MqttBridgeError::Timeout | MqttBridgeError::Io(_)),
        "expected bounded connect failure, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "connect blocked for {elapsed:?}"
    );

    // 2. Broker completes CONNECT/SUBSCRIBE, then goes silent.
    let (cert, key) = self_signed();
    let (port, broker) = spawn_broker(
        cert.clone(),
        key,
        vec![ScriptStep::Sleep(Duration::from_secs(1))],
    );
    let mut bridge = MqttBridgeClient::connect(
        &bridge_config(port, 512),
        &MqttTlsTrust::with_roots([cert]),
        monotonic_clock(),
    )
    .expect("bridge connect");

    let started = Instant::now();
    let error = bridge
        .read_reading_with_timeout(Duration::from_millis(250))
        .expect_err("silent broker must not block the read");
    let elapsed = started.elapsed();
    assert!(
        matches!(error, MqttBridgeError::Timeout | MqttBridgeError::Io(_)),
        "expected bounded read failure, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "read blocked for {elapsed:?}"
    );

    // The caller can keep calling with a fresh budget rather than hanging.
    assert!(matches!(
        bridge.read_reading_with_timeout(Duration::ZERO),
        Err(MqttBridgeError::Timeout)
    ));
    let _ = broker.join();
}
