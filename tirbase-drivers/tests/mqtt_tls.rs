// SPDX-License-Identifier: AGPL-3.0-only

//! CLAIM-34.2 integration: real MQTT 3.1.1 over rustls. TLS handshake must succeed
//! against a TLS broker and fail against a plaintext TCP server. No public plaintext
//! connect path exists.

use std::io::{Read, Write};
use std::net::TcpListener;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tirbase_drivers::{client_config_with_roots, MqttBridgeCodec, MqttError, MqttTlsClient};

fn read_packet(stream: &mut impl Read) -> Vec<u8> {
    let mut head = [0u8; 1];
    stream.read_exact(&mut head).expect("head");
    let mut len = 0usize;
    let mut mul = 1usize;
    let mut rem = Vec::new();
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).expect("rem");
        rem.push(b[0]);
        len += ((b[0] & 127) as usize) * mul;
        if (b[0] & 128) == 0 {
            break;
        }
        mul *= 128;
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("body");
    let mut out = vec![head[0]];
    out.extend(rem);
    out.extend(body);
    out
}

fn handle_mqtt_session(mut stream: impl Read + Write) {
    let codec = MqttBridgeCodec::new();
    let connect = read_packet(&mut stream);
    assert_eq!(connect[0], 0x10, "expected CONNECT");
    stream.write_all(&codec.encode_connack(false, 0)).unwrap();
    stream.flush().unwrap();
    for _ in 0..2 {
        let pkt = read_packet(&mut stream);
        if (pkt[0] & 0xF0) != 0x30 {
            break;
        }
        let (_topic, _payload, qos, pid) = codec.decode_publish(&pkt).unwrap();
        if matches!(qos, tirbase_drivers::MqttQoS::AtLeastOnce) {
            stream
                .write_all(&codec.encode_puback(pid.unwrap()))
                .unwrap();
            stream.flush().unwrap();
        }
    }
}

#[test]
fn claim_34_2_real_tls_broker_qos0_qos1_and_plaintext_server_rejected() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let certified =
        generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).expect("rcgen");
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .expect("key")
        .clone_key();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    let tls_listener = TcpListener::bind("127.0.0.1:0").expect("tls bind");
    let tls_addr = tls_listener.local_addr().unwrap();
    let server_config = Arc::new(server_config);
    thread::spawn(move || {
        let (tcp, _) = tls_listener.accept().expect("accept");
        let conn = rustls::ServerConnection::new(server_config).expect("server conn");
        let stream = rustls::StreamOwned::new(conn, tcp);
        handle_mqtt_session(stream);
    });

    let client_cfg = client_config_with_roots([cert_der], false).expect("client cfg");
    let uri = format!("mqtts://127.0.0.1:{}", tls_addr.port());
    let mut client =
        MqttTlsClient::connect_mqtts(&uri, "reference-client", client_cfg, Duration::from_secs(3))
            .expect("TLS MQTT connect must succeed");
    client.publish_qos0("coldroom/state", b"ok").expect("qos0");
    let pid = client
        .publish_qos1("coldroom/cmd", b"setpoint", Duration::from_secs(3))
        .expect("qos1");
    assert!(pid > 0);

 // Wiring/negative: connecting to a plaintext TCP server via MQTT TLS client must fail.
    let plain_listener = TcpListener::bind("127.0.0.1:0").expect("plain bind");
    let plain_addr = plain_listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut tcp, _) = plain_listener.accept().expect("accept plain");
 // Speak a little plaintext to ensure handshake cannot be confused.
        let _ = tcp.write_all(b"plain\n");
    });
    let client_cfg2 = client_config_with_roots([], false).unwrap_or_else(|_| {
 // no roots is fine; handshake should fail before trust matters on plaintext peer
        client_config_with_roots([], true).expect("webpki")
    });
    let err = MqttTlsClient::connect_mqtts(
        &format!("mqtts://127.0.0.1:{}", plain_addr.port()),
        "reference-plain",
        client_cfg2,
        Duration::from_secs(2),
    )
    .expect_err("plaintext server must be rejected by TLS handshake");
    assert!(
        matches!(err, MqttError::Tls(_) | MqttError::Io(_)),
        "expected TLS/IO handshake failure, got {err:?}"
    );
}

#[test]
fn claim_34_2_no_public_plaintext_connect_path() {
 // Compile-time/public-API assertion by construction: only mqtts URIs parse.
    assert!(matches!(
        tirbase_drivers::parse_mqtts_uri("mqtt://127.0.0.1:1883"),
        Err(MqttError::PlainTextRejected { .. })
    ));
}
