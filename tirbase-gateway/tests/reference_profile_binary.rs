// SPDX-License-Identifier: AGPL-3.0-only

//! gateway binary integration tests (CLAIM-34.1/2/3/5).
//! Spawns the real `CARGO_BIN_EXE_tirbase-gateway` binary.

use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::thread;

fn gateway() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
}

fn handle_mqtt_session(mut stream: impl std::io::Read + std::io::Write) {
    fn rp(stream: &mut impl std::io::Read) -> Vec<u8> {
        let mut head = [0u8; 1];
        stream.read_exact(&mut head).unwrap();
        let mut len = 0usize;
        let mut mul = 1usize;
        let mut rem = Vec::new();
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).unwrap();
            rem.push(b[0]);
            len += ((b[0] & 127) as usize) * mul;
            if (b[0] & 128) == 0 {
                break;
            }
            mul *= 128;
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();
        let mut out = vec![head[0]];
        out.extend(rem);
        out.extend(body);
        out
    }
    let codec = tirbase_drivers::MqttBridgeCodec::new();
    let _connect = rp(&mut stream);
    stream.write_all(&codec.encode_connack(false, 0)).unwrap();
    stream.flush().unwrap();
    for _ in 0..2 {
        let pkt = rp(&mut stream);
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
fn claim_34_5_gateway_binary_installs_valid_profile_and_rejects_invalid() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let trust = root.join("tirbase-gateway/testdata/reference_profiles/cold_room_pa.json");

    let ok = gateway()
        .args([
            "profile-install",
            root.join("profiles/cold_room.toml").to_str().unwrap(),
            trust.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&ok.stdout);
    let stderr = String::from_utf8_lossy(&ok.stderr);
    assert!(
        ok.status.success(),
        "valid profile install failed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("PROFILE_INSTALLED:device_class=cold_room"),
        "{stdout}"
    );

    let bad_trust = tempfile_path("pa_bad.json");
    std::fs::write(
        &bad_trust,
        r#"{"did":"did:key:z6MkwBad","public_key_hex":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}"#,
    )
    .unwrap();
    let bad = gateway()
        .args([
            "profile-install",
            root.join("profiles/cold_room.toml").to_str().unwrap(),
            bad_trust.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    let bstdout = String::from_utf8_lossy(&bad.stdout);
    let bstderr = String::from_utf8_lossy(&bad.stderr);
    assert!(
        !bad.status.success(),
        "invalid trust root must be rejected: {bstdout}\n{bstderr}"
    );
    assert!(
        bstderr.contains("rejected")
            || bstderr.contains("Signature")
            || bstderr.contains("install")
            || bstderr.contains("PolicyAuthority"),
        "{bstderr}"
    );
}

fn tempfile_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tirbase-reference-profile-{}-{}", std::process::id(), name))
}

#[test]
fn claim_34_1_gateway_binary_modbus_smoke_against_sim() {
    let server = tirbase_sim::ModbusSimServer::spawn().expect("spawn sim");
    {
        let bank = server.bank();
        let mut b = bank.lock().unwrap();
        b.set_holding(1, 11);
        b.set_input(2, 22);
    }
    let addr = server.addr.to_string();

    let out = gateway()
        .args(["modbus-smoke", &addr, "read-holding", "1", "1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("MODBUS_OK:op=read-holding regs=[11]"));

    let out = gateway()
        .args(["modbus-smoke", &addr, "read-input", "2", "1"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("MODBUS_OK:op=read-input regs=[22]"));

    let out = gateway()
        .args(["modbus-smoke", &addr, "write-single", "1", "99"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = gateway()
        .args(["modbus-smoke", &addr, "write-multiple", "3", "7", "8"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let bank = server.bank();
    let b = bank.lock().unwrap();
    assert_eq!(b.get_holding(1), 99);
    assert_eq!(b.get_holding(3), 7);
    assert_eq!(b.get_holding(4), 8);
    server.stop();
}

#[test]
fn claim_34_2_gateway_binary_mqtt_smoke_real_tls() {
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;

    tirbase_drivers::install_crypto_provider();
    let certified =
        generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).expect("rcgen");
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let ca_path = tempfile_path("ca.pem");
    std::fs::write(&ca_path, certified.cert.pem()).unwrap();
    let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .unwrap()
        .clone_key();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap(),
    );
    let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tls_listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (tcp, _) = tls_listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let stream = rustls::StreamOwned::new(conn, tcp);
        handle_mqtt_session(stream);
    });
    let uri = format!("mqtts://127.0.0.1:{port}");
    let out = gateway()
        .args([
            "mqtt-smoke",
            &uri,
            ca_path.to_str().unwrap(),
            "t/34",
            "payload",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "mqtt smoke failed: {stdout}\n{stderr}"
    );
    assert!(stdout.contains("MQTT_OK"), "{stdout}");
}

#[test]
fn claim_34_3_gateway_binary_cold_room_uses_canonical_model() {
    let out = gateway()
        .args(["cold-room-sim", "42", "256"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("COLD_ROOM_OK:seed=42 steps=256"),
        "{stdout}"
    );
    assert!(stdout.contains("temp_mdeg_c="), "{stdout}");
}

#[test]
fn claim_34_6_gateway_binary_validates_modbus_register_map() {
    let path =
        std::env::temp_dir().join(format!("tirbase_register_map_{}.toml", std::process::id()));
    std::fs::write(
        &path,
        r#"
device_class = "cold_room_modbus"

[[register]]
name = "temperature_c"
register = 0
function = 4
data_type = "i16"
scale_mantissa = 1
scale_exponent = -1
offset_mantissa = 0
offset_exponent = 0
word_order = "big_endian"
unit_id = 1
writable = false
quantity = 1
"#,
    )
    .expect("write register map");

    let out = gateway()
        .args(["modbus-register-map", path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_file(&path);

    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("REGISTER_MAP_OK:device_class=cold_room_modbus registers=1"),
        "{stdout}"
    );
    assert!(
        stdout.contains("REGISTER:0 name=temperature_c function=4 type=i16 width=1 writable=false"),
        "{stdout}"
    );
}
