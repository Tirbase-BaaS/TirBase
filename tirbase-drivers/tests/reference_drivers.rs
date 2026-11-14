// SPDX-License-Identifier: AGPL-3.0-only

//! integration/wiring tests: Modbus FC 03/04/06/16 round-trip against the
//! tirbase-sim Modbus server, MQTT TLS-only enforcement, cold-room model determinism,
//! and register-map parsing (CLAIM-34.1..34.4/34.8, PV-10.5..10.7).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tirbase_drivers::{
    connect_tls_only, decode_read_registers_response, decode_write_multiple_response,
    decode_write_single_response, parse_tcp_adu, ColdRoomSimDriver, FirstOrderThermalModel,
    ModbusRegisterMap, ModbusTcpCodec, MqttBridgeCodec, MqttConnectConfig, MqttQoS,
    RegisterMapError,
};
use tirbase_types::UNIT_DEG_C;

fn read_adu(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut mbap = [0u8; 7];
    stream.read_exact(&mut mbap).expect("read MBAP");
    let len = u16::from_be_bytes([mbap[4], mbap[5]]) as usize;
    let mut rest = vec![0u8; len.saturating_sub(1)];
    stream.read_exact(&mut rest).expect("read PDU");
    let mut out = mbap.to_vec();
    out.extend_from_slice(&rest);
    out
}

#[test]
fn claim_34_1_modbus_fc03_fc04_fc06_fc16_round_trip_against_sim_server() {
 // Production caller path for codec: tirbase-drivers/src/modbus.rs via ModbusTcpCodec.
    let server = tirbase_sim::ModbusSimServer::spawn().expect("spawn modbus sim");
    {
        let bank = server.bank();
        let mut b = bank.lock().unwrap();
        b.set_holding(10, 1234);
        b.set_input(20, 0xFF9C); // -100
    }
    let mut stream = TcpStream::connect(server.addr).expect("connect sim");
    let mut codec = ModbusTcpCodec::new(1, UNIT_DEG_C).with_registers(10, 20);

 // FC03 read holding
    let req = codec.build_fc03(10, 1);
    stream.write_all(&req).unwrap();
    let resp = read_adu(&mut stream);
    let adu = parse_tcp_adu(&resp).unwrap();
    let regs = decode_read_registers_response(&adu.pdu, 0x03).unwrap();
    assert_eq!(regs, vec![1234], "FC03 must round-trip");

 // FC04 read input
    let req = codec.build_fc04(20, 1);
    stream.write_all(&req).unwrap();
    let resp = read_adu(&mut stream);
    let adu = parse_tcp_adu(&resp).unwrap();
    let regs = decode_read_registers_response(&adu.pdu, 0x04).unwrap();
    assert_eq!(regs[0] as i16, -100, "FC04 must round-trip");

 // FC06 write single
    let req = codec.build_fc06(10, 4321);
    stream.write_all(&req).unwrap();
    let resp = read_adu(&mut stream);
    let adu = parse_tcp_adu(&resp).unwrap();
    decode_write_single_response(&adu.pdu, 10, 4321).expect("FC06 echo");
    assert_eq!(server.bank().lock().unwrap().get_holding(10), 4321);

 // FC16 write multiple
    let req = codec.build_fc16(10, &[7, 8, 9]);
    stream.write_all(&req).unwrap();
    let resp = read_adu(&mut stream);
    let adu = parse_tcp_adu(&resp).unwrap();
    decode_write_multiple_response(&adu.pdu, 10, 3).expect("FC16 echo");
    let bank = server.bank();
    let b = bank.lock().unwrap();
    assert_eq!(
        (b.get_holding(10), b.get_holding(11), b.get_holding(12)),
        (7, 8, 9)
    );
    server.stop();
}

// Wiring mutation check (34.1): removing FC04 support breaks this test.
#[test]
fn wiring_mutation_fc04_is_required() {
    let mut codec = ModbusTcpCodec::new(1, UNIT_DEG_C);
    let req = codec.build_fc04(1, 1);
    let adu = parse_tcp_adu(&req).unwrap();
    assert_eq!(adu.pdu[0], 0x04);
}

// Wiring mutation check (34.1): removing FC06 support breaks this test.
#[test]
fn wiring_mutation_fc06_is_required() {
    let mut codec = ModbusTcpCodec::new(1, UNIT_DEG_C);
    let req = codec.build_fc06(1, 1);
    let adu = parse_tcp_adu(&req).unwrap();
    assert_eq!(adu.pdu[0], 0x06);
}

// Wiring mutation check (34.1): removing FC16 support breaks this test.
#[test]
fn wiring_mutation_fc16_is_required() {
    let mut codec = ModbusTcpCodec::new(1, UNIT_DEG_C);
    let req = codec.build_fc16(1, &[1]);
    let adu = parse_tcp_adu(&req).unwrap();
    assert_eq!(adu.pdu[0], 0x10);
}

#[test]
fn claim_34_2_mqtt_tls_required_plain_text_rejected_qos0_qos1() {
    let plain = MqttConnectConfig {
        uri: "mqtt://127.0.0.1:1883".into(),
        client_id: "t".into(),
        tls_configured: false,
    };
 // Wiring mutation check (34.2): accepting plain-text must fail this test.
    assert!(
        connect_tls_only(&plain).is_err(),
        "plain-text MQTT must be rejected"
    );
    let tls = MqttConnectConfig {
        uri: "mqtts://broker.example:8883".into(),
        client_id: "t".into(),
        tls_configured: true,
    };
    assert!(connect_tls_only(&tls).is_ok(), "TLS MQTT must be accepted");

    let c = MqttBridgeCodec::new();
    let qos0 = c
        .encode_publish("a", b"p", MqttQoS::AtMostOnce, None)
        .unwrap();
    let (_, _, q, pid) = c.decode_publish(&qos0).unwrap();
    assert_eq!((q, pid), (MqttQoS::AtMostOnce, None));
    let qos1 = c
        .encode_publish("a", b"p", MqttQoS::AtLeastOnce, Some(9))
        .unwrap();
    let (_, _, q, pid) = c.decode_publish(&qos1).unwrap();
    assert_eq!((q, pid), (MqttQoS::AtLeastOnce, Some(9)));
}

#[test]
fn claim_34_3_cold_room_model_is_bit_identical_from_same_seed() {
    let mut a = FirstOrderThermalModel::new(0xC0FFEE, 8_000, 22_000);
    let mut b = FirstOrderThermalModel::new(0xC0FFEE, 8_000, 22_000);
    let va: Vec<i64> = (0..512).map(|_| a.step()).collect();
    let vb: Vec<i64> = (0..512).map(|_| b.step()).collect();
    assert_eq!(va, vb, "same seed must produce bit-identical output");
    let _driver = ColdRoomSimDriver::new(0xC0FFEE, "cold-room-1");
}

#[test]
fn claim_34_8_register_map_parser_has_field_level_errors() {
    let good = r#"
device_class = "cold_room_modbus"
[[register]]
name = "setpoint_c"
register = 0
function = 6
data_type = "i16"
scale_mantissa = 1
scale_exponent = -1
word_order = "big_endian"
unit_id = 1
writable = true
quantity = 1
"#;
    let m = ModbusRegisterMap::parse(good).expect("valid register map");
    assert_eq!(m.registers[0].function, 6);

    let bad = r#"
[[register]]
name = "x"
register = 0
function = 99
"#;
    let err = ModbusRegisterMap::parse(bad).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, RegisterMapError::InvalidField { .. }),
        "{msg}"
    );
    assert!(
        msg.contains("function"),
        "field-level error must name field: {msg}"
    );
}
