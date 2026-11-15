// SPDX-License-Identifier: AGPL-3.0-only

//! CC-04 BACnet/IP read bridge: recorded PDUs plus Who-Is/I-Am and
//! ReadProperty against the loopback simulator. No physical device required.
#![cfg(feature = "bacnet-ip")]

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tirbase_driver_api::bacnet_codec::{
    encode_i_am, encode_read_property_ack, encode_write_property, parse_message, BacnetError,
    BacnetMessage, BacnetValue, IAm, ObjectIdentifier, ObjectType, PropertyId,
    MAX_DISCOVERED_DEVICES,
};
use tirbase_drivers::bacnet::{BacnetIpClient, BacnetIpConfig};
use tirbase_sim::{BacnetSimDevice, BacnetSimServer, BacnetSimServerOptions};

// `tirbase-drivers` must not depend on `tirbase-core`'s TimeSource (layering),
// so tests use a local monotonic clock.
#[allow(clippy::disallowed_methods)]
fn real_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    let start = Instant::now();
    Arc::new(move || start.elapsed().as_millis() as u64)
}

fn config(timeout_ms: u64, retries: u8) -> BacnetIpConfig {
    BacnetIpConfig {
        local_addr: "127.0.0.1:0".into(),
        timeout: Duration::from_millis(timeout_ms),
        retries,
        max_devices: 16,
    }
}

fn client(timeout_ms: u64, retries: u8) -> BacnetIpClient {
    BacnetIpClient::bind(&config(timeout_ms, retries), real_clock()).expect("bind client")
}

fn object(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).expect("object identifier")
}

fn recorded_frames() -> BTreeMap<String, Vec<u8>> {
    include_str!("fixtures/bacnet/pdus.txt")
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (name, hex) = line.split_once('=')?;
            let bytes = hex
                .split_whitespace()
                .map(|byte| u8::from_str_radix(byte, 16).expect("recorded hex byte"))
                .collect();
            Some((name.trim().to_string(), bytes))
        })
        .collect()
}

#[test]
fn recorded_pdus_decode_and_reencode_byte_for_byte() {
    let frames = recorded_frames();
    assert_eq!(
        parse_message(&frames["who_is_global"]).unwrap(),
        BacnetMessage::WhoIs {
            low: 0,
            high: 0x3F_FFFF
        }
    );

    let BacnetMessage::IAm(i_am) = parse_message(&frames["i_am_device_1001"]).unwrap() else {
        panic!("expected I-Am");
    };
    assert_eq!(i_am, IAm::new(1001, 480, 0, 0x0021));
    assert_eq!(
        encode_i_am(&i_am).unwrap(),
        frames["i_am_device_1001"],
        "recorded I-Am must round-trip"
    );

    let BacnetMessage::ReadProperty(request) =
        parse_message(&frames["read_property_ai0_pv"]).unwrap()
    else {
        panic!("expected ReadProperty");
    };
    assert_eq!(request.object, object(ObjectType::AnalogInput, 0));
    assert_eq!(request.property, PropertyId::PRESENT_VALUE);
    assert_eq!(request.invoke_id, 1);

    let BacnetMessage::ReadPropertyAck { invoke_id, value } =
        parse_message(&frames["read_property_ack_ai0_21_5"]).unwrap()
    else {
        panic!("expected ReadProperty-ACK");
    };
    assert_eq!(invoke_id, 1);
    assert_eq!(value, BacnetValue::Real(21.5));
    assert_eq!(
        encode_read_property_ack(invoke_id, &value),
        frames["read_property_ack_ai0_21_5"]
    );

    let BacnetMessage::ReadPropertyAck { value, .. } =
        parse_message(&frames["read_property_ack_bi3_active"]).unwrap()
    else {
        panic!("expected binary ReadProperty-ACK");
    };
    assert_eq!(value.as_bool(), Some(true));

    assert_eq!(
        parse_message(&frames["error_unknown_property"]).unwrap(),
        BacnetMessage::Error {
            invoke_id: 3,
            service: 0x0C,
            error_class: 2,
            error_code: 32,
        }
    );
    assert_eq!(
        parse_message(&frames["reject_invoke4"]).unwrap(),
        BacnetMessage::Reject {
            invoke_id: 4,
            reason: 9,
        }
    );
}

fn simulation() -> (tirbase_sim::BacnetSimServerHandle, BacnetSimDevice) {
    let mut device = BacnetSimDevice::new(1001);
    device.set_present_value(ObjectType::AnalogInput, 0, BacnetValue::Real(21.5));
    device.set_present_value(ObjectType::AnalogValue, 7, BacnetValue::Unsigned(42));
    device.set_present_value(ObjectType::BinaryInput, 3, BacnetValue::Enumerated(0));
    device.set_present_value(ObjectType::BinaryValue, 9, BacnetValue::Enumerated(1));
    let server = BacnetSimServer::spawn(vec![device.clone()]).expect("spawn BACnet simulator");
    (server, device)
}

#[test]
fn discovery_and_read_property_work_against_the_simulator() {
    let (server, _device) = simulation();
    let mut client = client(500, 1);

    let devices = client.discover(server.addr).expect("discover");
    assert_eq!(devices.len(), 1, "{devices:?}");
    assert_eq!(devices[0].device, ObjectIdentifier::device(1001).unwrap());
    assert_eq!(devices[0].address, server.addr);
    assert_eq!(devices[0].max_apdu, 480);
    assert_eq!(devices[0].vendor_id, 0x0021);

    let analog_input = client
        .read_present_value(server.addr, object(ObjectType::AnalogInput, 0))
        .expect("read analog input");
    assert_eq!(analog_input, BacnetValue::Real(21.5));
    assert_eq!(
        analog_input.to_fixed_point(tirbase_types::UNIT_DEG_C, -1),
        Some(tirbase_types::FixedPointValue::new(
            215,
            -1,
            tirbase_types::UNIT_DEG_C
        ))
    );

    let analog_value = client
        .read_present_value(server.addr, object(ObjectType::AnalogValue, 7))
        .expect("read analog value");
    assert_eq!(analog_value.as_f64(), Some(42.0));

    let binary_input = client
        .read_present_value(server.addr, object(ObjectType::BinaryInput, 3))
        .expect("read binary input");
    assert_eq!(binary_input.as_bool(), Some(false));

    let binary_value = client
        .read_present_value(server.addr, object(ObjectType::BinaryValue, 9))
        .expect("read binary value");
    assert_eq!(binary_value.as_bool(), Some(true));

    assert_eq!(server.write_attempts(), 0);
}

#[test]
fn directed_discovery_honours_the_instance_range() {
    let (server, _device) = simulation();
    let client = client(300, 0);

    let none = client
        .discover_range(server.addr, 2000, 3000)
        .expect("range discovery");
    assert!(none.is_empty());

    let found = client
        .discover_range(server.addr, 1000, 2000)
        .expect("range discovery");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].device.instance, 1001);
}

#[test]
fn discovery_and_read_retry_bounded_timeouts() {
    let mut device = BacnetSimDevice::new(1001);
    device.set_present_value(ObjectType::AnalogInput, 0, BacnetValue::Real(20.0));
    let server = BacnetSimServer::spawn_with_options(
        vec![device],
        BacnetSimServerOptions {
            drop_first_who_is: true,
            drop_first_read: true,
        },
    )
    .expect("spawn simulator");
    let mut client = client(300, 1);

    let devices = client.discover(server.addr).expect("discover after retry");
    assert_eq!(devices.len(), 1);
    assert_eq!(server.who_is_requests(), 2, "one drop plus one retry");

    let value = client
        .read_present_value(server.addr, object(ObjectType::AnalogInput, 0))
        .expect("read after retry");
    assert_eq!(value, BacnetValue::Real(20.0));
    assert_eq!(server.read_requests(), 2, "one drop plus one retry");
}

#[test]
fn write_attempts_are_rejected_with_a_typed_error_before_sending() {
    let (server, _device) = simulation();
    let mut client = client(300, 0);
    let analog = object(ObjectType::AnalogValue, 7);

    let error = client
        .write_property(
            server.addr,
            analog,
            PropertyId::PRESENT_VALUE,
            &BacnetValue::Unsigned(0),
        )
        .expect_err("writes are rejected");
    assert!(
        matches!(
            error,
            BacnetError::WriteRejected {
                object,
                property: PropertyId::PRESENT_VALUE
            } if object == analog
        ),
        "expected typed write rejection, got {error:?}"
    );
    assert_eq!(
        server.write_attempts(),
        0,
        "the client must reject before any UDP datagram"
    );

    let encoded = encode_write_property(
        1,
        analog,
        PropertyId::PRESENT_VALUE,
        &BacnetValue::Unsigned(0),
    );
    assert!(matches!(encoded, Err(BacnetError::WriteRejected { .. })));
}

#[test]
fn missing_objects_surface_the_device_error_pdu() {
    let (server, _device) = simulation();
    let mut client = client(300, 0);
    let error = client
        .read_present_value(server.addr, object(ObjectType::AnalogInput, 99))
        .expect_err("unknown object must fail");
    assert!(matches!(
        error,
        BacnetError::ErrorPdu {
            error_class: 1,
            error_code: 31,
            ..
        }
    ));
}

#[test]
fn silent_device_times_out_within_the_bound() {
    // A bound socket that never replies: the send succeeds, the read deadline
    // expires, and retries stay bounded.
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = silent.local_addr().unwrap();
    let clock = real_clock();
    let started = clock();
    let mut client = BacnetIpClient::bind(&config(100, 1), Arc::clone(&clock)).unwrap();
    let error = client
        .read_present_value(target, object(ObjectType::AnalogInput, 0))
        .expect_err("silent device must time out");
    assert!(matches!(error, BacnetError::Timeout { .. }), "{error:?}");
    let elapsed = clock().saturating_sub(started);
    assert!(elapsed < 2_000, "bounded timeout took {elapsed} ms");
}

#[test]
fn oversized_device_cap_is_clamped() {
    let (server, _device) = simulation();
    let capped = BacnetIpConfig {
        max_devices: MAX_DISCOVERED_DEVICES + 1,
        ..config(300, 0)
    };
    let client = BacnetIpClient::bind(&capped, real_clock()).unwrap();
    // Construction clamps the cap, so a normal discovery still succeeds.
    assert_eq!(client.discover(server.addr).unwrap().len(), 1);
}
