// SPDX-License-Identifier: AGPL-3.0-only

//! CC-04 guard wiring: guard-owned BACnet reads and bounded polling against the
//! loopback simulator.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use tirbase_guard::{
    BacnetError, BacnetIpConfig, BacnetPoint, BacnetPollError, BacnetPoller, BacnetValue,
    GuardBacnetReader, ObjectIdentifier, ObjectType, MAX_BACNET_POINTS,
    MIN_BACNET_POLL_INTERVAL_MS,
};
use tirbase_sim::{BacnetSimDevice, BacnetSimServer};
use tirbase_types::{FixedPointValue, UNIT_BOOLEAN, UNIT_DEG_C};

fn real_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    // PV-3.12: use the process TimeSource rather than reading a clock directly.
    Arc::new(tirbase_core::traits::monotonic_now)
}

fn config() -> BacnetIpConfig {
    BacnetIpConfig {
        local_addr: "127.0.0.1:0".into(),
        timeout: Duration::from_millis(300),
        retries: 1,
        max_devices: 4,
    }
}

fn object(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).expect("object identifier")
}

fn point(
    name: &str,
    object_type: ObjectType,
    instance: u32,
    unit: u16,
    exponent: i8,
) -> BacnetPoint {
    BacnetPoint::new(name, object(object_type, instance), unit, exponent).expect("point")
}

fn simulator() -> tirbase_sim::BacnetSimServerHandle {
    let mut device = BacnetSimDevice::new(1001);
    device.set_present_value(ObjectType::AnalogInput, 0, BacnetValue::Real(21.5));
    device.set_present_value(ObjectType::BinaryInput, 3, BacnetValue::Enumerated(1));
    BacnetSimServer::spawn(vec![device]).expect("spawn BACnet simulator")
}

fn reader(server: &tirbase_sim::BacnetSimServerHandle) -> GuardBacnetReader {
    GuardBacnetReader::connect(server.addr, &config(), real_clock()).expect("guard reader")
}

#[test]
fn guard_reader_discovers_and_reads_present_values() {
    let server = simulator();
    let mut reader = reader(&server);

    let devices = reader.discover().expect("discovery");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device, ObjectIdentifier::device(1001).unwrap());

    let temperature = point(
        "room_temperature",
        ObjectType::AnalogInput,
        0,
        UNIT_DEG_C,
        -1,
    );
    let sample = reader.read_point(&temperature).expect("read temperature");
    assert_eq!(sample.point, "room_temperature");
    assert_eq!(sample.value, BacnetValue::Real(21.5));
    assert_eq!(
        sample.fixed_point,
        Some(FixedPointValue::new(215, -1, UNIT_DEG_C))
    );

    let running = point("fan_running", ObjectType::BinaryInput, 3, UNIT_BOOLEAN, 0);
    let sample = reader.read_point(&running).expect("read binary input");
    assert_eq!(sample.value.as_bool(), Some(true));
    assert_eq!(
        sample.fixed_point,
        Some(FixedPointValue::new(1, 0, UNIT_BOOLEAN))
    );

    // The guard-owned path is read-only end to end.
    assert_eq!(server.write_attempts(), 0);
}

#[test]
fn poller_reads_each_due_point_once_and_advances_the_schedule() {
    let server = simulator();
    let points = vec![
        point(
            "room_temperature",
            ObjectType::AnalogInput,
            0,
            UNIT_DEG_C,
            -1,
        ),
        point("fan_running", ObjectType::BinaryInput, 3, UNIT_BOOLEAN, 0),
    ];
    let mut poller = BacnetPoller::new(reader(&server), points, 1_000, 0).expect("poller");

    let first = poller.poll_due(0);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|outcome| outcome.result.is_ok()));
    assert!(first
        .iter()
        .all(|outcome| outcome.result.as_ref().unwrap().sampled_at_ms == 0));
    assert_eq!(poller.next_due_ms(), 1_000);

    // Not due: no reads and no schedule change.
    assert!(poller.poll_due(500).is_empty());
    assert_eq!(poller.next_due_ms(), 1_000);

    let second = poller.poll_due(1_000);
    assert_eq!(second.len(), 2);
    assert!(second
        .iter()
        .all(|outcome| outcome.result.as_ref().unwrap().sampled_at_ms == 1_000));
    assert_eq!(poller.next_due_ms(), 2_000);

    // No catch-up storm after a late poll: one round, next interval from now.
    let late = poller.poll_due(10_000);
    assert_eq!(late.len(), 2);
    assert_eq!(poller.next_due_ms(), 11_000);
}

#[test]
fn a_failed_point_does_not_suppress_the_others() {
    let server = simulator();
    let points = vec![
        point("missing", ObjectType::AnalogInput, 99, UNIT_DEG_C, -1),
        point(
            "room_temperature",
            ObjectType::AnalogInput,
            0,
            UNIT_DEG_C,
            -1,
        ),
    ];
    let mut poller = BacnetPoller::new(reader(&server), points, 1_000, 0).expect("poller");

    let outcomes = poller.poll_due(0);
    assert_eq!(outcomes.len(), 2);
    assert!(matches!(
        outcomes[0].result,
        Err(BacnetError::ErrorPdu {
            error_class: 1,
            error_code: 31,
            ..
        })
    ));
    assert_eq!(
        outcomes[1].result.as_ref().unwrap().value,
        BacnetValue::Real(21.5)
    );
}

#[test]
fn poller_validates_point_list_and_bounds_the_interval() {
    let server = simulator();
    let temperature = point("t", ObjectType::AnalogInput, 0, UNIT_DEG_C, -1);

    let error = BacnetPoller::new(reader(&server), Vec::new(), 1_000, 0).unwrap_err();
    assert!(matches!(error, BacnetPollError::EmptyPointList));

    let error = BacnetPoller::new(
        reader(&server),
        vec![temperature.clone(), temperature.clone()],
        1_000,
        0,
    )
    .unwrap_err();
    assert!(matches!(error, BacnetPollError::DuplicatePoint(_)));

    let too_many: Vec<_> = (0..=MAX_BACNET_POINTS)
        .map(|index| {
            BacnetPoint::new(
                format!("p{index}"),
                object(ObjectType::AnalogInput, index as u32),
                UNIT_DEG_C,
                -1,
            )
            .unwrap()
        })
        .collect();
    let error = BacnetPoller::new(reader(&server), too_many, 1_000, 0).unwrap_err();
    assert!(matches!(
        error,
        BacnetPollError::TooManyPoints {
            max: MAX_BACNET_POINTS,
            ..
        }
    ));

    let poller = BacnetPoller::new(reader(&server), vec![temperature], 1, 0).unwrap();
    assert_eq!(poller.interval_ms(), MIN_BACNET_POLL_INTERVAL_MS);
}
