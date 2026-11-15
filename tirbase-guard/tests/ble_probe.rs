// SPDX-License-Identifier: AGPL-3.0-only

//! CC-06 BLE probe: simulated GATT peripheral, reconnection, malformed
//! payloads, configurable UUIDs, and no-secret logging surface.
#![cfg(unix)]

use std::time::Duration;

use tirbase_driver_api::ble_gatt::{BleGattError, BleGattUuidMap, BleUuid};
use tirbase_drivers::ble::BleError;
use tirbase_guard::ble::{
    BlePairingSecret, BleProbeConfig, BleProbeError, BleProbeState, GuardBleProbe,
};
use tirbase_sim::SimBleGattPeripheral;
use tirbase_types::{FixedPointValue, UNIT_DEG_C, UNIT_PERCENT};

fn config(backoff_ms: u64) -> BleProbeConfig {
    BleProbeConfig {
        scan_timeout: Duration::from_millis(50),
        connect_timeout: Duration::from_millis(80),
        read_timeout: Duration::from_millis(60),
        backoff_base: Duration::from_millis(backoff_ms),
        backoff_max: Duration::from_secs(2),
        max_devices: 4,
        max_payload_bytes: 16,
        ..BleProbeConfig::default()
    }
}

fn probe(sim: SimBleGattPeripheral, backoff_ms: u64) -> GuardBleProbe<SimBleGattPeripheral> {
    GuardBleProbe::new(sim, config(backoff_ms)).expect("valid probe config")
}

#[test]
fn reads_standard_temperature_humidity_and_honours_timeouts() {
    let mut probe = probe(SimBleGattPeripheral::new(), 250);

    let reading = probe.poll(0).unwrap().expect("first reading");
    assert_eq!(reading.device.as_str(), "sim-th-01");
    assert_eq!(
        reading.climate.temperature,
        FixedPointValue::new(2_150, -2, UNIT_DEG_C)
    );
    assert_eq!(
        reading.climate.humidity,
        FixedPointValue::new(4_500, -2, UNIT_PERCENT)
    );
    assert!(matches!(probe.state(), BleProbeState::Connected { .. }));
    assert_eq!(probe.health().connects, 1);
    assert_eq!(probe.health().successful_reads, 1);

    let sim = probe.radio();
    assert_eq!(sim.last_scan_timeout(), Some(Duration::from_millis(50)));
    assert_eq!(sim.last_connect_timeout(), Some(Duration::from_millis(80)));
    assert_eq!(sim.last_read_timeout(), Some(Duration::from_millis(60)));
}

#[test]
fn probe_reconnects_after_a_disconnect_with_backoff() {
    let mut probe = probe(SimBleGattPeripheral::new(), 250);
    assert!(probe.poll(0).unwrap().is_some());
    assert_eq!(probe.radio().connect_calls(), 1);

    // The physical link drops before the next read.
    probe.radio_mut().drop_link();
    let failure = probe.poll(100).unwrap_err();
    assert!(matches!(
        failure,
        BleProbeError::Read(BleError::NotConnected)
    ));
    assert_eq!(probe.radio().connect_calls(), 1);
    assert!(matches!(
        probe.state(),
        BleProbeState::Backoff {
            until_ms: 350,
            attempt: 1
        }
    ));

    // Still inside the backoff window: no scan, no reconnect.
    assert!(probe.poll(349).unwrap().is_none());
    assert_eq!(probe.radio().scan_calls(), 1);

    // At the deadline the probe rescans, reconnects, and reads again.
    let reading = probe.poll(350).unwrap().expect("reconnected reading");
    assert_eq!(reading.climate.temperature.mantissa, 2_150);
    assert_eq!(probe.radio().scan_calls(), 2);
    assert_eq!(probe.radio().connect_calls(), 2);
    assert_eq!(probe.health().connects, 2);
    assert_eq!(probe.health().disconnects, 1);
}

#[test]
fn connect_failures_use_exponential_backoff_until_success() {
    let mut sim = SimBleGattPeripheral::new();
    sim.fail_next_connects(1);
    let mut probe = probe(sim, 250);

    let failure = probe.poll(0).unwrap_err();
    assert!(matches!(
        failure,
        BleProbeError::Connect(BleError::Radio(_))
    ));
    assert_eq!(probe.radio().connect_calls(), 1);
    assert!(matches!(
        probe.state(),
        BleProbeState::Backoff {
            until_ms: 250,
            attempt: 1
        }
    ));

    let reading = probe.poll(250).unwrap().expect("retry succeeds");
    assert_eq!(reading.climate.humidity.mantissa, 4_500);
    assert_eq!(probe.radio().connect_calls(), 2);
    assert_eq!(probe.health().connects, 1);
}

#[test]
fn malformed_payloads_are_rejected_without_reconnecting() {
    let mut sim = SimBleGattPeripheral::new();
    sim.set_malformed_temperature(true);
    let mut probe = probe(sim, 250);

    let error = probe.poll(0).unwrap_err();
    assert!(matches!(
        error,
        BleProbeError::Payload(BleGattError::PayloadLength {
            field: "temperature",
            len: 1
        })
    ));
    assert_eq!(probe.health().malformed_payloads, 1);
    assert!(matches!(probe.state(), BleProbeState::Connected { .. }));
    assert_eq!(probe.radio().connect_calls(), 1);

    // Fixing the payload returns a reading on the same connection.
    probe.radio_mut().set_malformed_temperature(false);
    let reading = probe.poll(1).unwrap().expect("recovered payload");
    assert_eq!(reading.climate.temperature.mantissa, 2_150);
    assert_eq!(probe.radio().connect_calls(), 1);
}

#[test]
fn malformed_humidity_and_impossible_values_are_rejected() {
    let mut sim = SimBleGattPeripheral::new();
    sim.set_malformed_humidity(true);
    let mut probe = probe(sim, 250);
    assert!(matches!(
        probe.poll(0).unwrap_err(),
        BleProbeError::Payload(BleGattError::PayloadLength {
            field: "humidity",
            ..
        })
    ));

    probe.radio_mut().set_malformed_humidity(false);
    probe.radio_mut().set_temperature_centi_celsius(-30_000);
    assert!(matches!(
        probe.poll(1).unwrap_err(),
        BleProbeError::Payload(BleGattError::ValueOutOfRange {
            field: "temperature"
        })
    ));
    assert_eq!(probe.health().malformed_payloads, 2);
}

#[test]
fn absent_peripheral_is_bounded_and_schedules_a_retry() {
    let mut sim = SimBleGattPeripheral::new();
    sim.set_present(false);
    let mut probe = probe(sim, 500);

    assert!(matches!(
        probe.poll(0).unwrap_err(),
        BleProbeError::NoMatchingDevice
    ));
    assert_eq!(probe.radio().scan_calls(), 1);
    assert!(matches!(
        probe.state(),
        BleProbeState::Backoff {
            until_ms: 500,
            attempt: 1
        }
    ));
    assert!(probe.poll(499).unwrap().is_none());
    assert_eq!(probe.radio().scan_calls(), 1);
}

#[test]
fn custom_uuid_map_is_used_end_to_end() {
    let map = BleGattUuidMap::new(
        BleUuid::parse("0000f000-0000-1000-8000-00805f9b34fb").unwrap(),
        BleUuid::parse("0000f001-0000-1000-8000-00805f9b34fb").unwrap(),
        BleUuid::parse("0000f002-0000-1000-8000-00805f9b34fb").unwrap(),
    )
    .unwrap();
    let sim = SimBleGattPeripheral::new().with_uuid_map(map);
    let mut config = config(250);
    config.uuid_map = map;
    let mut probe = GuardBleProbe::new(sim, config).unwrap();

    let reading = probe.poll(0).unwrap().expect("custom map reading");
    assert_eq!(reading.climate.humidity.mantissa, 4_500);
    assert_eq!(probe.radio().uuid_map(), map);
}

#[test]
fn pairing_secret_is_redacted_from_debug_and_health() {
    let secret_text = "pairing-pin-938471";
    let secret = BlePairingSecret::new(secret_text.as_bytes()).unwrap();
    assert_eq!(secret.len(), secret_text.len());
    assert!(!format!("{secret:?}").contains(secret_text));

    let mut config = config(250);
    config.pairing_secret = Some(secret);
    let mut probe = GuardBleProbe::new(SimBleGattPeripheral::new(), config).unwrap();

    let fingerprint = format!("{probe:?}");
    assert!(fingerprint.contains("<redacted>"));
    assert!(!fingerprint.contains(secret_text));
    assert!(!format!("{:?}", probe.health()).contains(secret_text));

    let error = {
        probe.radio_mut().set_present(false);
        probe.poll(0).unwrap_err()
    };
    assert!(!error.to_string().contains(secret_text));
    assert!(!format!("{error:?}").contains(secret_text));
    assert_eq!(probe.health().scan_attempts, 1);
}

#[test]
fn configuration_bounds_are_enforced() {
    let mut candidate = config(250);
    candidate.max_devices = 0;
    assert!(matches!(
        GuardBleProbe::new(SimBleGattPeripheral::new(), candidate),
        Err(BleProbeError::InvalidConfig(_))
    ));

    let mut candidate = config(250);
    candidate.backoff_max = Duration::from_millis(100);
    assert!(matches!(
        GuardBleProbe::new(SimBleGattPeripheral::new(), candidate),
        Err(BleProbeError::InvalidConfig(_))
    ));

    let mut candidate = config(250);
    candidate.scan_timeout = Duration::ZERO;
    assert!(matches!(
        GuardBleProbe::new(SimBleGattPeripheral::new(), candidate),
        Err(BleProbeError::InvalidConfig(_))
    ));
}
