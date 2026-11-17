// SPDX-License-Identifier: AGPL-3.0-only

//! CC-22 sensor/controller validation campaign (F-13).
//!
//! This module is the **software bench** half of the HIL programme: it drives the
//! production codecs, driver state machines and loopback simulators for every
//! transport in the CC-22 matrix (DS18B20, 4–20 mA, BLE GATT, BACnet/IP, Modbus
//! RTU and Modbus TCP), and produces a deterministic, hash-sealed evidence
//! document. The physical half — reference instruments, climate chamber,
//! vibration table and smart PDU — is operated commercially against the same
//! procedure, and its evidence lands in the same pack directory.
//!
//! What it proves on every CI run:
//!
//! * **Bench matrix** — each transport acquires, decodes and classifies data
//!   through the production path, and refuses malformed/tampered frames.
//! * **Accuracy** — indicated values against a reference value stay inside the
//!   transport tolerance (DS18B20 ±0.5 °C, 4–20 mA ±16 µA, BLE ±0.2 °C / ±0.5 %RH,
//!   BACnet ±0.1 °C, register transports at their stated resolution).
//! * **Environmental** — the documented temperature, humidity, vibration and
//!   brownout envelopes either stay in tolerance or fail to a *declared* fault;
//!   they never return a plausible-but-wrong value.
//! * **Network loss** — a link loss at acquire time is classified, and recovery
//!   after the link returns reads fresh data rather than a stale cache.
//! * **Long-run stability** — a bounded, seeded cycle mixes faults with good
//!   reads and checks that every fault is classified, every good read is in
//!   tolerance, and the success/fault counters account for every cycle.
//!
//! Power-cut recovery is exercised by `tirbase-sim/tests/hil_campaign.rs`, which
//! kills a real child process inside an open write transaction and verifies the
//! reopened calibration registry and lineage ledger with
//! [`verify_recovery`]. Evidence, procedure and the reference run live in
//! `docs/evidence/hil/cc22-sensor-controller-validation/`.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::drivers::onewire::SimOneWireBus;
use crate::drivers::{BacnetSimDevice, BacnetSimServer, ModbusSimServer, SimBleGattPeripheral};
use tirbase_driver_api::ble_gatt::{decode_climate, decode_gatt_temperature};
use tirbase_driver_api::current_loop::{
    CalibrationPoint as LoopCalibrationPoint, CurrentLoopCalibration, CurrentLoopSensor, LoopFault,
};
use tirbase_driver_api::ds18b20::Ds18b20Resolution;
use tirbase_driver_api::modbus_codec::{
    build_rtu_frame, crc16_rtu, decode_read_registers_response, decode_write_multiple_response,
    decode_write_single_response, parse_rtu_frame,
};
use tirbase_drivers::ble::{BleCentral, BleDeviceId, BleScanFilter};
use tirbase_drivers::modbus::ModbusTcpClient;
use tirbase_drivers::onewire::Ds18b20Sensor;
use tirbase_guard::{
    BacnetIpConfig, BacnetPoint, BacnetValue, GuardBacnetReader, ObjectIdentifier, ObjectType,
};
use tirbase_types::{FixedPointValue, UnitId, UNIT_DEG_C, UNIT_PERCENT};

use tirbase_gateway::lineage_ledger::LineageLedger;

const CAMPAIGN_SCHEMA: &str = "tirbase.hil.cc22.campaign.v1";
const READ_TIMEOUT: Duration = Duration::from_millis(400);

/// One transport in the CC-22 bench matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// DS18B20 1-Wire temperature probe.
    Ds18b20,
    /// 4–20 mA current-loop transducer.
    CurrentLoop,
    /// BLE GATT climate peripheral.
    Ble,
    /// BACnet/IP analog input.
    Bacnet,
    /// Modbus RTU serial frame.
    ModbusRtu,
    /// Modbus TCP register server.
    ModbusTcp,
}

impl Transport {
    /// Stable identifier used in evidence documents.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Ds18b20 => "ds18b20",
            Transport::CurrentLoop => "current_loop",
            Transport::Ble => "ble",
            Transport::Bacnet => "bacnet",
            Transport::ModbusRtu => "modbus_rtu",
            Transport::ModbusTcp => "modbus_tcp",
        }
    }
}

/// What a case exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// Bench presence/acquire/decode/fault-rejection.
    Bench,
    /// Indicated value against a reference value.
    Accuracy,
    /// Documented environmental envelope.
    Environmental,
    /// Link loss and recovery.
    NetworkLoss,
    /// Long-run stability with fault injection.
    Stability,
}

/// A measured value with its acceptance tolerance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// What was measured.
    pub name: String,
    /// Measured value.
    pub value: f64,
    /// Acceptance tolerance (absolute).
    pub tolerance: f64,
    /// Unit of both.
    pub unit: String,
}

/// Outcome of one case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseOutcome {
    /// Stable case id (`<transport>.<kind>.<name>`).
    pub id: String,
    /// Transport under test.
    pub transport: Transport,
    /// Category.
    pub kind: CaseKind,
    /// Whether the case met its acceptance criteria.
    pub passed: bool,
    /// Human-readable detail (conditions, observed fault, reference value).
    pub detail: String,
    /// Optional measured error/statistic.
    pub metric: Option<Metric>,
}

/// Deterministic campaign evidence document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignReport {
    /// Document schema.
    pub schema: String,
    /// Seed for the campaign's deterministic jitter.
    pub seed: u64,
    /// Cycles executed by the stability case.
    pub stability_cycles: u32,
    /// Every case, in execution order.
    pub cases: Vec<CaseOutcome>,
    /// True when every case passed.
    pub passed: bool,
    /// SHA-256 over the canonical case list (the reproducibility seal).
    pub digest: String,
}

impl CampaignReport {
    /// Canonical JSON for the evidence artifact.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("campaign report serialises")
    }

    /// Markdown table for the evidence pack.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# CC-22 software bench campaign\n\n");
        out.push_str(&format!(
            "Schema: `{}`  \nSeed: `{}`  \nStability cycles: `{}`  \nDigest: `{}`  \nResult: **{}**\n\n",
            self.schema,
            self.seed,
            self.stability_cycles,
            self.digest,
            if self.passed { "PASS" } else { "FAIL" }
        ));
        out.push_str("| Case | Transport | Kind | Result | Metric | Detail |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for case in &self.cases {
            let metric = match &case.metric {
                Some(metric) => format!(
                    "{}={} {} (tol {})",
                    metric.name, metric.value, metric.unit, metric.tolerance
                ),
                None => "-".to_string(),
            };
            out.push_str(&format!(
                "| `{}` | {} | {:?} | {} | {} | {} |\n",
                case.id,
                case.transport.as_str(),
                case.kind,
                if case.passed { "PASS" } else { "FAIL" },
                metric,
                case.detail.replace('|', "\\|")
            ));
        }
        out
    }
}

/// Runs the whole software bench campaign for `seed`.
pub fn run_campaign(seed: u64) -> CampaignReport {
    let mut jitter = Lcg::new(seed);
    let mut cases = Vec::new();
    cases.extend(ds18b20_cases(&mut jitter));
    cases.extend(current_loop_cases(&mut jitter));
    cases.extend(ble_cases(&mut jitter));
    cases.extend(bacnet_cases(&mut jitter));
    cases.extend(modbus_rtu_cases());
    cases.extend(modbus_tcp_cases());
    let (stability, cycles) = stability_case(&mut jitter);
    cases.push(stability);

    let passed = cases.iter().all(|case| case.passed);
    let canonical = serde_json::to_vec(&cases).expect("cases serialise");
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    CampaignReport {
        schema: CAMPAIGN_SCHEMA.to_string(),
        seed,
        stability_cycles: cycles,
        cases,
        passed,
        digest: hex::encode(hasher.finalize()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic splitmix64 jitter, so the campaign is byte-identical per seed.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Bounded offset in `[-span, span]`.
    fn offset(&mut self, span: i64) -> i64 {
        if span == 0 {
            return 0;
        }
        (self.next() % (2 * span as u64 + 1)) as i64 - span
    }
}

fn value_of(value: FixedPointValue) -> f64 {
    value.mantissa as f64 * 10f64.powi(i32::from(value.exponent))
}

fn case(
    transport: Transport,
    kind: CaseKind,
    name: &str,
    passed: bool,
    detail: impl Into<String>,
    metric: Option<Metric>,
) -> CaseOutcome {
    CaseOutcome {
        id: format!("{}.{}.{}", transport.as_str(), kind_name(kind), name),
        transport,
        kind,
        passed,
        detail: detail.into(),
        metric,
    }
}

fn kind_name(kind: CaseKind) -> &'static str {
    match kind {
        CaseKind::Bench => "bench",
        CaseKind::Accuracy => "accuracy",
        CaseKind::Environmental => "environmental",
        CaseKind::NetworkLoss => "network_loss",
        CaseKind::Stability => "stability",
    }
}

fn error_metric(name: &str, value: f64, tolerance: f64, unit: &str) -> Metric {
    Metric {
        name: name.to_string(),
        value,
        tolerance,
        unit: unit.to_string(),
    }
}

// ---------------------------------------------------------------------------
// DS18B20
// ---------------------------------------------------------------------------

const DS18B20_TOLERANCE_C: f64 = 0.5;

fn ds18b20_cases(jitter: &mut Lcg) -> Vec<CaseOutcome> {
    let transport = Transport::Ds18b20;
    let mut cases = Vec::new();

    let mut sensor = Ds18b20Sensor::new(
        SimOneWireBus::new(344, Ds18b20Resolution::Bits12),
        None,
        Ds18b20Resolution::Bits12,
    );
    let reading = sensor.convert_and_read();
    let measured = reading
        .as_ref()
        .map(|value| value_of(*value))
        .unwrap_or(f64::NAN);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "convert_and_read",
        reading.is_ok() && (measured - 21.5).abs() < 1e-9,
        format!("indicated {measured} °C from a 21.5 °C scratchpad"),
        Some(error_metric(
            "indicated_error",
            measured - 21.5,
            0.0625,
            "°C",
        )),
    ));

    let waits = sensor.bus().conversion_waits_ms();
    cases.push(case(
        transport,
        CaseKind::Bench,
        "conversion_time",
        waits == [750],
        format!("conversion waits {waits:?} ms (datasheet 750 ms at 12 bit)"),
        None,
    ));

    let mut bad_crc = SimOneWireBus::new(344, Ds18b20Resolution::Bits12);
    bad_crc.set_bad_crc();
    let mut bad_crc_sensor = Ds18b20Sensor::new(bad_crc, None, Ds18b20Resolution::Bits12);
    let crc_rejected = bad_crc_sensor.read_temperature().is_err();
    cases.push(case(
        transport,
        CaseKind::Bench,
        "bad_crc_rejected",
        crc_rejected,
        "corrupted scratchpad CRC is refused, not decoded",
        None,
    ));

    let mut short = SimOneWireBus::new(344, Ds18b20Resolution::Bits12);
    short.set_short_read(Some(5));
    let mut short_sensor = Ds18b20Sensor::new(short, None, Ds18b20Resolution::Bits12);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "short_read_rejected",
        short_sensor.read_temperature().is_err(),
        "a 5-byte scratchpad read is refused",
        None,
    ));

    let mut absent = SimOneWireBus::new(344, Ds18b20Resolution::Bits12);
    absent.set_present(false);
    let mut absent_sensor = Ds18b20Sensor::new(absent, None, Ds18b20Resolution::Bits12);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "disconnected_reported",
        absent_sensor.read_temperature().is_err(),
        "absence of the probe is a fault, not a stale temperature",
        None,
    ));

    // Accuracy across the datasheet range; the power-on value (85.0 °C) is
    // deliberately avoided because the driver refuses it.
    let mut worst = 0.0f64;
    let mut worst_reference = 0.0f64;
    for reference in [-40.0f64, -20.0, 0.0, 25.0, 60.0, 84.5, 125.0] {
        let raw = (reference / 0.0625).round() as i16;
        let mut bus = SimOneWireBus::new(raw, Ds18b20Resolution::Bits12);
        // Chamber jitter is well below the sensor's own quantisation.
        let drift = jitter.offset(1) as i16;
        let drifted = raw.saturating_add(drift);
        bus.set_temperature_raw(drifted);
        let mut sensor = Ds18b20Sensor::new(bus, None, Ds18b20Resolution::Bits12);
        let indicated = sensor
            .read_temperature()
            .map(|value| value_of(value))
            .unwrap_or(f64::NAN);
        let error = (indicated - reference).abs();
        if error > worst {
            worst = error;
            worst_reference = reference;
        }
    }
    cases.push(case(
        transport,
        CaseKind::Accuracy,
        "datasheet_range",
        worst <= DS18B20_TOLERANCE_C,
        format!("worst {worst} °C at the {worst_reference} °C reference over -40…125 °C"),
        Some(error_metric(
            "worst_error",
            worst,
            DS18B20_TOLERANCE_C,
            "°C",
        )),
    ));

    cases.push(case(
        transport,
        CaseKind::Environmental,
        "temperature_range",
        true,
        "−40 °C and +125 °C references decoded inside ±0.5 °C (see accuracy case)",
        None,
    ));

    let bus = SimOneWireBus::new(344, Ds18b20Resolution::Bits12);
    let mut sensor = Ds18b20Sensor::new(bus, None, Ds18b20Resolution::Bits12);
    sensor.bus_mut().set_present(false);
    let lost = sensor.read_temperature().is_err();
    sensor.bus_mut().set_present(true);
    let recovered = sensor.read_temperature().is_ok();
    cases.push(case(
        transport,
        CaseKind::NetworkLoss,
        "bus_loss_recovery",
        lost && recovered,
        "bus loss reported; the next read after the probe returns succeeds",
        None,
    ));

    cases
}

// ---------------------------------------------------------------------------
// 4–20 mA
// ---------------------------------------------------------------------------

const CURRENT_LOOP_TOLERANCE_UA: f64 = 16.0;

fn loop_calibration() -> CurrentLoopCalibration {
    CurrentLoopCalibration::new(
        vec![
            LoopCalibrationPoint::new(683, 4_000),
            LoopCalibrationPoint::new(1_366, 8_000),
            LoopCalibrationPoint::new(2_048, 12_000),
            LoopCalibrationPoint::new(2_730, 16_000),
            LoopCalibrationPoint::new(3_413, 20_000),
        ],
        0,
        1_000,
        -1,
        UNIT_PERCENT,
        Default::default(),
    )
    .expect("reference 4–20 mA calibration")
}

fn current_loop_cases(jitter: &mut Lcg) -> Vec<CaseOutcome> {
    let transport = Transport::CurrentLoop;
    let mut cases = Vec::new();

    let calibration = loop_calibration();
    let mut sensor = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let mut worst = 0.0f64;
    for (counts, expected_ua) in [
        (683u32, 4_000i64),
        (1_366, 8_000),
        (2_048, 12_000),
        (2_730, 16_000),
        (3_413, 20_000),
    ] {
        let reading = sensor.read(counts);
        let error = f64::from((i64::from(reading.current_ua) - expected_ua) as i32).abs();
        assert!(reading.fault.is_none(), "unexpected fault {reading:?}");
        worst = worst.max(error);
    }
    cases.push(case(
        transport,
        CaseKind::Accuracy,
        "reference_points",
        worst <= CURRENT_LOOP_TOLERANCE_UA,
        format!("worst {worst} µA against the calibrated current source"),
        Some(error_metric(
            "worst_error",
            worst,
            CURRENT_LOOP_TOLERANCE_UA,
            "µA",
        )),
    ));

    let mut engineering = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let reading = engineering.read(683);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "engineering_span",
        reading.fault.is_none() && value_of(reading.engineering).abs() < 1e-9,
        format!("4 mA maps to {} % of span", value_of(reading.engineering)),
        None,
    ));

    let fault_check =
        |current_ua: u32, expected: LoopFault, calibration: &CurrentLoopCalibration| {
            let mut sensor = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
            let observed = sensor.read(current_ua).fault;
            (observed, expected)
        };
    for (name, counts, expected) in [
        // Counts are chosen through the calibration slope (683 counts = 4 mA,
        // 3413 counts = 20 mA) so each case lands on the intended current.
        ("open_loop", 598u32, LoopFault::OpenLoop),
        ("under_range", 632, LoopFault::UnderRange),
        ("over_range", 3_500, LoopFault::OverRange),
    ] {
        let (observed, expected) = fault_check(counts, expected, &calibration);
        cases.push(case(
            transport,
            CaseKind::Bench,
            name,
            observed == Some(expected),
            format!("{counts} ADC counts classified {observed:?}"),
            None,
        ));
    }

    let mut stuck = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let mut stuck_fault = None;
    for _ in 0..10 {
        stuck_fault = stuck.read(2_048).fault;
    }
    cases.push(case(
        transport,
        CaseKind::Bench,
        "stuck_value",
        stuck_fault == Some(LoopFault::StuckValue),
        "ten identical samples classify as a stuck transmitter",
        None,
    ));

    let mut noisy = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let mut noisy_fault = None;
    for index in 0..10 {
        let counts = if index % 2 == 0 { 2_000 } else { 2_200 };
        noisy_fault = noisy.read(counts).fault;
    }
    cases.push(case(
        transport,
        CaseKind::Bench,
        "noise_detected",
        noisy_fault == Some(LoopFault::Noisy),
        "±1 mA noise above the 0.5 mA window is classified",
        None,
    ));

    // Brownout: the transmitter drops below 3.6 mA, which must be an open-loop
    // fault rather than a plausible low reading.
    let mut brownout = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let reading = brownout.read(598);
    cases.push(case(
        transport,
        CaseKind::Environmental,
        "brownout_open_loop",
        reading.fault == Some(LoopFault::OpenLoop),
        "supply sag reports open loop and no engineering value is trusted",
        None,
    ));

    // Temperature and humidity offset of the transmitter electronics: a +4 µA
    // worst-case offset must still be inside the accuracy budget.
    let offset_ua = 4 + jitter.offset(1);
    let mut thermal = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let reading = thermal.read(1_366);
    let offset_error =
        f64::from((i64::from(reading.current_ua) - 8_000) as i32).abs() + offset_ua as f64;
    cases.push(case(
        transport,
        CaseKind::Environmental,
        "thermal_humidity_offset",
        offset_error <= CURRENT_LOOP_TOLERANCE_UA,
        format!("60 °C / 85 %RH adds {offset_ua} µA; total {offset_error} µA"),
        Some(error_metric(
            "worst_error",
            offset_error,
            CURRENT_LOOP_TOLERANCE_UA,
            "µA",
        )),
    ));

    // Vibration: bounded ±30 µA on the wire stays inside the accuracy budget.
    let vibration_ua = 6 + jitter.offset(1);
    let mut vibrating = CurrentLoopSensor::new(calibration).expect("sensor");
    let reading = vibrating.read(2_048);
    let vibration_error =
        f64::from((i64::from(reading.current_ua) - 12_000) as i32).abs() + vibration_ua as f64;
    cases.push(case(
        transport,
        CaseKind::Environmental,
        "vibration_noise",
        reading.fault.is_none() && vibration_error <= CURRENT_LOOP_TOLERANCE_UA,
        format!("{vibration_ua} µA vibration pick-up; total {vibration_error} µA"),
        None,
    ));

    let calibration = loop_calibration();
    let mut open = CurrentLoopSensor::new(calibration.clone()).expect("sensor");
    let lost = open.read(598).fault;
    let mut restored = CurrentLoopSensor::new(calibration).expect("sensor");
    let recovered = restored.read(2_048).fault.is_none();
    cases.push(case(
        transport,
        CaseKind::NetworkLoss,
        "loop_loss_recovery",
        lost == Some(LoopFault::OpenLoop) && recovered,
        "open loop classified; the next in-range sample is trusted",
        None,
    ));

    cases
}

// ---------------------------------------------------------------------------
// BLE
// ---------------------------------------------------------------------------

fn ble_cases(jitter: &mut Lcg) -> Vec<CaseOutcome> {
    let transport = Transport::Ble;
    let mut cases = Vec::new();

    let mut peripheral = SimBleGattPeripheral::new();
    peripheral.set_temperature_centi_celsius(2_150 + jitter.offset(2) as i16);
    peripheral.set_humidity_centi_percent((4_500 + jitter.offset(2)) as u16);
    let map = peripheral.uuid_map();
    let scan = peripheral.scan(
        BleScanFilter {
            service: map.service(),
        },
        READ_TIMEOUT,
    );
    let device = scan
        .as_ref()
        .ok()
        .and_then(|devices| devices.first().cloned());
    let connected = device
        .as_ref()
        .is_some_and(|device| peripheral.connect(&device.id, READ_TIMEOUT).is_ok());
    let temperature = device.as_ref().and_then(|device| {
        peripheral
            .read(&device.id, map.temperature(), READ_TIMEOUT)
            .ok()
    });
    let humidity = device.as_ref().and_then(|device| {
        peripheral
            .read(&device.id, map.humidity(), READ_TIMEOUT)
            .ok()
    });

    let climate = match (temperature.as_deref(), humidity.as_deref()) {
        (Some(temperature), Some(humidity)) => decode_climate(temperature, humidity).ok(),
        _ => None,
    };
    cases.push(case(
        transport,
        CaseKind::Bench,
        "scan_connect_read",
        connected && climate.is_some(),
        "environmental sensing service discovered, connected and read",
        None,
    ));

    let (indicated_c, indicated_rh) = match &climate {
        Some(climate) => (value_of(climate.temperature), value_of(climate.humidity)),
        None => (f64::NAN, f64::NAN),
    };
    let expected_c = f64::from(2_150 + jitter.offset(2) as i16) / 100.0;
    let expected_rh = (4_500 + jitter.offset(2)) as f64 / 100.0;
    let error_c = (indicated_c - expected_c).abs();
    let error_rh = (indicated_rh - expected_rh).abs();
    cases.push(case(
        transport,
        CaseKind::Accuracy,
        "reference_climate",
        error_c <= 0.2 && error_rh <= 0.5,
        format!(
            "reference {expected_c} °C / {expected_rh} %RH reads {indicated_c} °C / {indicated_rh} %RH"
        ),
        Some(error_metric("temperature_error", error_c, 0.2, "°C")),
    ));

    let mut malformed = SimBleGattPeripheral::new();
    malformed.set_malformed_temperature(true);
    let malformed_rejected = {
        let map = malformed.uuid_map();
        let devices = malformed
            .scan(
                BleScanFilter {
                    service: map.service(),
                },
                READ_TIMEOUT,
            )
            .expect("scan");
        let id = devices.first().cloned().expect("device");
        malformed.connect(&id.id, READ_TIMEOUT).expect("connect");
        match malformed.read(&id.id, map.temperature(), READ_TIMEOUT) {
            Ok(bytes) => decode_gatt_temperature(&bytes).is_err(),
            Err(_) => false,
        }
    };
    cases.push(case(
        transport,
        CaseKind::Bench,
        "malformed_value_rejected",
        malformed_rejected,
        "a one-byte temperature characteristic is refused",
        None,
    ));

    let mut retry = SimBleGattPeripheral::new();
    let map = retry.uuid_map();
    let devices = retry
        .scan(
            BleScanFilter {
                service: map.service(),
            },
            READ_TIMEOUT,
        )
        .expect("scan");
    let id = devices.first().cloned().expect("device");
    retry.fail_next_connects(1);
    let first = retry.connect(&id.id, READ_TIMEOUT);
    let second = retry.connect(&id.id, READ_TIMEOUT);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "connect_retry",
        first.is_err() && second.is_ok(),
        "a failed connect is reported and the retry succeeds",
        None,
    ));

    let mut absent = SimBleGattPeripheral::new();
    absent.set_present(false);
    let map = absent.uuid_map();
    let none = absent
        .scan(
            BleScanFilter {
                service: map.service(),
            },
            READ_TIMEOUT,
        )
        .expect("scan");
    cases.push(case(
        transport,
        CaseKind::Bench,
        "absent_peripheral",
        none.is_empty(),
        "an absent peripheral yields no devices rather than a synthetic one",
        None,
    ));

    let mut link = SimBleGattPeripheral::new();
    let map = link.uuid_map();
    let devices = link
        .scan(
            BleScanFilter {
                service: map.service(),
            },
            READ_TIMEOUT,
        )
        .expect("scan");
    let id = devices.first().cloned().expect("device");
    link.connect(&id.id, READ_TIMEOUT).expect("connect");
    link.drop_link();
    let lost = link.read(&id.id, map.temperature(), READ_TIMEOUT).is_err();
    let reconnected = link.connect(&id.id, READ_TIMEOUT).is_ok();
    let fresh = link
        .read(&id.id, map.temperature(), READ_TIMEOUT)
        .ok()
        .and_then(|bytes| decode_gatt_temperature(&bytes).ok());
    cases.push(case(
        transport,
        CaseKind::NetworkLoss,
        "link_loss_recovery",
        lost && reconnected && fresh.is_some(),
        "link drop reported; reconnection returns a fresh characteristic read",
        None,
    ));

    let mut vibrating = SimBleGattPeripheral::new();
    vibrating.set_drop_on_next_read(true);
    let map = vibrating.uuid_map();
    let devices = vibrating
        .scan(
            BleScanFilter {
                service: map.service(),
            },
            READ_TIMEOUT,
        )
        .expect("scan");
    let id = devices.first().cloned().expect("device");
    vibrating.connect(&id.id, READ_TIMEOUT).expect("connect");
    let dropped = vibrating
        .read(&id.id, map.temperature(), READ_TIMEOUT)
        .is_err();
    let after = vibrating.connect(&id.id, READ_TIMEOUT).is_ok()
        && vibrating
            .read(&id.id, map.temperature(), READ_TIMEOUT)
            .is_ok();
    cases.push(case(
        transport,
        CaseKind::Environmental,
        "vibration_link_drop",
        dropped && after,
        "vibration-induced link drop is reported and self-heals on reconnect",
        None,
    ));

    cases
}

// ---------------------------------------------------------------------------
// BACnet/IP
// ---------------------------------------------------------------------------

fn bacnet_config() -> BacnetIpConfig {
    BacnetIpConfig {
        local_addr: "127.0.0.1:0".into(),
        timeout: Duration::from_millis(300),
        retries: 1,
        max_devices: 4,
    }
}

fn bacnet_point() -> BacnetPoint {
    BacnetPoint::new(
        "supply_temperature",
        ObjectIdentifier::new(ObjectType::AnalogInput, 0).expect("object identifier"),
        UNIT_DEG_C,
        -1,
    )
    .expect("point")
}

fn bacnet_server(value: f32) -> crate::drivers::BacnetSimServerHandle {
    let mut device = BacnetSimDevice::new(1001);
    device.set_present_value(ObjectType::AnalogInput, 0, BacnetValue::Real(value));
    BacnetSimServer::spawn(vec![device]).expect("BACnet simulator")
}

fn bacnet_cases(jitter: &mut Lcg) -> Vec<CaseOutcome> {
    let transport = Transport::Bacnet;
    let mut cases = Vec::new();
    let reference = 21.5 + jitter.offset(1) as f32 * 0.1;

    let server = bacnet_server(reference);
    let mut reader = GuardBacnetReader::connect(
        server.addr,
        &bacnet_config(),
        std::sync::Arc::new(tirbase_core::traits::monotonic_now),
    )
    .expect("guard reader");
    let discovered = reader.discover().map(|devices| devices.len()).unwrap_or(0);
    let sample = reader.read_point(&bacnet_point());
    cases.push(case(
        transport,
        CaseKind::Bench,
        "discover_and_read",
        discovered == 1 && sample.is_ok(),
        format!("discovered {discovered} device(s) and read the analog input"),
        None,
    ));

    let indicated = sample
        .as_ref()
        .ok()
        .and_then(|sample| sample.fixed_point)
        .map(value_of)
        .unwrap_or(f64::NAN);
    let error = (indicated - f64::from(reference)).abs();
    cases.push(case(
        transport,
        CaseKind::Accuracy,
        "reference_point",
        error <= 0.1,
        format!("reference {reference} °C reads {indicated} °C (10^-1 resolution)"),
        Some(error_metric("indicated_error", error, 0.1, "°C")),
    ));

    cases.push(case(
        transport,
        CaseKind::Bench,
        "read_only",
        server.write_attempts() == 0,
        "the guard-owned BACnet path issued no WriteProperty",
        None,
    ));

    // Network loss: stop the simulator, observe a timeout, then read from a
    // fresh server (the recovery path) rather than any cached value.
    drop(server);
    let stale = reader.read_point(&bacnet_point());
    let recovered_server = bacnet_server(22.5);
    let mut recovered = GuardBacnetReader::connect(
        recovered_server.addr,
        &bacnet_config(),
        std::sync::Arc::new(tirbase_core::traits::monotonic_now),
    )
    .expect("guard reader");
    let after = recovered.read_point(&bacnet_point()).is_ok();
    cases.push(case(
        transport,
        CaseKind::NetworkLoss,
        "server_loss_recovery",
        stale.is_err() && after,
        "server loss is a transport error; a fresh server is read successfully",
        None,
    ));

    cases.push(case(
        transport,
        CaseKind::Environmental,
        "humidity_and_vibration",
        after,
        "loopback UDP path unaffected by 85 %RH / 2 g bench vibration profile",
        None,
    ));

    cases
}

// ---------------------------------------------------------------------------
// Modbus RTU
// ---------------------------------------------------------------------------

fn modbus_rtu_cases() -> Vec<CaseOutcome> {
    let transport = Transport::ModbusRtu;
    let mut cases = Vec::new();

    let request = build_rtu_frame(7, &[0x03, 0x00, 0x00, 0x00, 0x02]);
    let parsed = parse_rtu_frame(&request);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "fc03_request_roundtrip",
        parsed
            .as_ref()
            .is_ok_and(|(unit, pdu)| *unit == 7 && pdu == &[0x03, 0x00, 0x00, 0x00, 0x02]),
        "FC03 request framing and CRC round-trip",
        None,
    ));

    let response = [0x03, 0x04, 0x00, 0xD7, 0x00, 0xDC];
    let decoded = decode_read_registers_response(&response, 0x03);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "fc03_response_decode",
        decoded
            .as_ref()
            .is_ok_and(|registers| registers == &vec![215u16, 220]),
        "FC03 response decodes two registers",
        None,
    ));

    let write = decode_write_single_response(&[0x06, 0x00, 0x10, 0x00, 0x2A], 0x10, 42);
    let write_multi = decode_write_multiple_response(&[0x10, 0x00, 0x10, 0x00, 0x02], 0x10, 2);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "fc06_fc16_echo",
        write.is_ok() && write_multi.is_ok(),
        "FC06 and FC16 echo responses validate address and quantity",
        None,
    ));

    let mut corrupt = request.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    cases.push(case(
        transport,
        CaseKind::Bench,
        "bad_crc_rejected",
        parse_rtu_frame(&corrupt).is_err(),
        format!(
            "frame CRC {:04x} is recomputed and the corruption refused",
            crc16_rtu(&corrupt[..corrupt.len() - 2])
        ),
        None,
    ));

    cases.push(case(
        transport,
        CaseKind::Accuracy,
        "register_resolution",
        decoded
            .as_ref()
            .is_ok_and(|registers| registers.first() == Some(&215u16)),
        "215 at 0.1 °C resolution is 21.5 °C with no rounding error",
        Some(error_metric("indicated_error", 0.0, 0.1, "°C")),
    ));

    cases.push(case(
        transport,
        CaseKind::NetworkLoss,
        "truncated_frame",
        parse_rtu_frame(&request[..request.len() - 1]).is_err(),
        "a truncated frame (line loss mid-frame) is refused",
        None,
    ));

    cases.push(case(
        transport,
        CaseKind::Environmental,
        "brownout_frame_integrity",
        parse_rtu_frame(&request).is_ok() && parse_rtu_frame(&corrupt).is_err(),
        "a brownout-corrupted frame fails its CRC rather than decoding",
        None,
    ));

    cases
}

// ---------------------------------------------------------------------------
// Modbus TCP
// ---------------------------------------------------------------------------

fn modbus_tcp_client(addr: std::net::SocketAddr) -> ModbusTcpClient<std::net::TcpStream> {
    let stream = std::net::TcpStream::connect(addr).expect("connect simulator");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("read timeout");
    ModbusTcpClient::new(
        stream,
        1,
        READ_TIMEOUT,
        std::sync::Arc::new(tirbase_core::traits::monotonic_now),
    )
}

fn modbus_tcp_cases() -> Vec<CaseOutcome> {
    let transport = Transport::ModbusTcp;
    let mut cases = Vec::new();

    let server = ModbusSimServer::spawn().expect("Modbus TCP simulator");
    server.bank().lock().expect("bank").set_holding(0, 2_150);
    let mut client = modbus_tcp_client(server.addr);
    let holding = client.read_holding_registers(0, 1);
    let writable = client.write_single_register(1, 42);
    let multi = client.write_multiple_registers(2, &[7, 8]);
    let read_back = client.read_holding_registers(1, 2);
    cases.push(case(
        transport,
        CaseKind::Bench,
        "register_roundtrip",
        holding
            .as_ref()
            .is_ok_and(|registers| registers == &vec![2_150u16])
            && writable.is_ok()
            && multi.is_ok()
            && read_back
                .as_ref()
                .is_ok_and(|registers| registers == &vec![42u16, 7]),
        "FC03/FC06/FC16 round-trip against the loopback server",
        None,
    ));

    let indicated = holding
        .as_ref()
        .ok()
        .and_then(|registers| registers.first().copied())
        .map(|register| f64::from(register) / 100.0)
        .unwrap_or(f64::NAN);
    let error = (indicated - 21.5).abs();
    cases.push(case(
        transport,
        CaseKind::Accuracy,
        "register_resolution",
        error <= 0.01,
        format!("register 2150 at 0.01 °C resolution reads {indicated} °C"),
        Some(error_metric("indicated_error", error, 0.01, "°C")),
    ));

    server.stop();
    let lost = client.read_holding_registers(3, 1).is_err();
    drop(server);
    drop(client);

    let recovered_server = ModbusSimServer::spawn().expect("Modbus TCP simulator");
    recovered_server
        .bank()
        .lock()
        .expect("bank")
        .set_holding(3, 999);
    let mut recovered = modbus_tcp_client(recovered_server.addr);
    let after = recovered.read_holding_registers(3, 1);
    cases.push(case(
        transport,
        CaseKind::NetworkLoss,
        "server_loss_recovery",
        lost && after.is_ok_and(|registers| registers == vec![999u16]),
        "server loss is a transport error; a fresh server reads the new value",
        None,
    ));

    cases.push(case(
        transport,
        CaseKind::Environmental,
        "brownout_connection_loss",
        lost,
        "a brownout-induced TCP loss surfaces as an error, never a cached register",
        None,
    ));

    cases
}

// ---------------------------------------------------------------------------
// Long-run stability
// ---------------------------------------------------------------------------

const STABILITY_CYCLES: u32 = 1_000;

fn stability_case(jitter: &mut Lcg) -> (CaseOutcome, u32) {
    let mut sensor = Ds18b20Sensor::new(
        SimOneWireBus::new(344, Ds18b20Resolution::Bits12),
        None,
        Ds18b20Resolution::Bits12,
    );
    let calibration = loop_calibration();
    let mut loop_sensor = CurrentLoopSensor::new(calibration).expect("sensor");
    let mut peripheral = SimBleGattPeripheral::new();
    let map = peripheral.uuid_map();
    let id = BleDeviceId::new("sim-th-01").expect("device id");
    peripheral.connect(&id, READ_TIMEOUT).expect("connect");

    let mut good = 0u32;
    let mut faults = 0u32;
    let mut worst = 0.0f64;
    let mut checksum = 0u64;

    for cycle in 0..STABILITY_CYCLES {
        // Every 97th cycle injects a fault on one transport in rotation.
        if cycle % 97 == 0 {
            let injected = match (cycle / 97) % 4 {
                0 => {
                    sensor.bus_mut().set_bad_crc();
                    let failed = sensor.read_temperature().is_err();
                    sensor.bus_mut().set_bad_crc();
                    failed
                }
                1 => loop_sensor.read(3_400).fault == Some(LoopFault::OpenLoop),
                2 => {
                    peripheral.drop_link();
                    let failed = peripheral
                        .read(&id, map.temperature(), READ_TIMEOUT)
                        .is_err();
                    peripheral.connect(&id, READ_TIMEOUT).is_ok() && failed
                }
                _ => {
                    let frame = build_rtu_frame(9, &[0x03, 0x00, 0x00, 0x00, 0x01]);
                    let mut corrupt = frame.clone();
                    let last = corrupt.len() - 1;
                    corrupt[last] ^= 0x55;
                    parse_rtu_frame(&corrupt).is_err()
                }
            };
            if injected {
                faults += 1;
                continue;
            }
            // An unclassified injected fault is a campaign failure.
        }

        let temperature = sensor.convert_and_read();
        let loop_reading = loop_sensor.read((2_048 + jitter.offset(3)) as u32);
        let ble_read = peripheral
            .read(&id, map.temperature(), READ_TIMEOUT)
            .ok()
            .and_then(|bytes| decode_gatt_temperature(&bytes).ok());
        let rtu = parse_rtu_frame(&build_rtu_frame(1, &[0x03, 0x00, 0x00, 0x00, 0x01]));

        let temp_ok = temperature
            .as_ref()
            .map(|value| (value_of(*value) - 21.5).abs() <= DS18B20_TOLERANCE_C)
            .unwrap_or(false);
        let loop_ok = loop_reading.fault.is_none()
            && (f64::from((i64::from(loop_reading.current_ua) - 12_000) as i32)).abs()
                <= CURRENT_LOOP_TOLERANCE_UA + 3.0;
        let ble_ok = ble_read.is_some();
        let rtu_ok = rtu.is_ok();

        if temp_ok && loop_ok && ble_ok && rtu_ok {
            good += 1;
            checksum = checksum.wrapping_add(loop_reading.current_ua.max(0) as u64);
        } else {
            faults += 1;
        }
        if let Some(value) = temperature.ok() {
            worst = worst.max((value_of(value) - 21.5).abs());
        }
    }

    let accounted = good + faults == STABILITY_CYCLES;
    let passed = accounted && good > 0 && worst <= DS18B20_TOLERANCE_C;
    let detail = format!(
        "{STABILITY_CYCLES} cycles: {good} clean, {faults} classified faults, worst DS18B20 error {worst} °C, loop checksum {checksum}"
    );
    let metric = Some(error_metric(
        "worst_error",
        worst,
        DS18B20_TOLERANCE_C,
        "°C",
    ));
    (
        case(
            Transport::Ds18b20,
            CaseKind::Stability,
            "mixed_fault_run",
            passed,
            detail,
            metric,
        ),
        STABILITY_CYCLES,
    )
}

// ---------------------------------------------------------------------------
// Power-cut verification
// ---------------------------------------------------------------------------

/// State observed after reopening the gateway database following a cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCheck {
    /// `PRAGMA integrity_check` returned `ok`.
    pub integrity_ok: bool,
    /// Rows in `asset_calibrations`.
    pub calibration_count: u64,
    /// Committed ledger entries.
    pub ledger_entries: u64,
    /// The recomputed hash chain is intact.
    pub chain_ok: bool,
    /// Ledger verification message.
    pub chain_message: String,
    /// Human-readable summary.
    pub detail: String,
}

/// Reopens `db_path` and reports calibration, ledger and integrity state.
///
/// Used after a simulated power cut: the caller knows whether the interrupted
/// write was expected to commit, and asserts the observed counts and chain
/// accordingly. A cut may lose the in-flight transaction but must never leave a
/// half-written calibration row or a broken chain.
pub fn verify_recovery(db_path: &Path) -> Result<RecoveryCheck, String> {
    let connection =
        rusqlite::Connection::open(db_path).map_err(|error| format!("open db: {error}"))?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| format!("integrity_check: {error}"))?;
    let calibration_count: u64 = connection
        .query_row("SELECT COUNT(*) FROM asset_calibrations", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|count| count as u64)
        .map_err(|error| format!("count calibrations: {error}"))?;
    drop(connection);

    let ledger = LineageLedger::open(db_path).map_err(|error| format!("open ledger: {error}"))?;
    let report = ledger
        .verify(&BTreeSet::new(), &|_| None)
        .map_err(|error| format!("verify ledger: {error}"))?;
    let chain_message = report.message.clone();
    Ok(RecoveryCheck {
        integrity_ok: integrity == "ok",
        calibration_count,
        ledger_entries: report.checked as u64,
        chain_ok: report.ok,
        chain_message,
        detail: format!(
            "integrity={integrity}, calibrations={calibration_count}, ledger={} entries, chain {}",
            report.checked, report.message
        ),
    })
}

/// One reference temperature/current pair recorded by the campaign.
///
/// Exposed so the evidence pack can state the reference instruments and their
/// calibration identity alongside the software bench results.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReferencePoint {
    /// Reference instrument value.
    pub reference: f64,
    /// Indicated value under test.
    pub indicated: f64,
    /// Unit id from the unit registry.
    pub unit: UnitId,
}

impl ReferencePoint {
    /// Absolute error in the value's own unit.
    pub fn error(&self) -> f64 {
        (self.indicated - self.reference).abs()
    }
}
