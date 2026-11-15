// SPDX-License-Identifier: Apache-2.0

//! Vendor conformance test: golden frames plus the published harness.
//!
//! This test uses only the public Apache-2.0 `tirbase-driver-api` surface, which
//! is exactly what a third-party driver author has available.

use tirbase_driver_api::conformance::{run_conformance, CodecCase, SourceFile};
use tirbase_driver_api::register_map::RegisterWordOrder;
use tirbase_driver_api::tirbase_types::{FixedPointValue, TargetId, UNIT_DEG_C};
use tirbase_driver_api::{ActuationPermitRef, DriverTrait};

use tirbase_example_vendor_driver::AcmeThermostatDriver;

fn golden(name: &str) -> Vec<u8> {
    let document = include_str!("../golden/frames.txt");
    for line in document.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("malformed golden line: {line}"));
        if key.trim() == name {
            return value
                .split_whitespace()
                .map(|byte| {
                    u8::from_str_radix(byte, 16)
                        .unwrap_or_else(|_| panic!("bad hex byte '{byte}' in {name}"))
                })
                .collect();
        }
    }
    panic!("golden frame '{name}' is missing");
}

fn permit() -> ActuationPermitRef {
    ActuationPermitRef {
        target_id: TargetId::new("acme-thermostat-7"),
        param: "setpoint_c".into(),
        value: FixedPointValue::new(250, -1, UNIT_DEG_C),
        entry_id: [7u8; 16],
    }
}

fn cases() -> Vec<CodecCase> {
    vec![
        CodecCase {
            name: "temperature".into(),
            parameter: "temperature_c".into(),
            read_response: golden("temperature_response"),
            expected_read: FixedPointValue::new(250, -1, UNIT_DEG_C),
            read_back_frame: golden("read_back_response"),
            expected_read_back: FixedPointValue::new(250, -1, UNIT_DEG_C),
            actuation: permit(),
            expected_actuation: Some(golden("actuation_request")),
            health_response: golden("health_response"),
            expected_healthy: true,
        },
        CodecCase {
            name: "energy".into(),
            parameter: "energy_kwh".into(),
            read_response: golden("energy_response"),
            expected_read: FixedPointValue::new(1234, 0, 0),
            read_back_frame: golden("energy_read_back_response"),
            expected_read_back: FixedPointValue::new(1234, 0, 0),
            actuation: permit(),
            expected_actuation: Some(golden("actuation_request")),
            health_response: golden("health_response"),
            expected_healthy: true,
        },
    ]
}

#[test]
fn driver_matches_golden_frames() {
    let driver = AcmeThermostatDriver::new(7).expect("bundled register map must parse");

    assert_eq!(
        driver.encode_read("temperature_c").unwrap(),
        golden("read_temperature_request")
    );
    assert_eq!(
        driver.encode_read("energy_kwh").unwrap(),
        golden("read_energy_request")
    );
    assert_eq!(
        driver.encode_actuation(&permit()).unwrap(),
        golden("actuation_request")
    );
    assert_eq!(
        driver.encode_health_check().unwrap(),
        golden("health_request")
    );

    assert_eq!(
        driver
            .decode_read_response(&golden("temperature_response"))
            .unwrap(),
        FixedPointValue::new(250, -1, UNIT_DEG_C)
    );
    assert_eq!(
        driver
            .decode_read_response(&golden("energy_response"))
            .unwrap(),
        FixedPointValue::new(1234, 0, 0)
    );
    assert_eq!(
        driver
            .decode_read_back(&golden("read_back_response"))
            .unwrap(),
        FixedPointValue::new(250, -1, UNIT_DEG_C)
    );
    assert!(
        driver
            .decode_health_response(&golden("health_response"))
            .unwrap()
            .healthy
    );

    let energy = driver.parameter("energy_kwh").unwrap();
    assert_eq!(energy.word_order, RegisterWordOrder::MidLittleEndian);
    assert_eq!(energy.registers_per_value().unwrap(), 2);
}

/// Wall clock for the bounded-time check.
///
/// Production drivers must not read a clock; the guard injects a `TimeSource`.
/// A conformance test needs real elapsed time, so this test supplies one here.
#[allow(clippy::disallowed_methods)]
fn wall_clock() -> impl Fn() -> u64 {
    let start = std::time::Instant::now();
    move || start.elapsed().as_millis() as u64
}

#[test]
fn driver_passes_conformance_harness() {
    let driver = AcmeThermostatDriver::new(7).unwrap();
    let sources = [SourceFile {
        path: "src/lib.rs",
        contents: include_str!("../src/lib.rs"),
    }];
    let report = run_conformance(&driver, &cases(), driver.map(), &sources, &wall_clock());
    report.assert_ok();
}

#[test]
fn vendor_depends_only_on_the_apache_crate() {
    let manifest = include_str!("../Cargo.toml");
    let dependencies: String = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(dependencies.contains("tirbase-driver-api ="));
    for forbidden in [
        "tirbase-drivers",
        "tirbase-core",
        "tirbase-guard",
        "tirbase-gateway",
        "tirbase-admin",
        "tirbase-sim",
    ] {
        assert!(
            !dependencies.contains(forbidden),
            "vendor example must not depend on {forbidden}"
        );
    }
}
