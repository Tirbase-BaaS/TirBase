// SPDX-License-Identifier: AGPL-3.0-only

//! CC-05 4–20 mA transducer: simulator-backed calibration, fault
//! classification, clamping, drift, and calibration persistence.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tirbase_guard::current_loop::{
    CalibrationPoint, CurrentLoopCalibration, CurrentLoopCalibrationStore, CurrentLoopSensor,
    FaultThresholds, LoopFault,
};
use tirbase_guard::CurrentLoopCalibrationStore as ReexportedStore;
use tirbase_sim::Sim4To20MaAdc;
use tirbase_types::{FixedPointValue, UNIT_PERCENT};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

fn temp_path(name: &str) -> PathBuf {
    let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tirbase-cc05-{}-{id}-{name}.json",
        std::process::id()
    ))
}

/// 12-bit reference calibration: 4 mA at 683 counts, 20 mA at 3413 counts,
/// engineering 0–100.0 % at exponent -1.
fn calibration(thresholds: FaultThresholds) -> CurrentLoopCalibration {
    CurrentLoopCalibration::new(
        vec![
            CalibrationPoint::new(683, 4_000),
            CalibrationPoint::new(1_366, 8_000),
            CalibrationPoint::new(2_048, 12_000),
            CalibrationPoint::new(2_730, 16_000),
            CalibrationPoint::new(3_413, 20_000),
        ],
        0,
        1_000,
        -1,
        UNIT_PERCENT,
        thresholds,
    )
    .expect("reference calibration")
}

fn simulator() -> Sim4To20MaAdc {
    let mut adc = Sim4To20MaAdc::default();
    adc.set_loop_ma(12.0);
    adc
}

#[test]
fn calibrated_simulator_readings_match_reference_vectors() {
    let mut adc = simulator();
    let mut sensor = CurrentLoopSensor::new(calibration(FaultThresholds::default())).unwrap();

    let counts = adc.read_counts();
    assert_eq!(counts, 2_048, "12 mA on a 12-bit 0–24 mA scale");
    let reading = sensor.read(counts);
    assert_eq!(reading.current_ua, 12_000);
    assert_eq!(
        reading.engineering,
        FixedPointValue::new(500, -1, UNIT_PERCENT)
    );
    assert_eq!(reading.fault, None);

    // Measurement endpoints from the same simulator.
    adc.set_loop_ma(4.0);
    let reading = sensor.read(adc.read_counts());
    assert_eq!(reading.current_ua, 4_000);
    assert_eq!(reading.engineering.mantissa, 0);

    adc.set_loop_ma(20.0);
    let reading = sensor.read(adc.read_counts());
    assert_eq!(reading.current_ua, 20_000);
    assert_eq!(reading.engineering.mantissa, 1_000);
}

#[test]
fn open_loop_under_range_and_over_range_are_distinguishable() {
    let mut adc = simulator();
    let mut sensor = CurrentLoopSensor::new(calibration(FaultThresholds::default())).unwrap();

    adc.set_open_loop();
    let open = sensor.read(adc.read_counts());
    assert_eq!(open.fault, Some(LoopFault::OpenLoop));
    assert!(open.current_ua < 3_600);

    adc.set_under_range();
    let under = sensor.read(adc.read_counts());
    assert_eq!(under.fault, Some(LoopFault::UnderRange));
    assert!((3_600..3_800).contains(&under.current_ua));
    assert_eq!(under.engineering.mantissa, 0, "clamped engineering span");

    adc.set_over_range();
    let over = sensor.read(adc.read_counts());
    assert_eq!(over.fault, Some(LoopFault::OverRange));
    assert!(over.current_ua > 20_500);
    assert_eq!(over.engineering.mantissa, 1_000, "clamped engineering span");

    assert_ne!(open.fault, under.fault);
    assert_ne!(under.fault, over.fault);
}

#[test]
fn noise_and_stuck_value_are_classified() {
    let noise_thresholds = FaultThresholds {
        noise_window: 4,
        max_noise_ua: 500,
        ..FaultThresholds::default()
    };
    let mut adc = simulator();
    adc.set_noise(1_000);
    let mut sensor = CurrentLoopSensor::new(calibration(noise_thresholds)).unwrap();
    let mut noise_fault = None;
    for _ in 0..noise_thresholds.noise_window {
        noise_fault = sensor.read(adc.read_counts()).fault;
    }
    assert_eq!(noise_fault, Some(LoopFault::Noisy));

    let stuck_thresholds = FaultThresholds {
        stuck_window: 4,
        ..FaultThresholds::default()
    };
    let mut adc = simulator();
    adc.set_stuck(true);
    let mut sensor = CurrentLoopSensor::new(calibration(stuck_thresholds)).unwrap();
    let mut stuck_fault = None;
    for _ in 0..stuck_thresholds.stuck_window {
        stuck_fault = sensor.read(adc.read_counts()).fault;
    }
    assert_eq!(stuck_fault, Some(LoopFault::StuckValue));

    // The ADC stays frozen even when the physical loop changes.
    adc.set_loop_ma(16.0);
    let frozen = sensor.read(adc.read_counts());
    assert_eq!(frozen.current_ua, 12_000);
    assert_eq!(frozen.fault, Some(LoopFault::StuckValue));

    // Releasing the stuck ADC clears the fault on the next fresh value.
    adc.set_stuck(false);
    let recovered = sensor.read(adc.read_counts());
    assert_eq!(recovered.current_ua, 16_000);
    assert_eq!(recovered.fault, None);
}

#[test]
fn calibration_survives_restart_and_is_reused_by_the_sensor() {
    let path = temp_path("restart");
    let original = calibration(FaultThresholds::default());
    {
        let store = CurrentLoopCalibrationStore::new(&path);
        store.save(&original).unwrap();
    }

    // New store, no in-memory state.
    let reopened = CurrentLoopCalibrationStore::new(&path);
    let loaded = reopened.load().unwrap().expect("persisted calibration");
    assert_eq!(loaded, original);

    let mut adc = simulator();
    let mut sensor = CurrentLoopSensor::new(loaded).unwrap();
    let reading = sensor.read(adc.read_counts());
    assert_eq!(reading.current_ua, 12_000);
    assert_eq!(
        reading.engineering,
        FixedPointValue::new(500, -1, UNIT_PERCENT)
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn persisted_baseline_detects_calibration_drift() {
    let path = temp_path("drift");
    let store = ReexportedStore::new(&path);
    store
        .save(&calibration(FaultThresholds::default()))
        .unwrap();

    let shifted = CurrentLoopCalibration::new(
        vec![
            CalibrationPoint::new(683, 4_000),
            CalibrationPoint::new(1_366, 8_000),
            CalibrationPoint::new(2_048, 12_060),
            CalibrationPoint::new(2_730, 16_000),
            CalibrationPoint::new(3_413, 20_000),
        ],
        0,
        1_000,
        -1,
        UNIT_PERCENT,
        FaultThresholds::default(),
    )
    .unwrap();

    let report = store.detect_drift(&shifted, 50).unwrap().expect("baseline");
    assert!(report.drifted);
    assert_eq!(report.max_abs_delta_ua, 60);
    assert!(
        !store
            .detect_drift(&shifted, 60)
            .unwrap()
            .expect("baseline")
            .drifted
    );
    let _ = std::fs::remove_file(path);
}
