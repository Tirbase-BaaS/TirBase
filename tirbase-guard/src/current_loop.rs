// SPDX-License-Identifier: AGPL-3.0-only

//! Guard-owned 4–20 mA calibration persistence (CC-05).
//!
//! [`CurrentLoopCalibrationStore`] persists a validated calibration as JSON with
//! an atomic temp-file + rename write. Loading re-validates every invariant and
//! rejects unsupported versions, so a corrupted or hand-edited file cannot put
//! an invalid calibration into the runtime.
//!
//! [`CurrentLoopCalibrationStore::detect_drift`] loads the stored baseline and
//! compares it with a freshly measured calibration using the Apache-2.0
//! `detect_drift` function.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use tirbase_driver_api::current_loop::{
    detect_drift, CalibrationDrift, CalibrationPoint, CurrentLoopCalibration, CurrentLoopError,
    CurrentLoopReading, CurrentLoopSensor, DriftPoint, FaultDetector, FaultThresholds, LoopFault,
    MicroAmps,
};

/// On-disk calibration schema version.
pub const CALIBRATION_FILE_VERSION: u32 = 1;

/// Calibration store failure.
#[derive(Debug)]
pub enum CalibrationStoreError {
    Io(io::Error),
    Serialize(String),
    InvalidCalibration(CurrentLoopError),
    UnsupportedVersion { found: u32, supported: u32 },
}

impl fmt::Display for CalibrationStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "calibration store I/O: {error}"),
            Self::Serialize(error) => write!(f, "calibration serialization: {error}"),
            Self::InvalidCalibration(error) => write!(f, "invalid stored calibration: {error}"),
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "unsupported calibration version {found} (supported: {supported})"
            ),
        }
    }
}

impl std::error::Error for CalibrationStoreError {}

impl From<io::Error> for CalibrationStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CurrentLoopError> for CalibrationStoreError {
    fn from(error: CurrentLoopError) -> Self {
        Self::InvalidCalibration(error)
    }
}

/// JSON-backed calibration store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentLoopCalibrationStore {
    path: PathBuf,
}

impl CurrentLoopCalibrationStore {
    /// Store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Backing file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persists `calibration` atomically (write temp file, fsync, rename).
    pub fn save(&self, calibration: &CurrentLoopCalibration) -> Result<(), CalibrationStoreError> {
        calibration.validate()?;
        let persisted = PersistedCalibration::from(calibration);
        let bytes = serde_json::to_vec_pretty(&persisted)
            .map_err(|error| CalibrationStoreError::Serialize(error.to_string()))?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let temp = self.temp_path();
        {
            use std::io::Write;
            let mut file = fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temp, &self.path)?;
        Ok(())
    }

    /// Loads the stored calibration, or `None` when no file exists yet.
    pub fn load(&self) -> Result<Option<CurrentLoopCalibration>, CalibrationStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(CalibrationStoreError::Io(error)),
        };
        let persisted: PersistedCalibration = serde_json::from_slice(&bytes)
            .map_err(|error| CalibrationStoreError::Serialize(error.to_string()))?;
        if persisted.version != CALIBRATION_FILE_VERSION {
            return Err(CalibrationStoreError::UnsupportedVersion {
                found: persisted.version,
                supported: CALIBRATION_FILE_VERSION,
            });
        }
        persisted.try_into().map(Some)
    }

    /// Compares the stored baseline with `candidate`.
    ///
    /// Returns `None` when no calibration has been persisted.
    pub fn detect_drift(
        &self,
        candidate: &CurrentLoopCalibration,
        tolerance_ua: MicroAmps,
    ) -> Result<Option<CalibrationDrift>, CalibrationStoreError> {
        let Some(reference) = self.load()? else {
            return Ok(None);
        };
        Ok(Some(detect_drift(&reference, candidate, tolerance_ua)?))
    }

    fn temp_path(&self) -> PathBuf {
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "calibration.json".into());
        self.path.with_file_name(format!(".{file_name}.tmp"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCalibration {
    version: u32,
    points: Vec<PersistedPoint>,
    eng_min: i64,
    eng_max: i64,
    exponent: i8,
    unit: u16,
    thresholds: PersistedThresholds,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPoint {
    adc_counts: u32,
    loop_ua: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedThresholds {
    open_loop_ua: i32,
    under_range_ua: i32,
    over_range_ua: i32,
    max_noise_ua: i32,
    noise_window: usize,
    stuck_window: usize,
    stuck_epsilon_ua: i32,
}

impl From<&CurrentLoopCalibration> for PersistedCalibration {
    fn from(calibration: &CurrentLoopCalibration) -> Self {
        let thresholds = calibration.thresholds();
        Self {
            version: CALIBRATION_FILE_VERSION,
            points: calibration
                .points()
                .iter()
                .map(|point| PersistedPoint {
                    adc_counts: point.adc_counts,
                    loop_ua: point.loop_ua,
                })
                .collect(),
            eng_min: calibration.eng_min(),
            eng_max: calibration.eng_max(),
            exponent: calibration.exponent(),
            unit: calibration.unit(),
            thresholds: PersistedThresholds {
                open_loop_ua: thresholds.open_loop_ua,
                under_range_ua: thresholds.under_range_ua,
                over_range_ua: thresholds.over_range_ua,
                max_noise_ua: thresholds.max_noise_ua,
                noise_window: thresholds.noise_window,
                stuck_window: thresholds.stuck_window,
                stuck_epsilon_ua: thresholds.stuck_epsilon_ua,
            },
        }
    }
}

impl TryFrom<PersistedCalibration> for CurrentLoopCalibration {
    type Error = CalibrationStoreError;

    fn try_from(persisted: PersistedCalibration) -> Result<Self, Self::Error> {
        let thresholds = FaultThresholds {
            open_loop_ua: persisted.thresholds.open_loop_ua,
            under_range_ua: persisted.thresholds.under_range_ua,
            over_range_ua: persisted.thresholds.over_range_ua,
            max_noise_ua: persisted.thresholds.max_noise_ua,
            noise_window: persisted.thresholds.noise_window,
            stuck_window: persisted.thresholds.stuck_window,
            stuck_epsilon_ua: persisted.thresholds.stuck_epsilon_ua,
        };
        let points = persisted
            .points
            .into_iter()
            .map(|point| CalibrationPoint::new(point.adc_counts, point.loop_ua))
            .collect();
        CurrentLoopCalibration::new(
            points,
            persisted.eng_min,
            persisted.eng_max,
            persisted.exponent,
            persisted.unit,
            thresholds,
        )
        .map_err(CalibrationStoreError::InvalidCalibration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tirbase_types::UNIT_PERCENT;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-current-loop-{}-{id}-{name}.json",
            std::process::id()
        ))
    }

    fn calibration() -> CurrentLoopCalibration {
        CurrentLoopCalibration::new(
            vec![
                CalibrationPoint::new(0, 4_000),
                CalibrationPoint::new(2_048, 12_000),
                CalibrationPoint::new(4_095, 20_000),
            ],
            0,
            1_000,
            -1,
            UNIT_PERCENT,
            FaultThresholds::default(),
        )
        .unwrap()
    }

    #[test]
    fn calibration_survives_a_store_restart() {
        let path = temp_path("restart");
        let stored = calibration();
        {
            let store = CurrentLoopCalibrationStore::new(&path);
            assert_eq!(store.load().unwrap(), None);
            store.save(&stored).unwrap();
        }

        // New store instance and no in-memory state: load from disk only.
        let reopened = CurrentLoopCalibrationStore::new(&path);
        let loaded = reopened.load().unwrap().expect("persisted calibration");
        assert_eq!(loaded, stored);
        assert_eq!(
            loaded.current_to_engineering(12_000),
            tirbase_types::FixedPointValue::new(500, -1, UNIT_PERCENT)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn corrupted_and_future_files_are_rejected() {
        let path = temp_path("corrupt");
        fs::write(&path, b"{not-json").unwrap();
        let error = CurrentLoopCalibrationStore::new(&path).load().unwrap_err();
        assert!(matches!(error, CalibrationStoreError::Serialize(_)));

        fs::write(&path, br#"{"version":999}"#).unwrap();
        let error = CurrentLoopCalibrationStore::new(&path).load().unwrap_err();
        assert!(matches!(
            error,
            CalibrationStoreError::Serialize(_) | CalibrationStoreError::UnsupportedVersion { .. }
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unsupported_version_is_typed() {
        let path = temp_path("version");
        let mut value = serde_json::to_value(PersistedCalibration::from(&calibration())).unwrap();
        value["version"] = serde_json::json!(CALIBRATION_FILE_VERSION + 1);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = CurrentLoopCalibrationStore::new(&path).load().unwrap_err();
        assert!(matches!(
            error,
            CalibrationStoreError::UnsupportedVersion { found, .. }
                if found == CALIBRATION_FILE_VERSION + 1
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn drift_is_reported_against_the_persisted_baseline() {
        let path = temp_path("drift");
        let store = CurrentLoopCalibrationStore::new(&path);
        store.save(&calibration()).unwrap();

        let shifted = CurrentLoopCalibration::new(
            vec![
                CalibrationPoint::new(0, 4_000),
                CalibrationPoint::new(2_048, 12_040),
                CalibrationPoint::new(4_095, 20_000),
            ],
            0,
            1_000,
            -1,
            UNIT_PERCENT,
            FaultThresholds::default(),
        )
        .unwrap();

        let drift = store.detect_drift(&shifted, 20).unwrap().expect("baseline");
        assert!(drift.drifted);
        assert_eq!(drift.max_abs_delta_ua, 40);
        assert!(
            !store
                .detect_drift(&shifted, 40)
                .unwrap()
                .expect("baseline")
                .drifted
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn drift_without_a_baseline_is_none() {
        let path = temp_path("no-baseline");
        let store = CurrentLoopCalibrationStore::new(&path);
        assert!(store.detect_drift(&calibration(), 10).unwrap().is_none());
    }
}
