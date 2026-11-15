// SPDX-License-Identifier: AGPL-3.0-only

//! Guard-owned BLE probe with bounded scan/connect/read and reconnect backoff
//! (CC-06).
//!
//! [`GuardBleProbe`] is a **step scheduler**: the caller supplies a monotonic
//! timestamp and calls [`GuardBleProbe::poll`]. It never spawns a task, never
//! loops beyond one scan/connect/read cycle, and every radio operation carries
//! the configured timeout. A transport failure moves the probe into a bounded
//! exponential backoff state; the next `poll` after the deadline rescans and
//! reconnects.
//!
//! ## Pairing material
//!
//! The probe performs no pairing and stores no credential. An optional
//! [`BlePairingSecret`] can be supplied by the F-05 credential path; it is held
//! only in memory, zeroized on drop, never serialized, and its `Debug` output
//! is redacted. The probe never logs payload bytes, and its error/health types
//! contain neither pairing material nor GATT values.

use std::fmt;
use std::time::Duration;

use tirbase_driver_api::ble_gatt::{
    decode_climate, BleClimateReading, BleGattError, BleGattUuidMap,
};
use tirbase_drivers::ble::{BleCentral, BleDevice, BleDeviceId, BleError, BleScanFilter};
use zeroize::Zeroizing;

/// Maximum devices retained from one scan round.
pub const MAX_SCAN_DEVICES: usize = 64;
/// Maximum accepted GATT payload.
pub const MAX_GATT_PAYLOAD_BYTES: usize = 512;
/// Maximum backoff exponent (bounded so a delay cannot overflow).
const MAX_BACKOFF_SHIFT: u32 = 16;

/// In-memory pairing material.
///
/// Storage follows the F-05 rule for key material: no export, no serialization,
/// redacted `Debug`, and zeroization on drop. The probe never persists or logs
/// it.
pub struct BlePairingSecret {
    bytes: Zeroizing<Vec<u8>>,
}

impl BlePairingSecret {
    /// Wraps 1–64 bytes of pairing material.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, BleProbeError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > 64 {
            return Err(BleProbeError::InvalidConfig(
                "pairing secret must be 1..=64 bytes",
            ));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Length in bytes. The material itself is intentionally not exported.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for BlePairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Probe configuration.
pub struct BleProbeConfig {
    pub uuid_map: BleGattUuidMap,
    pub scan_timeout: Duration,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    pub max_devices: usize,
    pub max_payload_bytes: usize,
    /// Optional F-05-supplied pairing material; never logged or persisted.
    pub pairing_secret: Option<BlePairingSecret>,
}

impl fmt::Debug for BleProbeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BleProbeConfig")
            .field("uuid_map", &self.uuid_map)
            .field("scan_timeout", &self.scan_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("backoff_base", &self.backoff_base)
            .field("backoff_max", &self.backoff_max)
            .field("max_devices", &self.max_devices)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field(
                "pairing_secret",
                &self.pairing_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Default for BleProbeConfig {
    fn default() -> Self {
        Self {
            uuid_map: BleGattUuidMap::standard(),
            scan_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(3),
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            max_devices: 32,
            max_payload_bytes: 128,
            pairing_secret: None,
        }
    }
}

impl BleProbeConfig {
    /// Validates timeouts, bounds, and backoff ordering.
    pub fn validate(&self) -> Result<(), BleProbeError> {
        if self.scan_timeout.is_zero() {
            return Err(BleProbeError::InvalidConfig(
                "scan timeout must be non-zero",
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(BleProbeError::InvalidConfig(
                "connect timeout must be non-zero",
            ));
        }
        if self.read_timeout.is_zero() {
            return Err(BleProbeError::InvalidConfig(
                "read timeout must be non-zero",
            ));
        }
        if self.backoff_base.is_zero() {
            return Err(BleProbeError::InvalidConfig(
                "backoff base must be non-zero",
            ));
        }
        if self.backoff_max < self.backoff_base {
            return Err(BleProbeError::InvalidConfig(
                "backoff max must not be below the base",
            ));
        }
        if self.max_devices == 0 || self.max_devices > MAX_SCAN_DEVICES {
            return Err(BleProbeError::InvalidConfig("max_devices must be 1..=64"));
        }
        if !(2..=MAX_GATT_PAYLOAD_BYTES).contains(&self.max_payload_bytes) {
            return Err(BleProbeError::InvalidConfig(
                "max_payload_bytes must be 2..=512",
            ));
        }
        Ok(())
    }
}

/// Probe lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleProbeState {
    /// No peripheral is connected and no backoff is scheduled.
    Disconnected,
    /// A peripheral is connected and ready to read.
    Connected { device: BleDeviceId },
    /// Waiting until `until_ms` before the next scan/connect attempt.
    Backoff { until_ms: u64, attempt: u32 },
}

/// Counters only: no credentials, payload bytes, or device addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BleProbeHealth {
    pub scan_attempts: u64,
    pub devices_seen: u64,
    pub connect_attempts: u64,
    pub connects: u64,
    pub disconnects: u64,
    pub read_attempts: u64,
    pub read_failures: u64,
    pub malformed_payloads: u64,
    pub successful_reads: u64,
}

/// One successful climate reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleProbeReading {
    pub device: BleDeviceId,
    pub climate: BleClimateReading,
}

/// Probe failure. Never contains credential or payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleProbeError {
    InvalidConfig(&'static str),
    Radio(String),
    Scan(BleError),
    Connect(BleError),
    Read(BleError),
    Payload(BleGattError),
    NoMatchingDevice,
}

impl fmt::Display for BleProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid BLE probe config: {reason}"),
            Self::Radio(context) => write!(f, "BLE probe radio error: {context}"),
            Self::Scan(error) => write!(f, "BLE scan failed: {error}"),
            Self::Connect(error) => write!(f, "BLE connect failed: {error}"),
            Self::Read(error) => write!(f, "BLE read failed: {error}"),
            Self::Payload(error) => write!(f, "BLE payload rejected: {error}"),
            Self::NoMatchingDevice => f.write_str("no BLE peripheral advertises the service"),
        }
    }
}

impl std::error::Error for BleProbeError {}

/// Step-driven BLE climate probe.
pub struct GuardBleProbe<R: BleCentral> {
    radio: R,
    config: BleProbeConfig,
    connected: Option<BleDeviceId>,
    state: BleProbeState,
    next_attempt_ms: u64,
    attempt: u32,
    health: BleProbeHealth,
}

impl<R: BleCentral> fmt::Debug for GuardBleProbe<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardBleProbe")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("next_attempt_ms", &self.next_attempt_ms)
            .field("attempt", &self.attempt)
            .field("health", &self.health)
            .finish()
    }
}

impl<R: BleCentral> GuardBleProbe<R> {
    /// Builds a probe from a radio and validated configuration.
    pub fn new(radio: R, config: BleProbeConfig) -> Result<Self, BleProbeError> {
        config.validate()?;
        Ok(Self {
            radio,
            config,
            connected: None,
            state: BleProbeState::Disconnected,
            next_attempt_ms: 0,
            attempt: 0,
            health: BleProbeHealth::default(),
        })
    }

    pub fn config(&self) -> &BleProbeConfig {
        &self.config
    }

    pub fn health(&self) -> &BleProbeHealth {
        &self.health
    }

    pub fn state(&self) -> &BleProbeState {
        &self.state
    }

    pub fn radio(&self) -> &R {
        &self.radio
    }

    pub fn radio_mut(&mut self) -> &mut R {
        &mut self.radio
    }

    /// One bounded scheduler step.
    ///
    /// Returns a reading when a peripheral was scanned/connected and both
    /// characteristics decoded successfully. A transport failure schedules the
    /// next attempt and returns the failure once; calls before the backoff
    /// deadline return `Ok(None)`.
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<BleProbeReading>, BleProbeError> {
        if let Some(device) = self.connected.clone() {
            return self.read_connected(device, now_ms).map(Some);
        }

        if let BleProbeState::Backoff { until_ms, .. } = self.state {
            if now_ms < until_ms {
                return Ok(None);
            }
        }

        let Some(device) = self.scan_and_connect(now_ms)? else {
            return Ok(None);
        };
        self.read_connected(device, now_ms).map(Some)
    }

    /// Drops the current link and schedules an immediate reconnect attempt.
    pub fn disconnect(&mut self, now_ms: u64) {
        if let Some(device) = self.connected.take() {
            let _ = self.radio.disconnect(&device);
            self.health.disconnects = self.health.disconnects.saturating_add(1);
        }
        self.attempt = 0;
        self.next_attempt_ms = now_ms;
        self.state = BleProbeState::Disconnected;
    }

    fn scan_and_connect(&mut self, now_ms: u64) -> Result<Option<BleDeviceId>, BleProbeError> {
        self.health.scan_attempts = self.health.scan_attempts.saturating_add(1);
        let filter = BleScanFilter {
            service: self.config.uuid_map.service(),
        };
        let devices = match self.radio.scan(filter, self.config.scan_timeout) {
            Ok(devices) => devices,
            Err(error) => {
                self.schedule_backoff(now_ms);
                return Err(BleProbeError::Scan(error));
            }
        };
        self.health.devices_seen = self
            .health
            .devices_seen
            .saturating_add(devices.len() as u64);

        let Some(device) = choose_device(devices, &self.config) else {
            self.schedule_backoff(now_ms);
            return Err(BleProbeError::NoMatchingDevice);
        };
        let device_id = device.id.clone();

        self.health.connect_attempts = self.health.connect_attempts.saturating_add(1);
        if let Err(error) = self.radio.connect(&device_id, self.config.connect_timeout) {
            self.schedule_backoff(now_ms);
            return Err(BleProbeError::Connect(error));
        }

        self.health.connects = self.health.connects.saturating_add(1);
        self.attempt = 0;
        self.next_attempt_ms = 0;
        self.connected = Some(device_id.clone());
        self.state = BleProbeState::Connected {
            device: device_id.clone(),
        };
        Ok(Some(device_id))
    }

    fn read_connected(
        &mut self,
        device: BleDeviceId,
        now_ms: u64,
    ) -> Result<BleProbeReading, BleProbeError> {
        self.health.read_attempts = self.health.read_attempts.saturating_add(1);
        let temperature = match self.radio.read(
            &device,
            self.config.uuid_map.temperature(),
            self.config.read_timeout,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.handle_transport_failure(now_ms);
                return Err(BleProbeError::Read(error));
            }
        };
        if temperature.len() > self.config.max_payload_bytes {
            self.health.read_failures = self.health.read_failures.saturating_add(1);
            self.health.malformed_payloads = self.health.malformed_payloads.saturating_add(1);
            return Err(BleProbeError::Payload(BleGattError::PayloadLength {
                field: "temperature",
                len: temperature.len(),
            }));
        }

        let humidity = match self.radio.read(
            &device,
            self.config.uuid_map.humidity(),
            self.config.read_timeout,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.handle_transport_failure(now_ms);
                return Err(BleProbeError::Read(error));
            }
        };
        if humidity.len() > self.config.max_payload_bytes {
            self.health.read_failures = self.health.read_failures.saturating_add(1);
            self.health.malformed_payloads = self.health.malformed_payloads.saturating_add(1);
            return Err(BleProbeError::Payload(BleGattError::PayloadLength {
                field: "humidity",
                len: humidity.len(),
            }));
        }

        // Both length caps are checked above; decode now classifies malformed
        // payloads and physically impossible values without reconnecting.
        match decode_climate(&temperature, &humidity) {
            Ok(climate) => {
                self.health.successful_reads = self.health.successful_reads.saturating_add(1);
                Ok(BleProbeReading { device, climate })
            }
            Err(error) => {
                self.health.read_failures = self.health.read_failures.saturating_add(1);
                self.health.malformed_payloads = self.health.malformed_payloads.saturating_add(1);
                Err(BleProbeError::Payload(error))
            }
        }
    }

    fn handle_transport_failure(&mut self, now_ms: u64) {
        self.health.read_failures = self.health.read_failures.saturating_add(1);
        if let Some(device) = self.connected.take() {
            let _ = self.radio.disconnect(&device);
            self.health.disconnects = self.health.disconnects.saturating_add(1);
        }
        self.schedule_backoff(now_ms);
    }

    fn schedule_backoff(&mut self, now_ms: u64) {
        let base_ms = self.config.backoff_base.as_millis() as u64;
        let max_ms = self.config.backoff_max.as_millis() as u64;
        let shift = self.attempt.min(MAX_BACKOFF_SHIFT);
        let delay_ms = base_ms.saturating_mul(1u64 << shift).min(max_ms);
        self.attempt = self.attempt.saturating_add(1);
        self.next_attempt_ms = now_ms.saturating_add(delay_ms);
        self.state = BleProbeState::Backoff {
            until_ms: self.next_attempt_ms,
            attempt: self.attempt,
        };
    }
}

fn choose_device(devices: Vec<BleDevice>, config: &BleProbeConfig) -> Option<BleDevice> {
    devices
        .into_iter()
        .take(config.max_devices)
        .filter(|device| device.advertisement.has_service(config.uuid_map.service()))
        .max_by_key(|device| device.rssi.unwrap_or(i16::MIN))
}

#[cfg(all(unix, feature = "ble-radio"))]
impl GuardBleProbe<tirbase_drivers::ble::BtleplugCentral> {
    /// Opens the native BLE stack and builds the production probe.
    pub fn open(config: BleProbeConfig) -> Result<Self, BleProbeError> {
        let radio = tirbase_drivers::ble::BtleplugCentral::new()
            .map_err(|error| BleProbeError::Radio(error.to_string()))?;
        Self::new(radio, config)
    }
}
