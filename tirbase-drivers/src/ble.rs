// SPDX-License-Identifier: AGPL-3.0-only

//! BLE probe transport boundary and native radio adapter (CC-06).
//!
//! The driver defines the bounded [`BleCentral`] radio interface used by the
//! guard-owned probe and parses advertisements/GATT values through the
//! Apache-2.0 [`tirbase_driver_api::ble_gatt`] module. The production
//! [`BtleplugCentral`] adapter is compiled with the `ble-radio` feature and
//! uses the same `btleplug` stack as the mesh BLE bridge.
//!
//! Every operation takes an explicit timeout. The adapter opens no background
//! task of its own; each call is a bounded `block_on` around one radio
//! operation.

use std::fmt;
use std::time::Duration;

pub use tirbase_driver_api::ble_gatt::{
    decode_climate, decode_gatt_humidity, decode_gatt_temperature, encode_humidity_centi_percent,
    encode_temperature_centi_celsius, parse_advertisement, BleAdvertisement, BleClimateReading,
    BleGattError, BleGattUuidMap, BleUuid, CLIMATE_EXPONENT, ENVIRONMENTAL_SENSING_SERVICE,
    HUMIDITY_CHARACTERISTIC, TEMPERATURE_CHARACTERISTIC,
};

/// Stable identifier of a discovered peripheral.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BleDeviceId(String);

impl BleDeviceId {
    /// Validates a peripheral identifier.
    pub fn new(id: impl Into<String>) -> Result<Self, BleError> {
        let id = id.into();
        if id.is_empty() || id.len() > 128 {
            return Err(BleError::InvalidConfig("device id must be 1..=128 bytes"));
        }
        if id.chars().any(char::is_control) {
            return Err(BleError::InvalidConfig(
                "device id must not contain control characters",
            ));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BleDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One peripheral returned by a bounded scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleDevice {
    pub id: BleDeviceId,
    pub advertisement: BleAdvertisement,
    pub rssi: Option<i16>,
}

/// Scan filter accepted by a radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleScanFilter {
    pub service: BleUuid,
}

/// Bounded BLE central operations consumed by the guard-owned probe.
///
/// Implementations must honour the supplied timeout and must not block
/// indefinitely; they do not own reconnect policy, which lives in the guard.
pub trait BleCentral {
    /// Scans for at most `timeout`, returning at most a bounded device list.
    fn scan(
        &mut self,
        filter: BleScanFilter,
        timeout: Duration,
    ) -> Result<Vec<BleDevice>, BleError>;

    /// Connects to `device_id`, bounded by `timeout`.
    fn connect(&mut self, device_id: &BleDeviceId, timeout: Duration) -> Result<(), BleError>;

    /// Disconnects from `device_id`; idempotent when already disconnected.
    fn disconnect(&mut self, device_id: &BleDeviceId) -> Result<(), BleError>;

    /// Reads one characteristic, bounded by `timeout`.
    fn read(
        &mut self,
        device_id: &BleDeviceId,
        characteristic: BleUuid,
        timeout: Duration,
    ) -> Result<Vec<u8>, BleError>;

    /// Whether the peripheral is currently connected.
    fn is_connected(&mut self, device_id: &BleDeviceId) -> Result<bool, BleError>;
}

/// BLE transport error. Messages never contain pairing credentials or payload
/// bytes; callers may log the display text safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleError {
    InvalidConfig(&'static str),
    NoAdapter,
    Timeout { operation: &'static str },
    DeviceNotFound,
    NotConnected,
    Radio(String),
    Payload(BleGattError),
}

impl fmt::Display for BleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid BLE configuration: {reason}"),
            Self::NoAdapter => f.write_str("no BLE adapter available"),
            Self::Timeout { operation } => write!(f, "BLE {operation} timed out"),
            Self::DeviceNotFound => f.write_str("BLE peripheral not found"),
            Self::NotConnected => f.write_str("BLE peripheral is not connected"),
            Self::Radio(context) => write!(f, "BLE radio error: {context}"),
            Self::Payload(error) => write!(f, "BLE payload rejected: {error}"),
        }
    }
}

impl std::error::Error for BleError {}

impl From<BleGattError> for BleError {
    fn from(error: BleGattError) -> Self {
        Self::Payload(error)
    }
}

// ─── Native btleplug adapter ────────────────────────────────────────────────

#[cfg(feature = "ble-radio")]
mod radio {
    use super::*;
    use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use std::collections::BTreeMap;
    use tokio::time::timeout as async_timeout;

    const SCAN_POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Cross-platform BLE central backed by the native `btleplug` stack.
    pub struct BtleplugCentral {
        runtime: tokio::runtime::Runtime,
        adapter: Adapter,
        discovered: BTreeMap<String, Peripheral>,
        connected: Option<(String, Peripheral)>,
    }

    impl fmt::Debug for BtleplugCentral {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("BtleplugCentral")
                .field("discovered", &self.discovered.len())
                .field("connected", &self.connected.as_ref().map(|(id, _)| id))
                .finish()
        }
    }

    impl BtleplugCentral {
        /// Opens the first available native BLE adapter.
        pub fn new() -> Result<Self, BleError> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| BleError::Radio("could not create BLE runtime".into()))?;
            let adapter = runtime.block_on(async {
                let manager = Manager::new()
                    .await
                    .map_err(|error| BleError::Radio(format!("manager init failed: {error}")))?;
                let adapters = manager.adapters().await.map_err(|error| {
                    BleError::Radio(format!("adapter enumeration failed: {error}"))
                })?;
                adapters.into_iter().next().ok_or(BleError::NoAdapter)
            })?;
            Ok(Self {
                runtime,
                adapter,
                discovered: BTreeMap::new(),
                connected: None,
            })
        }

        fn peripheral(&self, device_id: &BleDeviceId) -> Result<Peripheral, BleError> {
            if let Some((id, peripheral)) = &self.connected {
                if id == device_id.as_str() {
                    return Ok(peripheral.clone());
                }
            }
            self.discovered
                .get(device_id.as_str())
                .cloned()
                .ok_or(BleError::DeviceNotFound)
        }
    }

    impl BleCentral for BtleplugCentral {
        fn scan(
            &mut self,
            filter: BleScanFilter,
            scan_timeout: Duration,
        ) -> Result<Vec<BleDevice>, BleError> {
            let adapter = self.adapter.clone();
            let scan_adapter = adapter.clone();
            let (devices, discovered) = self.runtime.block_on(async move {
                scan_adapter
                    .start_scan(ScanFilter::default())
                    .await
                    .map_err(|error| BleError::Radio(format!("scan start failed: {error}")))?;

                let scan = async_timeout(scan_timeout, async move {
                    let mut found = Vec::new();
                    let mut discovered = BTreeMap::new();
                    loop {
                        let peripherals = scan_adapter.peripherals().await.map_err(|error| {
                            BleError::Radio(format!("peripheral enumeration failed: {error}"))
                        })?;
                        for peripheral in peripherals {
                            let Ok(device_id) = BleDeviceId::new(peripheral.id().to_string())
                            else {
                                continue;
                            };
                            let Some(properties) =
                                peripheral.properties().await.map_err(|error| {
                                    BleError::Radio(format!(
                                        "peripheral properties failed: {error}"
                                    ))
                                })?
                            else {
                                continue;
                            };
                            let services = properties
                                .services
                                .iter()
                                .map(|uuid| BleUuid::from_bytes(*uuid.as_bytes()));
                            let Ok(advertisement) =
                                BleAdvertisement::new(services, properties.local_name)
                            else {
                                continue;
                            };
                            if !advertisement.has_service(filter.service) {
                                continue;
                            }
                            if !found
                                .iter()
                                .any(|device: &BleDevice| device.id == device_id)
                            {
                                discovered.insert(device_id.as_str().to_string(), peripheral);
                                found.push(BleDevice {
                                    id: device_id,
                                    advertisement,
                                    rssi: properties.rssi,
                                });
                            }
                        }
                        if !found.is_empty() {
                            break;
                        }
                        tokio::time::sleep(SCAN_POLL_INTERVAL).await;
                    }
                    Ok::<_, BleError>((found, discovered))
                })
                .await;

                let _ = adapter.stop_scan().await;
                match scan {
                    Ok(result) => result,
                    Err(_) => Err(BleError::Timeout { operation: "scan" }),
                }
            })?;
            self.discovered.extend(discovered);
            Ok(devices)
        }

        fn connect(
            &mut self,
            device_id: &BleDeviceId,
            connect_timeout: Duration,
        ) -> Result<(), BleError> {
            let peripheral = self.peripheral(device_id)?;
            self.runtime.block_on(async {
                async_timeout(connect_timeout, peripheral.connect())
                    .await
                    .map_err(|_| BleError::Timeout {
                        operation: "connect",
                    })?
                    .map_err(|error| BleError::Radio(format!("connect failed: {error}")))?;
                async_timeout(connect_timeout, peripheral.discover_services())
                    .await
                    .map_err(|_| BleError::Timeout {
                        operation: "service discovery",
                    })?
                    .map_err(|error| BleError::Radio(format!("service discovery failed: {error}")))
            })?;
            self.connected = Some((device_id.as_str().to_string(), peripheral));
            Ok(())
        }

        fn disconnect(&mut self, device_id: &BleDeviceId) -> Result<(), BleError> {
            let Some((id, peripheral)) = self.connected.take() else {
                return Ok(());
            };
            if id != device_id.as_str() {
                self.connected = Some((id, peripheral));
                return Ok(());
            }
            self.runtime
                .block_on(peripheral.disconnect())
                .map_err(|error| BleError::Radio(format!("disconnect failed: {error}")))
        }

        fn read(
            &mut self,
            device_id: &BleDeviceId,
            characteristic: BleUuid,
            read_timeout: Duration,
        ) -> Result<Vec<u8>, BleError> {
            let peripheral = self.peripheral(device_id)?;
            self.runtime.block_on(async {
                if !peripheral
                    .is_connected()
                    .await
                    .map_err(|error| BleError::Radio(format!("link state failed: {error}")))?
                {
                    return Err(BleError::NotConnected);
                }
                let characteristic = peripheral
                    .characteristics()
                    .into_iter()
                    .find(|candidate| candidate.uuid.as_bytes() == characteristic.as_bytes())
                    .ok_or_else(|| {
                        BleError::Radio("characteristic is not present on the peripheral".into())
                    })?;
                async_timeout(read_timeout, peripheral.read(&characteristic))
                    .await
                    .map_err(|_| BleError::Timeout { operation: "read" })?
                    .map_err(|error| BleError::Radio(format!("read failed: {error}")))
            })
        }

        fn is_connected(&mut self, device_id: &BleDeviceId) -> Result<bool, BleError> {
            let peripheral = self.peripheral(device_id)?;
            self.runtime
                .block_on(peripheral.is_connected())
                .map_err(|error| BleError::Radio(format!("link state failed: {error}")))
        }
    }
}

#[cfg(feature = "ble-radio")]
pub use radio::BtleplugCentral;
