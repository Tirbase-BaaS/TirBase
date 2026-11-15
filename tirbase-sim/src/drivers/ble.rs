// SPDX-License-Identifier: AGPL-3.0-only

//! Simulated BLE GATT peripheral for the CC-06 probe (F-13).
//!
//! [`SimBleGattPeripheral`] implements the driver's [`BleCentral`] boundary
//! with an in-memory temperature/humidity GATT table. No radio, threads, or
//! sleeps are involved: the probe's timeout arguments are recorded so tests can
//! assert they are the configured bounds.

use std::time::Duration;

use tirbase_drivers::ble::{
    encode_humidity_centi_percent, encode_temperature_centi_celsius, BleAdvertisement, BleCentral,
    BleDevice, BleDeviceId, BleError, BleGattUuidMap, BleScanFilter, BleUuid,
};

const DEVICE_ID: &str = "sim-th-01";

/// Deterministic GATT peripheral implementing the BLE central boundary.
#[derive(Debug, Clone)]
pub struct SimBleGattPeripheral {
    uuid_map: BleGattUuidMap,
    local_name: String,
    present: bool,
    connected: bool,
    drop_on_next_read: bool,
    malformed_temperature: bool,
    malformed_humidity: bool,
    temperature_centi: i16,
    humidity_centi: u16,
    connect_failures_remaining: u32,
    scan_calls: u64,
    connect_calls: u64,
    read_calls: u64,
    disconnect_calls: u64,
    last_scan_timeout: Option<Duration>,
    last_connect_timeout: Option<Duration>,
    last_read_timeout: Option<Duration>,
}

impl Default for SimBleGattPeripheral {
    fn default() -> Self {
        Self {
            uuid_map: BleGattUuidMap::standard(),
            local_name: "Sim TH".to_string(),
            present: true,
            connected: false,
            drop_on_next_read: false,
            malformed_temperature: false,
            malformed_humidity: false,
            temperature_centi: 2_150,
            humidity_centi: 4_500,
            connect_failures_remaining: 0,
            scan_calls: 0,
            connect_calls: 0,
            read_calls: 0,
            disconnect_calls: 0,
            last_scan_timeout: None,
            last_connect_timeout: None,
            last_read_timeout: None,
        }
    }
}

impl SimBleGattPeripheral {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the standard UUID map with a custom profile.
    pub fn with_uuid_map(mut self, uuid_map: BleGattUuidMap) -> Self {
        self.uuid_map = uuid_map;
        self
    }

    pub fn uuid_map(&self) -> BleGattUuidMap {
        self.uuid_map
    }

    pub fn set_present(&mut self, present: bool) {
        self.present = present;
        if !present {
            self.connected = false;
        }
    }

    pub fn set_local_name(&mut self, name: impl Into<String>) {
        self.local_name = name.into();
    }

    /// Simulates a physical link drop on the next read.
    pub fn set_drop_on_next_read(&mut self, drop: bool) {
        self.drop_on_next_read = drop;
    }

    /// Drops the current link immediately (the next read reports no connection).
    pub fn drop_link(&mut self) {
        self.connected = false;
    }

    pub fn set_temperature_centi_celsius(&mut self, value: i16) {
        self.temperature_centi = value;
    }

    pub fn set_humidity_centi_percent(&mut self, value: u16) {
        self.humidity_centi = value;
    }

    pub fn set_malformed_temperature(&mut self, malformed: bool) {
        self.malformed_temperature = malformed;
    }

    pub fn set_malformed_humidity(&mut self, malformed: bool) {
        self.malformed_humidity = malformed;
    }

    /// Fails the next `count` connect attempts, then succeeds.
    pub fn fail_next_connects(&mut self, count: u32) {
        self.connect_failures_remaining = count;
    }

    pub fn scan_calls(&self) -> u64 {
        self.scan_calls
    }

    pub fn connect_calls(&self) -> u64 {
        self.connect_calls
    }

    pub fn read_calls(&self) -> u64 {
        self.read_calls
    }

    pub fn disconnect_calls(&self) -> u64 {
        self.disconnect_calls
    }

    pub fn last_scan_timeout(&self) -> Option<Duration> {
        self.last_scan_timeout
    }

    pub fn last_connect_timeout(&self) -> Option<Duration> {
        self.last_connect_timeout
    }

    pub fn last_read_timeout(&self) -> Option<Duration> {
        self.last_read_timeout
    }

    fn device_id(&self) -> BleDeviceId {
        BleDeviceId::new(DEVICE_ID).expect("static simulator device id")
    }
}

impl BleCentral for SimBleGattPeripheral {
    fn scan(
        &mut self,
        filter: BleScanFilter,
        timeout: Duration,
    ) -> Result<Vec<BleDevice>, BleError> {
        self.scan_calls = self.scan_calls.saturating_add(1);
        self.last_scan_timeout = Some(timeout);
        if timeout.is_zero() {
            return Err(BleError::Timeout { operation: "scan" });
        }
        if !self.present || filter.service != self.uuid_map.service() {
            return Ok(Vec::new());
        }
        let advertisement =
            BleAdvertisement::new([self.uuid_map.service()], Some(self.local_name.clone()))?;
        Ok(vec![BleDevice {
            id: self.device_id(),
            advertisement,
            rssi: Some(-42),
        }])
    }

    fn connect(&mut self, device_id: &BleDeviceId, timeout: Duration) -> Result<(), BleError> {
        self.connect_calls = self.connect_calls.saturating_add(1);
        self.last_connect_timeout = Some(timeout);
        if timeout.is_zero() {
            return Err(BleError::Timeout {
                operation: "connect",
            });
        }
        if !self.present || device_id.as_str() != DEVICE_ID {
            return Err(BleError::DeviceNotFound);
        }
        if self.connect_failures_remaining > 0 {
            self.connect_failures_remaining -= 1;
            return Err(BleError::Radio("simulated connect failure".to_string()));
        }
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self, _device_id: &BleDeviceId) -> Result<(), BleError> {
        self.disconnect_calls = self.disconnect_calls.saturating_add(1);
        self.connected = false;
        Ok(())
    }

    fn read(
        &mut self,
        _device_id: &BleDeviceId,
        characteristic: BleUuid,
        timeout: Duration,
    ) -> Result<Vec<u8>, BleError> {
        self.read_calls = self.read_calls.saturating_add(1);
        self.last_read_timeout = Some(timeout);
        if timeout.is_zero() {
            return Err(BleError::Timeout { operation: "read" });
        }
        if self.drop_on_next_read {
            self.drop_on_next_read = false;
            self.connected = false;
            return Err(BleError::NotConnected);
        }
        if !self.connected {
            return Err(BleError::NotConnected);
        }
        if characteristic == self.uuid_map.temperature() {
            if self.malformed_temperature {
                return Ok(vec![0x01]);
            }
            Ok(encode_temperature_centi_celsius(self.temperature_centi).to_vec())
        } else if characteristic == self.uuid_map.humidity() {
            if self.malformed_humidity {
                return Ok(vec![0x01, 0x02, 0x03]);
            }
            Ok(encode_humidity_centi_percent(self.humidity_centi).to_vec())
        } else {
            Err(BleError::Radio(
                "characteristic is not present on the simulated peripheral".to_string(),
            ))
        }
    }

    fn is_connected(&mut self, _device_id: &BleDeviceId) -> Result<bool, BleError> {
        Ok(self.connected)
    }
}
