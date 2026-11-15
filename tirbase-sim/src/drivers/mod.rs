// SPDX-License-Identifier: AGPL-3.0-only

//! Simulated device servers/backends for reference drivers (PV-10.7, CLAIM-34.1/34.3).

pub mod bacnet_server;
pub mod ble;
pub mod cold_room;
pub mod modbus_server;
pub mod onewire;
pub mod simulators;

pub use bacnet_server::{
    BacnetSimDevice, BacnetSimServer, BacnetSimServerHandle, BacnetSimServerOptions,
};
pub use ble::SimBleGattPeripheral;
pub use cold_room::ColdRoomThermalSim;
pub use modbus_server::{ModbusServerHandle, ModbusSimServer};
pub use onewire::SimOneWireBus;
pub use simulators::{
    GateState, Sim4To20MaAdc, SimGateController, SimulatorDescriptor, SimulatorKind,
};
