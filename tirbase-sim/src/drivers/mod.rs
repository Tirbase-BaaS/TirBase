//! Simulated device servers/backends for reference drivers (PV-10.7, CLAIM-34.1/34.3).

pub mod cold_room;
pub mod modbus_server;

pub use cold_room::ColdRoomThermalSim;
pub use modbus_server::{ModbusServerHandle, ModbusSimServer};
