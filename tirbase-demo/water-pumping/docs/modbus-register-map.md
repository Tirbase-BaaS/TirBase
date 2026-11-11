# Water/Pumping Station Modbus Register Map (CLAIM-48.2)

Device class: `water_pumping` (pump controller, Modbus simulator)

| Name | Register | Function | Type | Unit | Scale | Writable | Notes |
|---|---:|---:|---|---:|---|:---:|---|
| `flow_rate_m3h` | 0 | 04 (Read Input) | u16 | m3/h (9), exp -1 | 0.1 m3/h/count | no | Measured discharge flow |
| `pump_speed_rpm` | 1 | 03/06 (Read/Write Holding) | u16 | rpm (3), exp 0 | 1 rpm/count | yes | Pump speed setpoint; envelope [0, 3000] rpm, 50 rpm/s, min-off 30s |
| `discharge_pressure_kpa` | 2 | 03/06 (Read/Write Holding) | u16 | kPa (8), exp 0 | 1 kPa/count | yes | Pressure target; envelope [50, 800] kPa, 10 kPa/s |
| `pump_run` | 3 | 01/05 (Coil) | bool | boolean (7) | 1 | yes | Pump enable (derived) |

Simulator: `tirbase-demo/water-pumping/sim/config.toml` drives a deterministic Modbus register model for CI.
