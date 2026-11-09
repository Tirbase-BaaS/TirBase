# Cold Room Modbus Reference Driver Pack (CLAIM-34.7, PV-10)

Reference pack for the simulated cold-room controller backed by `tirbase-sim`.

## Transport

- Modbus TCP client driver (`tirbase_drivers::ModbusTcpCodec`) connects to the
  `tirbase-sim` Modbus TCP server (`tirbase_sim::ModbusSimServer`).
- Supported function codes: **FC 03** (read holding registers), **FC 04**
  (read input registers), **FC 06** (write single register), **FC 16** (write
  multiple registers).

## Register map

See [`register-map-format.md`](./register-map-format.md) and
`profiles/cold_room_modbus.register-map.toml`.

| Address | FC read | FC write | Type | Scale | Unit | Parameter | Writable |
|---:|---:|---:|---|---:|---:|---|:---:|
| 0 | 04 | — | INT16 | 0.1 °C | degC (1) | `temperature_c` | no |
| 1 | 03 | 06,16 | INT16 | 0.1 °C | degC (1) | `setpoint_c` | yes |
| 2 | 03 | 06 | UINT16 | 1 | boolean (7) | `compressor_on` | yes |

## Thermal model

The `tirbase-sim` cold-room model is a deterministic first-order thermal process:
`T_{k+1} = T_k + (step/tau) * (T_target - T_k) + bounded_seed_noise`. The same
seed produces bit-identical trajectories (integration test: 512 steps).
