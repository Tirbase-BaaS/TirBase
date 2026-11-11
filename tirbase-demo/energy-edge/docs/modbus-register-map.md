# Energy Edge Modbus Register Map (CLAIM-48.1)

Device class: `energy_edge` (inverter/battery controller)

| Name | Register | Function | Type | Unit | Scale | Writable | Notes |
|---|---:|---:|---|---:|---|:---:|---|
| `grid_power_kw` | 0 | 04 (Read Input) | i16 | kW (5), exp -1 | 0.1 kW/count | no | Measured grid exchange power |
| `battery_soc_pct` | 1 | 04 (Read Input) | u16 | % (6), exp 0 | 1 %/count | no | Current battery state of charge |
| `inverter_power_kw` | 2 | 03/06 (Read/Write Holding) | i16 | kW (5), exp -1 | 0.1 kW/count | yes | Commanded inverter power; envelope [-100.0, +100.0] kW, 2.0 kW/s |
| `battery_soc_target_pct` | 3 | 03/06 (Read/Write Holding) | u16 | % (6), exp 0 | 1 %/count | yes | Target SOC; envelope [20, 95] %, 5 %/s |

All writable registers are actuated only through the TirBase guard path.
