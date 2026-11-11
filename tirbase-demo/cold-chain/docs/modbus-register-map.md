# Cold-Chain Modbus Register Map (CLAIM-47.1)

Device class: `cold_chain` (simulated cold-room controller)

| Name | Register | Function | Type | Unit | Scale | Writable | Notes |
|---|---:|---:|---|---:|---|:---:|---|
| `temperature_c` | 0 | 04 (Read Input Registers) | i16 | degC (1), exp -1 | 0.1 C/count | no | Current cabinet temperature |
| `temperature_setpoint_c` | 1 | 03/06 (Read/Write Holding) | i16 | degC (1), exp -1 | 0.1 C/count | yes | Guarded setpoint; envelope [-25.0, +8.0] C, 0.5 C/s rate limit |
| `compressor_on` | 2 | 01/05 (Read/Write Coil) | bool | boolean (7) | 1 | yes | Compressor state; min-off 60 s, safe default ON |

All writable registers are actuated only through the TirBase guard path
(`CommandGuard::admit()` -> `ActuationPermit` -> driver). Direct writes outside the
envelope are rejected (S1), cumulative drift is bounded (S2), and replays are
deduplicated (S3).
