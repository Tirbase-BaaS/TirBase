# Buildings/BMS Register Map — BACnet Simulator Placeholder (CLAIM-48.4)

Device class: `buildings_bms` (HVAC/BMS controller)

This demo pack uses a **BACnet simulator placeholder**: no live BACnet stack is
required in CI. The envelope/profile below documents the guarded points that a
BACnet integration would expose.

| Name | Object (placeholder) | Type | Unit | Writable | Notes |
|---|---|---|---:|:---:|---|
| `zone_temp_c` | AI:1 | analog-input | degC (1), exp -1 | no | Measured zone temperature |
| `zone_temp_setpoint_c` | AV:1 | analog-value | degC (1), exp -1 | yes | Setpoint; envelope [16.0, 28.0] C, 0.2 C/s |
| `ahu_fan_enable` | BV:1 | binary-value | boolean (7) | yes | AHU fan enable; min-off 30s, safe default OFF |

Future work: replace placeholder with a BACnet/IP simulator driver when
available; guard semantics (S1/S2) are demonstrated via the envelope tests.
