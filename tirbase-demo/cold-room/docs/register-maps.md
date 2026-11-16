# Cold-room register maps and units

Two controllers are supported. Both expose the same five parameter names and
unit ids as `profiles/cold_room.toml`, so the same profile applies to either
controller — only the transport mapping differs.

Scaling for every register:

```text
engineering_value = (raw * scale_mantissa * 10^scale_exponent)
                  + (offset_mantissa * 10^offset_exponent)
```

Units follow `docs/unit-registry.md`: `1 = degC`, `7 = boolean`. Boolean
registers accept `data_type = "bool"` (any non-zero raw value reads as 1) or a
`u16`/`i16` carrying 0/1.

## Reference controller (`register-maps/cold_room_reference.register-map.toml`)

| Parameter | Register | Function | Type | Scale | Unit | Direction |
| --- | --- | --- | --- | --- | --- | --- |
| `temperature_c` | 0 | 4 (input) | i16 | ×0.1 | degC | read |
| `temperature_setpoint_c` | 1 | 6 (holding) | i16 | ×0.1 | degC | write |
| `door_open` | 2 | 6 (holding) | bool | — | boolean | write |
| `defrost_mode` | 3 | 6 (holding) | bool | — | boolean | write |
| `defrost_termination_c` | 4 | 6 (holding) | i16 | ×0.1 | degC | write |
| `compressor_on` | 5 | 6 (holding) | bool | — | boolean | write |

`temperature_c` is a sensor reading: it is read-only in the map and is not a
commandable profile parameter. `door_open` is the door interlock output, so the
dwell and min-off limits apply to the command path that drives it. Both maps use
the same `temperature_c` name so operators can monitor the room either way.

## Legacy controller (`register-maps/cold_room_legacy.register-map.toml`)

| Parameter | Register | Function | Type | Scale | Unit | Direction |
| --- | --- | --- | --- | --- | --- | --- |
| `temperature_c` | 10–11 | 4 (input) | i32, mid-big word order | ×0.1 | degC | read |
| `temperature_setpoint_c` | 20 | 16 (multiple holding) | i16 | ×0.1 | degC | write |
| `door_open` | 12 | 6 (holding) | bool | — | boolean | write |
| `defrost_mode` | 30 | 6 (holding) | u16 (0/1) | — | boolean | write |
| `defrost_termination_c` | 31 | 6 (holding) | i16 | ×0.1 | degC | write |
| `compressor_on` | 32 | 6 (holding) | u16 (0/1) | — | boolean | write |

## Binding rules

- A writable register's `name` and `unit_id` must match a parameter declared by
  the pack profile; `tests/cold_room_pack_structure.rs` enforces this for both
  maps.
- Register numbers are never part of the profile. Changing controller firmware
  that moves registers requires a new register map, not a re-signed profile.
- Scale exponents must reproduce the profile's canonical `-1` (degC) encoding;
  a map with a different scale needs a matching profile revision.
