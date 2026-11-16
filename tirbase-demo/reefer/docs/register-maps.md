# Reefer register maps and units

Two transport controllers are supported. Both expose the same six parameter
names and unit ids as `profiles/reefer.toml`, so the same profile applies to
either controller — only the transport mapping differs.

Scaling for every register:

```text
engineering_value = (raw * scale_mantissa * 10^scale_exponent)
                  + (offset_mantissa * 10^offset_exponent)
```

Units follow `docs/unit-registry.md`: `1 = degC`, `7 = boolean`. Boolean
registers accept `data_type = "bool"` (any non-zero raw value reads as 1) or a
`u16`/`i16` carrying 0/1.

## Reference controller (`register-maps/reefer_reference.register-map.toml`)

| Parameter | Register | Function | Type | Scale | Unit | Direction |
| --- | --- | --- | --- | --- | --- | --- |
| `container_temp_c` | 0 | 4 (input) | i16 | ×0.1 | degC | read |
| `ambient_c` | 1 | 6 (holding) | i16 | ×0.1 | degC | write |
| `temperature_setpoint_c` | 2 | 6 (holding) | i16 | ×0.1 | degC | write |
| `door_open` | 12 | 6 (holding) | bool | — | boolean | write |
| `power_state` | 13 | 6 (holding) | bool | — | boolean | write |
| `defrost_mode` | 14 | 6 (holding) | bool | — | boolean | write |
| `compressor_on` | 15 | 6 (holding) | bool | — | boolean | write |

`container_temp_c` is the cargo-space sensor: read-only in the map, and not a
commandable profile parameter. `ambient_c` is written by the gateway's probe
poller, which is why it is a holding register and therefore defended by the
ambient envelope and drift window.

## Legacy controller (`register-maps/reefer_legacy.register-map.toml`)

| Parameter | Register | Function | Type | Word order | Scale | Unit | Direction |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `container_temp_c` | 100 | 4 (input) | i16 | big | ×0.1 | degC | read |
| `ambient_c` | 101 | 6 (holding) | i16 | big | ×0.1 | degC | write |
| `temperature_setpoint_c` | 102 | 6 (holding) | i16 | big | ×0.1 | degC | write |
| `door_open` | 110 | 6 (holding) | bool | little | — | boolean | write |
| `power_state` | 111 | 6 (holding) | bool | little | — | boolean | write |
| `defrost_mode` | 112 | 6 (holding) | bool | little | — | boolean | write |
| `compressor_on` | 113 | 6 (holding) | bool | little | — | boolean | write |

## Binding rules

- A writable register's `name` and `unit_id` must match a parameter declared by
  the pack profile; `tests/reefer_pack_structure.rs` enforces this for both
  maps.
- Register numbers are never part of the profile. Changing controller firmware
  that moves registers requires a new register map, not a re-signed profile.
- Scale exponents must reproduce the profile's canonical `-1` (degC) encoding;
  a map with a different scale needs a matching profile revision.
- `power_state`, `door_open`, and `compressor_on` are interlock outputs. The
  dwell/min-off limits in the profile protect the hardware those bits drive
  (mains contactor, door, compressor), so their register direction must stay
  writable.
