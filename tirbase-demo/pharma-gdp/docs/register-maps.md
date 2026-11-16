# Pharma GDP register maps and units

Two controller families are supported. Both expose the same five parameter names
and unit ids as every profile in `profiles/`, so one profile per storage class
applies to either controller — only the transport mapping differs.

Scaling for every register:

```text
engineering_value = (raw * scale_mantissa * 10^scale_exponent)
                  + (offset_mantissa * 10^offset_exponent)
```

Units follow `docs/unit-registry.md`: `1 = degC`, `6 = percent`, `7 = boolean`.
Boolean registers accept `data_type = "bool"` (any non-zero raw value reads as 1)
or a `u16`/`i16` carrying 0/1.

## Reference controller (`register-maps/gdp_reference.register-map.toml`)

| Register name | Address | Function | Type | Scale | Unit | Direction |
| --- | --- | --- | --- | --- | --- | --- |
| `storage_temp_c` | 0 | 4 (input) | i16 | ×0.1 | degC | read |
| `relative_humidity_rh` | 1 | 4 (input) | u16 | ×1 | percent | read |
| `temperature_setpoint_c` | 10 | 6 (holding) | i16 | ×0.1 | degC | write |
| `humidity_setpoint_rh` | 11 | 6 (holding) | u16 | ×1 | percent | write |
| `door_open` | 20 | 6 (holding) | bool | — | boolean | write |
| `defrost_mode` | 21 | 6 (holding) | bool | — | boolean | write |
| `compressor_on` | 22 | 6 (holding) | bool | — | boolean | write |

## Legacy controller (`register-maps/gdp_legacy.register-map.toml`)

| Register name | Address | Function | Type | Word order | Scale | Unit | Direction |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `storage_temp_c` | 100 | 4 (input) | i16 | little | ×0.1 | degC | read |
| `relative_humidity_rh` | 101 | 4 (input) | u16 | little | ×1 | percent | read |
| `temperature_setpoint_c` | 110 | 6 (holding) | i16 | little | ×0.1 | degC | write |
| `humidity_setpoint_rh` | 111 | 6 (holding) | u16 | little | ×1 | percent | write |
| `door_open` | 120 | 6 (holding) | bool | little | — | boolean | write |
| `defrost_mode` | 121 | 6 (holding) | bool | little | — | boolean | write |
| `compressor_on` | 122 | 6 (holding) | bool | little | — | boolean | write |

## Binding rules

- A writable register's `name` and `unit_id` must match a parameter declared by
  every profile in the pack; `tests/pharma_gdp_pack_structure.rs` enforces this
  for both maps and all three storage classes.
- Register numbers are never part of a profile. Firmware that moves registers
  requires a new register map, not a re-signed profile.
- `storage_temp_c` and `relative_humidity_rh` are monitoring inputs: read-only in
  the map, and not commandable profile parameters. They are the values the
  excursion workflow samples for MKT; this pack does not write them.
- `temperature_setpoint_c` is the critical parameter (single-use challenge nonce
  plus Stage 15 quorum); the boolean outputs are interlocked by dwell and min-off
  in the profiles.
