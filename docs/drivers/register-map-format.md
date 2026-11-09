# Modbus Register Map Format (CLAIM-34.8, PV-10.4, PV-10.7)

This document defines the Modbus register-map format used by TirBase reference
driver packs and parsed by `tirbase_drivers::ModbusRegisterMap`.

## Document structure

```toml
device_class = "cold_room_modbus"

[[register]]
name = "temperature_c"      # parameter name
register = 0                # register address (0-based in data files)
function = 4                # FC: 3=read holding, 4=read input, 6=write single, 16=write multiple
data_type = "i16"           # u16|i16|u32|i32|bool
scale_mantissa = 1          # value = (raw * scale_mantissa * 10^scale_exponent) + (offset...)
scale_exponent = -1
offset_mantissa = 0
offset_exponent = 0
word_order = "big_endian"   # big_endian|little_endian|mid_big|mid_little
unit_id = 1                 # docs/unit-registry.md (1 = degC)
writable = false
quantity = 1                # number of 16-bit registers
```

## Example (cold room)

| Register | FC | Type | Scale | Offset | Word order | Unit | Writable | Parameter |
|---|---:|---|---:|---:|---|---:|:---:|---|
| 0 | 04 | INT16 | 0.1 (`1e-1`) | 0 | big_endian | 1 (degC) | no | `temperature_c` |
| 1 | 03/06/16 | INT16 | 0.1 (`1e-1`) | 0 | big_endian | 1 (degC) | yes | `setpoint_c` |
| 2 | 03/06 | UINT16 | 1 (`1e0`) | 0 | big_endian | 7 (boolean) | yes | `compressor_on` |

## Validation

- `function` must be one of 3, 4, 6, 16.
- `name` is required.
- `quantity >= 1`.
- Parser errors are field-level (`register map field '<field>': ...`) and are
  suitable for operator diagnostics.

A committed fuzz target (`tirbase-drivers/fuzz/fuzz_targets/register_map_parse.rs`)
and seed corpus exercise the parser on arbitrary inputs.
