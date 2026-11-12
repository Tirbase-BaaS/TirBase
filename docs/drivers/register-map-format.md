# Modbus Register Map Format (CLAIM-34.8, PV-10.4, PV-10.7)

This document defines the Modbus register-map format used by TirBase reference
driver packs and parsed by `tirbase_drivers::ModbusRegisterMap` (`tirbase-drivers/src/register_map.rs`).

## Address notation

- `register` is the **0-based** Modbus data-model/register address as used in
 TirBase register-map files and by the reference codec/client helpers.
- Vendor datasheets may publish 0-based, 1-based, or 4xxxx/3xxxx notation; map
 files must normalize to the 0-based data address used in Modbus PDUs
 (e.g. holding register 40001/1-based 1 → `register = 0`).
- `quantity` is the number of 16-bit Modbus registers consumed by the value.

## Function-code mapping

| FC | Meaning | Read/write in map | Typical use |
|---:|---|---|---|
| 03 | Read Holding Registers | read | writable holding/process state |
| 04 | Read Input Registers | read | read-only sensor/input state |
| 06 | Write Single Register | write | single 16-bit writable register |
| 16 | Write Multiple Registers | write | multi-register/compound writable values |

`function` must be `3|4|6|16`. `writable=true` requires `function` `6` or `16`.

## Data types and signedness

| `data_type` | Registers | Signedness | Raw decode range |
|---|---:|---|---|
| `bool` / `boolean` | 1 | unsigned flag | 0/1 |
| `u16` / `uint16` | 1 | unsigned | 0..65535 |
| `i16` / `int16` | 1 | signed two's complement | -32768..32767 |
| `u32` / `uint32` | 2 | unsigned | 0..2^32-1 |
| `i32` / `int32` | 2 | signed two's complement | -2^31..2^31-1 |

## Scale/offset and fixed-point value

Decoded engineering value (integer fixed-point units at `scale_exponent`):

```text
scaled = raw * scale_mantissa * 10^scale_exponent + offset_mantissa * 10^offset_exponent
```

Parser helpers in `tirbase_drivers::ModbusRegisterMap`:
- `RegisterDef::decode_raw_i128` — decode raw register words to typed integer.
- `RegisterDef::decode_to_scaled_i64` — apply scale/offset.
- `RegisterDef::encode_raw_i128` / `encode_scaled_i64` — inverse path for writes.

## 32-bit word order

`word_order` applies to multi-register (`u32`/`i32`) values; single-register
values are normalized as `big_endian`:

| `word_order` | Wire register order (high..low bytes as stored) |
|---|---|
| `big_endian` | ABCD (most significant word first) |
| `little_endian` | DCBA |
| `mid_big` / `big_endian_word_swap` | BADC (word swap) |
| `mid_little` / `little_endian_word_swap` | CDAB |

## RTU framing, CRC, exceptions, timeouts

- **RTU request/response framing**: `[unit_id][PDU][CRC16_lo][CRC16_hi]`
 (`build_rtu_frame`/`parse_rtu_frame`, Modbus CRC-16 polynomial 0xA001).
- **TCP framing**: MBAP header + PDU (`build_tcp_request`/`parse_tcp_response`).
- **Exception responses**: PDU function code has bit 7 set (`fc | 0x80`) with an
 exception code byte; clients/parsers surface this as a typed driver error.
- **Timeouts**: real `ModbusTcpClient`/`ModbusRtuClient` accept I/O timeout
 (`Duration`) and return `DriverError::Timeout` on bounded read/write timeout;
 callers must not use unbounded blocking reads in production paths.
- **Unit/slave id**: TCP client uses `unit_id` in MBAP; RTU uses frame unit id
 and validates response unit id/FC.

## Document structure

```toml
device_class = "cold_room_modbus"

[[register]]
name = "temperature_c" # parameter name
register = 0 # 0-based data address
function = 4 # FC 3/4/6/16
data_type = "i16" # bool|u16|i16|u32|i32
scale_mantissa = 1 # fixed-point scale
scale_exponent = -1
offset_mantissa = 0
offset_exponent = 0
word_order = "big_endian"
unit_id = 1 # docs/unit-registry.md (1 = degC)
writable = false
quantity = 1 # number of 16-bit registers
```

## Example (cold room)

| Register (0-based) | FC | Type | Scale | Offset | Word order | Unit | Writable | Parameter |
|---:|---:|---|---:|---:|---|---:|:---:|---|
| 0 | 04 | i16 | 0.1 (`1e-1`) | 0 | big_endian | 1 (degC) | no | `temperature_c` |
| 1 | 03/06/16 | i16 | 0.1 (`1e-1`) | 0 | big_endian | 1 (degC) | yes | `setpoint_c` |
| 2 | 03/06 | u16 | 1 (`1e0`) | 0 | big_endian | 7 (boolean) | yes | `compressor_on` |

See `profiles/cold_room_modbus.register-map.toml` and
`docs/drivers/cold_room_modbus.md`.

## Validation

- `function` must be one of 3, 4, 6, 16.
- `name` is required and unique per map.
- `quantity >= 1` and must match `data_type` register width.
- `(register, function)` pairs must be unique.
- Unknown register fields are rejected.
- Parser errors are field-level (`register map field '<field>': ...`) and are
 suitable for operator diagnostics.

Fuzz: `tirbase-drivers/fuzz/fuzz_targets/register_map_parse.rs` with committed
seed corpus (`register_map_parse/`, `register_map/`). CI smoke build/run is
required (CLAIM-34.4/34.8).

