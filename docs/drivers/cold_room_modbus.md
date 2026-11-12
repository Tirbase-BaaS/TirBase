# Cold Room Modbus Reference Driver Pack (CLAIM-34.7, PV-10)

Reference pack for the simulated cold-room controller backed by `tirbase-sim`/`tirbase-drivers` canonical thermal model.

## Transport

- **Modbus TCP client**: `tirbase_drivers::ModbusTcpClient` (real `Read+Write` client, bounded timeouts, tx-id/unit-id matching) connects to `tirbase_sim::ModbusSimServer`.
- **Modbus RTU client**: `tirbase_drivers::ModbusRtuClient` over generic `Read+Write` with RTU request/response framing and CRC-16 validation.
- **Physical device fd ownership (34.8/S35)**: `tirbase-guard::DeviceTransport` owns the TCP socket / serial fd; guard passes fd to driver child via `SCM_RIGHTS` (`tirbase-guard/tests/driver_isolation.rs::test_scm_rights_blocked` proves real child receipt and Linux sandbox blocking of post-sandbox `SCM_RIGHTS`).
- Gateway production smoke path: `CARGO_BIN_EXE_tirbase-gateway modbus-smoke ...` (`tirbase-gateway/src/reference_cli.rs`, `tests/reference_profile_binary.rs`).

## Supported function codes

| FC | Name | Cold-room use | Notes |
|---:|---|---|---|
| 03 | Read Holding Registers | `setpoint_c`, `compressor_on` read | response: byte count + register words |
| 04 | Read Input Registers | `temperature_c` | read-only input register |
| 06 | Write Single Register | `setpoint_c` or `compressor_on` single write | response echoes address/value |
| 16 | Write Multiple Registers | `setpoint_c` multi-write path | response echoes address/quantity |

Exception responses (`fc | 0x80`, exception code) are surfaced as typed driver errors.

## RTU framing, CRC, timeouts

- **RTU frame**: `[unit_id][PDU][CRC16_lo][CRC16_hi]` (Modbus CRC-16, 0xA001 init).
- **TCP frame**: MBAP `[tx_id][proto=0][length][unit_id]` + PDU.
- **Timeouts**: clients take bounded `io_timeout`/connect timeout and return `DriverError::Timeout` (no unbounded blocking read in production client path).
- **Address notation**: register map uses 0-based data addresses; see `docs/drivers/register-map-format.md`.

## Register map

See [`register-map-format.md`](./register-map-format.md) and `profiles/cold_room_modbus.register-map.toml`.

| Address (0-based) | FC read | FC write | Type | Signedness | Scale | Offset | Word order | Unit | Parameter | Writable |
|---:|---:|---:|---|---|---:|---:|---|---:|---|:---:|
| 0 | 04 | — | i16 | signed | 0.1 °C (`1e-1`) | 0 | big_endian | degC (1) | `temperature_c` | no |
| 1 | 03 | 06,16 | i16 | signed | 0.1 °C (`1e-1`) | 0 | big_endian | degC (1) | `setpoint_c` | yes |
| 2 | 03 | 06 | u16 | unsigned | 1 (`1e0`) | 0 | big_endian | boolean (7) | `compressor_on` | yes |

## Thermal model

The canonical cold-room model is `tirbase_drivers::cold_room_sim::FirstOrderThermalModel` (integer millidegree state). `tirbase-sim` wraps this model; `tirbase-sim/tests/claim_34_3.rs` proves bit-identical output across crates/seeds (512 steps). Gateway `cold-room-sim` uses `ColdRoomSimDriver` over the same canonical model.

## Tests/evidence

- Modbus codec/client: `tirbase-drivers/tests/modbus_client.rs`, `reference_drivers.rs`; gateway binary smoke: `tirbase-gateway/tests/reference_profile_binary.rs::claim_34_1_gateway_binary_modbus_smoke_against_sim`.
- Register-map parser/fuzz: `tirbase-drivers/src/register_map.rs`, `tirbase-drivers/fuzz/fuzz_targets/register_map_parse.rs`.
- S35 fd isolation: `tirbase-guard/tests/driver_isolation.rs::test_scm_rights_blocked`, `tirbase-guard/tests/device_transport_s35.rs`.

