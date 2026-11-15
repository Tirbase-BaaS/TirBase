# Modbus Thermostat Profiles (CC-03)

Reusable thermostat control on the existing Modbus TCP/RTU clients. Profiles
map six semantic fields — current temperature, setpoint, mode, fan, alarm, and
fault — onto a validated register map. Both bundled maps are **original
layouts**, not copies of vendor manuals.

- **Pure profiles (Apache-2.0):** `tirbase_driver_api::thermostat`
  (`ThermostatProfile`, field/mode/fan types, decode/encode helpers).
- **Runtime (AGPL-3.0-only):** `tirbase_drivers::thermostat`
  (`ThermostatDevice`, `ModbusClient`).
- **Profile files:** `profiles/thermostat_generic_a.register-map.toml`,
  `profiles/thermostat_generic_b.register-map.toml`.

## Profile A — `generic_thermostat_a` (unit 1)

| Field | Register | FC read/write | Type | Scale | Access |
|---|---:|---|---|---:|---|
| `current_temperature` | input 0 | 04 | i16 | 0.1 °C | read |
| `alarm` | input 1 | 04 | u16 | raw | read |
| `fault` | input 2 | 04 | u16 | raw | read |
| `setpoint` | holding 0 | 03 / 06 | i16 | 0.1 °C | write |
| `mode` | holding 1 | 03 / 06 | u16 | raw | write |
| `fan` | holding 2 | 03 / 06 | u16 | raw | write |

## Profile B — `generic_thermostat_b` (unit 2)

| Field | Register | FC read/write | Type | Scale | Access |
|---|---:|---|---|---:|---|
| `current_temperature` | input 100 | 04 | i16 | 0.1 °C | read |
| `alarm` | input 101 | 04 | u16 | raw | read |
| `fault` | input 102 | 04 | u16 | raw | read |
| `setpoint` | holding 200 | 03 / 16 | i16 | 0.1 °C | write |
| `mode` | holding 201 | 03 / 06 | u16 | raw | write |
| `fan` | holding 202 | 03 / 06 | u16 | raw | write |

Writable holding registers are read back with FC 03. Setpoint uses FC 06 in
profile A and FC 16 in profile B, so both write paths are exercised.

## Mode and fan codes

| Mode | Value | Fan | Value |
|---|---:|---|---:|
| Off | 0 | Off | 0 |
| Heat | 1 | Low | 1 |
| Cool | 2 | Medium | 2 |
| Auto | 3 | High | 3 |

Alarm and fault registers are raw `u16`; bit assignments remain
application-defined. Unknown mode/fan values are typed errors.

## Install and use

```rust
use std::time::Duration;
use tirbase_drivers::modbus::ModbusTcpClient;
use tirbase_drivers::thermostat::{
    generic_thermostat_a, ThermostatDevice, ThermostatFan, ThermostatMode,
};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

let profile = generic_thermostat_a()?;
let client = ModbusTcpClient::connect(
    "127.0.0.1:502",
    profile.unit_id().unwrap(),
    Duration::from_secs(2),
    clock,
)?;
let mut thermostat = ThermostatDevice::install(client, profile)?
    .with_retries(1); // retry bounded timeouts

let reading = thermostat.read_all()?;
thermostat.write_setpoint(&FixedPointValue::new(195, -1, UNIT_DEG_C))?;
thermostat.write_mode(ThermostatMode::Auto)?;
thermostat.write_fan(ThermostatFan::High)?;
```

`ThermostatProfile::parse` accepts the documented register-map subset, and
`ThermostatProfile::new` validates that all six fields exist, have the right
read/write function, are `i16`/`u16`, are single-register, and share one unit
id. `ThermostatDevice::install` revalidates before doing I/O.

## Exceptions, timeouts, retries

- Exception PDUs (`FC | 0x80`, exception code) surface as
  `DriverError::Exception { function_code, exception_code }` on both TCP and
  RTU. RTU reads the response header first, so a 5-byte exception frame is
  decoded instead of waiting for a success-length frame.
- Reads and writes are bounded by the client's `io_timeout` and the injected
  monotonic clock; expiry returns `DriverError::Timeout`.
- `ThermostatDevice::with_retries(n)` retries **only** bounded timeouts, up to
  `n` extra attempts. Default is 0. Exceptions, malformed frames, and
  unsupported parameters are never retried.

## Tests/evidence

- `tirbase-driver-api/src/thermostat.rs` — built-in profile validation,
  mode/fan round-trips.
- `tirbase-drivers/tests/thermostat.rs` — TOML/built-in equivalence; profile A
  and B install, read all fields, and write setpoint/mode/fan against
  `tirbase_sim::ModbusSimServer` over TCP; RTU framing with profile B; typed TCP
  and RTU exceptions; bounded TCP timeout; timeout retry/no-retry behavior;
  missing-field validation.
- Cold-room regression: `tirbase-drivers/tests/reference_drivers.rs`,
  `tirbase-drivers/tests/modbus_client.rs` (FC 03/04/06/16, RTU/TCP, timeout).

## Limits

- One unit id per installed profile; multi-unit aggregation is out of scope.
- Coils, alarm bit definitions, schedules, and PID control are not modelled.
- Temperature scaling is fixed to the profile's register exponent; values with
  finer precision are truncated during encoding.
- RTU serial-port setup remains the guard-owned `open_modbus_rtu` path.
