# BLE Probes (CC-06)

Guard-owned BLE scanning, connection, and GATT reads for battery-powered
temperature/humidity probes. The probe reconnects with bounded exponential
backoff after a link loss and never runs an unbounded task: the caller supplies
a monotonic timestamp and drives one bounded step at a time.

| Layer | Crate | Contents |
|---|---|---|
| Pure codec (Apache-2.0) | `tirbase_driver_api::ble_gatt` | Advertising-data parser, UUID map, SIG temperature/humidity decoding, typed errors |
| Driver boundary (AGPL-3.0-only) | `tirbase_drivers::ble` | `BleCentral` radio trait, bounded operations, native `BtleplugCentral` adapter behind `ble-radio` |
| Guard probe (AGPL-3.0-only) | `tirbase_guard::ble` | `GuardBleProbe` step scheduler, reconnect backoff, health counters, credential redaction |
| Simulator (AGPL-3.0-only) | `tirbase_sim::SimBleGattPeripheral` | In-memory GATT table, link drops, malformed payloads, connect failures |

## Generic climate profile

The default profile is the Bluetooth SIG Environmental Sensing service:

| Field | UUID | Encoding | Unit |
|---|---|---|---|
| Service | `0x181A` | — | — |
| Temperature | `0x2A6E` | sint16 LE, 0.01 °C | `UNIT_DEG_C`, exponent −2 |
| Humidity | `0x2A6F` | uint16 LE, 0.01 %RH | `UNIT_PERCENT`, exponent −2 |

`BleGattUuidMap::new(service, temperature, humidity)` accepts vendor UUIDs while
keeping the SIG payload encoding. Temperature below absolute zero and humidity
above 100 % are rejected as physically impossible, not reported as readings.

Advertising data is parsed as BLE length/type/value structures. 16-bit and
128-bit service lists, complete/incomplete lists, and local names are supported;
truncated records, odd-length UUID lists, non-UTF-8 names, oversized
advertisements, and more than 16 service UUIDs are rejected.

## Probe lifecycle

```rust
use std::time::Duration;
use tirbase_guard::ble::{BleProbeConfig, GuardBleProbe};
use tirbase_sim::SimBleGattPeripheral;

let mut probe = GuardBleProbe::new(
    SimBleGattPeripheral::new(),
    BleProbeConfig {
        scan_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(10),
        read_timeout: Duration::from_secs(3),
        backoff_base: Duration::from_millis(500),
        backoff_max: Duration::from_secs(30),
        ..BleProbeConfig::default()
    },
)?;

// Call from the guard's normal scheduler tick; `now_ms` is monotonic.
match probe.poll(now_ms) {
    Ok(Some(reading)) => record(reading.climate),
    Ok(None) => {} // still inside a backoff window
    Err(error) => report(error),
}
```

A step performs at most one scan, one connect, and one temperature/humidity
read pair. On success the probe remains connected and the next step reads
again. On a transport failure it disconnects, schedules the next attempt, and
returns the failure once; calls before the deadline return `Ok(None)`.

Backoff is `base × 2^attempt`, capped at `backoff_max` (attempt exponent capped
at 16). A successful connection resets the attempt counter. `disconnect()`
drops the link and schedules an immediate reconnect on the next step.

## Bounds

| Limit | Default / maximum |
|---|---|
| Scan timeout | 5 s (must be non-zero) |
| Connect timeout | 10 s (must be non-zero) |
| Read timeout | 3 s (must be non-zero) |
| Backoff | 500 ms base, 30 s cap, base ≤ cap |
| Devices retained per scan | 32 default, 64 maximum |
| GATT payload | 128 default, 512 maximum |

The native adapter (`btleplug`, feature `ble-radio`) runs each radio operation
under the supplied timeout in a current-thread runtime. It opens no background
task; scanning itself is deadline-bounded and stops at the first matching
peripheral round.

## Pairing material and logs

The probe performs no pairing or bonding, so it never accepts or persists a
pairing secret. If a deployment injects pairing material, `BlePairingSecret`
holds it under the F-05 custody rules: in memory only, zeroized on drop,
redacted `Debug`, and never serialized. The probe never logs GATT payloads or
credentials. `BleProbeHealth` contains counters only (scan/connect/read
attempts, failures, malformed payloads), and error display strings contain no
credential or payload bytes.

## Tests

- `tirbase-driver-api/src/ble_gatt.rs`: UUID parsing, 16/128-bit advertising
  lists, truncated/oversized records, UUID-map collisions, SIG decoding,
  malformed payload lengths, and impossible physical values.
- `tirbase-guard/tests/ble_probe.rs`: simulator-backed standard and custom UUID
  profiles, reconnect after a dropped link, exponential backoff after connect
  failure, malformed temperature/humidity rejection, absent peripherals,
  configured timeout propagation, and pairing-secret redaction from debug,
  health, and error output.

Run locally:

```sh
cargo test -p tirbase-driver-api --lib ble_gatt
cargo test -p tirbase-guard --test ble_probe
cargo check -p tirbase-guard --features ble-radio
```

## Limits

- One climate profile per probe; a probe reads both characteristics.
- No pairing/bonding, notifications, or writes; reads are on demand.
- The native adapter uses platform bonding state managed by the OS agent.
- BLE address privacy/rotation is delegated to the platform stack.
