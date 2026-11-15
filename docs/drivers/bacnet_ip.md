# BACnet/IP Read Bridge (CC-04)

Read-only BACnet/IP transport for building and energy devices. The MVP covers
Who-Is/I-Am discovery and ReadProperty on analog and binary inputs/values. It
is built on the CC-01 driver split and extends the F-13 simulator catalogue.

| Layer | Crate | Contents |
|---|---|---|
| Pure codec (Apache-2.0) | `tirbase_driver_api::bacnet_codec` | BVLC, NPDU and APDU encoding/decoding; Who-Is/I-Am; ReadProperty; typed write rejection |
| Transport (AGPL-3.0-only) | `tirbase_drivers::bacnet` (feature `bacnet-ip`) | UDP client, bounded discovery/read retries and deadlines |
| Guard wiring (AGPL-3.0-only) | `tirbase_guard::bacnet` | Guard-owned reader plus bounded polling scheduler |
| Simulator (AGPL-3.0-only) | `tirbase_sim::drivers::bacnet_server` | Loopback UDP device with an in-memory object table |

## Scope

Supported object types: `analog-input`, `analog-output`, `analog-value`,
`binary-input`, `binary-output`, `binary-value`. Discovery identifies device
objects. ReadProperty supports Present-Value (and any other property the peer
returns, decoded as a BACnet application value).

**Writes are rejected.** This is a contractual part of the MVP, not a runtime
policy that can be toggled:

- `encode_write_property` returns `BacnetError::WriteRejected { object, property }`
  and produces no bytes.
- `BacnetIpClient::write_property` returns the same error before any socket
  operation. A test asserts the simulator's write counter stays at zero.
- `From<BacnetError> for DriverError` maps a rejection to
  `DriverError::UnsupportedParam` at the guard boundary, so callers cannot
  mistake it for a successful actuation.

## Bounds

| Limit | Value | Enforcement |
|---|---:|---|
| BVLC datagram | 1500 bytes (`MAX_BVLC_LENGTH`) | `parse_bvlc` rejects longer input |
| APDU | 1024 bytes (`MAX_APDU_LENGTH`) | encoder and parser reject longer APDUs |
| Retries | 3 (`MAX_RETRIES`) | transport clamps configuration |
| Discovery devices | 256 (`MAX_DISCOVERED_DEVICES`) | transport clamps the cap and stops receiving at it |
| Broadcasts | one Who-Is per bounded attempt | `discover_broadcast` sends a single global Who-Is per attempt |

Every receive loop re-checks a caller-supplied monotonic clock, so a deadline
cannot be extended by a stream of datagrams. Discovery retries only when no
device replied; ReadProperty retries only bounded timeouts.

Segmented confirmed requests and routed NPDUs are rejected with typed errors;
the bridge is a single-datagram, directly addressed reader.

## Install and use

```toml
# Cargo.toml — enables the transport
tirbase-drivers = { version = "0.1", features = ["bacnet-ip"] }
```

```rust
use std::sync::Arc;
use std::time::{Duration, Instant};
use tirbase_driver_api::bacnet_codec::{ObjectIdentifier, ObjectType, PropertyId};
use tirbase_drivers::bacnet::{BacnetIpClient, BacnetIpConfig};

let start = Instant::now();
let clock = Arc::new(move || start.elapsed().as_millis() as u64);
let config = BacnetIpConfig {
    local_addr: "0.0.0.0:47808".into(),
    timeout: Duration::from_millis(500),
    retries: 1,
    max_devices: 64,
};
let mut client = BacnetIpClient::bind(&config, clock)?;

// Directed Who-Is (no broadcast). discover_broadcast() emits one global
// Who-Is per bounded attempt on 255.255.255.255:47808.
let devices = client.discover("192.0.2.10:47808".parse()?)?;
let target = devices[0].address;

let sensor = ObjectIdentifier::new(ObjectType::AnalogInput, 0)?;
let value = client.read_present_value(target, sensor)?;
let temp = value.to_fixed_point(tirbase_types::UNIT_DEG_C, -1);

// Always Err(BacnetError::WriteRejected { .. }); nothing is sent.
let _ = client.write_property(target, sensor, PropertyId::PRESENT_VALUE, &value);
```

## Guard wiring and polling

The guard owns the device endpoint: `GuardBacnetReader` binds the UDP socket and
no other guard code opens one. It exposes directed discovery and Present-Value
reads, re-exports the codec types it uses, and offers no write method.

`BacnetPoller` is a **step scheduler**, not a thread. The caller supplies the
clock and calls `poll_due(now_ms)`; each due call reads every point at most
once, advances the next deadline by one interval from `now_ms` (no catch-up
storm), and returns a per-point outcome so one failed device does not suppress
the rest.

```rust
use std::sync::Arc;
use std::time::{Duration, Instant};
use tirbase_guard::{
    BacnetIpConfig, BacnetPoint, BacnetPoller, GuardBacnetReader, ObjectIdentifier, ObjectType,
};
use tirbase_types::UNIT_DEG_C;

let start = Instant::now();
let clock = Arc::new(move || start.elapsed().as_millis() as u64);
let config = BacnetIpConfig {
    local_addr: "0.0.0.0:47808".into(),
    timeout: Duration::from_millis(500),
    retries: 1,
    max_devices: 64,
};
let reader = GuardBacnetReader::connect(device_addr, &config, clock)?;
let point = BacnetPoint::new(
    "room_temperature",
    ObjectIdentifier::new(ObjectType::AnalogInput, 0)?,
    UNIT_DEG_C,
    -1,
)?;
let mut poller = BacnetPoller::new(reader, vec![point], 5_000, 0)?;

for outcome in poller.poll_due(now_ms) {
    match outcome.result {
        Ok(sample) => record(outcome.point, sample.fixed_point),
        Err(error) => report(outcome.point, error),
    }
}
```

Poll bounds: at most `MAX_BACNET_POINTS` (64) points, interval clamped to
100 ms–24 h, exponents restricted to `-9..=9`, unique point names, and at least
one point. Each read still carries the transport's timeout/retry budget, so a
poll round is bounded by `points × (retries + 1) × timeout`.

## Tests

- **Recorded PDUs:** `tirbase-drivers/tests/fixtures/bacnet/pdus.txt` holds
  loopback captures of Who-Is, I-Am, ReadProperty, ACK, Error and Reject
  frames. `tests/bacnet_ip.rs` decodes each and re-encodes structural frames
  byte-for-byte.
- **Guard wiring:** `tirbase-guard/tests/bacnet_poll.rs` covers guard-owned
discovery and fixed-point reads, poll scheduling/freshness, per-point failure
isolation, interval clamping, and point-list validation against the simulator.
- **Simulator:** `BacnetSimServer` binds an ephemeral loopback port and serves
  an in-memory object table. Tests cover discovery, instance-range filtering,
  analog/binary reads, missing-object Error PDUs, retry after dropped Who-Is and
  ReadProperty datagrams, and bounded timeouts against a silent socket. No
  physical device or network broadcast is needed in CI.
- **Parser fuzzing:** `tirbase-drivers/fuzz/fuzz_targets/bacnet_ip.rs` feeds
  arbitrary bytes to `parse_message`/`parse_bvlc` and re-encodes decoded
  messages. Deterministic parser-totality and value round-trip property tests
  live in the codec module.

Run locally:

```sh
cargo test -p tirbase-driver-api
cargo test -p tirbase-drivers --features bacnet-ip --test bacnet_ip
cargo +nightly fuzz run bacnet_ip            # from tirbase-drivers/fuzz
```
