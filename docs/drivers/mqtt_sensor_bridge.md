# MQTT Sensor Bridge (CC-07)

TLS-only bridge for battery-free MQTT temperature/humidity sensors. The bridge
owns the broker connection, subscribes only to allowlisted topics, and validates
every message before it reaches the guard pipeline.

| Layer | Crate | Contents |
|---|---|---|
| Pure packet codec (Apache-2.0) | `tirbase_driver_api::mqtt_codec` | CONNECT (with/without per-device credentials), SUBSCRIBE/SUBACK, PUBLISH/PUBACK, DISCONNECT, bounded field validation |
| Transport + bridge (AGPL-3.0-only) | `tirbase_drivers::mqtt` | `MqttTlsClient` (rustls), `MqttBridgeClient`, topic allowlist, payload schema, replay guard, TLS trust |

## Scope

The bridge is a **subscriber**, not a general MQTT client. It:

- connects over `mqtts://` only (there is no public plaintext connect path);
- authenticates with **per-device** username/password credentials;
- subscribes to a fixed, allowlisted set of topics at QoS 0 or 1;
- reads one bounded batch of PUBLISH packets, validates each, and returns
  [`MqttSensorReading`];
- never retries in a loop: a broker outage is a bounded error on the read path.

Publishing helpers (`publish_qos0`/`publish_qos1`) exist on the low-level
`MqttTlsClient` for the gateway reference profile; the sensor bridge does not
publish.

## Topic schema

Topics are **exact strings** by default. The conventional layout is:

```text
tirbase/devices/<device-id>/reading
```

- `<device-id>` is the same identifier that appears in the payload `device`
  field (`[A-Za-z0-9._:-]`, 1–64 bytes).
- One topic carries many readings over time; the bridge does not use retained
  messages.
- The allowlist is built with `MqttTopicAllowlist::exact([...])`. It holds at
  most `MAX_TOPIC_ALLOWLIST_ENTRIES` (64) filters, and duplicate filters are
  rejected.

### Wildcard subscriptions

Wildcard subscriptions are **disabled by default**. `MqttTopicAllowlist::exact`
rejects any filter containing `+` or `#`, and an inbound PUBLISH whose topic is
not an exact allowlist entry is rejected by the bridge even if the broker sends
it.

Wildcards require the explicit opt-in constructor:

```rust
use tirbase_drivers::mqtt::MqttTopicAllowlist;

// Exact: the default.
let exact = MqttTopicAllowlist::exact(["tirbase/devices/coldroom-1/reading"])?;

// Opt-in: one wildcard level. Review this at the call site; any publisher on
// the broker can then inject readings for that topic family.
let wild = MqttTopicAllowlist::with_wildcards(["tirbase/devices/+/reading"])?;
# Ok::<(), tirbase_drivers::mqtt::MqttBridgeError>(())
```

Malformed filters such as `tirbase/de#vices`, `tirbase/#/reading`, and
`tirbase/dev+ices` are rejected in both modes.

## Payload schema (version 1)

Six ASCII `key=value` fields separated by `;`, in any order:

```text
v=1;device=coldroom-1;seq=17;ts=1763200000000;temp_mc=4512;rh_cp=5560
```

| Field | Meaning | Constraint |
|---|---|---|
| `v` | schema version | exactly `1` |
| `device` | device identifier | 1–64 characters of `[A-Za-z0-9._:-]` |
| `seq` | per-device sequence number | decimal `u64`, `>= 1`, strictly increasing |
| `ts` | source timestamp | decimal Unix milliseconds |
| `temp_mc` | temperature, milli-°C | −100,000…200,000 |
| `rh_cp` | relative humidity, centi-%RH | 0…10,000 |

Decoding produces `FixedPointValue`s:

| Field | Unit | Exponent | Example `mantissa` |
|---|---|---|---|
| `temp_mc` | `UNIT_DEG_C` | −3 | `4512` → 4.512 °C |
| `rh_cp` | `UNIT_PERCENT` | −2 | `5560` → 55.60 %RH |

Key=value was chosen over JSON so the parser is dependency-free, has no nesting
or duplicate-key ambiguity, and can be fuzzed as a pure function.

Rejected as `PayloadError`:

| Case | Error |
|---|---|
| More than 6 fields (including a trailing `;`) | `TooManyFields` |
| Unknown key | `UnknownField` |
| Repeated key | `DuplicateField` |
| Missing required key | `MissingField` |
| Empty payload | `Empty` |
| Non-UTF-8 bytes | `NotUtf8` |
| Missing `=`, empty key/value, extra `=` | `Malformed` |
| `v` ≠ `1` | `UnsupportedVersion` |
| `device` empty, > 64 bytes, or bad character | `InvalidDeviceId` |
| `seq`/`ts` not decimal digits | `InvalidInteger` |
| `seq == 0`, `temp_mc`/`rh_cp` out of physical range | `OutOfRange` |
| Larger than `max_payload_bytes` | `PayloadTooLarge` |

## Size and allocation bounds

| Limit | Default | Hard ceiling | Enforcement |
|---|---:|---:|---|
| `max_payload_bytes` | 512 | 4,096 | Bridge rejects the payload; parser re-checks |
| MQTT packet remaining length | payload + 512 + 8 | — | Checked **before** the body buffer is allocated |
| `MAX_TOPIC_LEN` | 512 | — | Codec rejects longer topics |
| Replay window | 300 s | — | `MqttReplayGuard` |
| Tracked devices | 1,024 | 1,024 | Oldest watermark evicted deterministically |
| `connect_timeout` | 5 s | 30 s | TCP connect + handshake + CONNACK + SUBACK |
| `io_timeout` | 2 s | 30 s | One read |

A hostile packet header cannot cause a large allocation: `read_packet_bounded`
parses the remaining length, compares it with `max_payload_bytes + MAX_TOPIC_LEN
+ 8`, and only then allocates.

## Replay protection

`MqttReplayGuard` tracks a watermark per device: the last accepted `seq` and
`ts`. A message is accepted only when:

1. `ts + replay_window_ms >= now` — older messages are `StaleTimestamp`;
2. `ts <= now + MAX_FUTURE_SKEW_MS` (60 s) — otherwise `FutureTimestamp`;
3. `seq > last accepted seq` — equal or lower is `DuplicateSequence`.

This catches a byte-identical replay, a re-ordered older message, and a message
re-injected from a captured broker log. State is in-memory and bounded, so a
restart forgets watermarks; replay across a restart is the freshness layer's
concern, not the driver's. `now` comes from the caller-supplied `MqttClockFn`
(the driver never reads a clock); `tirbase-drivers` does not depend on
`tirbase-core`. The clock and payload `ts` must share a time base — pass Unix
milliseconds — or every message falls outside the window.

## QoS handling

- `subscribe_qos` (default QoS 1) is requested in SUBSCRIBE and recorded from the
  SUBACK. A SUBACK that rejects the subscription (`0x80`) or carries the wrong
  packet identifier fails the connect.
- Inbound QoS 1 PUBLISH packets are acknowledged with PUBACK **before** payload
  validation, so a rejected message is not redelivered forever. Duplicate
  deliveries are then stopped by the replay guard.
- An inbound PUBLISH with a QoS higher than the subscribed QoS is a protocol
  error.
- QoS 2 is not implemented; `MqttQoS` only has 0 and 1.

## TLS verification

`MqttBridgeClient::connect` takes `&MqttTlsTrust`, not a `rustls::ClientConfig`.
`MqttTlsTrust` can only carry CA roots (`webpki()`, `with_roots`,
`with_roots_and_webpki`), and the bridge builds the `ClientConfig` itself. There
is:

- no `dangerous()` escape hatch in the bridge API;
- no "accept invalid certificates" flag;
- no way to supply a custom verifier;
- no plaintext URI path (`mqtt://`, `tcp://`, `ws://` are rejected).

The unit test `bridge_source_contains_no_verifier_bypass` scans the bridge
source for verifier-override tokens, and the integration test
`tls_verification_cannot_be_disabled_through_the_bridge_api` proves that a
self-signed broker is refused when the bridge trusts only webpki roots. Because
verification is structural (the type system has no unverified variant), it
cannot be relaxed by a production build flag.

## Broker outage behaviour

`MqttBridgeClient` opens no background task and has no reconnect loop. Every
call is bounded:

- `connect` uses `connect_timeout` for TCP connect, TLS handshake, CONNACK and
  every SUBACK; a broker that never answers fails the call.
- `read_reading` derives an absolute deadline from `MqttClockFn` + `io_timeout`
  and re-checks it before every socket read; a broker that accepts the
  connection then stops sending produces `MqttBridgeError::Timeout`.

Device reads on other transports (Modbus, 1-Wire, BACnet, BLE) share no lock or
thread with the bridge, so an MQTT broker outage cannot stall them.

## Install and use

```toml
# Cargo.toml — the bridge is always compiled (no extra feature)
tirbase-drivers = { version = "0.1" }
```

```rust
use std::sync::Arc;
use std::time::{Duration, Instant};
use tirbase_drivers::mqtt::{
    MqttBridgeClient, MqttBridgeConfig, MqttDeviceCredentials, MqttTlsTrust, MqttTopicAllowlist,
};

let start = Instant::now();
let clock: tirbase_drivers::mqtt::MqttClockFn =
    Arc::new(move || start.elapsed().as_millis() as u64);

let topics = MqttTopicAllowlist::exact(["tirbase/devices/coldroom-1/reading"])?;
let credentials = MqttDeviceCredentials::new("device-coldroom-1", device_secret)?;
let mut config = MqttBridgeConfig::new(
    "mqtts://broker.example.com:8883",
    "guard-coldroom-1",
    credentials,
    topics,
);
config.max_payload_bytes = 512;
config.io_timeout = Duration::from_secs(2);

let trust = MqttTlsTrust::webpki(); // or with_roots(private_ca)
let mut bridge = MqttBridgeClient::connect(&config, &trust, clock)?;

// Bounded: a broker outage returns Err within io_timeout.
let reading = bridge.read_reading()?;
println!("{}: {} @ {}", reading.device_id, reading.temperature.mantissa, reading.timestamp_ms);
# Ok::<(), tirbase_drivers::mqtt::MqttBridgeError>(())
```

Credentials print as `<redacted>` in `Debug` and are only written into the
CONNECT packet.

## Tests

| Test | Proves |
|---|---|
| `tests/mqtt_bridge.rs::valid_qos1_reading_is_accepted_and_acknowledged` | TLS handshake, per-device credentials in CONNECT, exact QoS 1 SUBSCRIBE, reading decode, PUBACK |
| `tests/mqtt_bridge.rs::repeated_invalid_and_oversized_payloads_are_rejected` | replay, schema, size, and topic rejection over one live connection |
| `tests/mqtt_bridge.rs::wildcard_allowlist_requires_opt_in_and_is_enforced_on_read` | wildcard filters only reach the bridge after explicit opt-in, and inbound topics are still filtered |
| `tests/mqtt_bridge.rs::tls_verification_cannot_be_disabled_through_the_bridge_api` | self-signed broker refused with webpki roots; wildcards rejected by default |
| `tests/mqtt_bridge.rs::broker_outage_fails_reads_within_the_deadline` | CONNECT and read both fail within their deadlines against a silent broker |
| `tirbase-drivers/src/mqtt.rs` unit tests | schema cases, allowlist matching, wildcard opt-in, replay window/eviction, config bounds, credential redaction |
| `tirbase-drivers/fuzz/fuzz_targets/mqtt_frame.rs` | `decode_publish`/`decode_puback` and `parse_sensor_payload` never panic on arbitrary bytes |

The local broker is the existing rustls test harness (self-signed certificate,
loopback listener) extended with CONNECT/SUBSCRIBE/PUBLISH handling, so no
external broker process is needed in CI.
