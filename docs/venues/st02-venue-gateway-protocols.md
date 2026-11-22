# ST-02 — Venue gateway protocols

`tirbase-venue-gateway` ingests building and gate protocols into the ST-01 venue
model. It is deliberately a **decode-and-map** layer: device transports are owned
by the caller, and no API in the crate emits a command, setpoint or write frame.

## Protocol feature gates and dependency review

Every protocol is a separate Cargo feature, off by default. The crate has no
transport dependencies; frames are passed in by a caller-owned transport or the
deterministic simulators.

| Protocol | Feature | Decode source | Frames accepted | Write path |
| --- | --- | --- | --- | --- |
| BACnet/IP | `bacnet` | Apache-2.0 `tirbase_driver_api::bacnet_codec` | ReadProperty-ACK only | `encode_write_property` returns `WriteRejected`; SimpleACK is rejected |
| Modbus TCP/RTU | `modbus` | Apache-2.0 `tirbase_driver_api::modbus_codec` | FC03/FC04 read responses | FC06/FC16 responses rejected; FC06/FC16 addresses cannot be mapped |
| KNX/IP | `knx` | Built-in read-only subset in `protocol::knx` | KNXnet/IP TUNNELING_REQUEST with cEMI `L_Data.ind` GroupValueWrite/Response, DPT1 and DPT9 | `L_Data.req` rejected; no bus-write encoder exists |
| MQTT 3.1.1 | `mqtt` | Apache-2.0 `tirbase_driver_api::mqtt_codec` | Inbound PUBLISH (QoS 0/1) | No PUBLISH encoder is exposed by the gateway |

Dependency review:

- No new third-party crate is introduced by any protocol; all codecs come from
  the existing Apache-2.0 `tirbase-driver-api` integration surface.
- The crate is AGPL-3.0-only, matching the venue domain and gateway layers.
- The gateway adds no socket, TLS, serial or async runtime dependency. A
  transport implementation must be supplied by the deployment.
- Feature combinations are independent; enabling one protocol never pulls in
  another protocol's code.

Enable protocols with `--features bacnet,modbus,knx,mqtt` or
`--features all-protocols`.

## Point mapping

`PointMapping` binds a protocol address to a venue target:

| Target | Meaning |
| --- | --- |
| `Gate` | Gate/lane signal such as open, occupied or fault |
| `Occupancy` | Live zone occupancy count |
| `Environment` | Zone temperature, humidity or air quality |
| `Equipment` | Venue equipment (AHU, escalator, turnstile motor) in a zone |

Registration validates the target against the topology version: gates must
exist, and zones referenced by occupancy, environment and equipment mappings
must exist. Addresses are unique, so one protocol reading maps to exactly one
venue point.

`SafetyClass::LifeSafety` marks fire/life-safety systems for audit. It does not
change the data path: every point is read-only, and there is no command type in
the crate.

## Health and stale detection

- `ConnectionSupervisor` tracks one link per protocol with bounded exponential
  backoff (`BackoffPolicy`: base delay, max delay, max attempts). Failures raise
  `ReconnectScheduled` events; exceeding the attempt bound raises
  `ReconnectExhausted`; recovery raises `Connected`.
- `VenueGateway::tick(now)` marks a point stale when its last reading is older
  than `stale_after_us` and raises exactly one `PointStale` event per stale
  episode. A fresh reading raises `PointRecovered`.
- Stale occupancy points are excluded from `occupancy_total`, so capacity and
  occupancy views never count frozen values as live.

## Simulators and tests

`tirbase_venue_gateway::sim` provides deterministic peers for each protocol
(`BacnetSim`, `ModbusSim`, `KnxSim`, `MqttSim`). Tests feed recorded byte
sequences, including literal frames for all four protocols, and verify:

- points from all four protocols appear in one venue snapshot;
- a stale point raises a health event and recovers on refresh;
- reconnect backoff is bounded and recovery is reported;
- write-path frames (BACnet write encoding, Modbus FC06, KNX `L_Data.req`) are
  rejected.

Run them with:

```sh
cargo test -p tirbase-venue-gateway --all-features
```
