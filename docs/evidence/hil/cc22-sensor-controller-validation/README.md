# CC-22 sensor/controller validation evidence pack

**Scope:** bench matrix, calibration/accuracy runs, environmental envelope, power-cut
and network-loss recovery, long-run stability and fault injection for the five
CC-22 transports (DS18B20, 4–20 mA, BLE GATT, BACnet/IP, Modbus RTU and Modbus TCP).

**Licence:** the harness and this pack are AGPL-3.0-only. The physical lab campaign
(reference instruments, climate chamber, vibration table, smart PDU) is operated
commercially by the lab/operator; this pack defines exactly what they run.

**Reference run:** `campaign.json` (seeded, hash-sealed) and `power-cut.json`,
produced by the commands below. `campaign.md` is the same run rendered for review.
The committed `campaign.json` is checked against a fresh run by
`tirbase-sim/tests/hil_campaign.rs::committed_evidence_matches_a_fresh_run`, so a
change in behaviour that moves the digest fails CI until the pack is regenerated
deliberately.

## 1. Reproduce the software bench

```bash
cargo test -p tirbase-sim --test hil_campaign -- --nocapture
```

The suite writes `target/hil-evidence/cc22/{campaign.json,campaign.md,power-cut.json}`.
Campaign seed `22` is the reference run; `run_campaign(seed)` is byte-identical for a
given seed and is asserted twice in the same test. The evidence document's `digest`
is SHA-256 over the canonical case list.

## 2. Bench matrix

Each transport is driven through its production path (`tirbase-driver-api` codecs,
`tirbase-drivers` client/sensor state machines, `tirbase-guard` readers) against the
in-repo loopback simulator. Cases, all `PASS` in the reference run:

| Transport | Bench cases |
| --- | --- |
| DS18B20 | convert-and-read at 21.5 °C; 750 ms conversion wait; bad CRC rejected; short read rejected; disconnect reported |
| 4–20 mA | engineering span; open loop; under range; over range; stuck value; noise |
| BLE GATT | environmental-sensing scan/connect/read; malformed characteristic rejected; failed connect retried; absent peripheral; vibration link drop |
| BACnet/IP | discover + read analog input; read-only path (no WriteProperty); server loss and recovery |
| Modbus RTU | FC03 request round-trip; FC03 response decode; FC06/FC16 echo validation; bad CRC rejected; truncated frame refused |
| Modbus TCP | FC03/FC06/FC16 register round-trip; server loss and recovery |

## 3. Calibration and accuracy runs

Reference values are the calibration certificate points of the lab instruments; on
the software bench they are injected as exact physical values. Acceptance criteria:

| Transport | Reference source | Tolerance | Reference run |
| --- | --- | --- | --- |
| DS18B20 | dry-block at −40, −20, 0, 25, 60, 84.5, 125 °C | ±0.5 °C | worst 0.0625 °C (one LSB) |
| 4–20 mA | calibrated current source at 4/8/12/16/20 mA | ±16 µA (0.1 % FS) | worst 0 µA |
| BLE | reference thermometer/hygrometer | ±0.2 °C, ±0.5 %RH | at characteristic resolution |
| BACnet/IP | reference thermometer over the simulator | ±0.1 °C (10⁻¹ resolution) | 0 °C error |
| Modbus RTU/TCP | register resolution 0.1 °C / 0.01 °C | one resolution step | 0 °C error |

The physical campaign records the instrument serial number, certificate id, due date
and measured error per point in the lab summary (see §7); this pack's `campaign.json`
holds the same fields for the software bench.

## 4. Environmental tests

| Condition | Envelope | Expectation | Cases |
| --- | --- | --- | --- |
| Temperature | −40 °C … +125 °C (DS18B20 datasheet), 60 °C electronics | in tolerance or declared fault | `ds18b20.*temperature*`, `current_loop.environmental.thermal_humidity_offset` |
| Humidity | 85 %RH | offset stays inside the accuracy budget | `current_loop.environmental.thermal_humidity_offset` |
| Vibration | 2 g sweep, bounded pick-up | in tolerance; link drops self-heal | `current_loop.environmental.vibration_noise`, `ble.environmental.vibration_link_drop` |
| Brownout | supply sag below the transmitter's 3.6 mA threshold; corrupted serial frame | declared open-loop fault / CRC rejection, never a plausible value | `current_loop.environmental.brownout_open_loop`, `modbus_rtu.environmental.brownout_frame_integrity`, `modbus_tcp.environmental.brownout_connection_loss` |

## 5. Power-cut and network-loss recovery

Network loss is covered at acquire time for every transport (`*.network_loss.*`):
the loss is classified as a fault, and the next read after the link returns is a
fresh acquisition, not a cached value.

Power cuts are proven with a real child process killed inside an open write
transaction (`power_cut_during_write_leaves_calibration_and_ledger_consistent`).
`power-cut.json` records, for each stage, `PRAGMA integrity_check`, the committed
calibration count, the ledger entry count and the recomputed hash chain:

| Stage | Cut point | Result |
| --- | --- | --- |
| `calibration-uncommitted` | inside `BEGIN IMMEDIATE`, before commit | row rolled back; integrity ok; chain intact |
| `calibration-committed` | after the calibration committed | record durable and complete; chain intact |
| `ledger-uncommitted` | inside the ledger transaction | entry absent; chain intact |
| `ledger-committed` | after the append committed | entry durable and linked; chain intact |

This is the CC-22 acceptance condition “a power cut during a write does not corrupt
calibration or ledger state”, exercised at the storage durability boundary, plus the
physical PDU runs in `docs/hil-test-procedure.md` §3 at the device boundary.

## 6. Long-run stability and fault injection

One seeded 1,000-cycle run mixes DS18B20 conversions, 4–20 mA samples, BLE GATT
reads and Modbus RTU framing. Every 97th cycle injects a fault in rotation (bad CRC,
open loop, BLE link drop, corrupted RTU frame); a fault must be classified, a clean
cycle must be in tolerance, and `clean + classified == cycles`. The case reports the
worst DS18B20 error and a loop checksum so a drift or a silent value change is
visible. Long-duration soak stays in `docs/soak-test-procedure.md`.

## 7. Physical lab counterpart

Run the same case list on the bench described in `docs/reference-hardware.md`,
recording per case: instrument serial and certificate id, ambient temperature and
humidity, vibration profile, PDU event timestamps, bus/PCAP traces, and the gateway
commit SHA with config/profile hashes. Store the artifacts under
`docs/evidence/hil/<YYYY-MM-DD>-<campaign-id>/` per `docs/hil-lab-checklist.md` §7
and link the summary from `CLAIMS.md` CLAIM-52.6. Physical execution is commercial;
the software bench above is the reproducible part of the same procedure.

## 8. Reference-run identity

- Campaign schema: `tirbase.hil.cc22.campaign.v1`
- Seed: `22`; stability cycles: `1000`
- Digest: `013e920e6a673d2b7a35fc75154972a79d2f207d4d84433269101e939c6aa217`
- Result: PASS (43 cases; 6 transports; 4 power-cut stages)
