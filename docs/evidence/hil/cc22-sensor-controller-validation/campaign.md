# CC-22 software bench campaign

Schema: `tirbase.hil.cc22.campaign.v1`  
Seed: `22`  
Stability cycles: `1000`  
Digest: `013e920e6a673d2b7a35fc75154972a79d2f207d4d84433269101e939c6aa217`  
Result: **PASS**

| Case | Transport | Kind | Result | Metric | Detail |
| --- | --- | --- | --- | --- | --- |
| `ds18b20.bench.convert_and_read` | ds18b20 | Bench | PASS | indicated_error=0 °C (tol 0.0625) | indicated 21.5 °C from a 21.5 °C scratchpad |
| `ds18b20.bench.conversion_time` | ds18b20 | Bench | PASS | - | conversion waits [750] ms (datasheet 750 ms at 12 bit) |
| `ds18b20.bench.bad_crc_rejected` | ds18b20 | Bench | PASS | - | corrupted scratchpad CRC is refused, not decoded |
| `ds18b20.bench.short_read_rejected` | ds18b20 | Bench | PASS | - | a 5-byte scratchpad read is refused |
| `ds18b20.bench.disconnected_reported` | ds18b20 | Bench | PASS | - | absence of the probe is a fault, not a stale temperature |
| `ds18b20.accuracy.datasheet_range` | ds18b20 | Accuracy | PASS | worst_error=0.0625 °C (tol 0.5) | worst 0.0625 °C at the -40 °C reference over -40…125 °C |
| `ds18b20.environmental.temperature_range` | ds18b20 | Environmental | PASS | - | −40 °C and +125 °C references decoded inside ±0.5 °C (see accuracy case) |
| `ds18b20.network_loss.bus_loss_recovery` | ds18b20 | NetworkLoss | PASS | - | bus loss reported; the next read after the probe returns succeeds |
| `current_loop.accuracy.reference_points` | current_loop | Accuracy | PASS | worst_error=0 µA (tol 16) | worst 0 µA against the calibrated current source |
| `current_loop.bench.engineering_span` | current_loop | Bench | PASS | - | 4 mA maps to 0 % of span |
| `current_loop.bench.open_loop` | current_loop | Bench | PASS | - | 598 ADC counts classified Some(OpenLoop) |
| `current_loop.bench.under_range` | current_loop | Bench | PASS | - | 632 ADC counts classified Some(UnderRange) |
| `current_loop.bench.over_range` | current_loop | Bench | PASS | - | 3500 ADC counts classified Some(OverRange) |
| `current_loop.bench.stuck_value` | current_loop | Bench | PASS | - | ten identical samples classify as a stuck transmitter |
| `current_loop.bench.noise_detected` | current_loop | Bench | PASS | - | ±1 mA noise above the 0.5 mA window is classified |
| `current_loop.environmental.brownout_open_loop` | current_loop | Environmental | PASS | - | supply sag reports open loop and no engineering value is trusted |
| `current_loop.environmental.thermal_humidity_offset` | current_loop | Environmental | PASS | worst_error=4 µA (tol 16) | 60 °C / 85 %RH adds 4 µA; total 4 µA |
| `current_loop.environmental.vibration_noise` | current_loop | Environmental | PASS | - | 5 µA vibration pick-up; total 5 µA |
| `current_loop.network_loss.loop_loss_recovery` | current_loop | NetworkLoss | PASS | - | open loop classified; the next in-range sample is trusted |
| `ble.bench.scan_connect_read` | ble | Bench | PASS | - | environmental sensing service discovered, connected and read |
| `ble.accuracy.reference_climate` | ble | Accuracy | PASS | temperature_error=0 °C (tol 0.2) | reference 21.52 °C / 45 %RH reads 21.52 °C / 44.99 %RH |
| `ble.bench.malformed_value_rejected` | ble | Bench | PASS | - | a one-byte temperature characteristic is refused |
| `ble.bench.connect_retry` | ble | Bench | PASS | - | a failed connect is reported and the retry succeeds |
| `ble.bench.absent_peripheral` | ble | Bench | PASS | - | an absent peripheral yields no devices rather than a synthetic one |
| `ble.network_loss.link_loss_recovery` | ble | NetworkLoss | PASS | - | link drop reported; reconnection returns a fresh characteristic read |
| `ble.environmental.vibration_link_drop` | ble | Environmental | PASS | - | vibration-induced link drop is reported and self-heals on reconnect |
| `bacnet.bench.discover_and_read` | bacnet | Bench | PASS | - | discovered 1 device(s) and read the analog input |
| `bacnet.accuracy.reference_point` | bacnet | Accuracy | PASS | indicated_error=0.0000003814697286941282 °C (tol 0.1) | reference 21.4 °C reads 21.400000000000002 °C (10^-1 resolution) |
| `bacnet.bench.read_only` | bacnet | Bench | PASS | - | the guard-owned BACnet path issued no WriteProperty |
| `bacnet.network_loss.server_loss_recovery` | bacnet | NetworkLoss | PASS | - | server loss is a transport error; a fresh server is read successfully |
| `bacnet.environmental.humidity_and_vibration` | bacnet | Environmental | PASS | - | loopback UDP path unaffected by 85 %RH / 2 g bench vibration profile |
| `modbus_rtu.bench.fc03_request_roundtrip` | modbus_rtu | Bench | PASS | - | FC03 request framing and CRC round-trip |
| `modbus_rtu.bench.fc03_response_decode` | modbus_rtu | Bench | PASS | - | FC03 response decodes two registers |
| `modbus_rtu.bench.fc06_fc16_echo` | modbus_rtu | Bench | PASS | - | FC06 and FC16 echo responses validate address and quantity |
| `modbus_rtu.bench.bad_crc_rejected` | modbus_rtu | Bench | PASS | - | frame CRC 6dc4 is recomputed and the corruption refused |
| `modbus_rtu.accuracy.register_resolution` | modbus_rtu | Accuracy | PASS | indicated_error=0 °C (tol 0.1) | 215 at 0.1 °C resolution is 21.5 °C with no rounding error |
| `modbus_rtu.network_loss.truncated_frame` | modbus_rtu | NetworkLoss | PASS | - | a truncated frame (line loss mid-frame) is refused |
| `modbus_rtu.environmental.brownout_frame_integrity` | modbus_rtu | Environmental | PASS | - | a brownout-corrupted frame fails its CRC rather than decoding |
| `modbus_tcp.bench.register_roundtrip` | modbus_tcp | Bench | PASS | - | FC03/FC06/FC16 round-trip against the loopback server |
| `modbus_tcp.accuracy.register_resolution` | modbus_tcp | Accuracy | PASS | indicated_error=0 °C (tol 0.01) | register 2150 at 0.01 °C resolution reads 21.5 °C |
| `modbus_tcp.network_loss.server_loss_recovery` | modbus_tcp | NetworkLoss | PASS | - | server loss is a transport error; a fresh server reads the new value |
| `modbus_tcp.environmental.brownout_connection_loss` | modbus_tcp | Environmental | PASS | - | a brownout-induced TCP loss surfaces as an error, never a cached register |
| `ds18b20.stability.mixed_fault_run` | ds18b20 | Stability | PASS | worst_error=0 °C (tol 0.5) | 1000 cycles: 971 clean, 29 classified faults, worst DS18B20 error 0 °C, loop checksum 11651508 |
