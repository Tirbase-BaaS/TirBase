# POS-08 — Scale, scanner and kitchen display (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-08 is device-codec engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, and has no physical-device qualification. The simulators are not a
> substitute for the F-13 HIL campaign.

**Record ID:** POS-08-PERIPHERALS-0001
**Date (UTC):** 2026-11-17
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01, F-13
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Two scale serial protocols, stable-weight detection, tare, units, overflow/underload | `tirbase-pos/src/scale.rs`, `ScaleCodec`, `ScaleEndpoint`, `Weight`, `WeightUnit` |
| 2 | HID/keyboard-wedge and serial scanner framing; GS1 AI parsing | `tirbase-pos/src/scanner.rs`, `HidScanner`, `SerialScanner`, `ScannerCodec`, `Gs1Data` |
| 3 | KDS ticket/line/status codec, idempotent IDs, ack/retry | `tirbase-pos/src/kds.rs`, `KdsCodec`, `KdsEndpoint` |
| 4 | Guard-owned endpoints; drivers are codecs | `device::DeviceTransport`; each endpoint keeps its transport private |
| 5 | Recorded vectors, fuzz, timeout and fault tests | `tirbase-pos/tests/pos08.rs`, `tirbase-pos/tests/pos08_properties.rs`, `fuzz/fuzz_targets/pos08_device_input.rs` |
| 6 | Simulators for all three | `SimulatedScale`, `SimulatedScanner`, `SimulatedKds` |

POS-08 adds no card-data field, no processor client, no persistence adapter, no
clock access and no jurisdiction default. Weighed quantities are POS-01
`Quantity` values and scanned items are ordinary POS-01 `LineItem` values; the
printer path from POS-07 is unchanged.

## 2. Scale codec and endpoint

Two protocols are public:

| Protocol | Frame |
|---|---|
| `MettlerToledo` | `ST,GS,+001.234,kg\r\n` — status `ST`/`US`/`OL`/`UL`, mode `GS`/`NT`, sign, three integer digits, `.`, three decimals, unit, CRLF |
| `CasBinary` | `02 status sign dddddd unit 03 xor` — 12 bytes; status bit 0 stable, bit 1 net, bit 2 overflow, bit 3 underload; unit codes `0` kg, `1` g, `2` lb, `3` oz |

Recorded vectors:

```text
text stable gross:  53 54 2C 47 53 2C 2B 30 30 31 2E 32 33 34 2C 6B 67 0D 0A
binary stable net:  02 03 2B 30 30 31 32 33 34 30 03 1F
```

`Weight` stores thousandths of the display unit and converts through exact
integer nanograms. Gram, kilogram and pound factors are exact; ounce is rounded
to the nearest nanogram. `Weight::to_quantity` converts to POS-01 kilograms and
rejects zero or negative weights.

`ScaleEndpoint` enforces:

- a fixed 128-byte receive buffer and a 32-byte frame limit;
- text frames only on CRLF, binary frames only at exactly 12 bytes with `STX`,
  `ETX` and a matching XOR checksum;
- consecutive identical stable frames (`stable_samples`, default 3) before a
  `stable_weight` is exposed; an unstable or faulted frame resets the count;
- overflow (`OL`/bit 2) and underload (`UL`/bit 3) surfaced as
  `ScaleReading::fault` and never as a stable weight;
- a protocol tare command (`T\r\n` or `ENQ`) and net/gross mode reporting;
- a caller-supplied-time stall deadline (`stall_timeout_ms`, default 2 s),
  reported as `scale.timeout`.

A partial frame stays buffered and is never decoded. A buffer that fills
without a boundary is rejected as `scale.frame.too_long`.

## 3. Scanner codec and endpoints

Serial framing is configurable: prefix byte, suffix byte and checksum
(`None`, `Xor`, `Sum8`). A frame that does not end in its suffix is
`scanner.frame.truncated`; a bad checksum, control byte, empty payload or
payload over 256 bytes is rejected. Recorded XOR vector:

```text
payload ABC123 -> 02 41 42 43 31 32 33 70 03
```

`HidScanner` accumulates printable ASCII characters from a keyboard wedge until
Enter/Tab, bounded by a caller-supplied payload limit and 256 keys. Non-ASCII
input, control characters, overflow and transport timeouts are typed errors.

`SerialScanner` reassembles frames across reads in a fixed 528-byte buffer and
enforces a read budget. Unterminated input with no further reads ends in
`scanner.timeout`; it is never treated as a barcode.

`ScannerCodec::decode_payload` supports plain printable payloads and GS1
element strings. The GS1 parser supports this bounded retail subset:

| AIs | Meaning |
|---|---|
| 00 | SSCC-18 |
| 01, 02 | GTIN-14 with check digit |
| 11, 12, 13, 15, 16, 17 | YYMMDD dates |
| 20 | variant |
| 10, 21, 22 | batch/serial (variable, GS separator) |
| 30, 37 | count/quantity (variable) |
| 3100–3699 | net weight, six digits, implied decimal in the last AI digit |
| 3900–3959 | amount payable (variable) |
| 90–99 | internal/retailer variable fields |

Fixed-length fields do not need a separator; variable fields end at ASCII GS
(`0x1D`) or end of input. Unknown AIs, bad GTIN check digits, impossible dates,
empty variables and truncation are errors. `Gs1Data::net_weight` returns AI
310n as a kilogram `Weight`; GTIN and arbitrary element lookup are exposed.

## 4. KDS codec and endpoint

The ticket codec is line-oriented and percent-escaped:

```text
KDS1
I ticket-1
O order-1
C check-1
S 7
L line-1 2000 grill queued Burger%20one
L line-2 1000 cold queued Salad
END
```

`END` is mandatory, so a truncated ticket is rejected. Fields must appear once,
line IDs must be unique, quantities are positive thousandths, and names are
bounded to 64 bytes with no controls. Stations are `grill`, `fry`, `cold`,
`bar`, `expo`; line states are `queued`, `preparing`, `ready`, `served`. Ticket
status is derived from its lines. Acknowledgements use:

```text
ACK ticket-1 7
```

`KdsEndpoint` owns the transport and a ticket journal:

1. If the ID was delivered with identical content, return `Duplicate` without
   writing. If the ID is reused for different content, return
   `kds.ticket_conflict`.
2. Otherwise encode once and attempt delivery up to `max_attempts`;
   [`KdsEndpoint::with_defaults`] uses the three-attempt
   `DEFAULT_KDS_ATTEMPTS`.
3. Send, then read one acknowledgement into a fixed 256-byte buffer. The ack
   must carry the same ticket ID and sequence; anything else is
   `kds.ack_mismatch`.
4. Transport failures, empty acks and timeouts are retried. After the budget,
   return `kds.retry_exhausted`.

The journal is only updated after a valid acknowledgement, so a failed
delivery never looks delivered.

## 5. Bounds

| Bound | Value | Applies to |
|---|---|---|
| `MAX_SCALE_FRAME_BYTES` | 32 | one scale frame |
| `MAX_SCALE_BUFFER_BYTES` | 128 | inter-frame buffer |
| `MAX_SCALE_READ_BYTES` | 64 | one scale transport read |
| `MAX_SCAN_PAYLOAD_BYTES` | 256 | one barcode payload |
| `MAX_SCAN_FRAME_BYTES` | 264 | one serial scan frame |
| `MAX_SCAN_KEYS` | 256 | one HID scan |
| `MAX_GS1_ELEMENTS` | 32 | one GS1 element string |
| `MAX_KDS_TICKET_BYTES` | 32 KiB | one encoded ticket |
| `MAX_KDS_LINES` | 128 | one ticket |
| `MAX_KDS_TEXT_BYTES` | 64 | ticket/line label |
| `MAX_KDS_ACK_BYTES` | 256 | one acknowledgement read |

No device-supplied length is used to size an allocation. Scales and KDS read
into fixed arrays; the serial scanner uses a fixed array; HID accumulation is
bounded by the endpoint constructor.

## 6. Simulators

- `SimulatedScale` produces frames for a settable gross weight, stability and
  fault; it applies the tare command and reports net weight; writes are
  journaled.
- `SimulatedScanner` implements both transports: a queue of HID keys and a
  queue of serial byte chunks.
- `SimulatedKds` accepts ticket frames, deduplicates by ID, queues
  acknowledgements, and can drop acks or fail sends.

They record host memory for tests and HIL rehearsals, not device firmware.

## 7. Acceptance evidence

| POS-08 "done when" | Evidence |
|---|---|
| A weighed item, scanned barcode and KDS ticket complete a flow | `a_weighed_item_a_scanned_barcode_and_a_kds_ticket_complete_a_flow` — split serial GS1 scan, two stable scale frames, exact POS-01 lines and totals, KDS delivery with a lost ack retry |
| A truncated frame is rejected | `truncated_and_corrupt_scanner_frames_are_rejected`, `truncated_kds_frames_are_rejected`, `malformed_scale_frames_are_rejected_without_panicking`, `a_partial_scale_frame_is_buffered_and_never_decoded`, `a_serial_scanner_times_out_on_an_unterminated_frame` |
| A duplicate KDS ticket is deduplicated | `duplicate_kds_tickets_are_deduplicated` — second identical submit returns `Duplicate`, writes nothing, journal has one ticket; different content is a conflict |

Supporting evidence:

- `recorded_scale_vectors_decode_and_encode_exactly`
- `recorded_scanner_vectors_frame_exactly`
- `stable_weight_requires_consecutive_identical_samples`
- `an_unstable_frame_resets_stability`
- `tare_reports_net_weight_after_a_command`
- `scale_faults_are_surfaced_and_do_not_become_stable_weight`
- `a_stalled_scale_reports_a_timeout`
- `weights_convert_units_and_become_exact_quantities`
- `a_hid_wedge_scan_and_its_bounds_are_enforced`
- `a_serial_scan_reassembles_split_frames`
- `gs1_element_strings_parse_to_typed_values`
- `malformed_gs1_data_is_rejected`
- `kds_ticket_codec_round_trips_exactly`
- `kds_delivery_retries_a_lost_ack_and_exhausts_its_budget`
- `a_mismatched_kds_ack_is_rejected`
- `arbitrary_device_bytes_never_panic`
- `pos08_properties`: arbitrary scale frames, scanner input, HID key streams and
  KDS frames never panic; KDS tickets round-trip within the bound.
- Fuzz: `cargo fuzz run pos08_device_input` from `fuzz/`.

Run: `cargo test -p tirbase-pos --test pos08` and
`cargo test -p tirbase-pos --test pos08_properties`.

## 8. Known limits / next

- No physical scale, scanner or kitchen display has been qualified. Frame
  timing, polarity, unit parsing and vendor-specific status bits must be
  confirmed in the F-13 HIL campaign.
- The text scale protocol is modelled on continuous-output ASCII and is not a
  vendor conformance claim. Only two protocols are implemented; other vendor
  modes, multi-drop addressing and request/response commands are absent.
- Stable-weight detection counts identical stable frames. It does not model
  motion thresholds, filtering windows or settling time; those belong to the
  device configuration.
- Tare is sent as a device command. There is no manual/software tare offset, no
  tare memory and no verification that the device accepted the command.
- Imperial weights are exact to the nearest nanogram; prices are still integer
  POS-01 money. Unit-price-per-pound conversion is the application's
  responsibility.
- GS1 support is the listed retail subset. Coupon, logistic, healthcare,
  extended-packaging and composite symbols are not modelled; unknown AIs are
  rejected rather than ignored. GS1 date validation is YYMMDD calendar shape,
  not an expiry policy.
- HID scanners deliver printable ASCII only. A GS1 FNC1 separator from a
  keyboard wedge is rejected; variable-length GS1 fields require a serial
  scanner configured to emit `0x1D`.
- The KDS endpoint delivers tickets. Inbound line-status updates are modelled
  by the codec and ticket status derivation, but there is no endpoint/transport
  path for the display to push status changes back yet.
- There is no persistence, authentication or encryption on any of these
  transports, no device discovery and no reconnect policy. The deployment
  adapter must supply framing, deadlines, credentials and an audit sink.
