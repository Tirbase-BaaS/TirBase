# POS-07 — ESC/POS receipt printer and cash drawer (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-07 is device-codec engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, and has no physical-printer qualification. The simulator is not a
> substitute for the F-13 HIL campaign.

**Record ID:** POS-07-ESCPOS-0001
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
| 1 | ESC/POS codec: text, alignment, bold, cut, feed, barcode/QR, code pages | `tirbase-pos/src/escpos.rs`, `EscPosCodec`, `CodePage`, `BarcodeType`, `QrOptions` |
| 2 | Cash-drawer kick and status query | `EscPosCodec::drawer_kick`, `status_query`; `ReceiptPrinter::pulse_drawer`, `query_status` |
| 3 | Error decoding and bounded buffers | `decode_status`, `decode_status_response`, `PrinterErrorCode`, `MAX_JOB_BYTES`, `MAX_TEXT_BYTES`, `MAX_QR_DATA_BYTES`, `MAX_STATUS_RESPONSE_BYTES` |
| 4 | Guard-owned transport; driver is a pure codec | `printer::ReceiptPrinter` owns `PrinterTransport`; `escpos` performs no I/O |
| 5 | Recorded byte vectors, fuzz and malformed-command tests | `tirbase-pos/tests/pos07.rs`, `tirbase-pos/tests/pos07_properties.rs`, `fuzz/fuzz_targets/escpos_device_input.rs` |
| 6 | Simulator for print/drawer flows | `printer::SimulatedPrinter` |

POS-07 adds no card-data field, no processor client, no persistence adapter, no
clock access and no jurisdiction default. Receipt money comes from the POS-01 check totals and is never recomputed on the
printer side.

## 2. Pure codec

`EscPosCodec` builds bytes only. It has no device handle, no thread, no I/O and
no clock. Supported commands:

| Operation | Bytes |
|---|---|
| Initialise | `1B 40` |
| Code page | `1B 74 n` (CP437 = 0, CP850 = 2, CP1252 = 16) |
| Alignment | `1B 61 00/01/02` |
| Emphasis | `1B 45 00/01` |
| Feed *n* | `1B 64 n` |
| Text | encoded under the selected page |
| CODE128 | `1D 6B 49 len data` |
| EAN-13 | `1D 6B 43 d1..d12` |
| QR | `GS ( k` model, module size, ECC, store, print |
| Cut | `1D 56 00/01` |
| Drawer kick | `1B 70 m 19 FA` (50 ms on, 500 ms off) |
| Status query | `10 04 n` |

Text is encoded strictly. A character outside the selected code page is
rejected with `escpos.unencodable_character`; it is never replaced with a
substitute glyph, so a receipt cannot silently lose an item name. Control
characters are rejected; line breaks come from `feed` or `line`.

## 3. Bounded buffers

All buffer sizes are fixed by the caller or by a module constant:

| Bound | Value | Applies to |
|---|---|---|
| `MAX_JOB_BYTES` | 64 KiB | one codec / one print job |
| `MAX_TEXT_BYTES` | 4 KiB | one `text` run |
| `MAX_BARCODE_BYTES` | 255 | CODE128 length byte |
| `MAX_QR_DATA_BYTES` | 1 KiB | one QR payload |
| `MAX_STATUS_RESPONSE_BYTES` | 8 | one status read |
| `MAX_RECEIPT_LINES` | 256 | one receipt |
| `MAX_RECEIPT_TEXT_BYTES` | 128 | title, footer, description, quantity |

`EscPosCodec::new` rejects a zero or oversized capacity.
`EscPosCodec::push` checks `len + bytes.len() > capacity` **before** extending
and returns `escpos.buffer_full`. Constructors that would reject input do so
before appending anything, so a failed command leaves the buffer unchanged.

`PrinterTransport::read_status` fills a caller-supplied slice. The guard always
passes exactly `[u8; MAX_STATUS_RESPONSE_BYTES]`, so a device cannot cause an
allocation by replying with a long burst. Responses longer than that slice are
truncated by the transport; `decode_status_response` also rejects an oversized
slice outright. Device input is never used as a length for an allocation.

## 4. Guard-owned transport

```text
print_sale(receipt, tender)
        |
        +-- Receipt::validate
        |     one currency, 1..=256 lines, exact components:
        |     total = subtotal - discount + tax + tip
        |
        +-- encode the whole job into the fixed-capacity codec
        |     (failure here writes nothing)
        |
        +-- query_status(DLE EOT 1) -> fixed 8-byte read
        |     offline / cover open / paper out / cutter / unrecoverable -> typed error
        |
        +-- one write_all + flush of the finished job
        |
        +-- cash tender: exactly one ESC p pulse
        +-- partial cut
```

`ReceiptPrinter` keeps the transport private. There is no public getter that
would let a caller write arbitrary bytes, skip the status check or bypass the
codec; `into_transport` consumes the guard for test inspection. A print job is
encoded completely before the first write, so a capacity error cannot leave a
half-printed receipt.

The drawer rule is structural: only `PaymentMethod::Cash` sets
`cash_drawer_opened`, and the pulse is appended once during job construction.
`pulse_drawer` is the explicit no-sale operation and is counted separately.

## 5. Error and status decoding

`decode_status(kind, byte)` interprets the common Epson `DLE EOT` bit layout
and ignores undefined bits:

| Register | Bits used |
|---|---|
| Printer (1) | bit 3 offline, bit 5 recovery, bit 0 drawer |
| Offline (2) | bit 3 offline, bit 2 cover, bit 5 recovery, bit 0 drawer |
| Error (3) | bit 2 cutter, bit 3 unrecoverable, bit 5 recoverable, bit 6 paper out |
| Paper (4) | bit 2 near end, bit 3 paper end |

Severity order for `StatusFlags::error_code` is: unrecoverable, cutter, paper
out, cover open, offline, recoverable, paper near end. A near-end warning alone
does not block printing (`is_ready`). Every byte value `0..=255` is decodable
for every register; decoding allocates nothing and cannot panic.

Transport failures (`Unavailable`, `WriteFailed`, `ReadFailed`, `Timeout`),
codec failures and device conditions (`PrinterErrorCode`) are separate typed
errors with stable `code()` strings.

## 6. Simulator

`SimulatedPrinter` implements `PrinterTransport` in process:

- every `write_all` is journaled in order;
- status queries are answered from a scripted queue (default ready byte
  `0x00`), truncating a scripted response at the guard's read buffer;
- `drawer_pulsed`, `drawer_pulse_count`, `cut_issued`, `status_queries` and
  `receipt_text` expose the flow for assertions;
- `set_offline`, `fail_next_write` and scripted status bytes exercise failures.

The simulator is for tests and HIL rehearsals. It records host memory, not
device input, and is not a firmware emulator.

## 7. Acceptance evidence

| POS-07 "done when" | Evidence |
|---|---|
| A sale prints a receipt and opens the drawer in simulation | `a_sale_prints_a_receipt_and_opens_the_drawer_in_simulation` (text, total, one pulse, cut, status query), `a_card_sale_prints_but_does_not_open_the_drawer` |
| Malformed commands do not panic | `malformed_status_bytes_never_panic_and_decode_deterministically`, `arbitrary_status_responses_never_panic`, `escpos_device_input` fuzz target |
| No unbounded allocation from device input | `status_reads_use_a_fixed_size_buffer`, `oversized_input_is_rejected_without_allocating_a_job`, `arbitrary_text_is_bounded_or_rejected`, `arbitrary_qr_payloads_are_bounded_or_rejected`, `a_receipt_job_never_exceeds_its_capacity` |

Supporting evidence:

- `recorded_command_vectors_are_exact`
- `drawer_and_status_vectors_are_exact`
- `barcode_and_qr_vectors_are_exact`
- `code_page_selection_and_encoding_are_exact`
- `a_ready_check_is_required_before_any_receipt_bytes_are_written`
- `an_encoding_failure_writes_nothing`
- `receipt_validation_preserves_exact_money`
- `pulse_drawer_is_a_guarded_standalone_operation`

Run: `cargo test -p tirbase-pos`. Fuzz: `cargo fuzz run escpos_device_input`
from `fuzz/`.

## 8. Known limits / next

- No physical printer has been qualified. Paper width, code-page numbering,
  pulse timing and cut behaviour vary by vendor and must be confirmed in the
  F-13 HIL campaign; the defaults here are common Epson values, not a
  hardware guarantee.
- The codec emits a small command subset. Images, raster bitmaps, page mode,
  multiple columns, buzzer, mark sensors and vendor extensions are not
  implemented.
- Code page tables cover CP437, CP850 and CP1252 only. Other pages, multi-byte
  encodings and Unicode printing are not modelled; unsupported characters fail
  the job rather than degrade.
- The transport trait is synchronous and has no retry, reconnect or write
  deadline. The deployment adapter must supply timeouts, framing for serial
  printers and an idempotent reprint policy.
- Receipts show a fixed 32-column layout. Wider paper, logos, per-store layouts
  and localised labels are not modelled.
- Drawer status is reported as an active-low connector signal, not proof that
  the drawer physically opened. There is no drawer sensor or close detection.
- `pulse_drawer` has no authorisation check in this crate; a POS-05-style
  approval or role gate must wrap no-sale drawer opens in deployment.
- Receipt/job bytes are not signed or persisted. Paper is the only copy; a
  reprint is a new job, not an idempotent device operation.
