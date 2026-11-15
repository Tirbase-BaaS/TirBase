# Driver API and vendor conformance kit

The device-driver surface is split into an Apache-2.0 integration crate and an
AGPL-3.0-only runtime crate. A vendor can implement, build, and test a driver
with **only the Apache-2.0 crate**.

| Crate | Licence | Contents |
|---|---|---|
| `tirbase-driver-api` | Apache-2.0 | `DriverTrait`, device models, register-map parser, pure Modbus and MQTT packet codecs, conformance harness |
| `tirbase-drivers` | AGPL-3.0-only | Modbus/MQTT transport clients, MQTT bridge, cold-room reference driver, out-of-process isolation and lifecycle machinery |

The vendor example at [`examples/vendor-driver`](../examples/vendor-driver) is
the reference submission: one Apache-2.0 dependency, a register map, golden
frames, and a conformance test.

## Licence boundary

1. **Pure codecs only.** Driver code encodes and decodes frames. It never opens
   a device, socket, file, or child process; the guard process owns all device
   I/O endpoints and passes frames across the driver boundary. The API crate
   therefore has no I/O capability to hand out.
2. **No runtime imports.** `tirbase-driver-api` depends only on
   `tirbase-types` (Apache-2.0). It must never depend on `tirbase-core`,
   `tirbase-guard`, `tirbase-drivers`, or any other AGPL crate. The dependency
   test `tirbase-driver-api/tests/agpl_free.rs` walks the resolved graph in
   `Cargo.lock` and fails if an AGPL crate becomes reachable, and
   `scripts/check-agpl-free.py` enforces the same rule for every Apache-2.0
   workspace crate in CI.
3. **Compatible re-exports are deprecated.** `tirbase-drivers` re-exports the
   API (and the pure Modbus codec) so existing in-tree callers keep compiling.
   The old paths — `tirbase_drivers::driver_trait`,
   `tirbase_drivers::register_map`, `tirbase_drivers::modbus_codec`, and the
   flat names such as `tirbase_drivers::DriverTrait` — carry `#[deprecated]`.
   New code imports from `tirbase_driver_api` directly.
4. **A vendor driver must not link AGPL code.** Adding any `tirbase-*` runtime
   crate to a driver's dependency list breaks this boundary. The vendor
   example's `vendor_depends_only_on_the_apache_crate` test asserts its manifest
   declares `tirbase-driver-api` and nothing else from the runtime.

Verify the boundary locally:

```sh
cargo test -p tirbase-driver-api
cargo tree -p tirbase-driver-api          # must contain no AGPL crate
python3 scripts/check-agpl-free.py
```

## Semver policy

`tirbase-driver-api` is versioned independently of the runtime crates.

- **0.x (current):** the crate is pre-1.0. A minor bump may contain breaking
  changes; a patch bump is limited to additive or behaviour-preserving fixes.
  Vendors should pin `tirbase-driver-api = "=0.1.x"` or the exact minor they
  tested against.
- **1.0 and later:** standard SemVer. Breaking changes require a major bump.
  Additive items (new trait methods with defaults, new helper functions, new
  enum variants on `#[non_exhaustive]` types) ship in a minor release.
- **What counts as breaking:** removing or renaming a public item, changing a
  method signature, adding a required trait method without a default, adding a
  variant to an enum that is not `#[non_exhaustive]`, or changing wire-format
  behaviour that existing golden frames depend on.
- **Deprecation window:** an item deprecated in a minor release stays available
  for at least one further minor release. The deprecated `tirbase_drivers`
  compatibility re-exports are removed at the next major version of
  `tirbase-drivers`.
- **Runtime compatibility:** `tirbase-drivers` states the minimum
  `tirbase-driver-api` version it implements. A driver built against an older
  compatible API version continues to load; the out-of-process boundary is the
  compatibility seam.

## Conformance harness

The harness lives in `tirbase_driver_api::conformance`. It is pure: it reads a
caller-supplied monotonic clock and never performs I/O.

| Check | Function | Rule |
|---|---|---|
| Encode/decode round-trip | `ConformanceHarness::check_codec` | Golden request/response frames decode to the documented `FixedPointValue`; read-back and actuation paths agree |
| Bounded time | `ConformanceHarness::check_bounded_time` | Every operation completes within `DRIVER_OPERATION_TIMEOUT` (5,000 ms) |
| Typed errors | `ConformanceHarness::check_typed_errors` | Unknown parameters produce `DriverError::UnsupportedParam`; empty frames produce `DriverError::InvalidFrame`; health always returns a typed result |
| Scaling | `check_register_scaling` | Register scale/offset round-trips and matches `raw * scale_mantissa + offset_mantissa * 10^(offset_exponent - scale_exponent)` |
| Word order | `check_word_order` | 32-bit values encode to the golden word permutation for `big_endian`, `little_endian`, `mid_big`, and `mid_little`, and decode back |
| No I/O | `check_no_io` | Driver sources contain no `std::fs`, `std::net`, `std::process`, `std::io`, `std::os::*`, socket/file APIs, `nix::`, or `libc::` references (comments are ignored) |

`run_conformance` runs all of them and returns a `ConformanceReport`;
`assert_ok` panics with the failing check names, which is the right behaviour
for an integration test.

```rust
use tirbase_driver_api::conformance::{run_conformance, CodecCase, SourceFile};

let report = run_conformance(
    &driver,
    &cases,                 // golden frames for each advertised parameter
    driver.map(),           // register map used for scaling checks
    &[SourceFile { path: "src/lib.rs", contents: include_str!("../src/lib.rs") }],
    &clock,                 // caller-supplied monotonic milliseconds
);
report.assert_ok();
```

The no-I/O guard is lexical: it catches imports and call sites, not
dynamically constructed API names. Process isolation and the guard-owned
transport remain the runtime enforcement.

## Vendor submission process

1. **Implement `DriverTrait`** against `tirbase-driver-api` only. Encode and
   decode frames; keep every operation pure and fast.
2. **Ship a register map** in the documented format
   ([`register-map-format.md`](drivers/register-map-format.md)) when the device
   has Modbus-style registers. Validate it at construction.
3. **Record golden frames** for every advertised read, actuation, read-back,
   and health path. Store them with the driver (see
   `examples/vendor-driver/golden/frames.txt`) so a wire-format change breaks a
   test rather than a deployment.
4. **Run the harness** from an integration test. `report.assert_ok()` must
   pass. Add focused tests for any protocol quirk the harness cannot know.
5. **Prove the licence boundary.** The manifest must list only
   `tirbase-driver-api` from this repository, and
   `cargo tree -p <your-driver>` must show no AGPL crate.
6. **Document** the device class, parameters, units, scaling, word order, and
   failure behaviour, and keep an SPDX `Apache-2.0` header in every source file.
7. **Submit** the driver with a DCO sign-off and a signed
   [Contributor Licence Agreement](../CLA.md). Drivers intended for the
   in-tree reference set are reviewed against the checklist below; out-of-tree
   vendors can self-certify with the same harness and keep their driver in
   their own repository.

### Review checklist

- [ ] Only `tirbase-driver-api` (and non-AGPL third-party crates) in `[dependencies]`.
- [ ] `cargo test -p <driver>` passes, including the conformance harness.
- [ ] Golden frames cover read, actuation, read-back, health, and malformed input.
- [ ] Register map parses and every `data_type`/`quantity` pair validates.
- [ ] Unknown parameters return `DriverError::UnsupportedParam`; malformed frames return `DriverError::InvalidFrame` or `DriverError::Codec`.
- [ ] No I/O, clock reads, sleeping, or global mutable state in codec paths.
- [ ] Semver impact of any `tirbase-driver-api` change is called out in the PR.
