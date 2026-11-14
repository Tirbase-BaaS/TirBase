# Licensing

TirBase uses a split licence. The **runtime is AGPL-3.0-only**; the **integration
surface is Apache-2.0**. There is no MIT-licensed first-party code in this
repository; third-party dependencies keep their own licences.

This file is the authoritative component matrix. The root [`LICENSE`](LICENSE)
contains the AGPL-3.0 text; [`LICENSE-APACHE`](LICENSE-APACHE) contains the
Apache-2.0 text.

## Component matrix

| Component | Path | Licence | Why |
|---|---|---|---|
| Core engine | `tirbase-core` | `AGPL-3.0-only` | The local-first/CRDT/mesh runtime. Copyleft keeps hosted derivatives open. |
| Command guard | `tirbase-guard` | `AGPL-3.0-only` | Safety and policy enforcement. This is the defensible runtime layer. |
| Gateway | `tirbase-gateway` | `AGPL-3.0-only` | The edge node server binary. |
| Driver API | `tirbase-driver-api` | `Apache-2.0` | Pure codec traits, device models, and register maps for third-party driver authors. |
| Drivers | `tirbase-drivers` | `AGPL-3.0-only` | Runtime device drivers (Modbus, MQTT, cold-room simulation) and isolation machinery. |
| Operator CLI | `tirbase-admin` | `AGPL-3.0-only` | Operates the runtime; shipped with the server. |
| Simulator | `tirbase-sim` | `AGPL-3.0-only` | Verification harness for the runtime. |
| Fuzz harnesses | `fuzz/`, `tirbase-*/fuzz/` | `AGPL-3.0-only` | Derived from the runtime crates. |
| WASM core | `@tirbase/core-wasm` (`tirbase-sdk/wasm`) | `AGPL-3.0-only` | `tirbase-core` compiled to WASM. |
| Data SDK | `@tirbase/sdk` | `Apache-2.0` | Thin wrapper that depends on `@tirbase/core-wasm`; it does not bundle the core. |
| Shared types | `tirbase-types` | `Apache-2.0` | Leaf crate for SDKs, drivers, and integrators. |
| Reference packs | `tirbase-demo` | `Apache-2.0` | Vertical demo packs are templates customers can copy. |
| Admin SDK | `@tirbase/gateway-admin-sdk` | `Apache-2.0` | Pure HTTP client generated from the admin OpenAPI spec. |

## SDK packaging

The package split is in place:

- `@tirbase/core-wasm` is the AGPL-3.0-only `tirbase-core` compiled to WASM.
  It is its own npm package under `tirbase-sdk/wasm/`.
- `@tirbase/sdk` is the Apache-2.0 TypeScript wrapper. It depends on
  `@tirbase/core-wasm` and deliberately does **not** include `wasm/` in its
  published files.

A proprietary application can therefore use the Apache-2.0 wrapper without
treating the wrapper itself as AGPL. The core WASM remains AGPL; a vendor that
wants to embed it in a closed product needs a commercial licence for the core,
just as it would for the Rust runtime. See the commercial section above.

## Commercial licensing

A separate commercial licence is available for:

- embedding the runtime in a proprietary product without AGPL obligations;
- OEM distribution and certified builds;
- compliance evidence packs, support SLAs, and warranty/indemnity;
- managed cloud ledger and fleet-console services (where offered).

Contact the maintainers for terms.

## Contributions

TirBase requires both a DCO sign-off and a signed
[Contributor Licence Agreement](CLA.md) before a contribution is merged. The DCO
is enough to accept a contribution under the project's open-source licence, but
it does **not** grant the rights needed to relicense that contribution
commercially. The CLA supplies that grant while leaving copyright ownership with
the contributor. This is a legal prerequisite for the dual-licensing/OEM model,
not a documentation preference.

## Third-party dependencies

Dependencies remain under their own licences. The `cargo-deny` allowlist in
[`deny.toml`](deny.toml) has been updated to permit the workspace's own
`AGPL-3.0-only` crates. This file is not legal advice; have counsel review the
distribution boundaries before signing OEM contracts.

Any departure from this matrix or the deny allowlist requires an entry in the
machine-checked [`licence-exceptions.toml`](licence-exceptions.toml) with a
named owner, reason, scope, and expiry. The process is documented in
[`docs/licensing-exceptions.md`](docs/licensing-exceptions.md); the blocking
`Licence boundary (F-01)` workflow fails on an expired or incomplete entry.
