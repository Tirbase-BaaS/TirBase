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
| Driver API | `tirbase-driver-api` | `Apache-2.0` | Pure codec traits, device models, register maps, Modbus/MQTT packet codecs, and the vendor conformance harness. |
| Drivers | `tirbase-drivers` | `AGPL-3.0-only` | Runtime device drivers (Modbus, MQTT, cold-room simulation), transport clients, and isolation machinery. |
| Vendor driver example | `examples/vendor-driver` | `Apache-2.0` | Worked vendor submission: driver, register map, golden frames, and conformance test built only against `tirbase-driver-api`. |
| Operator CLI | `tirbase-admin` | `AGPL-3.0-only` | Operates the runtime; shipped with the server. |
| Simulator | `tirbase-sim` | `AGPL-3.0-only` | Verification harness for the runtime. |
| Fuzz harnesses | `fuzz/`, `tirbase-*/fuzz/` | `AGPL-3.0-only` | Derived from the runtime crates. |
| WASM core | `@tirbase/core-wasm` (`tirbase-sdk/wasm`) | `AGPL-3.0-only` | `tirbase-core` compiled to WASM. |
| Data SDK | `@tirbase/sdk` | `Apache-2.0` | Thin wrapper that depends on `@tirbase/core-wasm`; it does not bundle the core. |
| Shared types | `tirbase-types` | `Apache-2.0` | Leaf crate for SDKs, drivers, and integrators. |
| Reference packs | `tirbase-demo` | `Apache-2.0` | Vertical demo packs are templates customers can copy. |
| Alert connectors | `tirbase-notify` | `Apache-2.0` | Connector interface, alert message model, secrets-by-reference, retry/on-call arithmetic and the generic email, webhook and console connectors, so closed vendor plugins can deliver without linking the AGPL runtime. |
| EPCIS adapter | `tirbase-epcis` | `Apache-2.0` | Maps signed ledger bundles to GS1 EPCIS 2.0 JSON/XML for integrators; reads the bundle as JSON and never links the AGPL runtime. |
| POS domain model | `tirbase-pos` | `AGPL-3.0-only` | Prototype order/check/line-item/money model (POS-01) under the POS-00 deferral; not production, not certified, no payment connectivity. |
| Integration framework | `tirbase-integrations` | `Apache-2.0` | Connector trait, mapping DSL, retry/backoff, idempotency keys, dead-letter queue and replay, OAuth2/mTLS/API-key/HMAC auth, generic HTTP, webhook, MQTT, CSV and SFTP connectors, mock vendor server and certification suite, so closed vendor connectors are written and tested without linking the AGPL runtime. |
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

The commercial cold-chain kit in `commercial/cold-chain-kit/` is **proprietary** and is
not part of the AGPL runtime or the Apache-2.0 integration surface. It contains documents,
control maps and templates only — no source, keys or customer data. Delivery is governed
by the proprietary notice in that directory and a signed agreement; the packaging gate
`scripts/check-cold-chain-kit.py` refuses a release archive without counsel and
accredited-assessor approvals.

The SAP, Odoo and TMS/WMS connectors are a **separate proprietary product** and
are not present in this repository at all. They are developed in a git-ignored
`closed/` staging tree, link only the Apache-2.0 `tirbase-integrations` surface,
and are delivered to licensees under the proprietary notice in that tree.
`scripts/check-closed-connectors.py` proves the closed tree has no tracked source,
vendor SDK or credential in the open repository and that its documentation and
crates are present; `scripts/package-closed-connectors.py` refuses to package
unless that gate passes.

The Slack, Microsoft Teams, PagerDuty and SMS alert connectors are the same kind
of **separate proprietary product** and are not in this repository. They are
developed in a git-ignored `closed/alerts/` tree, link only the Apache-2.0
`tirbase-notify` surface, and keep provider tokens in an encrypted tenant-scoped
vault rather than configuration. `scripts/check-alert-connectors.py` proves the
closed alert tree is untracked, free of provider SDKs and plaintext tokens, and
documented before `scripts/package-alert-connectors.py` will build a licensee
archive.

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
