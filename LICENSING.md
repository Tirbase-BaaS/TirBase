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
| Venue gate HIL bench | `tirbase-venue-hil` | `AGPL-3.0-only` | Software HIL bench, power/brownout/network/clock safety cases, emergency egress simulation, durability/event-flood tests and hash-sealed evidence. Physical safety assessment and lab execution are a separate commercial engagement. |
| Venue privacy runtime | `tirbase-venue-privacy` | `AGPL-3.0-only` | Field privacy register, metadata-only CCTV event store, enforced retention, legal holds, subject access/deletion and role-scoped access audit. The commercial venue compliance kit supplies customer-completion templates and review records. |
| Venue compliance kit | `commercial/venue-compliance-kit/` | `Proprietary` | Venue DPIA, retention, SAR/deletion and local-authority reporting templates, customer review record and delivery gate. Documents only; not part of the AGPL runtime; no legal advice or certification. |
| Stadium commercial kit | `commercial/stadium-kit/` | `Proprietary` | Stadium safety case, insurance evidence, local-authority templates, integrator certification, managed-venue operations and hardware policy. Documents only; draft until independent safety and counsel reviews are signed; no certification, cover or legal advice. |
| Venue command center backend | `tirbase-venue-command-center` | `AGPL-3.0-only` | Live venue command plane: incident workflow, approved lockdown controls, drill isolation and after-action reports, operating the ST-08 engine. |
| Venue command center UI | `console/venue-command-center/` | `Apache-2.0` | Static operator/supervisor/safety/auditor console. It consumes the AGPL backend over HTTP and links no runtime code. |
| Venue connector framework | `tirbase-venue-connectors` | `Apache-2.0` | Ticketing, access, BMS, CCTV and PA connector interfaces, venue event schemas, mapping, idempotency, retries, dead letters, signed webhook verification, venue privacy rules, mocks and a conformance suite, so a closed venue connector is built without linking the AGPL runtime. |
| Venue ticketing connectors (Ticketmaster, Eventim) | `closed/venue-ticketing/` | `Proprietary` | Two separately sold ticketing connectors: lifecycle feed, offline revocation cache for disconnected gates, scan ledger and reconciliation, signed feed webhooks, seat mapping, sandbox mock server and contract tests. Documents and source live only in the git-ignored closed tree; they link only the Apache-2.0 `tirbase-venue-connectors` surface. |
| Venue operations connectors (HID, LenelS2, Genetec, Siemens, Johnson Controls, ONVIF, PA) | `closed/venue-operations/` | `Proprietary` | Seven separately sold connectors: credential/access-event sync with offline revocation, BMS point mapping and alarm ingestion that refuses every life-safety point and alarm, metadata-only ONVIF events and camera health, and templated PA announcements with zone, priority and audit. Source and documents live only in the git-ignored closed tree; they link only the Apache-2.0 `tirbase-venue-connectors` surface and cannot control a fire or life-safety system. |
| Integration framework | `tirbase-integrations` | `Apache-2.0` | Connector trait, mapping DSL, retry/backoff, idempotency keys, dead-letter queue and replay, OAuth2/mTLS/API-key/HMAC auth, generic HTTP, webhook, MQTT, CSV and SFTP connectors, mock vendor server and certification suite, so closed vendor connectors are written and tested without linking the AGPL runtime. |
| EN 16931 adapter | `tirbase-en16931` | `Apache-2.0` | EN 16931 semantic model, UBL 2.1 and CII D16B serialization, validation and batch export, so a closed country profile can embed the core without linking the AGPL runtime. |
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

The Ticketmaster and Eventim ticketing connectors (ST-14) are a **separate
proprietary product** and are not present in this repository. They are developed
in a git-ignored `closed/venue-ticketing/` tree, link only the Apache-2.0
`tirbase-venue-connectors` surface, and are sold per connector. A successful
feed sync makes the offline ticket cache authoritative: a revoked ticket is
refused with no vendor call, and a replayed scan returns its original decision
rather than admitting twice. `scripts/check-venue-ticketing.py` proves the tree
is untracked, has no AGPL edge in `Cargo.lock`, bundles no vendor SDK or
credential, documents setup, credentials, sandbox, conformance and support, and
requires the two open-conformance certifications and the offline revocation and
replay regression tests by name. `scripts/package-venue-ticketing.py` refuses to
build a licensee archive unless that gate passes. The connectors are not
affiliated with, endorsed by or certified by Ticketmaster or Eventim; vendor API
approval and sandbox access remain the customer's agreement.

The HID, LenelS2, Genetec, Siemens, Johnson Controls, ONVIF CCTV and public
address connectors (ST-15) are a **separate proprietary product** and are not
present in this repository. They are developed in a git-ignored
`closed/venue-operations/` tree, link only the Apache-2.0
`tirbase-venue-connectors` surface, and are sold per connector. A credential sync
makes the venue's offline credential cache authoritative, a replayed access
decision, alarm or announcement is a duplicate rather than a second record, and
ONVIF events are metadata only. **No connector connects to, commands, inhibits or
substitutes for fire detection, fire suppression, smoke control, gas detection or
any other life-safety system**: BMS life-safety points, alarm families and point
writes are refused permanently. `scripts/check-venue-operations.py` proves the
tree is untracked, has no AGPL edge in `Cargo.lock`, bundles no vendor SDK,
credential or camera media, documents setup, credentials, sandbox, conformance,
failure recovery and support, and requires each product's open-conformance,
replay and family-guarantee tests by name.
`scripts/package-venue-operations.py` refuses to build a licensee archive unless
that gate passes. No vendor or ONVIF endorsement or certification is claimed.

The stadium commercial kit (ST-16) is a **separate proprietary deliverable** of
documents, not code. It is not part of the AGPL runtime and contains no source,
credential or customer data. It wraps ST-12..ST-15 with a pilot safety case (a
20-hazard log where every hazard has an owner, a mitigation and resolvable
evidence, a 5×5 risk assessment, 18 safety requirements, gate failure modes and an
independent review plan), insurance evidence, local-authority capacity, incident
and lockdown templates, integrator training/exam/badge/recertification and a
commissioning checklist, managed-venue operations (monitoring, on-call, incident
command, change management and SLA), and a hardware policy for controllers,
readers, spares, firmware support and EOL. `scripts/check-stadium-kit.py` proves
the kit is complete, contains no source, binary, secret or customer data, that
every hazard's evidence reference resolves and every hazard is covered by a
requirement, and that an unsigned review cannot be presented as approval;
`--release` fails while either review is pending. `scripts/package-stadium-kit.py`
builds only a watermarked draft archive until both the independent safety review
and the counsel review are approved. Neither review has taken place: both records
are unsigned, so no safety case is approved, no authority template is
counsel-approved and the kit must not be presented as certified.

The Stripe Terminal, Adyen and SumUp POS terminal connectors (POS-16) are a
**separate proprietary product** and are not present in this repository at all.
They are developed in a git-ignored `closed/pos-terminals/` tree, link only the
Apache-2.0 `tirbase-integrations` POS contract, and are delivered to licensees
under the proprietary notice in that tree. `scripts/check-pos-terminals.py`
proves the closed POS tree is untracked, free of processor SDKs, credentials and
card-number-shaped fixtures, documents its PCI scope, and passes its closed
contract and conformance suites before a release archive is built.

The DATEV, Xero and QuickBooks accounting connectors (POS-17) are the same kind
of **separate proprietary product** and are not present in this repository. They
are developed in a git-ignored `closed/pos-accounting/` tree, link only the
Apache-2.0 `tirbase-integrations` POS contract, and export journals, invoices,
payments, refunds and payouts through an explicit chart-of-accounts and
tax-code mapping with stable external ids and idempotent re-export. Unmapped
accounts are refused with a clear error and queued for operator attention rather
than guessed. `scripts/check-pos-accounting.py` proves the closed accounting
tree is untracked, free of vendor SDKs and credential or card-number-shaped
fixtures, and passes its closed contract and conformance suites before a
release archive is built.

The Uber Eats, Deliveroo and DoorDash delivery connectors (POS-18) are the same
kind of **separate proprietary product** and are not present in this repository.
They are developed in a git-ignored `closed/pos-delivery/` tree, link only the
Apache-2.0 `tirbase-integrations` POS contract, and ingest platform orders,
validate the platform menu version and every price against an explicit mapping,
accept/reject/cancel idempotently, push status and queue courier exceptions. A
replayed order is accepted once, and a menu or price mismatch is refused with a
clear error rather than mispriced. `scripts/check-pos-delivery.py` proves the
closed delivery tree is untracked, free of vendor SDKs and credential or
card-number-shaped fixtures, and passes its closed contract and conformance
suites before a release archive is built.

The KassenSichV/TSE, Registratore Telematico, NF525 and Veri*factu fiscal
modules (POS-19) are the same kind of **separate proprietary product** and are
not in this repository. They are developed in a git-ignored
`closed/pos-fiscal/` tree, link only the Apache-2.0 `tirbase-integrations` and
`tirbase-en16931` surfaces, and implement one stable `FiscalProvider` interface
behind a German TSE lifecycle and audit journal, an Italian RT authority
envelope and transmission, a French NF525 inalterable journal and evidence
pack, and a Spanish Veri*factu invoice chain and submission. No module is
certified or released: `release-manifest.toml` marks every module `blocked`,
`signed_off = false`, and the release gate refuses a plan until a signed lab
report with an artifact hash and scope covers it; marketing claims are audited
against that same scope. `scripts/check-pos-fiscal.py` proves the closed fiscal
tree is untracked, AGPL-free, free of vendor SDKs, certificate containers and
credential or card-number-shaped fixtures, has a plan and owner for every
module, and passes its closed suites before a release archive is built.

The PCI evidence and certified terminal/printer bundle (POS-20) is the same kind
of **separate proprietary product** and is not in this repository. It is
developed in a git-ignored `closed/pos-bundle/` tree with no TirBase runtime
dependency, and combines the PCI DSS scope, data-flow, segmentation, key and
logging evidence, a secure configuration baseline, incident-response and
forensic-readiness procedures, an attestation register with expiry-driven sales
holds, and an approved terminal/printer catalog the sales gate enforces. The
committed catalog contains no certified device, every attestation is pending
and the ASV scan and penetration test have not been run, so the bundle is on
hold and cannot be quoted as saleable or compliant. `scripts/check-pos-bundle.py`
proves the closed tree is untracked, every requirement maps to an existing
artifact, no uncertified device carries an approval id, no pending attestation
carries evidence, no credential or card-number-shaped fixture is present, and
the computed gate agrees with the reviewed hold before a release archive is
built.

The POS commercial kit and OEM programme (POS-21) is the same kind of
**separate proprietary product** and is not in this repository. It is developed
in a git-ignored `closed/pos-commercial/` tree with no TirBase runtime
dependency, and wraps the POS-13..POS-20 products with OEM and white-label
terms, partner pricing and entitlement enforcement, source-free installation,
commissioning and support runbooks, installer training and certification, the
SLA and escalation model, and a fictional demo dataset with a sales-engineering
script. Entitlements are signed Ed25519 claims verified against a public
anchor, the partner scope and a signed, sequence-numbered revocation list;
activation enforces the deployment cap, and the packager emits only compiled
binaries, docs, legal templates, demo data and a trust-anchor placeholder. No
counsel review has taken place: both legal templates are `0.9-draft`, the
review record is `pending`, the trust anchor is unprovisioned and the release
is a draft, so no partner may be appointed and no package may be sold. The
`pos-commercial` CLI issues and revokes entitlements with a caller-supplied
key; no private key or production token is committed.
`scripts/check-pos-commercial.py` proves the tree is untracked, required
documents and cross-references exist, the ledger and revocation register
agree, no credential, private key or card-number-shaped fixture is present,
and the pending review cannot be rendered as a release; `--require-reviewed`
fails until counsel review is recorded. `scripts/package-pos-commercial.py`
builds only a watermarked, source-free draft archive and refuses `--release`
while review, sign-off or the trust anchor is outstanding.

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
