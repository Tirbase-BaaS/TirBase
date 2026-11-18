# POS-14 — Generic POS integration framework (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-14 is Apache-2.0 integration engineering. It does not certify any vendor, does
> not move money and does not make a deployment PCI DSS compliant. Card-data
> handling is minimised by construction; the compliance obligation stays with the
> merchant, the acquirer and the terminal SDK.

**Record ID:** POS-14-POS-FRAMEWORK-0001
**Date (UTC):** 2026-11-18
**Licence:** `Apache-2.0`
**Crate:** `tirbase-integrations` (module `pos`)
**Depends:** POS-03 (payment intents), CC-20 (generic integration framework)
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

| # | Requirement | Where |
|---|---|---|
| 1 | POS-specific connector interfaces for payments, accounting, e-invoicing, delivery, tax | `pos/contract.rs` (`PosConnector`, per-family request types) |
| 2 | Config schema, mapping DSL, idempotency, retries, DLQ, reconciliation hooks | `pos/config.rs`, `mapping.rs`, `pos/mod.rs`, `pos/runtime.rs`, `pos/reconcile.rs` |
| 3 | Mock payment terminal, mock accounting API, mock delivery platform | `pos/mock.rs` (`MockPaymentTerminal`, `MockAccountingApi`, `MockDeliveryPlatform`, plus `MockTaxAuthority`) |
| 4 | Conformance suite a closed connector must pass | `pos/conformance.rs` (`certify_pos`) |
| 5 | Redacted logging and PCI-safe error handling | `pos/pci.rs`, `observability.rs`, `pos/runtime.rs` |
| 6 | Docs for building a closed connector | `docs/connectors/pos-connector-guide.md` |

## 2. Licence boundary — "a connector can be built without AGPL linkage"

The framework lives in `tirbase-integrations`, which declares `Apache-2.0` and
depends only on crates.io libraries (`serde`, `serde_json`, `sha2`, `hex`, `toml`,
`zeroize`, `reqwest`). It has no `tirbase-*` dependency of any kind, so a closed
connector crate can depend on it and combine it with any licence it likes.

The crate is now a workspace member (`Cargo.toml` `members`), which it previously
was not; without that it could not be built at all, and the `agpl_free` test could
not read its dependency graph from `Cargo.lock`.

Evidence:

- `tirbase-integrations/tests/agpl_free.rs` — walks `Cargo.lock` from the crate,
  refuses any `tirbase-*` direct dependency, refuses a reachable AGPL workspace
  crate, and keeps its denylist honest against `LICENSING.md`;
- `tirbase-integrations/tests/pos14.rs::a_closed_connector_needs_only_the_apache_framework_manifest`
  — re-checks the manifest licence and dependency list for the POS surface;
- `LICENSING.md` lists `tirbase-integrations` as `Apache-2.0`.

## 3. Contracts

One trait, `PosConnector`, with a method group per family and default
implementations returning `Permanent` ("not supported"), so a payments-only
connector implements four methods. `PosConnector::execute(PosOperation)` dispatches
to the group, so the runtime and suite drive every family the same way.

Twelve typed requests cover the families: `AuthorizeRequest`, `CaptureRequest`,
`VoidRequest`, `RefundRequest`, `JournalEntry`, `Invoice`, `CreditNote`,
`DeliveryOrder`, `DeliveryCancel`, `DeliveryStatus`, `TaxQuery`, `TaxVerify`. Each
carries its tenant, business reference and derived idempotency key, and
`PosOperation::validate` is the single invariant gate.

Every attempt returns one `OperationResult` — `Accepted`, `Replayed`, `Retryable`
or `Permanent` — plus the vendor reference, the amount the vendor recorded, an
optional `Retry-After` and a short, secret-free detail.

## 4. Money

Amounts are `Amount { currency, minor }`: integer minor units, three upper-case
letters, never negative. Addition refuses mixed currencies, subtraction refuses a
negative result, multiplication is checked. A refund above the refundable balance,
a capture above the uncaptured remainder and a credit note above its invoice are
refused by the request validator and again by the mocks. There is no floating point
anywhere in the module.

## 5. Idempotency, retries, dead letters

`pos_idempotency_key(connector, kind, reference)` hashes a domain separator, the
connector, the operation kind and the business reference into `pos-` + 32 hex
characters. A retry, a restart or a dead-letter replay presents the same key, so a
correct vendor records one operation.

`PosRuntime` owns the pending queue and the dead-letter queue. `submit` validates,
then deduplicates on the key (`AlreadyQueued`, `AlreadySettled`); `flush` validates
again, calls the connector, logs the attempt, compares the reported amount, and
classifies the consequence:

- `Accepted` / `Replayed` → settled, with the amount the vendor reported (or the
  operation's amount when the family has none);
- `Retryable` → bounded exponential backoff from the `RetryPolicy`, honouring a
  longer `Retry-After`, dead-lettering once the budget is exhausted;
- `Permanent` → dead-lettered immediately with its payload, attempts and key.

`replay` re-enqueues with the same key and refuses a letter whose operation has
since settled, so a replay is a downstream duplicate rather than a second record.

## 6. Configuration and mapping

`ConnectorConfig::from_toml` validates the schema version, connector name, a
non-empty unique family list, an `https` endpoint (plain HTTP only for a loopback
host with explicit `allow_insecure_loopback`), the timeout range, the retry
section, the reconciliation section, every secret reference and the embedded
mapping document. Secrets are references (`env:NAME`, `file:/path`), never values;
a secret named after a card field is refused. The mapping is the shared CC-20 DSL,
so one vocabulary shapes every vendor body.

## 7. PCI-safe handling

- `PaymentMethodToken` wraps an opaque terminal token. `new` accepts 6–64
  `[A-Za-z0-9_.:-]` characters and refuses anything that is all digits or contains
  a 13–19 digit run; `Debug` prints `***`.
- `PosError::Display` runs its message through `scrub_card_data`, so an error
  raised while handling malformed input cannot echo a PAN into a log.
- The runtime scrubs every log detail and stores it through `LogRecord`, which
  already masks credential-shaped fields and never records a payload.
- `contains_card_data` is the shared check: the conformance suite scans every
  result detail it observes (`no-card-data`), and the fixture test fails the build
  if a Luhn-valid 13–19 digit run appears in `src/pos`, the test fixtures, the
  POS-14 tests or these documents.
- The mocks record only tokens, references and amounts: a charge record has no
  instrument field at all.

## 8. Conformance suite

`certify_pos(connector, checked_est)` certifies the families the connector
declares. It is deterministic (every instant is `checked_est`) and returns a
`PosCertificationReport` with named checks, `summary()` for humans and `to_json()`
for CI.

Checks: `identity`, `families`, `idempotent-capability`, `amount-ceiling`,
`health`; payments `authorize`, `amount-echo`, `replay`,
`amount-mismatch-capture`, `amount-mismatch-refund`, `refund`,
`refund-amount-echo`, `void-after-capture-refused`, `tokenizes-card-data`;
accounting `journal-entry`, `journal-replay`, `journal-balance`; e-invoicing
`invoice`, `invoice-total-echo`, `invoice-replay`, `credit-cap`, `credit-note`;
delivery `delivery`, `delivery-replay`, `delivery-cancel`, `delivery-status`; tax
`tax-quote`, `tax-quote-amount`, `tax-verify`, `tax-verify-mismatch`; and
`no-card-data` over every detail observed.

A connector that answers `Accepted` for a repeated key fails `replay`. A connector
that accepts a capture or refund above what it holds fails the corresponding
`amount-mismatch` check. A connector that reports a different amount than it was
asked for fails `amount-echo`. All three are proven in
`tirbase-integrations/tests/pos14.rs`.

## 9. Reconciliation

`ReconciliationSource` is the hook a closed connector implements over the vendor's
settlement report. `reconcile` compares it with the register's settlements and
reports `missing_remote`, `missing_local`, `duplicate_remote`, `amount_mismatch`
(beyond `tolerance_minor`, or a currency difference) and `unsettled` (no vendor
confirmation within `unsettled_after_secs`). The runtime nets payment intents
(captures minus refunds) so a sale with a partial refund reconciles against one
settlement line. Nothing is auto-corrected.

## 10. Evidence

| POS-14 "done when" | Evidence |
|---|---|
| A connector can be built without AGPL linkage | `tirbase-integrations/tests/agpl_free.rs`, `pos14::a_closed_connector_needs_only_the_apache_framework_manifest`, and the crate's Apache-2.0 manifest; the module adds no new dependency |
| The conformance suite rejects replay and amount mismatch | `pos14::the_suite_rejects_a_connector_that_ignores_replay`, `pos14::the_suite_rejects_a_connector_that_accepts_an_amount_mismatch`, `pos14::the_reference_vendor_is_certified_for_all_five_families`, plus the unit tests in `pos/conformance.rs` |
| No card data appears in logs or fixtures | `pos14::tokens_errors_and_logs_never_carry_card_data`, `pos14::no_fixture_or_pos_source_contains_a_luhn_valid_card_number`, the `no-card-data` conformance check, and `pos/pci.rs` unit tests |

Configuration, mapping, runtime, mocks and reconciliation are covered by the rest
of `tests/pos14.rs` (21 tests).

## 11. Limitations

- **In-memory only.** The runtime has no durable store; a host must persist
  `records()`, `dead_letters()` and settlements itself. A crash between a vendor
  acceptance and the host's write loses the local record (the vendor still holds
  the idempotency key, so a replay is a duplicate rather than a second charge).
- **The framework does not talk to any vendor.** It defines, shapes, retries and
  certifies; the transport, auth and vendor payloads are the connector's.
- **Idempotency is only as strong as the vendor.** A vendor that ignores the key
  cannot be certified, and the suite reports it rather than working around it.
- **Reconciliation reports, it does not repair.** No correcting journal, no
  chargeback handling, no settlement file import — those are POS-12 and host work.
- **No PCI DSS scope reduction claim.** Tokens are passed through, not derived;
  whether a deployment is in scope for PCI DSS depends on the terminal SDK and the
  merchant's own controls.
- **No authoritative adapter is included.** The mocks are the reference
  implementations; a production connector must be certified against the vendor's
  sandbox before use.
