# Building a closed POS connector

This guide is for a vendor or systems integrator writing a **closed** (proprietary)
POS connector against TirBase. The connector links `tirbase-integrations`, which
is Apache-2.0 and reaches no AGPL crate, so a closed connector can be built,
shipped and audited without the AGPL runtime or its source obligations. The
dependency proof is `tirbase-integrations/tests/agpl_free.rs`, which walks
`Cargo.lock` and refuses any `tirbase-*` dependency.

- Framework: `tirbase-integrations/src/pos/` (`contract`, `runtime`, `mock`,
  `conformance`, `config`, `reconcile`, `pci`).
- Conformance suite: `tirbase_integrations::pos::certify_pos`.
- Reference implementations: the four mocks in `pos::mock`.

## 1. The surface you implement

One trait, five family groups. Implement the methods for the families you serve
and leave the rest to their defaults (they answer `Permanent`, "not supported"):

| Family | Methods | Request type |
|---|---|---|
| Payments | `authorize`, `capture`, `void`, `refund` | `AuthorizeRequest`, `CaptureRequest`, `VoidRequest`, `RefundRequest` |
| Accounting | `post_entry` | `JournalEntry` (`JournalLine`, `Direction`) |
| E-invoicing | `issue_invoice`, `credit_note` | `Invoice` (`InvoiceLine`), `CreditNote` |
| Delivery | `create_delivery`, `cancel_delivery`, `delivery_status` | `DeliveryOrder`, `DeliveryCancel`, `DeliveryStatus` |
| Tax | `quote_tax`, `verify_tax` | `TaxQuery` (`TaxQueryLine`), `TaxVerify` |

Also declare `name()`, `capabilities()` and `health()`. `capabilities()` lists the
families you actually implement, whether you are idempotent (you must be), whether
you only ever receive opaque tokens (`tokenizes_card_data`), your largest single
amount and your currencies. The suite checks all four.

`PosConnector::execute` dispatches a `PosOperation` to the right method; you get
it for free and the runtime and suite use it.

## 2. Say what actually happened

Every attempt returns one `OperationResult`:

| Outcome | Meaning |
|---|---|
| `Accepted` | The vendor recorded the operation. |
| `Replayed` | The vendor already had this idempotency key; nothing new was recorded. |
| `Retryable` | A transient failure (timeout, 429, 5xx). The runtime backs off and tries again. |
| `Permanent` | A refusal (decline, validation, 4xx, unknown reference). The runtime dead-letters it. |

Lying in either direction breaks the contract: `Retryable` for a decline burns the
retry budget, and `Accepted` for a rejection loses the sale. Set `amount` to the
amount the vendor recorded, `reference` to its identifier, and `detail` to a short,
secret-free explanation. Add `with_retry_after` when the vendor sends one.

## 3. Validate before you call the vendor

Call `operation.validate()` (or the equivalent checks for the request type) before
touching the network and return `Permanent` on failure. The conformance suite
hands your connector malformed operations directly — an over-capture, an
unbalanced journal, an invoice with a zero quantity — and requires a refusal. The
runtime validates again before every attempt, so a bug here is caught twice.

Rules the framework enforces for you:

- amounts are integer minor units in one currency per operation; no floats;
- a refund needs a non-negative amount and a non-empty reason;
- a journal entry needs at least two lines whose debits equal their credits;
- an invoice needs at least one line with a whole quantity and a unit price;
- idempotency keys are `pos-` plus 32 hex characters and are derived, never
  supplied by the caller.

## 4. Idempotency

The key is `pos_idempotency_key(connector, kind, reference)`, hashed from the
connector name, the operation kind (`authorize`, `capture`, `refund`,
`journal-entry`, `invoice`, `credit-note`, `delivery`, `tax-quote`, …) and the
business reference (payment intent, journal reference, invoice number, order).
Send it to the vendor as `Idempotency-Key` (or the vendor's equivalent) and treat
the vendor's duplicate response as `Replayed`.

The runtime also dedupes locally for the life of its state, so a retry inside one
process never reaches you twice; but the vendor-side contract still matters,
because a restart, a second terminal or a replay after a crash will present the
key again. A connector that accepts the same key twice fails the suite's `replay`
check.

## 5. Amount integrity

The runtime compares the amount you report with the amount the operation asked
for. A mismatch is a protocol violation: the operation is dead-lettered, the
result is never settled, and an `IntegrityViolation` is recorded for
reconciliation. So:

- echo the authorised/captured/refunded amount exactly;
- refuse a capture above the uncaptured remainder;
- refuse a refund above the captured-minus-refunded balance;
- refuse to void an authorisation that has already been captured.

The suite's `amount-echo`, `amount-mismatch-capture` and
`amount-mismatch-refund` checks fail a connector that sweeps a different figure.

## 6. Configuration

A connector is configured by one TOML document (see
`tirbase-integrations/tests/fixtures/pos-connector.toml`):

```toml
schema_version = 1
connector = "acme-pos"
families = ["payment", "accounting", "einvoicing", "delivery", "tax"]
endpoint = "https://pos.acme.example/v1"
timeout_ms = 4000

[retry]
max_attempts = 4
base_delay_secs = 3
factor = 2
max_delay_secs = 60

[reconciliation]
enabled = true
interval_secs = 900
tolerance_minor = 0
unsettled_after_secs = 1800

[[secret]]
name = "api_key"
from = "env:ACME_POS_API_KEY"

[mapping]
schema_version = 1

[[mapping.field]]
target = "payment.amount_minor"
source = "payload.amount_minor"
required = true
```

`ConnectorConfig::from_toml` rejects: an unsupported schema version, a missing or
duplicate family, a non-`https` endpoint (plain HTTP only for a loopback host with
`allow_insecure_loopback = true`), a URL carrying credentials, a timeout outside
the accepted range, a short reconciliation interval, a malformed secret reference,
a card-data-shaped secret name and an invalid mapping document.

Secrets are **references**, never values: `env:NAME` or `file:/path`. A
configuration file is safe to commit and safe to paste into a ticket.

The mapping DSL is the shared one (`crate::mapping`): `schema_version = 1`,
`[[field]]` with `target`, `source`, `required`, `default` and `transform`
(`identity`, `trim`, `lowercase`, `uppercase`, `string`), resolved against
`{event, payload}` with dot paths and array indexes, producing nested JSON for the
vendor body. `config.apply_mapping(&context)` returns the shaped payload.

## 7. Retries, dead letters and replay

Run every operation through `PosRuntime`:

```rust
use tirbase_integrations::pos::{PosRuntime, PosOperation};
use tirbase_integrations::retry::RetryPolicy;

let mut runtime = PosRuntime::new(connector).with_retry_policy(RetryPolicy::new(5, 5, 2, 300));
let submission = runtime.submit(operation, now_est)?;
let report = runtime.flush(now_est);          // attempt everything due
let letter = &runtime.dead_letters()[0];      // permanent failure or exhausted budget
runtime.replay(&letter.dlq_id, now_est + 60)?; // same key, no duplicate downstream
```

Behaviour you can rely on:

- backoff is bounded exponential, computed from the attempt count, with the
  vendor's `Retry-After` honoured when it is longer;
- a permanent failure or an exhausted budget moves the operation to the dead
  letter with its payload, attempts and idempotency key;
- replay re-enqueues with the **same** key and is refused once the operation has
  settled, so it cannot duplicate a charge, entry, invoice or job;
- `records()`, `dead_letters()`, `logs()` and `metrics()` are plain data a host can
  persist; nothing here reads the clock.

## 8. Reconciliation

Implement `ReconciliationSource` over the vendor's settlement report:

```rust
impl ReconciliationSource for AcmePos {
    fn settlements(&self, tenant: &str) -> Vec<RemoteSettlement> { /* … */ }
}
```

Then either call `runtime.reconcile(tenant, &connector, &policy, now)` or the pure
`reconcile(tenant, &local, &remote, &policy, now)` with your own local lines.
Payment intents are netted (captures minus refunds) so the local side matches a
settlement line; other families use their latest settled amount. The report names
`missing_remote`, `missing_local`, `duplicate_remote`, `amount_mismatch` and
`unsettled` references with both amounts. It never corrects anything — a
discrepancy is a human decision.

## 9. PCI: tokens only, no card data anywhere

- The framework models the instrument as `PaymentMethodToken`, an opaque token
  produced by your terminal SDK. Never accept, store, log or transmit a PAN,
  expiry, CVV or track data. `PaymentMethodToken::new` refuses a PAN-shaped value,
  and `validate` refuses one that arrives through a hand-built request.
- Put the token in the request and send it to the vendor as the vendor's token; do
  not derive anything from it.
- Return `detail` strings that name the failure, not the instrument:
  `"declined by issuer (05)"`, never anything from the card.
- If you must quote a vendor message, run it through `scrub_card_data` first.
  `PosError`'s `Display` does this already, and the runtime scrubs every log
  record. `contains_card_data` is the check the suite and the fixture test use.
- Never put a card number in a test, a fixture, a screenshot or a config file. The
  fixture test fails the build if a Luhn-valid 13–19 digit run appears in the POS
  sources, fixtures or this documentation.

## 10. Certify

```rust
use tirbase_integrations::pos::certify_pos;

let report = certify_pos(&connector, now_est);
assert!(report.certified, "{:?}", report.failures());
println!("{}", report.summary());
```

Point the suite at the mocks while you develop and at the vendor sandbox before
you ship. It checks, per family you declare:

| Check | What it proves |
|---|---|
| `identity`, `families`, `idempotent-capability`, `amount-ceiling`, `health` | The connector is describable and honest about itself. |
| `authorize`, `capture`, `refund` | The happy path settles. |
| `amount-echo`, `refund-amount-echo`, `invoice-total-echo`, `tax-quote-amount` | The vendor's reported figure is the requested figure. |
| `replay`, `journal-replay`, `invoice-replay`, `delivery-replay` | The same idempotency key twice is a duplicate, not a second record. |
| `amount-mismatch-capture`, `amount-mismatch-refund`, `credit-cap`, `journal-balance` | Over-capture, over-refund, over-credit and an unbalanced journal are refused. |
| `void-after-capture-refused` | A captured authorisation is not voidable. |
| `delivery`, `delivery-cancel`, `delivery-status` | The delivery lifecycle works. |
| `tax-quote`, `tax-verify`, `tax-verify-mismatch` | A quote is confirmed and a different total is refused. |
| `no-card-data` | No result detail contains a card-number-shaped run. |

A failure names the check and shows what was expected and what the connector
answered (`report.to_json()` is the machine-readable form for CI).

## 11. Checklist

- [ ] `PosConnector` implemented for the families you serve; other methods left at
      their defaults.
- [ ] `operation.validate()` (or equivalent) before every vendor call, `Permanent`
      on failure.
- [ ] Derived idempotency key sent to the vendor; duplicate responses reported as
      `Replayed`.
- [ ] Reported amounts equal requested amounts; over-capture, over-refund,
      over-credit and unbalanced journals refused.
- [ ] Only opaque tokens accepted; no card data in requests, results, logs,
      fixtures or documentation.
- [ ] `ReconciliationSource` implemented over the vendor's settlement report.
- [ ] `ConnectorConfig` document validates; secrets are `env:`/`file:` references.
- [ ] `certify_pos` passes against the mocks and against the vendor sandbox.
- [ ] `tests/agpl_free.rs` still passes: the connector adds no first-party
      dependency to the framework crate.

## 12. Limitations

- The runtime is in-memory. A host must persist `records()`, `dead_letters()` and
  the settled map to survive a restart; the framework does not ship a database.
- Idempotency is only as strong as the vendor's: a vendor that ignores the key
  cannot be certified, and the suite will say so.
- Reconciliation compares the register's view with a settlement report the
  connector supplies. It does not page anyone, retry a settlement or post a
  correcting entry.
- The framework carries no card data, so it also cannot perform card-present
  operations that require PAN-derived values; those belong in the terminal SDK.
