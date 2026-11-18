# POS-10 — Tax, localization, receipts and invoice numbering (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-10 is domain-model engineering permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, moves no money, and has no persistence, fiscal module or terminal
> connectivity. The rates in its tests are reference cases, not legal rates.

**Record ID:** POS-10-TAX-RECEIPT-0001
**Date (UTC):** 2026-11-17
**Licence:** `AGPL-3.0-only`
**Crate:** `tirbase-pos`
**Depends:** POS-00, POS-01, POS-04
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

Implemented in the open tree:

| # | Requirement | Where |
|---|---|---|
| 1 | Inclusive/exclusive, compound, exempt, zero-rated tax with rounding | `tirbase-pos/src/tax.rs` |
| 2 | Jurisdiction and product-tax applicability | `TaxProfile`, `TaxClassification`, `CatalogItem` |
| 3 | Receipt rendering with legal fields, reprints and print/email hooks | `tirbase-pos/src/receipt.rs` |
| 4 | Invoice numbering with gapless or documented gap policy | `tirbase-pos/src/numbering.rs` |
| 5 | Localized currency, date, number and language labels | `tirbase-pos/src/localization.rs` |
| 6 | Golden tests per reference jurisdiction | `tirbase-pos/tests/pos10.rs` |

Deliberately not added:

- No jurisdiction default, statutory rate table, tax holiday, fiscal signature,
  fiscal printer integration, certification claim or archival guarantee.
- No claim that a filled-in field set is legally sufficient in any country. The
  receipt layout is a plain-text engineering reference; a deployment must supply
  its own published requirements and legal review.
- No card data, processor integration or acquirer settlement.
- No persistent database, email provider, printer transport or timezone
  database. `ReceiptOutput` is a hook; the replacement is caller-supplied.
- No ABA/reference-number reuse mechanism. The register only moves forward.

Licence remains `AGPL-3.0-only`; the crate remains non-production under POS-00.

## 2. Tax engine

`TaxEngine` is configured with a `TaxPricing` convention, an explicit
`RoundingMode`, and an ordered list of `TaxComponent`s. A `TaxComponent` has an
identifier, a `Rate` in parts per million, and a `compounding` flag.

The ordering rule is structural: a non-compounding component may not follow a
compounding one. A compounding component is charged on `net + all earlier tax`;
a non-compounding component is charged on `net`. This makes the common
"GST then QST on GST" sequence explicit and prevents a caller from inventing an
arbitrary grouping. Duplicate component ids, more than `MAX_TAX_COMPONENTS`, and
an invalid order are rejected before any arithmetic.

| Convention | Input | Output |
|---|---|---|
| `TaxPricing::Exclusive` | Net | `gross = net + sum(tax)` |
| `TaxPricing::Inclusive` | Gross | Extracts net, then `net + tax = gross` exactly |

Inclusive extraction reverses the component order:

1. Undo compounding components from last to first by dividing by
   `1 + rate`.
2. Divide once by `1 + sum(non-compounding rates)`.
3. Recompute the component rows forward from the extracted net.
4. Apply any per-component rounding residual to the final component.

The residual is reported in `TaxBreakdown::rounding_adjustment`; it is not
hidden. `TaxBreakdown` exposes the treatment, pricing, net, tax, gross, component
rows and each row's taxable base.

`TaxTreatment::ZeroRated` and `TaxTreatment::Exempt` both collect zero tax, but
remain distinct in the result and never fall back to the standard components.
`TaxTreatment::Standard` is the only taxable treatment.

### Applicability

`TaxProfile` combines a `JurisdictionId`, one currency, one engine and a list of
`TaxClassification`s. Each classification maps a POS-04 `TaxApplicability` to a
treatment. Resolution precedence is:

1. exact `Item(CatalogItemId)`;
2. `Category(String)`;
3. `All`.

A product with no match uses `Standard`. Duplicate applicability entries are
rejected as ambiguous. The profile is a value object; it contains no clock,
effective-date store or built-in rate table.

## 3. Localization

`Locale` is a validated value object containing:

- a language tag;
- decimal and grouping separators, grouping style;
- currency-code placement and spacing;
- date order, date separator and 12/24-hour clock;
- a fixed UTC offset;
- a `ReceiptLabels` set.

`format_money` always prints the ISO currency code and uses integer minor units;
`format_rate` prints a rate as a percentage without floats; `format_quantity`
formats thousandths and trims trailing zeros; `format_number` applies Western,
Indian or no grouping. `format_date`, `format_time` and `format_datetime` convert
the caller-supplied UTC `Timestamp` using the configured fixed offset. This is
display formatting, not timezone conversion: DST transitions and an IANA
timezone database are out of scope.

Labels are keyed by `ReceiptLabel`; English, German and French sets are
provided. `ReceiptLabel` includes the legal-field labels, payment labels and
AM/PM markers. Unknown or empty labels cannot be inserted through the public
constructor.

## 4. Receipt rendering

`ReceiptDocument` requires:

- a `Merchant` legal name, 1-4 address lines and tax registration;
- the allocated `InvoiceNumber`;
- issue timestamp, terminal, operator and transaction reference;
- one or more item lines;
- `ReceiptTotals`, whose total and change are derived from subtotal, discount,
  tax, tip and paid;
- a `TaxBreakdown` whose net and tax equal the post-discount subtotal and tax
  total;
- one or more tender lines that sum to `paid`.

Construction rejects missing, malformed or cross-currency fields. `validate`
rejects an incomplete document before rendering, so an invalid document cannot
be printed or emailed.

The renderer includes the seller identity, tax registration, invoice number,
localized date/time, terminal/operator/reference, item lines, subtotal,
discount, tax component rows, tip, total, payment lines, paid and change, plus
an optional wrapped footer. For zero-rated or exempt sales the tax line names
the treatment instead of pretending a standard rate was charged.

`ReceiptCopy::Original` is the default. `ReceiptDocument::as_reprint(count)`
requires a positive count and sets `ReceiptCopy::Reprint`. Rendering then emits
`*** REPRINT #n ***` as the first line. The same invoice number is retained; no
register call is made by rendering. Both the print and email hooks receive the
same `RenderedReceipt`, including that marker.

### Delivery hooks

`ReceiptOutput` has two methods:

| Method | Meaning |
|---|---|
| `print(&RenderedReceipt)` | Hand the document to a printer/print queue |
| `email(&RenderedReceipt, &EmailAddress)` | Hand it to an email transport |

`EmailAddress` checks syntax only (one `@`, non-empty local part, dotted domain,
bounded length); it does not prove deliverability. A transport reports failure
as `ReceiptError::DeliveryFailed`; the crate never reports a document as
delivered on its own. No printer or mail provider is bundled.

## 5. Invoice numbering

`InvoiceRegister` owns a series, a fixed zero-padding width, a start sequence and
one of two gap policies.

| Policy | `issue` | `record_gap` |
|---|---|---|
| `Gapless` | Allocates the next number | Rejected; consumes nothing |
| `Documented` | Allocates the next number | Consumes the next number and records reason + time |

A number returned by `issue` is appended to the issued ledger and the internal
sequence advances. There is no set-next, rollback or reissue API. A reprint calls
`mark_reprinted` with the existing number, which only increments a reprint count
and rejects a number absent from the issued ledger.

`from_ledger` restores a persisted issued/gap ledger and derives the next
sequence. It rejects:

- duplicate issued or gap numbers;
- an issued number that also appears as a gap;
- a series/width mismatch;
- a gapless ledger containing a gap;
- an undocumented hole between the start and the last recorded sequence.

The constructor is only a consistency check. Durable, atomic persistence of the
issued/gap records remains the deployment's responsibility; an in-memory counter
is not a durability guarantee and POS-10 does not claim one.

## 6. Golden reference cases

The tests use reference cases to pin arithmetic, not to assert current law. Each
profile is supplied by the test; no default is compiled into the crate.

| Reference | Pricing | Components | Input | Expected |
|---|---|---|---|---|
| US-CA style | Exclusive | CA 8.25% | 100.00 USD net | 8.25 tax, 108.25 gross |
| GB style | Inclusive | VAT 20% | 120.00 GBP gross | 100.00 net, 20.00 tax |
| CA-QC style | Exclusive | GST 5%, QST 9.975% compounding | 100.00 CAD net | 5.00 GST, 10.50 QST base, 10.47 QST, 115.47 gross |
| AU style | Inclusive | GST 10% | 110.00 AUD gross | 100.00 net, 10.00 tax |
| DE style | Inclusive | VAT 19% | 19.95 EUR gross | 16.76 net, 3.19 tax, +0.01 residual applied |

The final case deliberately exercises the one-minor-unit residual correction.
Zero-rated and exempt cases run under both pricing conventions and assert zero
tax while retaining the treatment and component rows.

## 7. Acceptance evidence

| POS-10 "done when" | Evidence |
|---|---|
| Tax totals match reference cases | `golden_us_ca_exclusive_sales_tax`, `golden_gb_vat_inclusive`, `golden_quebec_compound_gst_qst`, `golden_australia_gst_inclusive_and_rounding_residual` |
| A reprint is marked as a reprint | `reprint_is_visibly_marked_and_does_not_allocate_a_number`, `print_and_email_hooks_receive_the_same_marked_document` |
| Invoice numbering cannot silently reuse a number | `gapless_register_refuses_to_consume_a_number`, `documented_gap_is_recorded_and_restored_without_reuse`, `reprint_uses_existing_number_and_next_issue_remains_unique` |

Supporting evidence:

- `zero_rated_and_exempt_keep_breakdown_and_collect_nothing`
- `compound_components_must_precede_simple_ones`
- `profile_applies_item_category_then_all_precedence`
- `localization_formats_money_dates_numbers_and_language`
- `localization_rejects_ambiguous_or_unsafe_configuration`
- `receipt_has_legal_fields_and_localized_tax_line`
- `invalid_receipt_is_rejected_before_rendering`

Run: `cargo test -p tirbase-pos --test pos10`.

## 8. Known limits / next

- Rates, tax registrations and receipt wording are caller data. There is no
  statutory table, effective-date resolver or legal review in this record.
- Rounding is per component with an explicit residual correction. It does not
  model jurisdiction-specific invoice-level rounding rules or cash rounding.
- Localization covers UTF-8 text labels, separators, grouping, currency-code
  placement and a fixed UTC offset. It does not provide translations for
  arbitrary languages, pluralization, right-to-left layout, timezone/DST
  resolution or printer code pages.
- The plain-text renderer is 32 columns. It is not a fiscal layout, a PDF, an
  ESC/POS job or a signed archive; the existing POS-07 printer path is separate.
- `ReceiptOutput` is only a hook. Transport retries, delivery receipts, address
  verification, bounce handling and provider credentials are deployment work.
- The invoice ledger is in-memory and serialized by its caller. Atomic
  persistence, crash recovery, multi-terminal coordination and fiscal authority
  reporting are not implemented. `from_ledger` validates a supplied ledger but
  cannot make a non-atomic write durable.
- Reprint counts are kept in the register and are not part of `from_ledger`
  restore; a deployment that needs durable audit of every copy must persist
  those marks itself.
- No certification, fiscal signature, legal-numbering validation or tax-authority
  submission is claimed.
