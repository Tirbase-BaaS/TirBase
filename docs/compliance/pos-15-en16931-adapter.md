# POS-15 — EN 16931 e-invoicing adapter (implementation record)

Status: prototype implementation record. **Not a compliance claim.** This
document describes what the Apache-2.0 adapter in `tirbase-en16931/` does, what it
deliberately does not do, and how that was verified. Nothing here asserts that any
document it emits is accepted by a tax authority, a national platform or a
business network, and nothing here states a national fiscal requirement.

## Scope

POS-15 asks for six things: a semantic mapping from POS invoice data, UBL and CII
serialization, validation against the official schemas, country-profile extension
points for closed commercial modules, golden invoices, and a CLI/library for batch
export. The acceptance conditions are that all golden invoices validate, that the
adapter is deterministic, and that no country-specific fiscal claim is made.

The adapter is a standalone crate, `tirbase-en16931`, licensed Apache-2.0. It does
not link `tirbase-core`, `tirbase-pos` or any other first-party crate, so a closed
country profile — or a POS product — can embed it without an AGPL edge. Its only
dependencies are `serde`, `serde_json`, `sha2` and `hex`; XML is written and read
by the crate itself (`src/xml.rs`), because a general XML library would have added
a dependency the licence matrix does not carry.

## Semantic model

`model::Invoice` is the EN 16931 core invoice restricted to what a POS sale needs:

- amounts in integer **minor units**, quantities in integer **thousandths**, rates
  in integer **basis points** — no floating point anywhere;
- one rounding step (`round_half_up`) for every division: line gross, line net,
  VAT per category, so a figure cannot drift with operation order;
- totals derived, never stored: BT-106 (line total), BT-107/108 (allowances and
  charges), BT-109 (total without VAT), BT-110 (VAT total), BT-112 (total with
  VAT), BT-115 (payable), and the BG-23 breakdown per category and rate;
- dates as a `Date` computed from epoch seconds with Howard Hinnant's
  civil-from-days algorithm, so no timer, time-zone database or locale is read.

`Invoice::validate` is the single model gate and returns every finding, with rule
identifiers that follow EN 16931 where the check *is* that rule (`BR-02` number,
`BR-03` issue date, `BR-05` currency, `BR-06`/`BR-07` parties, `BR-16` at least one
line, `BR-21` unique line identifier, `BR-25` mandatory line fields, `BR-31`
allowance amount, `BR-55` credit-note preceding invoice) and `MODEL-*` identifiers
for checks that only describe this crate's shape rules.

The POS mapping lives in `pos`: a register invoice (`PosInvoice`) carries the
tenant, number, issue and due instants, seller and buyer, and lines with a VAT
category and rate. `to_invoice` maps it and reports *every* problem at once:

- a document discount is apportioned across the VAT groups it applies to by
  largest-remainder rounding (proportional share floored, remaining minor units to
  the largest fractional parts, ties to the earlier group), so BT-109 still equals
  the sum of the BG-23 taxable bases;
- `refund_of` makes the document a type-381 credit note with a BT-25 reference to
  the invoice it corrects;
- non-standard VAT categories must carry a zero rate; standard-rated lines are the
  only taxed ones;
- dates come from the register's own instants, in UTC, with no lookup.

## Serialization

Two deterministic writers, both following the schema element order of their
syntax:

- `ubl` — UBL 2.1 `Invoice` / `CreditNote` with `cac:`/`cbc:`/`ext:` namespaces,
  `cbc:CustomizationID` `urn:cen.eu:en16931:2017`, UBL monetary totals, per-group
  `cac:TaxSubtotal`, line allowances, and `cbc:CreditedQuantity` on credit notes;
- `cii` — UN/CEFACT CII D16B `rsm:CrossIndustryInvoice` with `ram:`/`udt:`
  namespaces, the guideline context parameter, `ram:BilledQuantity`,
  `ram:ApplicableTradeTax` per group, `SpecifiedTradeAllowanceCharge` at both
  levels, the header monetary summation and `InvoiceReferencedDocument` for a
  credit note.

Output is fixed: XML declaration, two-space indentation, `\n` line endings,
attributes in the order written, amounts with exactly two decimals, percentages
with two decimals, dates as `YYYY-MM-DD` (UBL) or `YYYYMMDD` with `format="102"`
(CII), and every collection in a stable order (categories by code then rate, lines
by input order, documents by number).

## Validation

`validate::validate_document` parses the document back from its bytes and checks:

1. well-formedness (the crate's own strict reader);
2. root element, namespace declarations and the specification identifier;
3. requirement and **element order** against the schema sequence, with unknown or
   out-of-order elements reported (`XML-SEQ-01`, `XML-SEQ-02`);
4. datatypes and code lists — two-decimal amounts, three-decimal quantities,
   unit codes, two-digit payment means, ISO 3166-1 country codes, VAT category
   codes, document type codes — and that every `currencyID` equals BT-5;
5. **every figure against the model**: totals, VAT subtotals, line net amounts,
   unit prices, quantities, rates, party details, due date, and the precedent
   references on a credit note (`XML-FIG-*`, `XML-CARD-*`).

### Limitation, stated plainly

The official UBL 2.1 and CII D16B schema files are **not** vendored in this
repository, so this module does not run an XSD validator. It enforces the
structure those schemas require and the figures the model computed; it does not
prove schema validity to a schema-aware processor. Validating an exported document
against the published XSDs (and against the extra rules of whichever network
receives it) remains a deployment step and is the receiving side's requirement,
not a claim made here. The module documentation says the same thing, and a test
asserts the crate's own documents pass every check it does perform.

## Country profiles

`profiles::CountryProfile` is the **only** place country logic may live. A profile
is a closed commercial module that links the crate and implements four hooks:

- `customization_id()` — BT-24 (UBL `cbc:CustomizationID`, CII guideline
  `ram:ID`), so a national specification replaces the core identifier;
- `profile_id()` — BT-23 (UBL `cbc:ProfileID`);
- `extension(invoice)` — content for the standard UBL `ext:UBLExtensions`
  container, with the namespace the profile needs;
- `validate(invoice)` and `wrap(syntax, document)` — national rules, and a final
  pass over the finished core document, which is where national elements,
  identifiers or signatures belong (CII included).

Profiles are registered by identifier and looked up by name, so a host selects one
with `--profile <id>`. The crate ships exactly one, `en16931-core`, which adds no
rule and keeps the core identifier. `tests/golden.rs` proves the core documents
contain no URL, no platform identifier, no profile element and no national regime
name, and scans every source module to prove the crate itself names no national
regime.

**No country-specific fiscal claim is made.** The adapter emits no verification
URL, fiscal code, QR content, qualified signature, national schema identifier or
national tax rule. Whether a document satisfies any national requirement is a
question only a profile can answer, and no profile is part of this repository.

## Golden invoices

`tirbase-en16931/golden/` holds four register inputs and the exact bytes they
produce:

| Case | Input | What it pins down |
|---|---|---|
| Tax | `tax.json` | three VAT categories, two standard rates (21 %, 10 %), a zero-rated line, email endpoints, buyer reference, due date |
| Discount | `discount.json` | a line discount, plus a 3.00 document discount apportioned over three VAT groups (1.50 / 0.60 / 0.90) |
| Refund | `refund.json` | a credit note correcting `GOLDEN-TAX-1`, with BT-25 and `CreditNoteLine`/`CreditedQuantity` |
| Rounding | `rounding.json` | half-up VAT (12.90 → 2.71), a 5.00 prepayment and a −0.01 cash rounding, so BT-115 is 10.60 |

Each case is committed as `<number>.ubl.xml` and `<number>.cii.xml` under
`golden/expected/`, produced by the crate itself. The test re-serializes, compares
bytes, and re-validates both documents, so a serialization change is a visible,
reviewable change to a golden file rather than silent drift.

## Batch export and CLI

`batch::export` takes a batch file, an output directory, a syntax list and an
optional profile. It writes `<number>.<syntax>.xml` plus `manifest.json` recording
the syntax, file name, SHA-256 and size of every file, the document type and
currency, and every refused document with its reasons. A document is validated
before it is written, so the output directory never contains an e-invoice that
failed validation; a duplicate file stem or a duplicate number is refused rather
than overwriting. The manifest carries no timestamp and every list is sorted, so a
re-run produces byte-identical files and a byte-identical manifest (a test proves
this with two exports into separate directories).

The `en16931` binary exposes the library:

```console
$ en16931 export --input batch.json --output out --format both
$ en16931 validate --input batch.json
$ en16931 validate --xml out/GOLDEN-TAX-1.ubl.xml --syntax ubl --input batch.json --number GOLDEN-TAX-1
$ en16931 version
```

Exit status is 0 when every document is valid, 1 when one is not, and 2 for a
usage error.

## Determinism

Nothing in the crate reads the clock, the environment, the locale, the filesystem
ordering or a random source. Every figure is integer arithmetic through one
half-up step, every collection is ordered (`BTreeMap`/`BTreeSet`/sorted vectors),
and every date is derived from an instant the caller supplies. Serializing the
same invoice twice yields the same bytes, and two batch exports of the same input
yield the same files and the same manifest — both asserted by tests.

## Verification

```console
$ cargo fmt -p tirbase-en16931 --check
$ cargo clippy -p tirbase-en16931 --all-targets -- -D warnings
$ cargo test -p tirbase-en16931
```

The test suite is the crate's unit tests (model arithmetic and dates, XML writer
and reader, discount apportionment, both serializers, profile registration,
validation datatypes and tamper detection, file naming), `tests/golden.rs`
(golden bytes and validation, determinism, no-national-claim scan, closed-profile
extension), and the crate's documentation examples.

## Out of scope

- any national profile, national identifier, verification URL, QR content or
  signature scheme;
- schema validation by an XSD processor against the published UBL/CII schemas
  (the documents are built to the schema order, and the limitation is documented);
- transport to a receiving platform, acknowledgement handling, and any claim about
  whether a platform accepts a document;
- fiscal reporting, receipt printing or the register's own numbering and tax
  engine (POS-10 owns those; this adapter consumes their output);
- payment, settlement and reconciliation (POS-12, POS-14).

## Files

- `tirbase-en16931/src/model.rs` — semantic model, dates, totals, model rules.
- `tirbase-en16931/src/pos.rs` — register input and the mapping.
- `tirbase-en16931/src/ubl.rs`, `src/cii.rs` — serializers.
- `tirbase-en16931/src/xml.rs` — deterministic writer and strict reader.
- `tirbase-en16931/src/validate.rs` — rules, structure, figures, datatypes.
- `tirbase-en16931/src/profiles.rs` — the country-profile extension point.
- `tirbase-en16931/src/batch.rs` — batch export and manifest.
- `tirbase-en16931/src/main.rs` — the `en16931` binary.
- `tirbase-en16931/golden/` — golden inputs and expected documents.
- `tirbase-en16931/tests/golden.rs` — the acceptance tests.
- `docs/connectors/en16931-export-guide.md` — usage guide.
