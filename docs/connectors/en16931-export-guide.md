# EN 16931 export guide

`tirbase-en16931` (Apache-2.0) turns POS register invoices into EN 16931
e-invoices and validates them. It is a library plus the `en16931` binary, and it
links no first-party crate, so it can be embedded in a closed POS product or
wrapped by a closed country profile.

This guide covers the two ways to use it. For what the adapter does and does not
claim, see `docs/compliance/pos-15-en16931-adapter.md`; in short, it writes the
**EN 16931 core** document and makes no national fiscal claim.

## Batch file

A batch is one JSON document with an `invoices` array. Each invoice is the shape a
POS register already holds: whole quantities, prices in minor units, a VAT
category and rate in basis points, and the payment that settled the sale.

```json
{
  "invoices": [
    {
      "tenant": "acme",
      "number": "INV-2026-0001",
      "issued_est": 1767225600,
      "due_est": 1769904000,
      "currency": "EUR",
      "seller": {
        "name": "Acme Coffee SL",
        "trading_name": "Acme Coffee",
        "vat_id": "ESA12345674",
        "legal_id": "B87654321",
        "legal_scheme": "ES:NIF",
        "line1": "Calle Mayor 1",
        "city": "Madrid",
        "postcode": "28013",
        "country": "ES",
        "endpoint": "billing@acme.example",
        "endpoint_scheme": "EM"
      },
      "buyer": {
        "name": "Beta Bakery SL",
        "vat_id": "ESB87654321",
        "line1": "Calle Menor 2",
        "city": "Madrid",
        "postcode": "28014",
        "country": "ES"
      },
      "lines": [
        {
          "description": "Espresso beans 1 kg",
          "quantity": 2,
          "unit_price_minor": 1290,
          "vat_category": "standard",
          "vat_rate_bp": 2100,
          "discount_minor": 100
        },
        {
          "description": "Sourdough bread",
          "quantity": 3,
          "unit_price_minor": 250,
          "vat_category": "zero",
          "vat_rate_bp": 0
        }
      ],
      "document_discount_minor": 200,
      "prepaid_minor": 0,
      "rounding_minor": -1,
      "payment_code": "30",
      "payment_instruction": "SEPA credit transfer",
      "payment_reference": "INV-2026-0001",
      "buyer_reference": "PO-42",
      "note": "Delivered to the rear entrance.",
      "refund_of": null
    }
  ]
}
```

Fields:

| Field | Meaning |
|---|---|
| `tenant` | register tenant; used for grouping only and never serialized |
| `number` | document number (BT-1), at most 64 characters |
| `issued_est`, `due_est` | issue and due instants in epoch seconds; dates are derived in UTC |
| `currency` | ISO 4217 code (BT-5) |
| `seller`, `buyer` | party name, optional trading name / VAT id / legal id and scheme / electronic address and scheme, and a postal address whose country is an ISO 3166-1 alpha-2 code |
| `lines[].quantity` | whole quantity; the model stores thousandths |
| `lines[].unit_price_minor` | net unit price in minor units |
| `lines[].vat_category` | `standard`, `zero`, `exempt`, `reverse_charge`, `intra_community`, `export` or `outside_scope` |
| `lines[].vat_rate_bp` | rate in basis points (`2100` is 21 %); anything except `standard` must be zero |
| `lines[].unit_code` | UN/ECE Recommendation 20 code, default `C62` (unit) |
| `lines[].discount_minor` | line discount in minor units |
| `document_discount_minor` | invoice-level discount, apportioned over the VAT groups |
| `prepaid_minor` | amount already paid (BT-113) |
| `rounding_minor` | cash rounding of the payable amount (BT-114), may be negative |
| `payment_code` | UN/ECE 4461 payment means code, e.g. `30` credit transfer, `10` cash |
| `payment_reference`, `buyer_reference`, `note` | BT-83, BT-10, BT-22 |
| `refund_of` | the invoice this document corrects; presence makes it a credit note (381) |

Every object rejects unknown fields, so a misspelled key fails instead of being
ignored.

## Command line

```console
$ cargo run -p tirbase-en16931 --bin en16931 -- export \
    --input batch.json --output out --format both

wrote 1 document(s), 2 file(s), 14914 bytes into out
manifest: out/manifest.json (14914 bytes)
```

`--format` is `ubl`, `cii` or `both` (default `both`). The output directory gets
`<number>.ubl.xml` and `<number>.cii.xml` — characters outside `A-Za-z0-9.-_`
become `-` — plus `manifest.json`:

```json
{
  "generator": "tirbase-en16931 0.1.0",
  "specification": "urn:cen.eu:en16931:2017",
  "documents": [
    {
      "number": "INV-2026-0001",
      "document_type": "invoice",
      "currency": "EUR",
      "files": [
        {
          "syntax": "cii",
          "name": "INV-2026-0001.cii.xml",
          "sha256": "…",
          "bytes": 6912
        }
      ]
    }
  ],
  "failures": []
}
```

A document that fails mapping or validation is listed under `failures` with its
reasons and is **not** written. The manifest has no timestamp and every list is
sorted, so re-exporting unchanged input produces byte-identical output.

Validation without writing anything:

```console
$ en16931 validate --input batch.json
UBL 2.1 INV-2026-0001 ubl: valid
CII D16B INV-2026-0001 cii: valid
2 document(s) checked, 0 invalid
```

Validating a file someone else sent, against the invoice it must represent:

```console
$ en16931 validate --xml out/INV-2026-0001.ubl.xml --syntax ubl \
    --input batch.json --number INV-2026-0001
UBL 2.1 INV-2026-0001: valid
```

Exit status: `0` all valid, `1` at least one invalid document or refused invoice,
`2` usage error.

`en16931 version` prints the crate version, the specification identifier and the
registered profiles.

## Library

```rust,ignore
use tirbase_en16931::batch;
use tirbase_en16931::pos::PosInvoiceFile;
use tirbase_en16931::validate::Syntax;

fn export(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let file = PosInvoiceFile::from_json(&text)?;
    let formats = [Syntax::Ubl, Syntax::Cii];
    let report = batch::export(&file, std::path::Path::new("out"), &formats, None)?;
    assert!(report.complete());
    Ok(())
}
```

Mapping one invoice without touching the filesystem:

```rust
use tirbase_en16931::pos::PosInvoiceFile;
use tirbase_en16931::ubl;
use tirbase_en16931::validate::{validate_document, Syntax};

let file = PosInvoiceFile::from_json(&text)?;
let invoice = file.invoices[0].to_invoice().expect("mapped");
let document = ubl::serialize(&invoice);
let report = validate_document(&document, &invoice, Syntax::Ubl);
assert!(report.valid, "{}", report.render());
```

Rules and their identifiers are available without a document:
`invoice.validate()` and `tirbase_en16931::validate::validate_model(&invoice)` return
`ValidationIssue { rule, path, message, fatal }`.

## Embedding a country profile

A national profile is a closed module. It links the crate and implements the
trait; the core never learns about it:

```rust
use tirbase_en16931::model::{Invoice, ValidationIssue};
use tirbase_en16931::profiles::{self, CountryProfile, Extension};
use tirbase_en16931::validate::Syntax;

struct National;

impl CountryProfile for National {
    fn id(&self) -> &'static str {
        "national"
    }
    fn description(&self) -> &'static str {
        "Closed national profile"
    }
    fn customization_id(&self) -> &'static str {
        "urn:example:national:1"
    }
    fn profile_id(&self) -> Option<&'static str> {
        Some("urn:example:national:process")
    }
    fn extension(&self, _invoice: &Invoice) -> Option<Extension> {
        Some(Extension::new("nat", "urn:example:national:1", "Stamp").with_child("nat:ID", "S-1"))
    }
    fn validate(&self, _invoice: &Invoice) -> Vec<ValidationIssue> {
        Vec::new()
    }
    fn wrap(&self, _syntax: Syntax, document: String) -> Result<String, String> {
        Ok(document)
    }
}

static NATIONAL: National = National;
profiles::register(&NATIONAL).expect("registered once");

// UBL: BT-24/BT-23 and ext:UBLExtensions are written for you.
let extended = tirbase_en16931::ubl::serialize_with(&invoice, &NATIONAL)?;
// CII: BT-24 is replaced and `wrap` gets the last pass.
let document = tirbase_en16931::cii::serialize_with(&invoice, &NATIONAL)?;
```

On the command line, a registered profile is selected by identifier:
`en16931 export --input batch.json --output out --profile national`. The profile's
fatal findings become batch failures, so a document that breaks a national rule is
never written.

## Limits worth knowing

- The adapter writes the EN 16931 **core** document. It does not implement a
  national profile, verification URL, fiscal code, QR content or signature.
- The official UBL and CII schemas are not vendored, so the bundled validation
  checks structure and figures but is not an XSD run. Run the published schemas
  (and the receiver's extra rules) in your own pipeline before a document leaves
  the building.
- Credits and refunds are modelled as positive amounts on a type-381 credit note
  with a preceding-invoice reference, which is how EN 16931 represents them; the
  adapter refuses negative unit prices.
- A document-level discount is apportioned by VAT group, so the invoice may carry
  one `AllowanceCharge` per group rather than one for the whole discount.
- Amounts are minor units, quantities are thousandths and rates are basis points;
  a caller converting from floats must round before calling in.
