# GS1 EPCIS 2.0 adapter (CC-16)

`tirbase-epcis` is the Apache-2.0 bridge between a signed TirBase ledger bundle
(CC-14) and GS1 EPCIS 2.0. It reads the bundle JSON with its own serde model — it
does not link `tirbase-gateway` or any other AGPL crate — maps every ledger event
to an EPCIS event, writes JSON-LD and XML, and validates the result against the
vendored official schema.

```text
tirbase-epcis --bundle DIR|bundle.json [--signature FILE] [--out DIR]
              [--format json|xml|both] [--creation-est N]
              [--verify --trusted-key HEX] [--fail-on-unsupported]
```

| Flag | Meaning |
|---|---|
| `--bundle` | bundle directory (reads `bundle.json`) or the bundle file itself |
| `--signature` | detached signature file; defaults to `bundle.sig` beside the bundle |
| `--out` | write `epcis.json` / `epcis.xml` here; without it the output goes to stdout |
| `--format` | `json` (default), `xml`, or `both` |
| `--creation-est` | override `creationDate`; defaults to the bundle's `created_est` |
| `--verify --trusted-key HEX` | verify the Ed25519 bundle signature against this public key before mapping |
| `--fail-on-unsupported` | exit `3` when any entry had no EPCIS mapping |

Exit codes: `0` success, `1` input/output error, `2` usage, `3` unsupported
entries with `--fail-on-unsupported`, `4` the generated JSON failed schema
validation. Diagnostics, the mapped event counts and every unsupported entry go
to stderr, so stdout is pure EPCIS output.

Library use:

```rust
use tirbase_epcis::{json::to_json, mapping::map_bundle, parse_bundle, schema::validate_document};

let bundle = parse_bundle(&std::fs::read_to_string("bundle.json")?)?;
let mapped = map_bundle(&bundle, None);
let rendered = to_json(&mapped.document);
let document: serde_json::Value = serde_json::from_str(&rendered)?;
assert!(validate_document(&document).is_empty());
# Ok::<(), tirbase_epcis::AdapterError>(())
```

## Field mapping

| ledger `event_type` | EPCIS event | `action` | `bizStep` | `disposition` |
|---|---|---|---|---|
| `lot_registered` | `ObjectEvent` | `ADD` | `commissioning` | `active` |
| `lot_relocated` | `ObjectEvent` | `OBSERVE` | `storing` | — |
| `lot_split` | `TransformationEvent` | — | `disassembling` | — |
| `lot_merged` | `TransformationEvent` | — | `assembling` | — |
| `lot_repacked` | `AggregationEvent` | `ADD` | `repackaging` | — |
| `excursion_detected` | `ObjectEvent` | `OBSERVE` | `inspecting` | `in_progress` |
| `excursion_quarantined` | `ObjectEvent` | `OBSERVE` | `holding` | `in_progress` |
| `excursion_dispositioned` | `ObjectEvent` | `OBSERVE` | `holding` | from payload |
| `excursion_resolved` | `ObjectEvent` | `OBSERVE` | `holding` | from payload |
| `device_associated` | `AssociationEvent` | `ADD` | `installing` | — |

An operator disposition maps to the closest CBV term: `release` → `active`,
`hold` → `in_progress`, `reject` → `recalled`, `destroy` → `destroyed`; an
unknown or missing decision becomes `in_progress` rather than a guess.

A split merges into one `TransformationEvent` with `inputEPCList` from the
payload's `inputs` and `outputEPCList` from `outputs`, and
`transformationID = urn:tirbase:operation:<operation_id>`. A repack becomes an
`AggregationEvent` whose `parentID` is the new container (the first output lot)
and whose `childEPCs` are the consumed inputs.

## Identifier mapping

| EPCIS field | Source |
|---|---|
| `eventID` | `urn:tirbase:ledger:<entry_id>` |
| EPC (`epcList`, `childEPCs`, `inputEPCList`, `outputEPCList`) | the payload's `epc` when present, otherwise `urn:tirbase:lot:<lot_id>` |
| `readPoint.id` | payload `read_point`, otherwise `urn:tirbase:location:<location_id>` |
| `bizLocation.id` | payload `biz_location`, otherwise `urn:tirbase:location:<location_id>`, otherwise `urn:tirbase:site:<site_id>` |
| Association `parentID` | `urn:tirbase:location:<location_id>` |
| Association `childEPCs` | `urn:tirbase:device:<device_id>` |
| `transformationID` | `urn:tirbase:operation:<operation_id>` |

GS1 identifiers are never invented. A lot without a GS1 identity is published
under its TirBase URN, and the adapter emits an SGTIN only when the payload
carries one explicitly in `epc`; it does not derive a company prefix from a bare
GTIN.

## Time handling

* `eventTime` is the event's own payload time — `created_est`, `at_est`,
  `decided_est`, or `resolution_created_est`, whichever the event type records —
  falling back to the ledger `recorded_est` when the payload carries none.
* `recordTime` is always the ledger `recorded_est`.
* `creationDate` is the bundle manifest's `created_est`, or `--creation-est`.
* Every timestamp is rendered as UTC with `+00:00` (`eventTimeZoneOffset`,
  `eventTime`, `recordTime`, `creationDate`). The adapter never reads a clock, so
  the same bundle always produces the same document. Local-time and
  non-UTC-offset rendering is not implemented: an EPCIS consumer that needs the
  capturing site's local offset must recover it from the site's master data.

## Validation

`schema/epcis-json-schema.json` is the official GS1 EPCIS 2.0.0 JSON Schema,
vendored byte for byte (see `schema/NOTICE` for its source, hash and the GS1
disclaimer). `Schema::epcis_20()` parses it and `Schema::validate` checks a
document against it, implementing the draft-07 keywords that schema actually
uses: local `$ref`, `type`, `enum`, `const`, `required`, `properties`,
`propertyNames`, `additionalProperties`, `items`, `minItems`, `maxItems`,
`uniqueItems`, `pattern`, `format` (`uri`, `date-time`), `anyOf`, `allOf`,
`oneOf`, `not`, and `if`/`then`. Keywords the schema does not use are ignored
rather than guessed at, so validation cannot silently diverge from the official
artefact.

The CLI always validates and exits `4` on a violation; `tests/golden.rs` asserts
that every golden document validates with zero violations.

XML is emitted in the element order the EPCIS 2.0 XSD declares, with the
`urn:epcglobal:epcis:xsd:2` namespace, and is covered by golden and determinism
tests. It is **not** schema-validated: that would need the XSD and an XSD
validator, neither of which is a dependency. Treat the JSON form as the
validated output and the XML form as a convenience rendering.

## Unsupported fields

The ledger records operational detail that EPCIS 2.0 has no direct slot for. The
adapter drops it deliberately — it never smuggles it into `extension`, which
would make the output schema-invalid — and it is available to consumers in the
bundle itself:

| ledger data | why it is not in the EPCIS output |
|---|---|
| `payload_hash`, `prev_hash`, `entry_hash` | chain integrity is a ledger property; EPCIS has no field for it |
| `actor_did`, `operator_did`, `operator_role` | EPCIS 2.0 records no actor identity outside sensor metadata; attribution stays in the ledger |
| excursion `reasons`, `thresholds`, `samples` | detection evidence; no CBV event field, and mapping it to a disposition reason would be a claim the ledger does not support |
| `request_digest`, `evidence_digest` | digests of the originating request/evidence, not EPCIS data |
| lot `quantity`/`unit`, zone/calibration metadata | would be `quantityList`/sensor elements; the adapter emits EPC lists only and reports the lot identity instead of a fabricated ILMD or quantity |
| `note` on a disposition | free text; not published |
| attachments | referenced by the manifest only; never inlined |
| unknown `event_type` values | reported on stderr and in `MappedBundle::unsupported`, excluded from `eventList` so output stays valid |

Document-level context is `["https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld",
{"tirbase": "https://tirbase.example/vocab/"}]`; no `tirbase:` term is used by
any emitted field, so the prefix is a placeholder for downstream extensions and
nothing in the output depends on it.

## Licence boundary

The crate is Apache-2.0. `tests/agpl_free.rs` walks `Cargo.lock` from
`tirbase-epcis` and fails if any AGPL workspace crate is reachable, and
cross-checks its denylist against the component matrix in `LICENSING.md`. The
vendored GS1 schema keeps its own terms and is not relicensed.

## Tests

```sh
cargo test -p tirbase-epcis
cargo clippy -p tirbase-epcis --all-targets
```

`tests/fixtures/{excursion,quarantine,disposition,packing,split}/bundle.json`
are CC-14-format bundles; `tests/fixtures/expected/<case>.json|xml` are their
committed outputs. `tests/golden.rs` compares both renderings byte for byte,
validates every document against the official schema, maps each bundle twice to
prove determinism, and checks that an unknown event type is reported rather than
emitted.
