// SPDX-License-Identifier: Apache-2.0

//! Golden invoices: every case validates, the bytes are stable, and the core makes
//! no national fiscal claim.
//!
//! The committed documents in `golden/expected/` are the exact bytes the
//! serializers produce for the inputs in `golden/`. The test fails if either side
//! moves, so a change in serialization is a deliberate, reviewable change to a
//! golden file rather than a silent drift.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use tirbase_en16931::batch;
use tirbase_en16931::model::DocumentType;
use tirbase_en16931::pos::PosInvoiceFile;
use tirbase_en16931::profiles::{self, CountryProfile};
use tirbase_en16931::validate::{validate_document, Syntax};
use tirbase_en16931::{cii, ubl, SPECIFICATION_ID};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("golden")
}

fn case_files() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(golden_dir())
        .expect("golden directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

fn cases() -> Vec<(String, PosInvoiceFile)> {
    let paths = case_files();
    assert_eq!(
        paths.len(),
        4,
        "the four golden cases are tax, discount, refund and rounding"
    );
    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).expect("golden input");
            let file = PosInvoiceFile::from_json(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(
                file.invoices.len(),
                1,
                "{}: one invoice per case",
                path.display()
            );
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("stem")
                .to_string();
            (name, file)
        })
        .collect()
}

fn render(invoice: &tirbase_en16931::model::Invoice, syntax: Syntax) -> String {
    batch::render(invoice, syntax, None).expect("rendered")
}

#[test]
fn every_golden_invoice_validates_and_matches_its_bytes() {
    let cases = cases();
    let names: Vec<&str> = cases.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["discount", "refund", "rounding", "tax"]);
    let mut document_numbers = BTreeSet::new();
    for (name, file) in &cases {
        let source = &file.invoices[0];
        let invoice = source
            .to_invoice()
            .unwrap_or_else(|problems| panic!("{name}: {problems:?}"));
        assert!(
            document_numbers.insert(invoice.number.clone()),
            "{name}: duplicate document number {}",
            invoice.number
        );
        for syntax in [Syntax::Ubl, Syntax::Cii] {
            let document = render(&invoice, syntax);
            let expected = fs::read_to_string(golden_dir().join("expected").join(format!(
                "{}.{}.xml",
                invoice.number,
                syntax.id()
            )))
            .unwrap_or_else(|error| panic!("{name} {}: {error}", syntax.id()));
            assert_eq!(
                document,
                expected,
                "{name} ({}) does not match the committed golden document",
                syntax.id()
            );
            let report = validate_document(&document, &invoice, syntax);
            assert!(report.valid, "{name} {}: {}", syntax.id(), report.render());
        }
        if name == "refund" {
            assert_eq!(invoice.document_type, DocumentType::CreditNote);
            assert!(!invoice.preceding_invoices.is_empty());
        }
    }
}

#[test]
fn the_adapter_is_deterministic() {
    for (_name, file) in cases() {
        let invoice = file.invoices[0].to_invoice().expect("mapped");
        for syntax in [Syntax::Ubl, Syntax::Cii] {
            let first = render(&invoice, syntax);
            let second = render(&invoice, syntax);
            assert_eq!(first.as_bytes(), second.as_bytes());
            // The manifest carries no timestamp and no hash iteration order, so two
            // exports of the same input are byte-identical, manifest included.
            let left = tempfile::tempdir().expect("temp dir");
            let right = tempfile::tempdir().expect("temp dir");
            let batch_file = PosInvoiceFile {
                invoices: file.invoices.clone(),
            };
            let formats = [syntax];
            let left_report =
                batch::export(&batch_file, left.path(), &formats, None).expect("export");
            let right_report =
                batch::export(&batch_file, right.path(), &formats, None).expect("export");
            assert_eq!(left_report.documents, right_report.documents);
            assert_eq!(
                fs::read(left_report.manifest).expect("manifest"),
                fs::read(right_report.manifest).expect("manifest")
            );
            let mut left_names: Vec<String> = fs::read_dir(left.path())
                .expect("left")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            let mut right_names: Vec<String> = fs::read_dir(right.path())
                .expect("right")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            left_names.sort();
            right_names.sort();
            assert_eq!(left_names, right_names);
        }
    }
}

#[test]
fn no_country_specific_fiscal_claim_is_made() {
    // The documents carry the core specification identifier and nothing national.
    for (_name, file) in cases() {
        let invoice = file.invoices[0].to_invoice().expect("mapped");
        for syntax in [Syntax::Ubl, Syntax::Cii] {
            let document = render(&invoice, syntax);
            assert!(document.contains(SPECIFICATION_ID));
            for marker in [
                "http://",
                "https://",
                "verifactu",
                "ticketbai",
                "facturae",
                "signature",
                "xmldsig",
                "ProfileID",
                "UBLExtensions",
                "urn:cen.eu:en16931:2017#",
            ] {
                assert!(
                    !document.to_lowercase().contains(&marker.to_lowercase()),
                    "{} emits {marker:?}, which is a national or platform claim",
                    syntax.id()
                );
            }
        }
    }

    // The crate itself names no national regime anywhere in its source.
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;
    for entry in fs::read_dir(&source).expect("src directory") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("source file");
        let lowered = text.to_lowercase();
        for marker in [
            "verifactu",
            "ticketbai",
            "facturae",
            "fattura",
            "xrechnung",
            "zugferd",
            "ksef",
            "peppol",
            "chorus",
        ] {
            assert!(
                !lowered.contains(marker),
                "{} mentions {marker:?}; national logic belongs in a closed profile",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(checked >= 8, "the source scan should cover every module");

    // Only the core profile ships with the crate.
    assert_eq!(profiles::ids(), vec!["en16931-core"]);
}

#[test]
fn a_closed_profile_extends_the_core_without_changing_it() {
    struct Probe;

    impl CountryProfile for Probe {
        fn id(&self) -> &'static str {
            "golden-probe"
        }

        fn description(&self) -> &'static str {
            "closed-profile probe"
        }

        fn profile_id(&self) -> Option<&'static str> {
            Some("urn:example:golden-probe")
        }

        fn extension(
            &self,
            _invoice: &tirbase_en16931::model::Invoice,
        ) -> Option<profiles::Extension> {
            Some(
                profiles::Extension::new("probe", "urn:example:golden-probe:1", "Stamp")
                    .with_child("probe:ID", "P-1"),
            )
        }

        fn wrap(&self, _syntax: Syntax, document: String) -> Result<String, String> {
            Ok(document.replace(
                "</rsm:CrossIndustryInvoice>",
                "<!--probe--></rsm:CrossIndustryInvoice>",
            ))
        }
    }

    let probe = Probe;
    let (_name, file) = cases().remove(2);
    let invoice = file.invoices[0].to_invoice().expect("mapped");

    let core_ubl = ubl::serialize(&invoice);
    let extended_ubl = ubl::serialize_with(&invoice, &probe).expect("extended");
    assert_ne!(core_ubl, extended_ubl);
    assert!(extended_ubl.contains("cbc:ProfileID"));
    assert!(extended_ubl.contains("ext:UBLExtensions"));
    assert!(validate_document(&extended_ubl, &invoice, Syntax::Ubl).valid);

    let core_cii = cii::serialize(&invoice);
    let extended_cii = cii::serialize_with(&invoice, &probe).expect("extended");
    assert_ne!(core_cii, extended_cii);
    assert!(extended_cii.contains("<!--probe-->"));
    assert!(validate_document(&extended_cii, &invoice, Syntax::Cii).valid);
}
