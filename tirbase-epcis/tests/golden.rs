// SPDX-License-Identifier: Apache-2.0

//! Golden tests: every fixture bundle maps to its committed EPCIS output, that
//! output validates against the vendored official schema, and re-running the
//! mapping produces byte-identical JSON and XML.

use std::path::PathBuf;

use tirbase_epcis::json::to_json;
use tirbase_epcis::mapping::map_bundle;
use tirbase_epcis::schema::validate_document;
use tirbase_epcis::xml::to_xml;
use tirbase_epcis::{parse_bundle, AdapterError};

/// One directory per scenario under `tests/fixtures/`.
const CASES: [&str; 5] = ["excursion", "quarantine", "disposition", "packing", "split"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read_case(name: &str, file: &str) -> String {
    let path = fixtures().join(name).join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn expected(name: &str, extension: &str) -> String {
    let path = fixtures()
        .join("expected")
        .join(format!("{name}.{extension}"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn mapped(name: &str) -> tirbase_epcis::mapping::MappedBundle {
    let bundle = parse_bundle(&read_case(name, "bundle.json"))
        .unwrap_or_else(|e: AdapterError| panic!("{name}: {e}"));
    map_bundle(&bundle, None)
}

#[test]
fn every_fixture_bundle_maps_every_entry() {
    for name in CASES {
        let mapped = mapped(name);
        assert!(
            mapped.unsupported.is_empty(),
            "{name}: unsupported entries {:?}",
            mapped.unsupported
        );
        assert_eq!(mapped.document.events.len(), 1, "{name}: event count");
    }
}

#[test]
fn every_fixture_matches_its_golden_json() {
    for name in CASES {
        assert_eq!(
            to_json(&mapped(name).document),
            expected(name, "json"),
            "bundle {name}"
        );
    }
}

#[test]
fn every_fixture_matches_its_golden_xml() {
    for name in CASES {
        assert_eq!(
            to_xml(&mapped(name).document),
            expected(name, "xml"),
            "bundle {name}"
        );
    }
}

#[test]
fn every_golden_document_validates_against_the_official_schema() {
    for name in CASES {
        let rendered = to_json(&mapped(name).document);
        let document: serde_json::Value =
            serde_json::from_str(&rendered).expect("golden document parses");
        let violations = validate_document(&document);
        assert!(
            violations.is_empty(),
            "{name}: schema violations {violations:?}"
        );
    }
}

#[test]
fn mapping_the_same_bundle_twice_is_byte_identical() {
    for name in CASES {
        let first = mapped(name);
        let second = mapped(name);
        assert_eq!(
            to_json(&first.document),
            to_json(&second.document),
            "{name}: json"
        );
        assert_eq!(
            to_xml(&first.document),
            to_xml(&second.document),
            "{name}: xml"
        );
        assert_eq!(first, second, "{name}: mapped structure");
    }
}

#[test]
fn creation_date_comes_from_the_bundle_not_the_clock() {
    let bundle = parse_bundle(&read_case("split", "bundle.json")).expect("bundle");
    let default = map_bundle(&bundle, None);
    assert_eq!(default.document.creation_est, bundle.manifest.created_est);

    let overridden = map_bundle(&bundle, Some(0));
    assert_eq!(overridden.document.creation_est, 0);
    assert!(
        to_json(&overridden.document).contains("\"creationDate\": \"1970-01-01T00:00:00.000Z\""),
        "an explicit creation time must be used verbatim"
    );
}

#[test]
fn golden_events_carry_the_mapped_action_biz_step_and_disposition() {
    let cases: [(&str, &str, &str, &str); 5] = [
        ("excursion", "ObjectEvent", "inspecting", "in_progress"),
        ("quarantine", "ObjectEvent", "holding", "in_progress"),
        ("disposition", "ObjectEvent", "holding", "in_progress"),
        ("packing", "AggregationEvent", "repackaging", ""),
        ("split", "TransformationEvent", "disassembling", ""),
    ];
    for (name, event_type, biz_step, disposition) in cases {
        let document: serde_json::Value =
            serde_json::from_str(&expected(name, "json")).expect("golden json");
        let events = document["epcisBody"]["eventList"]
            .as_array()
            .expect("event list");
        assert_eq!(events.len(), 1, "{name}");
        let event = &events[0];
        assert_eq!(event["type"], event_type, "{name}");
        assert_eq!(event["bizStep"], biz_step, "{name}");
        if disposition.is_empty() {
            assert!(event.get("disposition").is_none(), "{name}");
        } else {
            assert_eq!(event["disposition"], disposition, "{name}");
        }
    }
}

#[test]
fn an_unknown_event_type_is_reported_and_left_out() {
    let mut bundle = parse_bundle(&read_case("excursion", "bundle.json")).expect("bundle");
    bundle.entries[0].event_type = "teleported".to_string();
    let mapped = map_bundle(&bundle, None);
    assert!(mapped.document.events.is_empty());
    assert_eq!(mapped.unsupported.len(), 1);
    assert_eq!(mapped.unsupported[0].event_type, "teleported");
    assert!(mapped.unsupported[0].reason.contains("no EPCIS mapping"));
}
