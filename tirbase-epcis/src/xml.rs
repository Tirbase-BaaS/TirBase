// SPDX-License-Identifier: Apache-2.0

//! EPCIS 2.0 XML writer.
//!
//! Elements are emitted in the order the EPCIS 2.0 XSD declares them
//! (`eventTime`, `recordTime`, `eventTimeZoneOffset`, `eventID`, then the
//! type-specific body, then the business fields), one element per line, so the
//! same bundle always produces byte-identical XML.
//!
//! Only the fields this adapter maps are written; see `docs/epcis-adapter.md`
//! for the unsupported list. XML is not schema-validated in CI — only the JSON
//! form is — because validating XML would need the XSD and an XSD validator.

use crate::model::{EpcisDocument, EpcisEvent};
use crate::time;

/// The EPCIS 2.0 XML namespace.
pub const EPCIS_XML_NAMESPACE: &str = "urn:epcglobal:epcis:xsd:2";

/// Render the document as EPCIS 2.0 XML.
pub fn to_xml(document: &EpcisDocument) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<epcis:EPCISDocument xmlns:epcis=\"{EPCIS_XML_NAMESPACE}\" schemaVersion=\"2.0\" \
         creationDate=\"{}\">\n",
        escape(&time::rfc3339_utc(document.creation_est))
    ));
    out.push_str("  <EPCISBody>\n    <EventList>\n");
    for event in &document.events {
        write_event(&mut out, event);
    }
    out.push_str("    </EventList>\n  </EPCISBody>\n</epcis:EPCISDocument>\n");
    out
}

fn write_event(out: &mut String, event: &EpcisEvent) {
    let base = event.base();
    out.push_str(&format!("      <{}>\n", event.event_type()));
    element(out, 8, "eventTime", &base.event_time());
    element(out, 8, "recordTime", &base.record_time());
    element(out, 8, "eventTimeZoneOffset", time::UTC_OFFSET);
    element(out, 8, "eventID", &base.event_id);

    match event {
        EpcisEvent::Object(event) => {
            collection(out, "epcList", "epc", &event.epc_list);
            element(out, 8, "action", event.action.as_str());
            business_fields(
                out,
                event.base.biz_step.as_deref(),
                event.base.disposition.as_deref(),
            );
            location(out, "readPoint", event.base.read_point.as_deref());
            location(out, "bizLocation", event.base.biz_location.as_deref());
        }
        EpcisEvent::Aggregation(event) => {
            element(out, 8, "parentID", &event.parent_id);
            collection(out, "childEPCs", "epc", &event.child_epcs);
            element(out, 8, "action", event.action.as_str());
            business_fields(
                out,
                event.base.biz_step.as_deref(),
                event.base.disposition.as_deref(),
            );
            location(out, "readPoint", event.base.read_point.as_deref());
            location(out, "bizLocation", event.base.biz_location.as_deref());
        }
        EpcisEvent::Transformation(event) => {
            collection(out, "inputEPCList", "epc", &event.input_epcs);
            collection(out, "outputEPCList", "epc", &event.output_epcs);
            element(out, 8, "transformationID", &event.transformation_id);
            business_fields(
                out,
                event.base.biz_step.as_deref(),
                event.base.disposition.as_deref(),
            );
            location(out, "readPoint", event.base.read_point.as_deref());
            location(out, "bizLocation", event.base.biz_location.as_deref());
        }
        EpcisEvent::Association(event) => {
            element(out, 8, "parentID", &event.parent_id);
            collection(out, "childEPCs", "epc", &event.child_epcs);
            element(out, 8, "action", event.action.as_str());
            business_fields(
                out,
                event.base.biz_step.as_deref(),
                event.base.disposition.as_deref(),
            );
            location(out, "readPoint", event.base.read_point.as_deref());
            location(out, "bizLocation", event.base.biz_location.as_deref());
        }
    }
    out.push_str(&format!("      </{}>\n", event.event_type()));
}

fn business_fields(out: &mut String, biz_step: Option<&str>, disposition: Option<&str>) {
    if let Some(step) = biz_step {
        element(out, 8, "bizStep", step);
    }
    if let Some(disposition) = disposition {
        element(out, 8, "disposition", disposition);
    }
}

fn element(out: &mut String, indent: usize, name: &str, value: &str) {
    out.push_str(&format!(
        "{:indent$}<{name}>{}</{name}>\n",
        "",
        escape(value),
        indent = indent
    ));
}

fn collection(out: &mut String, wrapper: &str, item: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    out.push_str(&format!(
        "        <{wrapper}>\n{}        </{wrapper}>\n",
        values
            .iter()
            .map(|value| format!("          <{item}>{}</{item}>\n", escape(value)))
            .collect::<String>()
    ));
}

fn location(out: &mut String, name: &str, id: Option<&str>) {
    if let Some(id) = id {
        out.push_str(&format!(
            "        <{name}>\n          <id>{}</id>\n        </{name}>\n",
            escape(id)
        ));
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EpcisAction, EventBase, ObjectEvent};

    #[test]
    fn writes_the_epcis_element_order_and_escapes_values() {
        let mut base = EventBase::new("lot-registered:LOT<A>", 1_770_000_000, 1_770_000_000);
        base.biz_step = Some("commissioning".to_string());
        base.disposition = Some("active".to_string());
        base.read_point = Some("urn:tirbase:location:loc-1".to_string());
        let document = EpcisDocument {
            creation_est: 1_770_000_000,
            events: vec![EpcisEvent::Object(ObjectEvent {
                base,
                action: EpcisAction::Add,
                epc_list: vec!["urn:tirbase:lot:LOT-A".to_string()],
            })],
        };
        let xml = to_xml(&document);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(xml.contains("xmlns:epcis=\"urn:epcglobal:epcis:xsd:2\""));
        assert!(xml.contains("<eventID>urn:tirbase:ledger:lot-registered:LOT&lt;A&gt;</eventID>"));
        // eventTime precedes action, which precedes bizStep.
        let time = xml.find("<eventTime>").expect("eventTime");
        let action = xml.find("<action>").expect("action");
        let step = xml.find("<bizStep>").expect("bizStep");
        assert!(time < action && action < step, "{xml}");
        assert!(xml.ends_with("</epcis:EPCISDocument>\n"));
    }
}
