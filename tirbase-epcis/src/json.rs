// SPDX-License-Identifier: Apache-2.0

//! EPCIS 2.0 JSON-LD writer.
//!
//! The document is built as a `serde_json::Value`, whose object keys are sorted,
//! so the same bundle always produces byte-identical output. `creationDate`
//! comes from the bundle, never from a clock.

use serde_json::{json, Map, Value};

use crate::model::{EpcisDocument, EpcisEvent};
use crate::time;

/// Context document published by GS1 for EPCIS 2.0.
pub const EPCIS_CONTEXT: &str = "https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld";

/// Build the JSON-LD document.
pub fn to_value(document: &EpcisDocument) -> Value {
    let events: Vec<Value> = document.events.iter().map(event_value).collect();
    json!({
        "@context": [EPCIS_CONTEXT, {"tirbase": "https://tirbase.example/vocab/"}],
        "type": "EPCISDocument",
        "schemaVersion": "2.0",
        "creationDate": time::rfc3339_utc(document.creation_est),
        "epcisBody": {"eventList": events},
    })
}

/// Render the document as pretty JSON.
pub fn to_json(document: &EpcisDocument) -> String {
    let mut json = serde_json::to_string_pretty(&to_value(document)).expect("json document");
    json.push('\n');
    json
}

fn event_value(event: &EpcisEvent) -> Value {
    let mut object = Map::new();
    object.insert("type".to_string(), json!(event.event_type()));
    let base = event.base();
    object.insert("eventTime".to_string(), json!(base.event_time()));
    object.insert("eventTimeZoneOffset".to_string(), json!(time::UTC_OFFSET));
    object.insert("recordTime".to_string(), json!(base.record_time()));
    object.insert("eventID".to_string(), json!(base.event_id));
    if let Some(step) = base.biz_step.as_ref() {
        object.insert("bizStep".to_string(), json!(step));
    }
    if let Some(disposition) = base.disposition.as_ref() {
        object.insert("disposition".to_string(), json!(disposition));
    }
    if let Some(point) = base.read_point.as_ref() {
        object.insert("readPoint".to_string(), json!({ "id": point }));
    }
    if let Some(location) = base.biz_location.as_ref() {
        object.insert("bizLocation".to_string(), json!({ "id": location }));
    }
    match event {
        EpcisEvent::Object(event) => {
            object.insert("action".to_string(), json!(event.action.as_str()));
            object.insert("epcList".to_string(), json!(event.epc_list));
        }
        EpcisEvent::Aggregation(event) => {
            object.insert("action".to_string(), json!(event.action.as_str()));
            object.insert("parentID".to_string(), json!(event.parent_id));
            object.insert("childEPCs".to_string(), json!(event.child_epcs));
        }
        EpcisEvent::Transformation(event) => {
            object.insert("inputEPCList".to_string(), json!(event.input_epcs));
            object.insert("outputEPCList".to_string(), json!(event.output_epcs));
            object.insert(
                "transformationID".to_string(),
                json!(event.transformation_id),
            );
        }
        EpcisEvent::Association(event) => {
            object.insert("action".to_string(), json!(event.action.as_str()));
            object.insert("parentID".to_string(), json!(event.parent_id));
            object.insert("childEPCs".to_string(), json!(event.child_epcs));
        }
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EpcisAction, EventBase, ObjectEvent};

    #[test]
    fn an_object_event_carries_every_required_field() {
        let mut base = EventBase::new("lot-registered:LOT-A", 1_770_000_000, 1_770_000_050);
        base.biz_step = Some("commissioning".to_string());
        base.disposition = Some("active".to_string());
        base.read_point = Some("urn:tirbase:location:loc-1".to_string());
        base.biz_location = Some("urn:tirbase:location:loc-1".to_string());
        let document = EpcisDocument {
            creation_est: 1_770_000_100,
            events: vec![EpcisEvent::Object(ObjectEvent {
                base,
                action: EpcisAction::Add,
                epc_list: vec!["urn:tirbase:lot:LOT-A".to_string()],
            })],
        };
        let value = to_value(&document);
        assert_eq!(value["type"], "EPCISDocument");
        assert_eq!(value["creationDate"], "2026-02-02T02:41:40.000Z");
        let event = &value["epcisBody"]["eventList"][0];
        assert_eq!(event["type"], "ObjectEvent");
        assert_eq!(event["eventTime"], "2026-02-02T02:40:00.000Z");
        assert_eq!(event["recordTime"], "2026-02-02T02:40:50.000Z");
        assert_eq!(event["eventTimeZoneOffset"], "+00:00");
        assert_eq!(event["eventID"], "urn:tirbase:ledger:lot-registered:LOT-A");
        assert_eq!(event["action"], "ADD");
        assert_eq!(event["readPoint"]["id"], "urn:tirbase:location:loc-1");
    }
}
