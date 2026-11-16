// SPDX-License-Identifier: Apache-2.0

//! Ledger event → EPCIS 2.0 event mapping.
//!
//! | ledger `event_type`        | EPCIS event         | action    | bizStep          | disposition |
//! |----------------------------|---------------------|-----------|------------------|-------------|
//! | `lot_registered`           | ObjectEvent         | `ADD`     | `commissioning`  | `active`    |
//! | `lot_relocated`            | ObjectEvent         | `OBSERVE` | `storing`        | —           |
//! | `lot_split`                | TransformationEvent | —         | `disassembling`  | —           |
//! | `lot_merged`               | TransformationEvent | —         | `assembling`     | —           |
//! | `lot_repacked`             | AggregationEvent    | `ADD`     | `repackaging`    | —           |
//! | `excursion_detected`       | ObjectEvent         | `OBSERVE` | `inspecting`     | `in_progress` |
//! | `excursion_quarantined`    | ObjectEvent         | `OBSERVE` | `holding`        | `in_progress` |
//! | `excursion_dispositioned`  | ObjectEvent         | `OBSERVE` | `holding`        | from payload |
//! | `excursion_resolved`       | ObjectEvent         | `OBSERVE` | `holding`        | from payload |
//! | `device_associated`        | AssociationEvent    | `ADD`     | `installing`     | —           |
//!
//! Anything else is reported in [`MappedBundle::unsupported`] and left out of
//! the document, so an unknown event never becomes a half-filled EPCIS event.
//! Identifiers, times and the unsupported fields are documented in
//! `docs/epcis-adapter.md`.

use serde_json::Value;

use crate::bundle::{Bundle, LedgerEntry};
use crate::model::{
    AggregationEvent, AssociationEvent, EpcisAction, EpcisDocument, EpcisEvent, EventBase,
    ObjectEvent, TransformationEvent,
};

/// A ledger entry the adapter could not map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedEntry {
    /// Ledger sequence.
    pub seq: u64,
    /// Ledger entry id.
    pub entry_id: String,
    /// Event type as recorded.
    pub event_type: String,
    /// Why it was not mapped.
    pub reason: String,
}

/// A document plus the entries that were left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedBundle {
    /// The EPCIS document.
    pub document: EpcisDocument,
    /// Entries with no EPCIS mapping, in ledger order.
    pub unsupported: Vec<UnsupportedEntry>,
}

/// Alias kept for callers that think of the document itself as the result.
pub type MappedDocument = EpcisDocument;

/// Map every entry of `bundle`.
///
/// `creation_est` overrides the document's `creationDate`; otherwise the
/// bundle's own `created_est` is used, so the same bundle always produces the
/// same document.
pub fn map_bundle(bundle: &Bundle, creation_est: Option<i64>) -> MappedBundle {
    let mut document = EpcisDocument::new(creation_est.unwrap_or(bundle.manifest.created_est));
    let mut unsupported = Vec::new();
    for entry in &bundle.entries {
        match map_entry(entry) {
            Ok(event) => document.events.push(event),
            Err(reason) => unsupported.push(UnsupportedEntry {
                seq: entry.seq,
                entry_id: entry.entry_id.clone(),
                event_type: entry.event_type.clone(),
                reason,
            }),
        }
    }
    MappedBundle {
        document,
        unsupported,
    }
}

/// Map one ledger entry, or explain why it has no EPCIS form.
pub fn map_entry(entry: &LedgerEntry) -> Result<EpcisEvent, String> {
    let payload = &entry.payload;
    let at = payload_time(
        payload,
        &[
            "created_est",
            "at_est",
            "decided_est",
            "resolution_created_est",
        ],
    )
    .unwrap_or(entry.recorded_est);
    let mut base = EventBase::new(&entry.entry_id, at, entry.recorded_est);
    base.read_point = read_point(payload);
    base.biz_location = biz_location(payload);

    match entry.event_type.as_str() {
        "lot_registered" => {
            let lot = lot_of(entry, payload)
                .ok_or_else(|| "lot_registered carries no lot id".to_string())?;
            base.biz_step = Some("commissioning".to_string());
            base.disposition = Some("active".to_string());
            Ok(EpcisEvent::Object(ObjectEvent {
                base,
                action: EpcisAction::Add,
                epc_list: vec![epc_for(&lot, payload)],
            }))
        }
        "lot_relocated" => {
            let lot = lot_of(entry, payload)
                .ok_or_else(|| "lot_relocated carries no lot id".to_string())?;
            base.biz_step = Some("storing".to_string());
            Ok(EpcisEvent::Object(ObjectEvent {
                base,
                action: EpcisAction::Observe,
                epc_list: vec![epc_for(&lot, payload)],
            }))
        }
        "lot_split" => transformation(entry, payload, base, "disassembling"),
        "lot_merged" => transformation(entry, payload, base, "assembling"),
        "lot_repacked" => {
            let inputs = lot_list(payload, "inputs");
            let outputs = lot_list(payload, "outputs");
            let parent = outputs
                .first()
                .cloned()
                .ok_or_else(|| "lot_repacked carries no output lot".to_string())?;
            if inputs.is_empty() {
                return Err("lot_repacked carries no input lot".to_string());
            }
            base.biz_step = Some("repackaging".to_string());
            Ok(EpcisEvent::Aggregation(AggregationEvent {
                base,
                action: EpcisAction::Add,
                parent_id: epc_for(&parent, payload),
                child_epcs: inputs.iter().map(|lot| epc_for(lot, payload)).collect(),
            }))
        }
        "excursion_detected"
        | "excursion_quarantined"
        | "excursion_dispositioned"
        | "excursion_resolved" => excursion(entry, payload, base),
        "device_associated" => {
            let location = payload
                .get("location_id")
                .and_then(Value::as_str)
                .map(|id| format!("urn:tirbase:location:{id}"))
                .or_else(|| base.biz_location.clone())
                .ok_or_else(|| "device_associated carries no location".to_string())?;
            let device = payload
                .get("device_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| entry.device_id.clone())
                .ok_or_else(|| "device_associated carries no device id".to_string())?;
            base.biz_step = Some("installing".to_string());
            Ok(EpcisEvent::Association(AssociationEvent {
                base,
                action: EpcisAction::Add,
                parent_id: location,
                child_epcs: vec![format!("urn:tirbase:device:{device}")],
            }))
        }
        other => Err(format!("no EPCIS mapping for event type {other:?}")),
    }
}

fn transformation(
    entry: &LedgerEntry,
    payload: &Value,
    mut base: EventBase,
    biz_step: &str,
) -> Result<EpcisEvent, String> {
    let operation_id = payload
        .get("operation_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| entry.entry_id.clone());
    let inputs = lot_list(payload, "inputs");
    let outputs = lot_list(payload, "outputs");
    if inputs.is_empty() || outputs.is_empty() {
        return Err("transformation event carries an empty input or output list".to_string());
    }
    base.biz_step = Some(biz_step.to_string());
    Ok(EpcisEvent::Transformation(TransformationEvent {
        base,
        input_epcs: inputs.iter().map(|lot| epc_for(lot, payload)).collect(),
        output_epcs: outputs.iter().map(|lot| epc_for(lot, payload)).collect(),
        transformation_id: format!("urn:tirbase:operation:{operation_id}"),
    }))
}

fn excursion(
    entry: &LedgerEntry,
    payload: &Value,
    mut base: EventBase,
) -> Result<EpcisEvent, String> {
    let biz_step = if entry.event_type == "excursion_detected" {
        "inspecting"
    } else {
        "holding"
    };
    base.biz_step = Some(biz_step.to_string());
    base.disposition = Some(match entry.event_type.as_str() {
        "excursion_detected" | "excursion_quarantined" => "in_progress".to_string(),
        _ => disposition_of(payload).to_string(),
    });
    let lot = lot_of(entry, payload);
    Ok(EpcisEvent::Object(ObjectEvent {
        base,
        action: EpcisAction::Observe,
        epc_list: lot.iter().map(|lot| epc_for(lot, payload)).collect(),
    }))
}

/// CBV disposition for an operator decision recorded in the payload.
fn disposition_of(payload: &Value) -> &'static str {
    match payload.get("disposition").and_then(Value::as_str) {
        Some("release") => "active",
        Some("hold") => "in_progress",
        Some("reject") => "recalled",
        Some("destroy") => "destroyed",
        _ => "in_progress",
    }
}

fn lot_of(entry: &LedgerEntry, payload: &Value) -> Option<String> {
    payload
        .get("lot_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| entry.lot_id.clone())
}

fn lot_list(payload: &Value, key: &str) -> Vec<String> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// EPCIS identifier for a lot.
///
/// The payload may carry an explicit `epc` (an EPC URI, e.g. an SGTIN); without
/// one the lot is identified by its TirBase URN. The adapter never fabricates a
/// GTIN/SGTIN from a bare lot id.
fn epc_for(lot_id: &str, payload: &Value) -> String {
    payload
        .get("epc")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("urn:tirbase:lot:{lot_id}"))
}

fn read_point(payload: &Value) -> Option<String> {
    if let Some(explicit) = payload.get("read_point").and_then(Value::as_str) {
        return Some(explicit.to_string());
    }
    payload
        .get("location_id")
        .and_then(Value::as_str)
        .map(|id| format!("urn:tirbase:location:{id}"))
}

fn biz_location(payload: &Value) -> Option<String> {
    if let Some(explicit) = payload.get("biz_location").and_then(Value::as_str) {
        return Some(explicit.to_string());
    }
    if let Some(location) = payload.get("location_id").and_then(Value::as_str) {
        return Some(format!("urn:tirbase:location:{location}"));
    }
    payload
        .get("site_id")
        .and_then(Value::as_str)
        .map(|id| format!("urn:tirbase:site:{id}"))
}

fn payload_time(payload: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(event_type: &str, payload: Value) -> LedgerEntry {
        LedgerEntry {
            seq: 1,
            entry_id: format!("test:{event_type}"),
            prev_hash: "0".repeat(64),
            entry_hash: "1".repeat(64),
            recorded_est: 1_770_000_100,
            actor_did: "did:key:z6MkTest".to_string(),
            device_id: None,
            lot_id: None,
            event_type: event_type.to_string(),
            payload_hash: "2".repeat(64),
            payload,
        }
    }

    #[test]
    fn an_unknown_event_is_reported_rather_than_mapped() {
        let error =
            map_entry(&entry("something_else", serde_json::json!({}))).expect_err("unsupported");
        assert!(error.contains("no EPCIS mapping"));
    }

    #[test]
    fn a_split_needs_both_sides() {
        let error = map_entry(&entry(
            "lot_split",
            serde_json::json!({"operation_id": "op-1", "inputs": ["LOT-A"], "outputs": []}),
        ))
        .expect_err("incomplete");
        assert!(error.contains("empty input or output list"));
    }
}
