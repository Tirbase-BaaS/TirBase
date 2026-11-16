// SPDX-License-Identifier: Apache-2.0

//! The EPCIS 2.0 event model the mapper produces and the writers consume.
//!
//! Only the fields this adapter can derive from a ledger event are modelled.
//! Everything else in EPCIS 2.0 (quantity lists, sensor elements, ILMD, business
//! transactions, source/destination lists, persistent disposition) is listed as
//! unsupported in `docs/epcis-adapter.md`.

use crate::time;

/// EPCIS `action` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpcisAction {
    /// The object was observed without changing state.
    Observe,
    /// The object was added.
    Add,
    /// The object was removed.
    Delete,
}

impl EpcisAction {
    /// The schema value.
    pub fn as_str(self) -> &'static str {
        match self {
            EpcisAction::Observe => "OBSERVE",
            EpcisAction::Add => "ADD",
            EpcisAction::Delete => "DELETE",
        }
    }
}

/// Fields every EPCIS event carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBase {
    /// When the event happened, in the ledger's time basis.
    pub event_time_est: i64,
    /// When the event was recorded in the ledger.
    pub record_time_est: i64,
    /// Stable EPCIS event identifier.
    pub event_id: String,
    /// CBV business step (short name or URI).
    pub biz_step: Option<String>,
    /// CBV disposition (short name or URI).
    pub disposition: Option<String>,
    /// EPCIS `readPoint`, as `{"id": uri}`.
    pub read_point: Option<String>,
    /// EPCIS `bizLocation`, as `{"id": uri}`.
    pub biz_location: Option<String>,
}

impl EventBase {
    /// Start a base from the ledger entry.
    pub fn new(entry_id: &str, event_time_est: i64, record_time_est: i64) -> Self {
        Self {
            event_time_est,
            record_time_est,
            event_id: format!("urn:tirbase:ledger:{entry_id}"),
            biz_step: None,
            disposition: None,
            read_point: None,
            biz_location: None,
        }
    }

    /// `eventTime` as RFC 3339.
    pub fn event_time(&self) -> String {
        time::rfc3339_utc(self.event_time_est)
    }

    /// `recordTime` as RFC 3339.
    pub fn record_time(&self) -> String {
        time::rfc3339_utc(self.record_time_est)
    }
}

/// An EPCIS `ObjectEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEvent {
    /// Common fields.
    pub base: EventBase,
    /// Action.
    pub action: EpcisAction,
    /// `epcList`.
    pub epc_list: Vec<String>,
}

/// An EPCIS `AggregationEvent` (packing and unpacking).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationEvent {
    /// Common fields.
    pub base: EventBase,
    /// Action.
    pub action: EpcisAction,
    /// `parentID`.
    pub parent_id: String,
    /// `childEPCs`.
    pub child_epcs: Vec<String>,
}

/// An EPCIS `TransformationEvent` (split, merge, repack).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformationEvent {
    /// Common fields.
    pub base: EventBase,
    /// `inputEPCList`.
    pub input_epcs: Vec<String>,
    /// `outputEPCList`.
    pub output_epcs: Vec<String>,
    /// `transformationID`, the ledger operation id as a URN.
    pub transformation_id: String,
}

/// An EPCIS `AssociationEvent` (equipment associated with a location).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationEvent {
    /// Common fields.
    pub base: EventBase,
    /// Action.
    pub action: EpcisAction,
    /// `parentID`.
    pub parent_id: String,
    /// `childEPCs`.
    pub child_epcs: Vec<String>,
}

/// One of the four EPCIS event types this adapter emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpcisEvent {
    /// `ObjectEvent`.
    Object(ObjectEvent),
    /// `AggregationEvent`.
    Aggregation(AggregationEvent),
    /// `TransformationEvent`.
    Transformation(TransformationEvent),
    /// `AssociationEvent`.
    Association(AssociationEvent),
}

impl EpcisEvent {
    /// The schema `type` value.
    pub fn event_type(&self) -> &'static str {
        match self {
            EpcisEvent::Object(_) => "ObjectEvent",
            EpcisEvent::Aggregation(_) => "AggregationEvent",
            EpcisEvent::Transformation(_) => "TransformationEvent",
            EpcisEvent::Association(_) => "AssociationEvent",
        }
    }

    /// Common fields.
    pub fn base(&self) -> &EventBase {
        match self {
            EpcisEvent::Object(event) => &event.base,
            EpcisEvent::Aggregation(event) => &event.base,
            EpcisEvent::Transformation(event) => &event.base,
            EpcisEvent::Association(event) => &event.base,
        }
    }

    /// Common fields, mutably.
    pub fn base_mut(&mut self) -> &mut EventBase {
        match self {
            EpcisEvent::Object(event) => &mut event.base,
            EpcisEvent::Aggregation(event) => &mut event.base,
            EpcisEvent::Transformation(event) => &mut event.base,
            EpcisEvent::Association(event) => &mut event.base,
        }
    }
}

/// An EPCIS 2.0 document as produced by one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpcisDocument {
    /// When the document was created (from the bundle, never a clock).
    pub creation_est: i64,
    /// Events in ledger sequence order.
    pub events: Vec<EpcisEvent>,
}

impl EpcisDocument {
    /// Empty document.
    pub fn new(creation_est: i64) -> Self {
        Self {
            creation_est,
            events: Vec::new(),
        }
    }

    /// Count of events per EPCIS type, in a stable order.
    pub fn counts(&self) -> Vec<(&'static str, usize)> {
        [
            "ObjectEvent",
            "AggregationEvent",
            "TransformationEvent",
            "AssociationEvent",
        ]
        .into_iter()
        .map(|name| {
            (
                name,
                self.events
                    .iter()
                    .filter(|event| event.event_type() == name)
                    .count(),
            )
        })
        .collect()
    }
}
