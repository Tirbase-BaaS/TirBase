// SPDX-License-Identifier: Apache-2.0

//! Venue connector interfaces.
//!
//! A closed connector implements [`VenueConnector`] once and opts into the
//! family traits it supports. The family traits provide typed entry points and
//! default to delivering the matching [`VenueEvent`], so a connector only writes
//! its vendor transport, not five parallel dispatch layers.
//!
//! | Family | Trait | Events |
//! |---|---|---|
//! | Ticketing | [`TicketingConnector`] | ticket scan |
//! | Access control | [`AccessConnector`] | access decision |
//! | Building management | [`BmsConnector`] | alarm, point write |
//! | CCTV | [`CctvConnector`] | alarm, metadata-only camera context |
//! | Public address | [`PaConnector`] | announcement |

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tirbase_integrations::{ConnectorHealth, ConnectorKind, DeliveryRequest, DeliveryResult};

use crate::event::{
    AccessDecision, Announcement, SchemaError, TicketScan, VenueAlarm, VenueEvent, VenueEventKind,
    MAX_ID_LEN, MAX_TEXT_LEN,
};

/// The venue subsystem a connector speaks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueDomain {
    /// Ticketing and credential validation.
    Ticketing,
    /// Gate and access-control hardware.
    Access,
    /// Building management (HVAC, lighting, points).
    Bms,
    /// Video management, metadata only.
    Cctv,
    /// Public address and displays.
    Pa,
}

impl VenueDomain {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            VenueDomain::Ticketing => "ticketing",
            VenueDomain::Access => "access",
            VenueDomain::Bms => "bms",
            VenueDomain::Cctv => "cctv",
            VenueDomain::Pa => "pa",
        }
    }

    /// Whether this domain consumes `kind`.
    ///
    /// Alarms fan out to both BMS and CCTV; the other families are one-to-one.
    pub fn accepts(self, kind: VenueEventKind) -> bool {
        match kind {
            VenueEventKind::TicketScan => self == VenueDomain::Ticketing,
            VenueEventKind::AccessDecision => self == VenueDomain::Access,
            VenueEventKind::Alarm => matches!(self, VenueDomain::Bms | VenueDomain::Cctv),
            VenueEventKind::Announcement => self == VenueDomain::Pa,
        }
    }
}

/// What a venue connector promises.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueCapabilities {
    /// Whether the vendor recognises the event's idempotency key.
    pub idempotent: bool,
    /// Whether the connector verifies inbound vendor webhooks.
    pub signed_webhooks: bool,
    /// Largest outbound payload accepted, in bytes.
    pub max_payload_bytes: usize,
    /// Transport family.
    pub transport: ConnectorKind,
}

impl Default for VenueCapabilities {
    fn default() -> Self {
        Self {
            idempotent: true,
            signed_webhooks: true,
            max_payload_bytes: 1024 * 1024,
            transport: ConnectorKind::Http,
        }
    }
}

/// The generic venue connector contract.
///
/// `deliver` is called with a **redacted** event: the dispatcher removes holder
/// names, emails and other direct identifiers before any connector sees it.
/// Implementations must be `Send + Sync`, must classify failures honestly, and
/// must return [`DeliveryOutcome::Duplicate`] when the vendor already has the
/// event's idempotency key.
pub trait VenueConnector: Send + Sync {
    /// Stable connector name used in idempotency keys and logs.
    fn name(&self) -> &str;

    /// Venue this connector is bound to.
    fn venue(&self) -> &str;

    /// Domains the connector supports.
    fn domains(&self) -> &[VenueDomain];

    /// What the connector promises.
    fn capabilities(&self) -> VenueCapabilities {
        VenueCapabilities::default()
    }

    /// Transport family.
    fn transport(&self) -> ConnectorKind {
        self.capabilities().transport
    }

    /// Current readiness.
    fn health(&self) -> ConnectorHealth;

    /// Deliver one redacted event.
    fn deliver(&self, event: &VenueEvent) -> DeliveryResult;
}

impl<T: VenueConnector + ?Sized> VenueConnector for Arc<T> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn venue(&self) -> &str {
        (**self).venue()
    }

    fn domains(&self) -> &[VenueDomain] {
        (**self).domains()
    }

    fn capabilities(&self) -> VenueCapabilities {
        (**self).capabilities()
    }

    fn transport(&self) -> ConnectorKind {
        (**self).transport()
    }

    fn health(&self) -> ConnectorHealth {
        (**self).health()
    }

    fn deliver(&self, event: &VenueEvent) -> DeliveryResult {
        (**self).deliver(event)
    }
}

/// Ticketing connector surface.
pub trait TicketingConnector: VenueConnector {
    /// Send a ticket scan to the ticketing vendor.
    fn on_ticket_scan(&self, scan: &TicketScan) -> DeliveryResult {
        self.deliver(&VenueEvent::ticket_scan(scan.clone()))
    }
}

/// Access-control connector surface.
pub trait AccessConnector: VenueConnector {
    /// Send a gate decision to the access-control platform.
    fn on_access_decision(&self, decision: &AccessDecision) -> DeliveryResult {
        self.deliver(&VenueEvent::access_decision(decision.clone()))
    }
}

/// Building-management point value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BmsValue {
    /// Numeric setpoint or reading.
    Number(f64),
    /// Boolean state.
    Bool(bool),
    /// Short text state.
    Text(String),
}

/// A BMS point write.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmsPointWrite {
    /// Venue.
    pub venue_id: String,
    /// Point identifier.
    pub point_id: String,
    /// New value.
    pub value: BmsValue,
    /// When the write was issued.
    pub occurred_est: i64,
}

impl BmsPointWrite {
    /// Build and validate a point write.
    pub fn new(
        venue_id: impl Into<String>,
        point_id: impl Into<String>,
        value: BmsValue,
        occurred_est: i64,
    ) -> Result<Self, SchemaError> {
        let write = Self {
            venue_id: venue_id.into(),
            point_id: point_id.into(),
            value,
            occurred_est,
        };
        if write.venue_id.trim().is_empty() || write.point_id.trim().is_empty() {
            return Err(SchemaError::new("point_id", "must not be empty"));
        }
        if write.venue_id.len() > MAX_ID_LEN || write.point_id.len() > MAX_ID_LEN {
            return Err(SchemaError::new(
                "point_id",
                format!("must be at most {MAX_ID_LEN} bytes"),
            ));
        }
        if let BmsValue::Number(number) = write.value {
            if !number.is_finite() {
                return Err(SchemaError::new("value", "must be finite"));
            }
        }
        if let BmsValue::Text(text) = &write.value {
            if text.len() > MAX_TEXT_LEN {
                return Err(SchemaError::new(
                    "value",
                    format!("must be at most {MAX_TEXT_LEN} bytes"),
                ));
            }
        }
        if write.occurred_est <= 0 {
            return Err(SchemaError::new("occurred_est", "must be positive"));
        }
        Ok(write)
    }
}

/// Building-management connector surface.
pub trait BmsConnector: VenueConnector {
    /// Send an alarm to the BMS.
    fn on_alarm(&self, alarm: &VenueAlarm) -> DeliveryResult {
        self.deliver(&VenueEvent::alarm(alarm.clone()))
    }

    /// Write a BMS point. Connectors that do not control points refuse it.
    fn write_point(&self, _write: &BmsPointWrite) -> DeliveryResult {
        DeliveryResult::permanent("this connector does not write BMS points")
    }
}

/// Metadata-only camera context handed to a CCTV connector.
///
/// There is deliberately no frame, clip, thumbnail, embedding or biometric
/// field: the framework cannot forward video or biometric data even if a vendor
/// API would accept it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CameraContext {
    /// Venue.
    pub venue_id: String,
    /// Camera identifier.
    pub camera_id: String,
    /// Zone the camera covers.
    pub zone_id: String,
    /// Alarm or scan that motivated the request.
    pub trigger_id: String,
    /// When the context was requested.
    pub requested_est: i64,
}

impl CameraContext {
    /// Build a metadata-only camera context.
    pub fn new(
        venue_id: impl Into<String>,
        camera_id: impl Into<String>,
        zone_id: impl Into<String>,
        trigger_id: impl Into<String>,
        requested_est: i64,
    ) -> Result<Self, SchemaError> {
        let context = Self {
            venue_id: venue_id.into(),
            camera_id: camera_id.into(),
            zone_id: zone_id.into(),
            trigger_id: trigger_id.into(),
            requested_est,
        };
        for (field, value) in [
            ("venue_id", &context.venue_id),
            ("camera_id", &context.camera_id),
            ("zone_id", &context.zone_id),
            ("trigger_id", &context.trigger_id),
        ] {
            if value.trim().is_empty() || value.len() > MAX_ID_LEN {
                return Err(SchemaError::new(
                    field,
                    format!("must be 1..={MAX_ID_LEN} bytes"),
                ));
            }
            let lower = value.to_ascii_lowercase();
            if lower.contains("data:image")
                || lower.contains("base64")
                || lower.contains("face_embedding")
                || lower.contains("biometric")
            {
                return Err(SchemaError::new(
                    field,
                    "camera context is metadata only: media and biometrics are refused",
                ));
            }
        }
        if context.requested_est <= 0 {
            return Err(SchemaError::new("requested_est", "must be positive"));
        }
        Ok(context)
    }
}

/// CCTV connector surface.
pub trait CctvConnector: VenueConnector {
    /// Send an alarm to the video platform.
    fn on_alarm(&self, alarm: &VenueAlarm) -> DeliveryResult {
        self.deliver(&VenueEvent::alarm(alarm.clone()))
    }

    /// Request camera attention using metadata only.
    fn camera_context(&self, _context: &CameraContext) -> DeliveryResult {
        DeliveryResult::permanent("this connector does not accept camera context")
    }
}

/// Public-address connector surface.
pub trait PaConnector: VenueConnector {
    /// Send an announcement to the PA system.
    fn on_announcement(&self, announcement: &Announcement) -> DeliveryResult {
        self.deliver(&VenueEvent::announcement(announcement.clone()))
    }
}

/// Adapter from a [`VenueConnector`] to the CC-20 [`tirbase_integrations::Connector`].
pub(crate) struct VenueConnectorAdapter {
    inner: Box<dyn VenueConnector>,
}

impl VenueConnectorAdapter {
    pub(crate) fn new(inner: Box<dyn VenueConnector>) -> Self {
        Self { inner }
    }
}

impl tirbase_integrations::Connector for VenueConnectorAdapter {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn kind(&self) -> ConnectorKind {
        self.inner.transport()
    }

    fn capabilities(&self) -> tirbase_integrations::ConnectorCapabilities {
        let capabilities = self.inner.capabilities();
        tirbase_integrations::ConnectorCapabilities {
            idempotent: capabilities.idempotent,
            auth: vec![tirbase_integrations::AuthKind::HmacSignature],
            max_payload_bytes: capabilities.max_payload_bytes,
        }
    }

    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult {
        let Some(kind) = crate::event::VenueEventKind::parse(&request.event_type) else {
            return DeliveryResult::permanent(format!(
                "unknown venue event type {:?}",
                request.event_type
            ));
        };
        let event = match VenueEvent::from_body(kind, request.payload.clone()) {
            Ok(event) => event,
            Err(error) => return DeliveryResult::permanent(error.to_string()),
        };
        if !self
            .inner
            .domains()
            .iter()
            .any(|domain| domain.accepts(event.kind()))
        {
            return DeliveryResult::permanent(format!(
                "connector {} does not handle {} events",
                self.inner.name(),
                event.kind().as_str()
            ));
        }
        self.inner.deliver(&event)
    }

    fn health(&self) -> ConnectorHealth {
        self.inner.health()
    }
}
