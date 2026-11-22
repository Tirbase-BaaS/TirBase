// SPDX-License-Identifier: Apache-2.0

//! Venue event schemas.
//!
//! Four events cross a venue integration boundary: a ticket scan, an access
//! decision, an alarm and a public-address announcement. Each struct is
//! `deny_unknown_fields`, so a vendor extension cannot smuggle an undeclared
//! field (a face template, a payment card, a free-text medical note) through the
//! schema. Every event is validated before it can be queued for delivery.
//!
//! Personal data is deliberately limited to two optional holder fields on
//! [`TicketScan`]; [`crate::privacy::PrivacyPolicy`] removes them before any
//! payload leaves the venue.

use serde::{Deserialize, Serialize};

/// Longest accepted identifier.
pub const MAX_ID_LEN: usize = 128;
/// Longest accepted announcement text.
pub const MAX_TEXT_LEN: usize = 500;
/// Longest accepted alarm or decision detail.
pub const MAX_DETAIL_LEN: usize = 1_000;

/// Why a schema value was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError {
    /// Offending field.
    pub field: String,
    /// Why it is unusable. Never contains the offending value.
    pub detail: String,
}

impl SchemaError {
    /// Build an error naming the field.
    pub fn new(field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.detail)
    }
}

impl std::error::Error for SchemaError {}

fn id(field: &str, value: &str) -> Result<(), SchemaError> {
    if value.trim().is_empty() {
        return Err(SchemaError::new(field, "must not be empty"));
    }
    if value.len() > MAX_ID_LEN {
        return Err(SchemaError::new(
            field,
            format!("must be at most {MAX_ID_LEN} bytes"),
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SchemaError::new(
            field,
            "must not contain whitespace or control characters",
        ));
    }
    Ok(())
}

fn text(field: &str, value: &str, max: usize) -> Result<(), SchemaError> {
    if value.trim().is_empty() {
        return Err(SchemaError::new(field, "must not be empty"));
    }
    if value.len() > max {
        return Err(SchemaError::new(
            field,
            format!("must be at most {max} bytes"),
        ));
    }
    if value.chars().any(|character| character == '\0') {
        return Err(SchemaError::new(field, "must not contain NUL"));
    }
    Ok(())
}

/// Direction of a ticket scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDirection {
    /// Entering the venue.
    Entry,
    /// Leaving the venue.
    Exit,
}

/// Why access was denied, as a stable reason code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The ticket window has passed.
    Expired,
    /// The ticket was revoked.
    Revoked,
    /// The ticket was already used.
    Replay,
    /// A capacity envelope is full.
    Capacity,
    /// A lockdown is active.
    Lockdown,
    /// The ticket is not valid for this gate or venue.
    Invalid,
    /// The gate could not decide.
    Unknown,
}

impl DenyReason {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::Expired => "expired",
            DenyReason::Revoked => "revoked",
            DenyReason::Replay => "replay",
            DenyReason::Capacity => "capacity",
            DenyReason::Lockdown => "lockdown",
            DenyReason::Invalid => "invalid",
            DenyReason::Unknown => "unknown",
        }
    }
}

/// The outcome of an access decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOutcome {
    /// The holder was admitted.
    Granted,
    /// The holder was refused for `reason`.
    Denied {
        /// Stable refusal code.
        reason: DenyReason,
    },
}

/// A ticket presented at a gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketScan {
    /// Scan identifier from the scanner.
    pub scan_id: String,
    /// Venue the scan belongs to.
    pub venue_id: String,
    /// Gate or lane identifier.
    pub gate_id: String,
    /// Ticket identifier carried by the credential.
    pub ticket_id: String,
    /// Opaque holder reference from the scanner. Pseudonymised before delivery.
    pub holder_ref: String,
    /// Holder name, when the scanner supplies one. Never delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_name: Option<String>,
    /// Holder email, when the scanner supplies one. Never delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_email: Option<String>,
    /// Entry or exit.
    pub direction: ScanDirection,
    /// When the scan happened, in caller-supplied seconds.
    pub occurred_est: i64,
}

impl TicketScan {
    /// Build and validate a scan.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scan_id: impl Into<String>,
        venue_id: impl Into<String>,
        gate_id: impl Into<String>,
        ticket_id: impl Into<String>,
        holder_ref: impl Into<String>,
        direction: ScanDirection,
        occurred_est: i64,
    ) -> Result<Self, SchemaError> {
        let scan = Self {
            scan_id: scan_id.into(),
            venue_id: venue_id.into(),
            gate_id: gate_id.into(),
            ticket_id: ticket_id.into(),
            holder_ref: holder_ref.into(),
            holder_name: None,
            holder_email: None,
            direction,
            occurred_est,
        };
        scan.validate()?;
        Ok(scan)
    }

    /// Attach personal fields that the privacy layer must strip.
    pub fn with_holder_details(
        mut self,
        name: Option<impl Into<String>>,
        email: Option<impl Into<String>>,
    ) -> Self {
        self.holder_name = name.map(Into::into);
        self.holder_email = email.map(Into::into);
        self
    }

    /// Validate every field.
    pub fn validate(&self) -> Result<(), SchemaError> {
        id("scan_id", &self.scan_id)?;
        id("venue_id", &self.venue_id)?;
        id("gate_id", &self.gate_id)?;
        id("ticket_id", &self.ticket_id)?;
        id("holder_ref", &self.holder_ref)?;
        if let Some(name) = &self.holder_name {
            text("holder_name", name, MAX_ID_LEN)?;
        }
        if let Some(email) = &self.holder_email {
            text("holder_email", email, MAX_ID_LEN)?;
            if !email.contains('@') {
                return Err(SchemaError::new("holder_email", "must contain '@'"));
            }
        }
        if self.occurred_est <= 0 {
            return Err(SchemaError::new("occurred_est", "must be positive"));
        }
        Ok(())
    }
}

/// The gate's decision for a scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessDecision {
    /// Decision identifier.
    pub decision_id: String,
    /// Scan this decision answers.
    pub scan_id: String,
    /// Venue.
    pub venue_id: String,
    /// Gate or lane.
    pub gate_id: String,
    /// Outcome.
    pub outcome: AccessOutcome,
    /// When the decision was made.
    pub decided_est: i64,
}

impl AccessDecision {
    /// Build and validate a decision.
    pub fn new(
        decision_id: impl Into<String>,
        scan_id: impl Into<String>,
        venue_id: impl Into<String>,
        gate_id: impl Into<String>,
        outcome: AccessOutcome,
        decided_est: i64,
    ) -> Result<Self, SchemaError> {
        let decision = Self {
            decision_id: decision_id.into(),
            scan_id: scan_id.into(),
            venue_id: venue_id.into(),
            gate_id: gate_id.into(),
            outcome,
            decided_est,
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Validate every field.
    pub fn validate(&self) -> Result<(), SchemaError> {
        id("decision_id", &self.decision_id)?;
        id("scan_id", &self.scan_id)?;
        id("venue_id", &self.venue_id)?;
        id("gate_id", &self.gate_id)?;
        if self.decided_est <= 0 {
            return Err(SchemaError::new("decided_est", "must be positive"));
        }
        Ok(())
    }
}

/// Alarm family. Fire detection and suppression are deliberately absent: this
/// framework never controls or replaces a fire system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmKind {
    /// Crowd density above plan.
    CrowdDensity,
    /// A gate reported a fault.
    GateFault,
    /// An occupancy sensor is unavailable or disagreeing.
    SensorFault,
    /// An intrusion or forced-door signal.
    Intrusion,
    /// A staff member raised the alarm.
    OperatorPanic,
    /// A controller lost its network.
    NetworkLoss,
}

impl AlarmKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AlarmKind::CrowdDensity => "crowd_density",
            AlarmKind::GateFault => "gate_fault",
            AlarmKind::SensorFault => "sensor_fault",
            AlarmKind::Intrusion => "intrusion",
            AlarmKind::OperatorPanic => "operator_panic",
            AlarmKind::NetworkLoss => "network_loss",
        }
    }
}

/// Alarm severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmSeverity {
    /// Informational.
    Info,
    /// Needs attention.
    Warning,
    /// Needs immediate operator attention.
    Critical,
}

/// An operational alarm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VenueAlarm {
    /// Alarm identifier.
    pub alarm_id: String,
    /// Venue.
    pub venue_id: String,
    /// Zone or area.
    pub zone_id: String,
    /// Alarm family.
    pub kind: AlarmKind,
    /// Severity.
    pub severity: AlarmSeverity,
    /// Where the alarm came from (`gate-controller`, `sensor`, `operator`, …).
    pub source: String,
    /// Optional operator-facing detail. Scrubbed before delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// When the alarm was raised.
    pub occurred_est: i64,
}

impl VenueAlarm {
    /// Build and validate an alarm.
    pub fn new(
        alarm_id: impl Into<String>,
        venue_id: impl Into<String>,
        zone_id: impl Into<String>,
        kind: AlarmKind,
        severity: AlarmSeverity,
        occurred_est: i64,
    ) -> Result<Self, SchemaError> {
        let alarm = Self {
            alarm_id: alarm_id.into(),
            venue_id: venue_id.into(),
            zone_id: zone_id.into(),
            kind,
            severity,
            source: "venue".to_string(),
            detail: None,
            occurred_est,
        };
        alarm.validate()?;
        Ok(alarm)
    }

    /// Set the alarm source.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// Set optional detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Validate every field.
    pub fn validate(&self) -> Result<(), SchemaError> {
        id("alarm_id", &self.alarm_id)?;
        id("venue_id", &self.venue_id)?;
        id("zone_id", &self.zone_id)?;
        id("source", &self.source)?;
        if let Some(detail) = &self.detail {
            text("detail", detail, MAX_DETAIL_LEN)?;
        }
        if self.occurred_est <= 0 {
            return Err(SchemaError::new("occurred_est", "must be positive"));
        }
        Ok(())
    }
}

/// Announcement urgency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementSeverity {
    /// Routine information.
    Info,
    /// Caution.
    Warning,
    /// Evacuation-supporting or urgent public message.
    Emergency,
}

/// A public-address announcement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Announcement {
    /// Announcement identifier.
    pub announcement_id: String,
    /// Venue.
    pub venue_id: String,
    /// Zones that should hear it.
    pub zone_ids: Vec<String>,
    /// Urgency.
    pub severity: AnnouncementSeverity,
    /// Text to speak or display. Direct identifiers are scrubbed before delivery.
    pub text: String,
    /// BCP-47-style language tag.
    #[serde(default = "default_language")]
    pub language: String,
    /// When it becomes active.
    pub starts_est: i64,
    /// When it stops being active, if bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_est: Option<i64>,
}

fn default_language() -> String {
    "en".to_string()
}

impl Announcement {
    /// Build and validate an announcement.
    pub fn new(
        announcement_id: impl Into<String>,
        venue_id: impl Into<String>,
        zone_ids: Vec<String>,
        severity: AnnouncementSeverity,
        text: impl Into<String>,
        starts_est: i64,
    ) -> Result<Self, SchemaError> {
        let announcement = Self {
            announcement_id: announcement_id.into(),
            venue_id: venue_id.into(),
            zone_ids,
            severity,
            text: text.into(),
            language: default_language(),
            starts_est,
            ends_est: None,
        };
        announcement.validate()?;
        Ok(announcement)
    }

    /// Bound the announcement window.
    pub fn until(mut self, ends_est: i64) -> Result<Self, SchemaError> {
        self.ends_est = Some(ends_est);
        self.validate()?;
        Ok(self)
    }

    /// Validate every field.
    pub fn validate(&self) -> Result<(), SchemaError> {
        id("announcement_id", &self.announcement_id)?;
        id("venue_id", &self.venue_id)?;
        if self.zone_ids.is_empty() {
            return Err(SchemaError::new("zone_ids", "must name at least one zone"));
        }
        for zone in &self.zone_ids {
            id("zone_ids", zone)?;
        }
        let unique = self
            .zone_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if unique.len() != self.zone_ids.len() {
            return Err(SchemaError::new("zone_ids", "must not repeat a zone"));
        }
        text("text", &self.text, MAX_TEXT_LEN)?;
        if self.language.len() < 2
            || self.language.len() > 16
            || !self
                .language
                .chars()
                .all(|character| character.is_ascii_alphabetic() || character == '-')
        {
            return Err(SchemaError::new(
                "language",
                "must be 2..=16 ASCII letters or '-'",
            ));
        }
        if self.starts_est <= 0 {
            return Err(SchemaError::new("starts_est", "must be positive"));
        }
        if let Some(ends) = self.ends_est {
            if ends <= self.starts_est {
                return Err(SchemaError::new("ends_est", "must be after starts_est"));
            }
        }
        Ok(())
    }
}

/// The event family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueEventKind {
    /// A ticket was scanned.
    TicketScan,
    /// A gate decided an access request.
    AccessDecision,
    /// An operational alarm was raised.
    Alarm,
    /// A public announcement was issued.
    Announcement,
}

impl VenueEventKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            VenueEventKind::TicketScan => "ticket_scan",
            VenueEventKind::AccessDecision => "access_decision",
            VenueEventKind::Alarm => "alarm",
            VenueEventKind::Announcement => "announcement",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ticket_scan" => Some(VenueEventKind::TicketScan),
            "access_decision" => Some(VenueEventKind::AccessDecision),
            "alarm" => Some(VenueEventKind::Alarm),
            "announcement" => Some(VenueEventKind::Announcement),
            _ => None,
        }
    }
}

/// A venue event crossing a connector boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VenueEvent {
    /// A ticket was scanned.
    TicketScan {
        /// Scan body.
        scan: TicketScan,
    },
    /// A gate decided an access request.
    AccessDecision {
        /// Decision body.
        decision: AccessDecision,
    },
    /// An alarm was raised.
    Alarm {
        /// Alarm body.
        alarm: VenueAlarm,
    },
    /// An announcement was issued.
    Announcement {
        /// Announcement body.
        announcement: Announcement,
    },
}

impl VenueEvent {
    /// Wrap a scan.
    pub fn ticket_scan(scan: TicketScan) -> Self {
        Self::TicketScan { scan }
    }

    /// Wrap a decision.
    pub fn access_decision(decision: AccessDecision) -> Self {
        Self::AccessDecision { decision }
    }

    /// Wrap an alarm.
    pub fn alarm(alarm: VenueAlarm) -> Self {
        Self::Alarm { alarm }
    }

    /// Wrap an announcement.
    pub fn announcement(announcement: Announcement) -> Self {
        Self::Announcement { announcement }
    }

    /// The event family.
    pub fn kind(&self) -> VenueEventKind {
        match self {
            VenueEvent::TicketScan { .. } => VenueEventKind::TicketScan,
            VenueEvent::AccessDecision { .. } => VenueEventKind::AccessDecision,
            VenueEvent::Alarm { .. } => VenueEventKind::Alarm,
            VenueEvent::Announcement { .. } => VenueEventKind::Announcement,
        }
    }

    /// The producer-assigned identifier for this event.
    pub fn native_id(&self) -> &str {
        match self {
            VenueEvent::TicketScan { scan } => &scan.scan_id,
            VenueEvent::AccessDecision { decision } => &decision.decision_id,
            VenueEvent::Alarm { alarm } => &alarm.alarm_id,
            VenueEvent::Announcement { announcement } => &announcement.announcement_id,
        }
    }

    /// The venue this event belongs to.
    pub fn venue_id(&self) -> &str {
        match self {
            VenueEvent::TicketScan { scan } => &scan.venue_id,
            VenueEvent::AccessDecision { decision } => &decision.venue_id,
            VenueEvent::Alarm { alarm } => &alarm.venue_id,
            VenueEvent::Announcement { announcement } => &announcement.venue_id,
        }
    }

    /// When the event happened.
    pub fn occurred_est(&self) -> i64 {
        match self {
            VenueEvent::TicketScan { scan } => scan.occurred_est,
            VenueEvent::AccessDecision { decision } => decision.decided_est,
            VenueEvent::Alarm { alarm } => alarm.occurred_est,
            VenueEvent::Announcement { announcement } => announcement.starts_est,
        }
    }

    /// Validate the body.
    pub fn validate(&self) -> Result<(), SchemaError> {
        match self {
            VenueEvent::TicketScan { scan } => scan.validate(),
            VenueEvent::AccessDecision { decision } => decision.validate(),
            VenueEvent::Alarm { alarm } => alarm.validate(),
            VenueEvent::Announcement { announcement } => announcement.validate(),
        }
    }

    /// Deterministic delivery identifier.
    ///
    /// Derived from the venue, event family and producer id, so a replay,
    /// restart or dead-letter replay presents the same id and key.
    pub fn event_id(&self) -> String {
        crate::idempotency::event_id(self)
    }

    /// Rebuild an event from its family and body.
    ///
    /// The dispatcher stores only the redacted body in the outbox; the adapter
    /// re-wraps it with the family from the delivery request.
    pub fn from_body(
        kind: VenueEventKind,
        payload: serde_json::Value,
    ) -> Result<Self, SchemaError> {
        let event = match kind {
            VenueEventKind::TicketScan => VenueEvent::ticket_scan(
                serde_json::from_value(payload)
                    .map_err(|error| SchemaError::new("payload", error.to_string()))?,
            ),
            VenueEventKind::AccessDecision => VenueEvent::access_decision(
                serde_json::from_value(payload)
                    .map_err(|error| SchemaError::new("payload", error.to_string()))?,
            ),
            VenueEventKind::Alarm => VenueEvent::alarm(
                serde_json::from_value(payload)
                    .map_err(|error| SchemaError::new("payload", error.to_string()))?,
            ),
            VenueEventKind::Announcement => VenueEvent::announcement(
                serde_json::from_value(payload)
                    .map_err(|error| SchemaError::new("payload", error.to_string()))?,
            ),
        };
        event.validate()?;
        Ok(event)
    }

    /// The event body without the kind tag.
    pub fn payload(&self) -> Result<serde_json::Value, SchemaError> {
        let value = match self {
            VenueEvent::TicketScan { scan } => serde_json::to_value(scan),
            VenueEvent::AccessDecision { decision } => serde_json::to_value(decision),
            VenueEvent::Alarm { alarm } => serde_json::to_value(alarm),
            VenueEvent::Announcement { announcement } => serde_json::to_value(announcement),
        };
        value.map_err(|error| SchemaError::new("payload", error.to_string()))
    }
}
