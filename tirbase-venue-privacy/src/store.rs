// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-privacy — ST-13 privacy runtime
//!
//! The venue privacy boundary is intentionally small:
//!
//! * **No raw video.** [`CctvEvent`] is metadata only. It has no frame, clip,
//!   thumbnail, embedding or biometric field, and [`CctvEvent::new`] refuses
//!   media/ biometric markers in every text field.
//! * **Retention is enforced.** A metadata event becomes unreadable at its
//!   retention deadline, and [`CctvStore::purge_expired`] removes it. A legal
//!   hold extends retention and blocks deletion.
//! * **Access is role-scoped and audited.** Every read, export, delete, hold and
//!   purge is recorded without copying the event payload into the audit log.
//! * **Subject access and erasure respect holds.** [`CctvStore::subject_export`]
//!   returns only the requested subject's retained metadata; deletion removes
//!   only unheld events and reports what a hold kept.
//!
//! The embedded register ([`privacy_register`]) is the field-level source of
//! truth for the DPIA pack: every field records purpose, lawful basis,
//! retention and access. `tests/st13_privacy.rs` fails if a field is incomplete.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Seconds in a day.
pub const SECONDS_PER_DAY: i64 = 86_400;
/// Operational CCTV metadata retention: 7 days.
pub const CCTV_OPERATIONAL_SECS: i64 = 7 * SECONDS_PER_DAY;
/// Security CCTV metadata retention: 30 days.
pub const CCTV_SECURITY_SECS: i64 = 30 * SECONDS_PER_DAY;
/// Safety CCTV metadata retention: 90 days.
pub const CCTV_SAFETY_SECS: i64 = 90 * SECONDS_PER_DAY;
/// Access-decision retention: 90 days.
pub const ACCESS_RETENTION_SECS: i64 = 90 * SECONDS_PER_DAY;
/// Ticket/credential operational retention after the event: 30 days.
pub const TICKET_RETENTION_SECS: i64 = 30 * SECONDS_PER_DAY;
/// Subject-access/deletion request record retention: 365 days.
pub const DSAR_RECORD_RETENTION_SECS: i64 = 365 * SECONDS_PER_DAY;

/// Embedded per-field privacy register.
pub const REGISTER_CSV: &str = include_str!("../../data/venue-privacy-register.csv");

/// Retention codes used by the register and the schedule.
pub const RETENTION_CODES: [&str; 9] = [
    "TICKET_30D",
    "CREDENTIAL_30D",
    "ACCESS_90D",
    "CCTV_SECURITY_30D",
    "CCTV_SAFETY_90D",
    "CCTV_OPERATIONAL_7D",
    "AUDIT_365D",
    "LEGAL_HOLD",
    "MINIMISED_OR_NONE",
];

/// Why the embedded register is unusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterError(pub String);

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RegisterError {}

/// Whether a register field is personal data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalData {
    /// Directly or indirectly identifies a person.
    Yes,
    /// Does not identify a person.
    No,
    /// Context-dependent; the deployment must decide before use.
    Maybe,
}

impl PersonalData {
    /// Parse the register marker.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Some(PersonalData::Yes),
            "n" | "no" => Some(PersonalData::No),
            "maybe" => Some(PersonalData::Maybe),
            _ => None,
        }
    }

    /// Stable register marker.
    pub fn as_str(self) -> &'static str {
        match self {
            PersonalData::Yes => "Y",
            PersonalData::No => "N",
            PersonalData::Maybe => "Maybe",
        }
    }
}

/// One row of the venue privacy register.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyField {
    /// Stable field id used by the DPIA and data-flow map.
    pub field_id: String,
    /// `ticket`, `credential`, `cctv` or `access`.
    pub domain: String,
    /// Logical field name.
    pub field_name: String,
    /// System, table, log or integration surface.
    pub location: String,
    /// Whether the field is personal data.
    pub personal_data: PersonalData,
    /// Why the field exists.
    pub purpose: String,
    /// Template lawful basis; local counsel must confirm it.
    pub lawful_basis: String,
    /// Retention code from [`RETENTION_CODES`].
    pub retention_code: String,
    /// Human retention rule.
    pub retention_detail: String,
    /// Who may read or use it.
    pub access_rule: String,
    /// How it is deleted or redacted.
    pub deletion_method: String,
    /// Boundary or cross-reference.
    pub notes: String,
}

/// Parse the embedded register. Commas are not permitted inside a cell; use
/// semicolons for lists so the small std-only parser remains unambiguous.
pub fn privacy_register() -> Result<Vec<PrivacyField>, RegisterError> {
    parse_register(REGISTER_CSV)
}

/// Parse a register with the exact ST-13 header.
pub fn parse_register(text: &str) -> Result<Vec<PrivacyField>, RegisterError> {
    const HEADER: &str = "field_id,domain,field_name,location,personal_data,purpose,lawful_basis,retention_code,retention_detail,access_rule,deletion_method,notes";
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Err(RegisterError("register is empty".to_string()));
    };
    if header.trim() != HEADER {
        return Err(RegisterError(format!(
            "register header must be {HEADER:?}, got {header:?}"
        )));
    }
    let mut fields = Vec::new();
    for (index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let columns: Vec<&str> = line.split(',').map(str::trim).collect();
        if columns.len() != 12 {
            return Err(RegisterError(format!(
                "register line {} has {} columns, expected 12",
                index + 2,
                columns.len()
            )));
        }
        let personal_data = PersonalData::parse(columns[4]).ok_or_else(|| {
            RegisterError(format!(
                "register line {} has invalid personal_data {:?}",
                index + 2,
                columns[4]
            ))
        })?;
        let field = PrivacyField {
            field_id: columns[0].to_string(),
            domain: columns[1].to_string(),
            field_name: columns[2].to_string(),
            location: columns[3].to_string(),
            personal_data,
            purpose: columns[5].to_string(),
            lawful_basis: columns[6].to_string(),
            retention_code: columns[7].to_string(),
            retention_detail: columns[8].to_string(),
            access_rule: columns[9].to_string(),
            deletion_method: columns[10].to_string(),
            notes: columns[11].to_string(),
        };
        if field.field_id.is_empty()
            || field.domain.is_empty()
            || field.field_name.is_empty()
            || field.location.is_empty()
            || field.purpose.is_empty()
            || field.lawful_basis.is_empty()
            || field.retention_code.is_empty()
            || field.retention_detail.is_empty()
            || field.access_rule.is_empty()
            || field.deletion_method.is_empty()
        {
            return Err(RegisterError(format!(
                "register line {} has an empty required cell",
                index + 2
            )));
        }
        if !RETENTION_CODES.contains(&field.retention_code.as_str()) {
            return Err(RegisterError(format!(
                "register line {} has unknown retention code {:?}",
                index + 2,
                field.retention_code
            )));
        }
        fields.push(field);
    }
    if fields.is_empty() {
        return Err(RegisterError("register has no fields".to_string()));
    }
    Ok(fields)
}

/// CCTV event families. The family selects the retention class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CctvEventKind {
    /// Intrusion, forced door, gate fault or security incident.
    Security,
    /// Access anomaly (denied/replayed credential at a lane).
    AccessAnomaly,
    /// Fire, crowd, medical or other safety event.
    Safety,
    /// Routine operational metadata.
    Operational,
}

impl CctvEventKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            CctvEventKind::Security => "security",
            CctvEventKind::AccessAnomaly => "access_anomaly",
            CctvEventKind::Safety => "safety",
            CctvEventKind::Operational => "operational",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "security" => Some(CctvEventKind::Security),
            "access_anomaly" | "access-anomaly" => Some(CctvEventKind::AccessAnomaly),
            "safety" => Some(CctvEventKind::Safety),
            "operational" => Some(CctvEventKind::Operational),
            _ => None,
        }
    }

    /// Retention class for this family.
    pub fn retention_class(self) -> CctvRetentionClass {
        match self {
            CctvEventKind::Security | CctvEventKind::AccessAnomaly => CctvRetentionClass::Security,
            CctvEventKind::Safety => CctvRetentionClass::Safety,
            CctvEventKind::Operational => CctvRetentionClass::Operational,
        }
    }
}

/// Retention classes in the CCTV schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CctvRetentionClass {
    /// 7 days.
    Operational,
    /// 30 days.
    Security,
    /// 90 days.
    Safety,
}

impl CctvRetentionClass {
    /// Maximum retention from occurrence, in seconds.
    pub fn max_secs(self) -> i64 {
        match self {
            CctvRetentionClass::Operational => CCTV_OPERATIONAL_SECS,
            CctvRetentionClass::Security => CCTV_SECURITY_SECS,
            CctvRetentionClass::Safety => CCTV_SAFETY_SECS,
        }
    }

    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            CctvRetentionClass::Operational => "operational",
            CctvRetentionClass::Security => "security",
            CctvRetentionClass::Safety => "safety",
        }
    }
}

/// A metadata-only CCTV event. There is deliberately no media field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CctvEvent {
    event_id: String,
    venue_id: String,
    camera_id: String,
    zone_id: String,
    kind: CctvEventKind,
    occurred_est: i64,
    subject_ref: Option<String>,
    note: Option<String>,
}

impl CctvEvent {
    /// Build metadata-only CCTV evidence.
    pub fn new(
        event_id: impl Into<String>,
        venue_id: impl Into<String>,
        camera_id: impl Into<String>,
        zone_id: impl Into<String>,
        kind: CctvEventKind,
        occurred_est: i64,
    ) -> Result<Self, CctvError> {
        let event = Self {
            event_id: event_id.into(),
            venue_id: venue_id.into(),
            camera_id: camera_id.into(),
            zone_id: zone_id.into(),
            kind,
            occurred_est,
            subject_ref: None,
            note: None,
        };
        event.validate()?;
        Ok(event)
    }

    /// Attach a pseudonymous subject reference.
    pub fn with_subject(mut self, subject_ref: impl Into<String>) -> Result<Self, CctvError> {
        self.subject_ref = Some(subject_ref.into());
        self.validate()?;
        Ok(self)
    }

    /// Attach an operator note. Media is refused.
    pub fn with_note(mut self, note: impl Into<String>) -> Result<Self, CctvError> {
        self.note = Some(note.into());
        self.validate()?;
        Ok(self)
    }

    /// Event identifier.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Venue.
    pub fn venue_id(&self) -> &str {
        &self.venue_id
    }

    /// Camera identifier.
    pub fn camera_id(&self) -> &str {
        &self.camera_id
    }

    /// Zone.
    pub fn zone_id(&self) -> &str {
        &self.zone_id
    }

    /// Event family.
    pub fn kind(&self) -> CctvEventKind {
        self.kind
    }

    /// Occurrence time.
    pub fn occurred_est(&self) -> i64 {
        self.occurred_est
    }

    /// Pseudonymous subject reference, when one exists.
    pub fn subject_ref(&self) -> Option<&str> {
        self.subject_ref.as_deref()
    }

    /// Operator note, when one exists.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Retention class selected by the event family.
    pub fn retention_class(&self) -> CctvRetentionClass {
        self.kind.retention_class()
    }

    /// Retention deadline without a legal hold.
    pub fn retention_deadline(&self) -> i64 {
        self.occurred_est
            .saturating_add(self.retention_class().max_secs())
    }

    /// Validate identifiers, time and text.
    pub fn validate(&self) -> Result<(), CctvError> {
        for (name, value) in [
            ("event_id", &self.event_id),
            ("venue_id", &self.venue_id),
            ("camera_id", &self.camera_id),
            ("zone_id", &self.zone_id),
        ] {
            validate_id(name, value)?;
        }
        if let Some(subject) = &self.subject_ref {
            validate_id("subject_ref", subject)?;
        }
        if let Some(note) = &self.note {
            if note.trim().is_empty() {
                return Err(CctvError::Invalid("note must not be empty".to_string()));
            }
            if note.len() > 1_000 {
                return Err(CctvError::Invalid(
                    "note must be at most 1000 bytes".to_string(),
                ));
            }
            if note.chars().any(|character| character == '\0') {
                return Err(CctvError::Invalid("note must not contain NUL".to_string()));
            }
            refuse_media("note", note)?;
        }
        for (name, value) in [
            ("event_id", &self.event_id),
            ("venue_id", &self.venue_id),
            ("camera_id", &self.camera_id),
            ("zone_id", &self.zone_id),
        ] {
            refuse_media(name, value)?;
        }
        if let Some(subject) = &self.subject_ref {
            refuse_media("subject_ref", subject)?;
        }
        if self.occurred_est <= 0 {
            return Err(CctvError::Invalid(
                "occurred_est must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

/// A legal hold that suspends retention/deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CctvLegalHold {
    hold_id: String,
    venue_id: String,
    scope: CctvHoldScope,
    reason: String,
    started_est: i64,
    released_est: Option<i64>,
}

impl CctvLegalHold {
    /// Create an active hold.
    pub fn new(
        hold_id: impl Into<String>,
        venue_id: impl Into<String>,
        scope: CctvHoldScope,
        reason: impl Into<String>,
        started_est: i64,
    ) -> Result<Self, CctvError> {
        let hold = Self {
            hold_id: hold_id.into(),
            venue_id: venue_id.into(),
            scope,
            reason: reason.into(),
            started_est,
            released_est: None,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Hold identifier.
    pub fn hold_id(&self) -> &str {
        &self.hold_id
    }

    /// Venue.
    pub fn venue_id(&self) -> &str {
        &self.venue_id
    }

    /// Scope.
    pub fn scope(&self) -> &CctvHoldScope {
        &self.scope
    }

    /// Reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Start.
    pub fn started_est(&self) -> i64 {
        self.started_est
    }

    /// Release time, if lifted.
    pub fn released_est(&self) -> Option<i64> {
        self.released_est
    }

    /// Whether this hold is still active.
    pub fn is_active(&self) -> bool {
        self.released_est.is_none()
    }

    fn validate(&self) -> Result<(), CctvError> {
        validate_id("hold_id", &self.hold_id)?;
        validate_id("venue_id", &self.venue_id)?;
        if self.reason.trim().is_empty() || self.reason.len() > 512 {
            return Err(CctvError::Invalid(
                "hold reason must be 1..=512 bytes".to_string(),
            ));
        }
        if self.started_est <= 0 {
            return Err(CctvError::Invalid(
                "hold started_est must be positive".to_string(),
            ));
        }
        match &self.scope {
            CctvHoldScope::Subject(subject) => validate_id("hold subject", subject)?,
            CctvHoldScope::Event(event) => validate_id("hold event", event)?,
            CctvHoldScope::Venue(venue) => validate_id("hold venue", venue)?,
        }
        Ok(())
    }

    fn covers(&self, event: &CctvEvent) -> bool {
        if !self.is_active() || self.venue_id != event.venue_id {
            return false;
        }
        match &self.scope {
            CctvHoldScope::Subject(subject) => event.subject_ref.as_deref() == Some(subject),
            CctvHoldScope::Event(event_id) => event.event_id == *event_id,
            CctvHoldScope::Venue(venue) => event.venue_id == *venue,
        }
    }
}

/// What a legal hold covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CctvHoldScope {
    /// Pseudonymous subject reference.
    Subject(String),
    /// One event.
    Event(String),
    /// Every event at a venue.
    Venue(String),
}

/// A role allowed to use CCTV metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CctvRole {
    /// Gate/security operator: security, anomaly and operational metadata.
    SecurityOperator,
    /// Safety officer: safety and security metadata.
    SafetyOfficer,
    /// Read-only auditor: all metadata, no export/deletion.
    Auditor,
    /// Data protection officer/privacy administrator: all metadata and DSAR work.
    PrivacyOfficer,
    /// Venue manager: operational metadata only.
    VenueManager,
}

impl CctvRole {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            CctvRole::SecurityOperator => "security_operator",
            CctvRole::SafetyOfficer => "safety_officer",
            CctvRole::Auditor => "auditor",
            CctvRole::PrivacyOfficer => "privacy_officer",
            CctvRole::VenueManager => "venue_manager",
        }
    }

    /// Parse a role name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "security_operator" | "security" => Some(CctvRole::SecurityOperator),
            "safety_officer" | "safety" => Some(CctvRole::SafetyOfficer),
            "auditor" => Some(CctvRole::Auditor),
            "privacy_officer" | "dpo" => Some(CctvRole::PrivacyOfficer),
            "venue_manager" | "manager" => Some(CctvRole::VenueManager),
            _ => None,
        }
    }

    /// Whether the role may read this event family.
    pub fn can_read(self, kind: CctvEventKind) -> bool {
        match self {
            CctvRole::PrivacyOfficer | CctvRole::Auditor => true,
            CctvRole::SecurityOperator => matches!(
                kind,
                CctvEventKind::Security | CctvEventKind::AccessAnomaly | CctvEventKind::Operational
            ),
            CctvRole::SafetyOfficer => {
                matches!(kind, CctvEventKind::Safety | CctvEventKind::Security)
            }
            CctvRole::VenueManager => matches!(kind, CctvEventKind::Operational),
        }
    }

    /// Whether the role may ingest, hold, purge, export or delete.
    pub fn can_admin(self) -> bool {
        self == CctvRole::PrivacyOfficer
    }
}

/// Authenticated CCTV actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CctvActor {
    /// Actor id from the authenticated session.
    pub actor_id: String,
    /// Role at the time of the request.
    pub role: CctvRole,
    /// Venue the actor is scoped to.
    pub venue_id: String,
}

impl CctvActor {
    /// Build an actor after authentication.
    pub fn new(
        actor_id: impl Into<String>,
        role: CctvRole,
        venue_id: impl Into<String>,
    ) -> Result<Self, CctvError> {
        let actor = Self {
            actor_id: actor_id.into(),
            role,
            venue_id: venue_id.into(),
        };
        validate_id("actor_id", &actor.actor_id)?;
        validate_id("actor venue_id", &actor.venue_id)?;
        Ok(actor)
    }
}

/// An audited CCTV action. It names the event/hold and actor, never the payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CctvAccessRecord {
    /// Monotonic sequence.
    pub seq: u64,
    /// When.
    pub at_est: i64,
    /// Actor.
    pub actor_id: String,
    /// Role.
    pub role: CctvRole,
    /// `ingest`, `read`, `list`, `purge`, `hold.add`, `hold.release`,
    /// `subject.export` or `subject.delete`.
    pub action: String,
    /// Event, hold id or request id, never the subject reference.
    pub target: String,
    /// Whether the action was allowed.
    pub allowed: bool,
}

/// What a retention sweep did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CctvRetentionReport {
    /// Expired events seen.
    pub expired_seen: usize,
    /// Event ids removed.
    pub purged: Vec<String>,
    /// Event ids kept because a legal hold covers them.
    pub retained_under_hold: Vec<String>,
    /// When the sweep ran.
    pub at_est: i64,
}

/// A subject-access response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CctvSubjectAccessReport {
    /// The requested subject reference.
    pub subject_ref: String,
    /// Retained events for that subject.
    pub events: Vec<CctvEvent>,
    /// Active holds covering those events.
    pub legal_holds: Vec<CctvLegalHold>,
    /// When generated.
    pub generated_est: i64,
    /// Whether an event was withheld because a hold keeps it beyond normal
    /// retention (it is still included, and this flag explains why).
    pub includes_held_events: bool,
}

/// A subject-deletion result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CctvDeletionReport {
    /// Request id.
    pub request_id: String,
    /// Event ids deleted.
    pub deleted: Vec<String>,
    /// Event ids retained under hold.
    pub retained_under_hold: Vec<String>,
    /// Active holds that caused retention.
    pub legal_holds: Vec<CctvLegalHold>,
    /// When.
    pub at_est: i64,
}

/// Why a CCTV privacy operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CctvError {
    /// Unknown event or hold.
    NotFound(String),
    /// Duplicate event or hold.
    Duplicate(String),
    /// Role is not allowed.
    Forbidden(String),
    /// Actor and event belong to different venues.
    VenueMismatch,
    /// Normal retention has expired and no hold applies.
    Expired(String),
    /// Invalid input.
    Invalid(String),
    /// Media or biometric data was offered.
    MediaRefused(String),
    /// Stored JSON is invalid.
    Corrupt(String),
}

impl std::fmt::Display for CctvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CctvError::NotFound(value) => write!(f, "not found: {value}"),
            CctvError::Duplicate(value) => write!(f, "duplicate: {value}"),
            CctvError::Forbidden(value) => write!(f, "forbidden: {value}"),
            CctvError::VenueMismatch => f.write_str("actor and event venue differ"),
            CctvError::Expired(value) => write!(f, "retention expired: {value}"),
            CctvError::Invalid(value) => write!(f, "invalid: {value}"),
            CctvError::MediaRefused(value) => write!(f, "media refused: {value}"),
            CctvError::Corrupt(value) => write!(f, "corrupt state: {value}"),
        }
    }
}

impl std::error::Error for CctvError {}

/// In-memory CCTV metadata store with enforced retention and holds.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CctvStore {
    events: BTreeMap<String, CctvEvent>,
    holds: Vec<CctvLegalHold>,
    access_log: Vec<CctvAccessRecord>,
}

impl CctvStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of retained events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the store has no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Retained event identifiers, in event-id order. Payload access goes
    /// through [`Self::read`] or [`Self::list`] so the role check and audit log
    /// cannot be bypassed.
    pub fn retained_event_ids(&self) -> Vec<String> {
        self.events.keys().cloned().collect()
    }

    /// Audit trail.
    pub fn access_log(&self) -> &[CctvAccessRecord] {
        &self.access_log
    }

    /// Active and released holds.
    pub fn holds(&self) -> &[CctvLegalHold] {
        &self.holds
    }

    /// Ingest a metadata event. Only a privacy officer may do so.
    pub fn insert(&mut self, actor: &CctvActor, event: CctvEvent) -> Result<(), CctvError> {
        if !actor.role.can_admin() {
            self.log(actor, "ingest", event.event_id(), false, 0);
            return Err(CctvError::Forbidden(
                "only a privacy officer may ingest CCTV metadata".to_string(),
            ));
        }
        if actor.venue_id != event.venue_id {
            self.log(actor, "ingest", event.event_id(), false, 0);
            return Err(CctvError::VenueMismatch);
        }
        event.validate()?;
        if self.events.contains_key(event.event_id()) {
            return Err(CctvError::Duplicate(event.event_id().to_string()));
        }
        let id = event.event_id().to_string();
        self.events.insert(id.clone(), event);
        self.log(actor, "ingest", &id, true, 0);
        Ok(())
    }

    /// Read one event; expiry is enforced before the payload is returned.
    pub fn read(
        &mut self,
        actor: &CctvActor,
        event_id: &str,
        now_est: i64,
    ) -> Result<CctvEvent, CctvError> {
        let Some(event) = self.events.get(event_id).cloned() else {
            self.log(actor, "read", event_id, false, now_est);
            return Err(CctvError::NotFound(event_id.to_string()));
        };
        if actor.venue_id != event.venue_id {
            self.log(actor, "read", event_id, false, now_est);
            return Err(CctvError::VenueMismatch);
        }
        if !actor.role.can_read(event.kind) {
            self.log(actor, "read", event_id, false, now_est);
            return Err(CctvError::Forbidden(format!(
                "{} may not read {} CCTV metadata",
                actor.role.as_str(),
                event.kind.as_str()
            )));
        }
        if !self.is_held(&event) && now_est > event.retention_deadline() {
            self.log(actor, "read", event_id, false, now_est);
            return Err(CctvError::Expired(event_id.to_string()));
        }
        self.log(actor, "read", event_id, true, now_est);
        Ok(event)
    }

    /// List visible, unexpired (or held) events for an actor.
    pub fn list(&mut self, actor: &CctvActor, now_est: i64) -> Vec<CctvEvent> {
        let events: Vec<CctvEvent> = self
            .events
            .values()
            .filter(|event| event.venue_id == actor.venue_id)
            .filter(|event| actor.role.can_read(event.kind))
            .filter(|event| self.is_held(event) || now_est <= event.retention_deadline())
            .cloned()
            .collect();
        self.log(
            actor,
            "list",
            &format!("{} event(s)", events.len()),
            true,
            now_est,
        );
        events
    }

    /// Add a legal hold. A hold blocks purge and subject deletion for its scope.
    pub fn add_legal_hold(
        &mut self,
        actor: &CctvActor,
        hold: CctvLegalHold,
        now_est: i64,
    ) -> Result<(), CctvError> {
        if !actor.role.can_admin() {
            self.log(actor, "hold.add", hold.hold_id(), false, now_est);
            return Err(CctvError::Forbidden(
                "only a privacy officer may add a legal hold".to_string(),
            ));
        }
        if actor.venue_id != hold.venue_id {
            self.log(actor, "hold.add", hold.hold_id(), false, now_est);
            return Err(CctvError::VenueMismatch);
        }
        if self
            .holds
            .iter()
            .any(|existing| existing.hold_id == hold.hold_id)
        {
            return Err(CctvError::Duplicate(hold.hold_id.clone()));
        }
        hold.validate()?;
        let id = hold.hold_id().to_string();
        self.holds.push(hold);
        self.log(actor, "hold.add", &id, true, now_est);
        Ok(())
    }

    /// Release a legal hold.
    pub fn release_legal_hold(
        &mut self,
        actor: &CctvActor,
        hold_id: &str,
        now_est: i64,
    ) -> Result<(), CctvError> {
        if !actor.role.can_admin() {
            self.log(actor, "hold.release", hold_id, false, now_est);
            return Err(CctvError::Forbidden(
                "only a privacy officer may release a legal hold".to_string(),
            ));
        }
        let Some(hold) = self.holds.iter_mut().find(|hold| hold.hold_id == hold_id) else {
            return Err(CctvError::NotFound(hold_id.to_string()));
        };
        if hold.venue_id != actor.venue_id {
            return Err(CctvError::VenueMismatch);
        }
        if !hold.is_active() {
            return Err(CctvError::Invalid(format!(
                "hold {hold_id} is already released"
            )));
        }
        hold.released_est = Some(now_est);
        self.log(actor, "hold.release", hold_id, true, now_est);
        Ok(())
    }

    /// Whether an active hold covers this event.
    pub fn is_held(&self, event: &CctvEvent) -> bool {
        self.holds.iter().any(|hold| hold.covers(event))
    }

    /// Active holds covering this event.
    pub fn holds_for(&self, event: &CctvEvent) -> Vec<CctvLegalHold> {
        self.holds
            .iter()
            .filter(|hold| hold.covers(event))
            .cloned()
            .collect()
    }

    /// Remove expired events. Every event left is either unexpired or held.
    pub fn purge_expired(
        &mut self,
        actor: &CctvActor,
        now_est: i64,
    ) -> Result<CctvRetentionReport, CctvError> {
        if !actor.role.can_admin() {
            self.log(actor, "purge", "retention", false, now_est);
            return Err(CctvError::Forbidden(
                "only a privacy officer may run retention".to_string(),
            ));
        }
        let expired: Vec<CctvEvent> = self
            .events
            .values()
            .filter(|event| event.venue_id == actor.venue_id)
            .filter(|event| now_est > event.retention_deadline())
            .cloned()
            .collect();
        let mut purged = Vec::new();
        let mut retained_under_hold = Vec::new();
        for event in &expired {
            if self.is_held(event) {
                retained_under_hold.push(event.event_id().to_string());
            } else {
                self.events.remove(event.event_id());
                purged.push(event.event_id().to_string());
            }
        }
        self.log(
            actor,
            "purge",
            &format!("{} purged/{} held", purged.len(), retained_under_hold.len()),
            true,
            now_est,
        );
        Ok(CctvRetentionReport {
            expired_seen: expired.len(),
            purged,
            retained_under_hold,
            at_est: now_est,
        })
    }

    /// Subject-access report. Only the privacy officer may generate one.
    pub fn subject_export(
        &mut self,
        actor: &CctvActor,
        subject_ref: &str,
        now_est: i64,
    ) -> Result<CctvSubjectAccessReport, CctvError> {
        if !actor.role.can_admin() {
            self.log(actor, "subject.export", "subject-access", false, now_est);
            return Err(CctvError::Forbidden(
                "only a privacy officer may export subject data".to_string(),
            ));
        }
        validate_id("subject_ref", subject_ref)?;
        let events: Vec<CctvEvent> = self
            .events
            .values()
            .filter(|event| event.venue_id == actor.venue_id)
            .filter(|event| event.subject_ref.as_deref() == Some(subject_ref))
            .filter(|event| self.is_held(event) || now_est <= event.retention_deadline())
            .cloned()
            .collect();
        let mut legal_holds = Vec::new();
        for event in &events {
            for hold in self.holds_for(event) {
                if !legal_holds
                    .iter()
                    .any(|existing: &CctvLegalHold| existing.hold_id() == hold.hold_id())
                {
                    legal_holds.push(hold);
                }
            }
        }
        let includes_held_events = events.iter().any(|event| self.is_held(event));
        self.log(actor, "subject.export", "subject-access", true, now_est);
        Ok(CctvSubjectAccessReport {
            subject_ref: subject_ref.to_string(),
            events,
            legal_holds,
            generated_est: now_est,
            includes_held_events,
        })
    }

    /// Erase a subject's unheld events. Held events are reported, not deleted.
    pub fn delete_subject(
        &mut self,
        actor: &CctvActor,
        subject_ref: &str,
        request_id: &str,
        now_est: i64,
    ) -> Result<CctvDeletionReport, CctvError> {
        if !actor.role.can_admin() {
            self.log(actor, "subject.delete", request_id, false, now_est);
            return Err(CctvError::Forbidden(
                "only a privacy officer may delete subject data".to_string(),
            ));
        }
        validate_id("subject_ref", subject_ref)?;
        validate_id("request_id", request_id)?;
        let matching: Vec<CctvEvent> = self
            .events
            .values()
            .filter(|event| event.venue_id == actor.venue_id)
            .filter(|event| event.subject_ref.as_deref() == Some(subject_ref))
            .cloned()
            .collect();
        let mut deleted = Vec::new();
        let mut retained_under_hold = Vec::new();
        let mut legal_holds = Vec::new();
        for event in &matching {
            let holds = self.holds_for(event);
            if holds.is_empty() {
                self.events.remove(event.event_id());
                deleted.push(event.event_id().to_string());
            } else {
                retained_under_hold.push(event.event_id().to_string());
                for hold in holds {
                    if !legal_holds
                        .iter()
                        .any(|existing: &CctvLegalHold| existing.hold_id() == hold.hold_id())
                    {
                        legal_holds.push(hold);
                    }
                }
            }
        }
        self.log(actor, "subject.delete", request_id, true, now_est);
        Ok(CctvDeletionReport {
            request_id: request_id.to_string(),
            deleted,
            retained_under_hold,
            legal_holds,
            at_est: now_est,
        })
    }

    /// Serialize the store for the CLI/persistent deployment.
    pub fn to_json(&self) -> Result<String, CctvError> {
        serde_json::to_string(self).map_err(|error| CctvError::Corrupt(error.to_string()))
    }

    /// Load and validate a store.
    pub fn from_json(text: &str) -> Result<Self, CctvError> {
        let store: Self =
            serde_json::from_str(text).map_err(|error| CctvError::Corrupt(error.to_string()))?;
        for event in store.events.values() {
            event.validate()?;
        }
        for hold in &store.holds {
            hold.validate()?;
        }
        Ok(store)
    }

    fn log(&mut self, actor: &CctvActor, action: &str, target: &str, allowed: bool, at_est: i64) {
        let seq = self.access_log.len() as u64 + 1;
        self.access_log.push(CctvAccessRecord {
            seq,
            at_est,
            actor_id: actor.actor_id.clone(),
            role: actor.role,
            action: action.to_string(),
            target: target.to_string(),
            allowed,
        });
    }
}

fn validate_id(field: &str, value: &str) -> Result<(), CctvError> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(CctvError::Invalid(format!("{field} must be 1..=128 bytes")));
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(CctvError::Invalid(format!(
            "{field} must not contain whitespace or control characters"
        )));
    }
    Ok(())
}

fn refuse_media(field: &str, value: &str) -> Result<(), CctvError> {
    let lower = value.to_ascii_lowercase();
    for marker in [
        "data:image",
        "data:video",
        "base64",
        "face_embedding",
        "biometric",
        "video/mp4",
    ] {
        if lower.contains(marker) {
            return Err(CctvError::MediaRefused(format!(
                "{field} contains {marker}"
            )));
        }
    }
    Ok(())
}
