// SPDX-License-Identifier: Apache-2.0

//! Idempotency, retries, dead letters and replay for venue events.
//!
//! [`VenueDispatcher`] owns one CC-20 delivery engine per connector. Both the
//! event id and the connector-specific idempotency key are deterministic
//! functions of the venue, event family and the producer's native scan or
//! announcement id, so:
//!
//! * submitting the same scan twice queues one record and delivers once;
//! * a replay of a dead-lettered announcement presents the original key, and the
//!   vendor answers `Duplicate` instead of publishing twice;
//! * restarting the process and rebuilding the dispatcher from the same events
//!   presents the same ids and keys.
//!
//! The engine owns retry arithmetic and the dead-letter queue; this module does
//! not re-implement either.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_integrations::outbox::SubmitOutcome;
use tirbase_integrations::{
    DeliveryEngine, EngineError, FlushReport, IntegrationEvent, RetryPolicy,
};

use crate::domain::{VenueConnector, VenueConnectorAdapter};
use crate::event::{SchemaError, VenueEvent};
use crate::privacy::{PrivacyError, PrivacyPolicy};

/// Domain separation for venue event ids.
pub const CONTEXT_EVENT_ID: &str = "TirBase/v1/VenueEventId";
/// Domain separation for venue idempotency keys.
pub const CONTEXT_IDEMPOTENCY: &str = "TirBase/v1/VenueIdempotency";

/// Deterministic truncated digest for a domain-separated tuple.
fn stable_id(context: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    for part in parts {
        hasher.update([0u8]);
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Deterministic delivery id for an event.
pub fn event_id(event: &VenueEvent) -> String {
    format!(
        "vne-{}",
        stable_id(
            CONTEXT_EVENT_ID,
            &[event.venue_id(), event.kind().as_str(), event.native_id()]
        )
    )
}

/// Idempotency key for a ticket scan on `connector`.
pub fn scan_idempotency_key(connector: &str, venue: &str, scan_id: &str) -> String {
    format!(
        "vsk-{}",
        stable_id(
            CONTEXT_IDEMPOTENCY,
            &[connector, venue, "ticket_scan", scan_id]
        )
    )
}

/// Idempotency key for an announcement on `connector`.
pub fn announcement_idempotency_key(connector: &str, venue: &str, announcement_id: &str) -> String {
    format!(
        "vak-{}",
        stable_id(
            CONTEXT_IDEMPOTENCY,
            &[connector, venue, "announcement", announcement_id]
        )
    )
}

/// What [`VenueDispatcher::submit`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueSubmit {
    /// A new record was queued at this sequence.
    Queued(u64),
    /// The event was already pending; nothing new was queued.
    AlreadyQueued(u64),
    /// The event was already delivered; replay would duplicate it.
    AlreadyDelivered(u64),
}

impl VenueSubmit {
    /// Whether the event was already accepted or pending.
    pub fn is_replay(self) -> bool {
        matches!(
            self,
            VenueSubmit::AlreadyQueued(_) | VenueSubmit::AlreadyDelivered(_)
        )
    }

    /// The outbox sequence involved.
    pub fn seq(self) -> u64 {
        match self {
            VenueSubmit::Queued(seq)
            | VenueSubmit::AlreadyQueued(seq)
            | VenueSubmit::AlreadyDelivered(seq) => seq,
        }
    }
}

impl From<SubmitOutcome> for VenueSubmit {
    fn from(outcome: SubmitOutcome) -> Self {
        match outcome {
            SubmitOutcome::Queued(seq) => VenueSubmit::Queued(seq),
            SubmitOutcome::AlreadyQueued(seq) => VenueSubmit::AlreadyQueued(seq),
            SubmitOutcome::AlreadyDelivered(seq) => VenueSubmit::AlreadyDelivered(seq),
        }
    }
}

/// Why a venue event could not be queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VenueError {
    /// The event is structurally invalid.
    Schema(String),
    /// The privacy policy refused it.
    Privacy(String),
    /// The delivery engine refused it.
    Engine(String),
}

impl fmt::Display for VenueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VenueError::Schema(detail) => write!(f, "event schema: {detail}"),
            VenueError::Privacy(detail) => write!(f, "privacy: {detail}"),
            VenueError::Engine(detail) => write!(f, "delivery engine: {detail}"),
        }
    }
}

impl std::error::Error for VenueError {}

impl From<SchemaError> for VenueError {
    fn from(error: SchemaError) -> Self {
        VenueError::Schema(error.to_string())
    }
}

impl From<PrivacyError> for VenueError {
    fn from(error: PrivacyError) -> Self {
        VenueError::Privacy(error.to_string())
    }
}

impl From<EngineError> for VenueError {
    fn from(error: EngineError) -> Self {
        VenueError::Engine(error.to_string())
    }
}

/// One connector plus the privacy policy and delivery engine.
pub struct VenueDispatcher {
    engine: DeliveryEngine,
    policy: PrivacyPolicy,
}

impl fmt::Debug for VenueDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VenueDispatcher")
            .field("connector", &self.engine.connector().name())
            .field("pending", &self.engine.outbox().pending())
            .field("dead_letters", &self.engine.outbox().dead_letters().len())
            .finish()
    }
}

impl VenueDispatcher {
    /// Build a dispatcher for one connector.
    pub fn new(
        connector: Box<dyn VenueConnector>,
        policy: PrivacyPolicy,
        retry: RetryPolicy,
    ) -> Self {
        let adapter = VenueConnectorAdapter::new(connector);
        let engine = DeliveryEngine::new(Box::new(adapter)).with_retry_policy(retry);
        Self { engine, policy }
    }

    /// The connector name.
    pub fn connector_name(&self) -> &str {
        self.engine.connector().name()
    }

    /// The privacy policy.
    pub fn policy(&self) -> &PrivacyPolicy {
        &self.policy
    }

    /// Queue a venue event.
    ///
    /// The event is validated and redacted first; only the redacted body is
    /// stored in the outbox and handed to the connector.
    pub fn submit(&mut self, event: &VenueEvent, now_est: i64) -> Result<VenueSubmit, VenueError> {
        let prepared: IntegrationEvent = self.policy.prepare(event)?;
        Ok(self.engine.submit(&prepared, now_est)?.into())
    }

    /// Attempt every due delivery once.
    pub fn flush(&mut self, now_est: i64) -> FlushReport {
        self.engine.flush(now_est)
    }

    /// Re-enqueue a dead letter with the same event id and idempotency key.
    pub fn replay(&mut self, dlq_id: &str, now_est: i64) -> Result<u64, VenueError> {
        Ok(self.engine.replay(dlq_id, now_est)?)
    }

    /// The delivery engine, for metrics and health.
    pub fn engine(&self) -> &DeliveryEngine {
        &self.engine
    }
}
