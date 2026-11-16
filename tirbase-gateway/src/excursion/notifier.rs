// SPDX-License-Identifier: AGPL-3.0-only

//! Pluggable excursion notifications with at-least-once delivery and
//! deduplication (CC-11).
//!
//! Delivery is driven by the workflow, not by the notifier: a notification is
//! written to the durable outbox *before* any transport is called, then handed
//! to every configured channel. A channel that accepts it is marked delivered; a
//! channel that fails stays pending with its attempt count and last error, so a
//! restart or a later call retries it. That is the at-least-once half.
//!
//! The deduplication half lives in [`ExcursionNotification::notification_id`].
//! The id is derived from the record, the channel, and the transition it
//! announces, so a retried delivery always carries the same id. A receiver that
//! keys on it (see [`DeduplicationFilter`]) turns two deliveries of one event into
//! one logical notification — the case a crash between "transport accepted" and
//! "outbox marked delivered" produces.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_types::FixedPointValue;

/// The state change a notification announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    /// The record was quarantined and needs operator attention.
    QuarantineOpened,
    /// An operator disposition was recorded (release, hold, reject, destroy).
    DispositionRecorded,
    /// The signed resolution closed the workflow's disposition step.
    ResolutionSigned,
}

impl NotificationEvent {
    /// Stable string form used in deduplication keys and payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            NotificationEvent::QuarantineOpened => "quarantine_opened",
            NotificationEvent::DispositionRecorded => "disposition_recorded",
            NotificationEvent::ResolutionSigned => "resolution_signed",
        }
    }
}

/// One notification handed to a channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcursionNotification {
    /// Deduplication key: stable across retries of the same event.
    pub notification_id: String,
    /// Record the notification belongs to.
    pub record_id: String,
    /// Channel that should deliver it.
    pub channel: String,
    /// Event being announced.
    pub event: NotificationEvent,
    /// Tenant owning the record.
    pub tenant: String,
    /// Site the record belongs to.
    pub site_id: String,
    /// Excursion reasons (stable codes, e.g. `temperature_out_of_band`).
    pub reasons: Vec<String>,
    /// Mean kinetic temperature at detection, if it was computed.
    pub mkt_c: Option<FixedPointValue>,
    /// When the quarantine opened (authenticated-time estimate, seconds).
    pub opened_est: i64,
    /// When this notification was first enqueued.
    pub enqueued_est: i64,
}

impl ExcursionNotification {
    /// Deduplication key for `(record, channel, event)`.
    ///
    /// The separator is a NUL byte, which the component strings cannot contain,
    /// so distinct triples can never collide.
    pub fn dedup_key(record_id: &str, channel: &str, event: NotificationEvent) -> String {
        let mut hasher = Sha256::new();
        hasher.update(record_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(channel.as_bytes());
        hasher.update([0u8]);
        hasher.update(event.as_str().as_bytes());
        let digest = hasher.finalize();
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// A delivery transport for one channel.
///
/// Implementations must be synchronous and must not block indefinitely; the
/// workflow calls them inside the delivery loop and treats any `Err` as
/// "not delivered yet".
pub trait ExcursionNotifier: Send + Sync {
    /// Stable channel name, for example `pager` or `email`.
    fn channel(&self) -> &str;

    /// Attempt delivery. `Err` means "retry later", not "drop".
    fn deliver(&self, notification: &ExcursionNotification) -> Result<(), String>;
}

/// Why a notification could not be delivered to a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyError {
    /// No notifier is registered for the channel.
    UnknownChannel(String),
    /// The channel rejected the notification; the string is retriable detail.
    DeliveryFailed { channel: String, detail: String },
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::UnknownChannel(channel) => {
                write!(f, "no notifier registered for channel {channel:?}")
            }
            NotifyError::DeliveryFailed { channel, detail } => {
                write!(f, "channel {channel:?} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for NotifyError {}

/// The set of channels a workflow delivers to.
#[derive(Default, Clone)]
pub struct NotifierDispatcher {
    notifiers: BTreeMap<String, Arc<dyn ExcursionNotifier>>,
}

impl std::fmt::Debug for NotifierDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifierDispatcher")
            .field("channels", &self.channels())
            .finish()
    }
}

impl NotifierDispatcher {
    /// An empty dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a notifier under its own channel name.
    ///
    /// Registering the same channel twice replaces the previous notifier, which
    /// keeps a test (or a reconfiguration) from delivering twice.
    pub fn with(mut self, notifier: Arc<dyn ExcursionNotifier>) -> Self {
        self.register(notifier);
        self
    }

    /// Register a notifier in place.
    pub fn register(&mut self, notifier: Arc<dyn ExcursionNotifier>) {
        self.notifiers
            .insert(notifier.channel().to_string(), notifier);
    }

    /// Channels in deterministic order.
    pub fn channels(&self) -> Vec<String> {
        self.notifiers.keys().cloned().collect()
    }

    /// Deliver one notification to one channel.
    pub fn deliver(
        &self,
        channel: &str,
        notification: &ExcursionNotification,
    ) -> Result<(), NotifyError> {
        let notifier = self
            .notifiers
            .get(channel)
            .ok_or_else(|| NotifyError::UnknownChannel(channel.to_string()))?;
        notifier
            .deliver(notification)
            .map_err(|detail| NotifyError::DeliveryFailed {
                channel: channel.to_string(),
                detail,
            })
    }
}

/// Receiver-side deduplication set.
///
/// A receiver keys on [`ExcursionNotification::notification_id`]; the second
/// delivery of an already-seen id is reported as a duplicate and must not
/// trigger a second alert. The set is bounded by `capacity` so a long-running
/// receiver cannot grow without limit; the identifier space is per record, so
/// dropping the oldest ids only risks re-alerting after many thousands of
/// excursions, never merging two distinct ones.
#[derive(Debug, Default)]
pub struct DeduplicationFilter {
    seen: std::collections::VecDeque<String>,
    capacity: usize,
}

impl DeduplicationFilter {
    /// A filter that remembers `capacity` notification ids.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// `true` when this id was already accepted, in which case the caller must
    /// not re-deliver the alert.
    pub fn is_duplicate(&mut self, notification_id: &str) -> bool {
        if self.seen.iter().any(|seen| seen == notification_id) {
            return true;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(notification_id.to_string());
        false
    }

    /// Number of remembered ids.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` when nothing has been accepted yet.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keys_are_stable_and_distinct() {
        let first =
            ExcursionNotification::dedup_key("rec-1", "pager", NotificationEvent::QuarantineOpened);
        let again =
            ExcursionNotification::dedup_key("rec-1", "pager", NotificationEvent::QuarantineOpened);
        assert_eq!(first, again);
        assert_eq!(first.len(), 64);
        assert_ne!(
            first,
            ExcursionNotification::dedup_key("rec-1", "email", NotificationEvent::QuarantineOpened)
        );
        assert_ne!(
            first,
            ExcursionNotification::dedup_key("rec-2", "pager", NotificationEvent::QuarantineOpened)
        );
        assert_ne!(
            first,
            ExcursionNotification::dedup_key("rec-1", "pager", NotificationEvent::ResolutionSigned)
        );
    }

    #[test]
    fn deduplication_filter_reports_repeats_once() {
        let mut filter = DeduplicationFilter::new(2);
        assert!(!filter.is_duplicate("a"));
        assert!(filter.is_duplicate("a"));
        assert!(!filter.is_duplicate("b"));
        assert!(!filter.is_duplicate("c"));
        // "a" aged out of the bounded memory.
        assert!(!filter.is_duplicate("a"));
        assert_eq!(filter.len(), 2);
    }

    #[test]
    fn unknown_channel_is_an_error_not_a_silent_drop() {
        let dispatcher = NotifierDispatcher::new();
        let notification = ExcursionNotification {
            notification_id: "id".into(),
            record_id: "rec".into(),
            channel: "pager".into(),
            event: NotificationEvent::QuarantineOpened,
            tenant: "default".into(),
            site_id: "site".into(),
            reasons: vec!["temperature_out_of_band".into()],
            mkt_c: None,
            opened_est: 1_000,
            enqueued_est: 1_000,
        };
        assert_eq!(
            dispatcher.deliver("pager", &notification),
            Err(NotifyError::UnknownChannel("pager".into()))
        );
    }
}
