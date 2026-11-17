// SPDX-License-Identifier: Apache-2.0

//! Durable-shaped outbox and dead-letter queue.
//!
//! The outbox holds one record per event. Submitting an event that is already
//! queued or delivered never creates a second record, and every record carries
//! the idempotency key the downstream dedupes on. The dead-letter queue keeps
//! the payload and attempts so a record can be replayed without the producer
//! re-sending it.
//!
//! This module is storage-agnostic and in-memory: [`Outbox::records`] and
//! [`Outbox::dead_letters`] are plain data a host can persist. All instants are
//! supplied by the caller.

use serde::{Deserialize, Serialize};

use crate::connector::{idempotency_key, IntegrationEvent};

/// Most pending records the outbox holds before refusing submissions.
pub const MAX_PENDING: usize = 100_000;

/// Largest dead-letter queue the outbox retains.
pub const MAX_DEAD_LETTERS: usize = 10_000;

/// Lifecycle of an outbox record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    /// Awaiting its next attempt.
    Pending,
    /// Accepted downstream.
    Delivered,
    /// Moved to the dead-letter queue.
    DeadLettered,
}

impl RecordState {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordState::Pending => "pending",
            RecordState::Delivered => "delivered",
            RecordState::DeadLettered => "dead_lettered",
        }
    }
}

/// One outbox record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboxRecord {
    /// Monotonic sequence within the outbox.
    pub seq: u64,
    /// Event identifier.
    pub event_id: String,
    /// Event type.
    pub event_type: String,
    /// Tenant.
    pub tenant: String,
    /// Idempotency key presented downstream.
    pub idempotency_key: String,
    /// Event body, retained for retries and replay.
    pub payload: serde_json::Value,
    /// Attempts made so far.
    pub attempts: u32,
    /// Current state.
    pub state: RecordState,
    /// Earliest next attempt.
    pub next_attempt_est: i64,
    /// Last failure detail.
    pub last_error: Option<String>,
    /// When the record was accepted into the outbox.
    pub created_est: i64,
    /// When the record last changed.
    pub updated_est: i64,
}

/// A dead-lettered record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeadLetter {
    /// Dead-letter id.
    pub dlq_id: String,
    /// Original outbox sequence.
    pub seq: u64,
    /// Event identifier.
    pub event_id: String,
    /// Event type.
    pub event_type: String,
    /// Tenant.
    pub tenant: String,
    /// Idempotency key, preserved so a replay is a duplicate rather than a
    /// second downstream record.
    pub idempotency_key: String,
    /// Event body.
    pub payload: serde_json::Value,
    /// Attempts made before dead-lettering.
    pub attempts: u32,
    /// Why it was dead-lettered.
    pub reason: String,
    /// When it was dead-lettered.
    pub dead_lettered_est: i64,
    /// When it was last replayed.
    pub replayed_est: Option<i64>,
    /// How many times it has been replayed.
    pub replay_count: u32,
}

/// What happened when an event was submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// A new record was queued at this sequence.
    Queued(u64),
    /// The event was already delivered; nothing was queued.
    AlreadyDelivered(u64),
    /// The event was already pending; nothing new was queued.
    AlreadyQueued(u64),
}

impl SubmitOutcome {
    /// The record sequence involved.
    pub fn seq(self) -> u64 {
        match self {
            SubmitOutcome::Queued(seq)
            | SubmitOutcome::AlreadyDelivered(seq)
            | SubmitOutcome::AlreadyQueued(seq) => seq,
        }
    }

    /// Whether a new record was created.
    pub fn queued(self) -> bool {
        matches!(self, SubmitOutcome::Queued(_))
    }
}

/// Why the outbox refused an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxError {
    /// Pending backlog is full.
    Backpressure {
        /// Pending records at the time.
        pending: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// The dead-letter id is unknown.
    UnknownDeadLetter(String),
    /// The record is not in a state that allows the operation.
    InvalidState {
        /// Record or dead letter involved.
        id: String,
        /// Current state.
        state: RecordState,
    },
    /// The dead-letter queue is full.
    DeadLetterFull {
        /// Configured ceiling.
        limit: usize,
    },
}

impl std::fmt::Display for OutboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboxError::Backpressure { pending, limit } => {
                write!(f, "outbox backpressure: {pending} pending (limit {limit})")
            }
            OutboxError::UnknownDeadLetter(id) => write!(f, "unknown dead letter {id:?}"),
            OutboxError::InvalidState { id, state } => {
                write!(f, "record {id:?} is {}", state.as_str())
            }
            OutboxError::DeadLetterFull { limit } => {
                write!(f, "dead-letter queue is full (limit {limit})")
            }
        }
    }
}

impl std::error::Error for OutboxError {}

/// The outbox and dead-letter queue.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    records: Vec<OutboxRecord>,
    dead_letters: Vec<DeadLetter>,
    next_seq: u64,
    max_pending: usize,
    max_dead_letters: usize,
}

impl Outbox {
    /// An empty outbox with default ceilings.
    pub fn new() -> Self {
        Self::with_limits(MAX_PENDING, MAX_DEAD_LETTERS)
    }

    /// An empty outbox with explicit ceilings.
    pub fn with_limits(max_pending: usize, max_dead_letters: usize) -> Self {
        Self {
            records: Vec::new(),
            dead_letters: Vec::new(),
            next_seq: 1,
            max_pending: max_pending.max(1),
            max_dead_letters: max_dead_letters.max(1),
        }
    }

    /// All records, in submission order.
    pub fn records(&self) -> &[OutboxRecord] {
        &self.records
    }

    /// All dead letters, in dead-letter order.
    pub fn dead_letters(&self) -> &[DeadLetter] {
        &self.dead_letters
    }

    /// Pending record count.
    pub fn pending(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.state == RecordState::Pending)
            .count()
    }

    /// Delivered record count.
    pub fn delivered(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.state == RecordState::Delivered)
            .count()
    }

    /// Record by event id.
    ///
    /// A dead-lettered event may have more than one record after a replay, so
    /// this reports the newest one; `submit` and `enqueue_replay` scan all of
    /// them for the state they care about.
    pub fn record_for_event(&self, event_id: &str) -> Option<&OutboxRecord> {
        self.records
            .iter()
            .rev()
            .find(|record| record.event_id == event_id)
    }

    /// Record by sequence.
    pub fn record(&self, seq: u64) -> Option<&OutboxRecord> {
        self.records.iter().find(|record| record.seq == seq)
    }

    /// Dead letter by id.
    pub fn dead_letter(&self, dlq_id: &str) -> Option<&DeadLetter> {
        self.dead_letters
            .iter()
            .find(|letter| letter.dlq_id == dlq_id)
    }

    /// Queue an event.
    ///
    /// Deduplicates on event id: an already-delivered event reports
    /// [`SubmitOutcome::AlreadyDelivered`] and an already-pending event reports
    /// [`SubmitOutcome::AlreadyQueued`], so neither can create a second record.
    pub fn submit(
        &mut self,
        event: &IntegrationEvent,
        connector: &str,
        now_est: i64,
    ) -> Result<SubmitOutcome, OutboxError> {
        if let Some(delivered) = self.records.iter().find(|record| {
            record.event_id == event.event_id && record.state == RecordState::Delivered
        }) {
            return Ok(SubmitOutcome::AlreadyDelivered(delivered.seq));
        }
        if let Some(pending) = self.records.iter().find(|record| {
            record.event_id == event.event_id && record.state == RecordState::Pending
        }) {
            return Ok(SubmitOutcome::AlreadyQueued(pending.seq));
        }
        if let Some(dead) = self.records.iter().find(|record| {
            record.event_id == event.event_id && record.state == RecordState::DeadLettered
        }) {
            return Ok(SubmitOutcome::AlreadyQueued(dead.seq));
        }
        let pending = self.pending();
        if pending >= self.max_pending {
            return Err(OutboxError::Backpressure {
                pending,
                limit: self.max_pending,
            });
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.records.push(OutboxRecord {
            seq,
            event_id: event.event_id.clone(),
            event_type: event.event_type.clone(),
            tenant: event.tenant.clone(),
            idempotency_key: idempotency_key(connector, &event.event_id),
            payload: event.payload.clone(),
            attempts: 0,
            state: RecordState::Pending,
            next_attempt_est: now_est,
            last_error: None,
            created_est: now_est,
            updated_est: now_est,
        });
        Ok(SubmitOutcome::Queued(seq))
    }

    /// Pending records whose next attempt is due at `now_est`, in order.
    pub fn due(&self, now_est: i64) -> Vec<u64> {
        self.records
            .iter()
            .filter(|record| {
                record.state == RecordState::Pending && record.next_attempt_est <= now_est
            })
            .map(|record| record.seq)
            .collect()
    }

    /// Mark an attempt as started and account for it.
    pub(crate) fn begin_attempt(&mut self, seq: u64, now_est: i64) -> Option<u32> {
        let record = self.records.iter_mut().find(|record| record.seq == seq)?;
        if record.state != RecordState::Pending {
            return None;
        }
        record.attempts = record.attempts.saturating_add(1);
        record.updated_est = now_est;
        Some(record.attempts)
    }

    /// Mark a record delivered.
    pub fn mark_delivered(&mut self, seq: u64, now_est: i64) {
        if let Some(record) = self.records.iter_mut().find(|record| record.seq == seq) {
            record.state = RecordState::Delivered;
            record.updated_est = now_est;
            record.last_error = None;
        }
    }

    /// Schedule a retry.
    pub fn mark_retry(&mut self, seq: u64, now_est: i64, next_attempt_est: i64, error: &str) {
        if let Some(record) = self.records.iter_mut().find(|record| record.seq == seq) {
            record.state = RecordState::Pending;
            record.next_attempt_est = next_attempt_est;
            record.updated_est = now_est;
            record.last_error = Some(error.to_string());
        }
    }

    /// Move a record to the dead-letter queue, returning the dead-letter id.
    pub fn mark_dead_letter(
        &mut self,
        seq: u64,
        now_est: i64,
        reason: &str,
    ) -> Result<String, OutboxError> {
        if self.dead_letters.len() >= self.max_dead_letters {
            return Err(OutboxError::DeadLetterFull {
                limit: self.max_dead_letters,
            });
        }
        let Some(record) = self.records.iter_mut().find(|record| record.seq == seq) else {
            return Err(OutboxError::InvalidState {
                id: seq.to_string(),
                state: RecordState::DeadLettered,
            });
        };
        if record.state != RecordState::Pending {
            return Err(OutboxError::InvalidState {
                id: format!("seq-{seq}"),
                state: record.state,
            });
        }
        record.state = RecordState::DeadLettered;
        record.updated_est = now_est;
        record.last_error = Some(reason.to_string());
        let dlq_id = format!("dlq-{seq:08}");
        self.dead_letters.push(DeadLetter {
            dlq_id: dlq_id.clone(),
            seq,
            event_id: record.event_id.clone(),
            event_type: record.event_type.clone(),
            tenant: record.tenant.clone(),
            idempotency_key: record.idempotency_key.clone(),
            payload: record.payload.clone(),
            attempts: record.attempts,
            reason: reason.to_string(),
            dead_lettered_est: now_est,
            replayed_est: None,
            replay_count: 0,
        });
        Ok(dlq_id)
    }

    /// Re-enqueue a dead letter with the same event id and idempotency key.
    ///
    /// Returns the sequence of the fresh pending record. Replaying a dead letter
    /// whose event has since been delivered is refused, so replay cannot produce
    /// a duplicate downstream record.
    pub fn enqueue_replay(&mut self, dlq_id: &str, now_est: i64) -> Result<u64, OutboxError> {
        let Some(letter) = self.dead_letter(dlq_id).cloned() else {
            return Err(OutboxError::UnknownDeadLetter(dlq_id.to_string()));
        };
        if self.is_delivered(&letter.event_id) {
            return Err(OutboxError::InvalidState {
                id: letter.event_id.clone(),
                state: RecordState::Delivered,
            });
        }
        if let Some(pending) = self.records.iter().find(|record| {
            record.event_id == letter.event_id && record.state == RecordState::Pending
        }) {
            // Already replayed and awaiting delivery.
            return Ok(pending.seq);
        }
        let pending = self.pending();
        if pending >= self.max_pending {
            return Err(OutboxError::Backpressure {
                pending,
                limit: self.max_pending,
            });
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.records.push(OutboxRecord {
            seq,
            event_id: letter.event_id.clone(),
            event_type: letter.event_type.clone(),
            tenant: letter.tenant.clone(),
            idempotency_key: letter.idempotency_key.clone(),
            payload: letter.payload.clone(),
            attempts: 0,
            state: RecordState::Pending,
            next_attempt_est: now_est,
            last_error: None,
            created_est: now_est,
            updated_est: now_est,
        });
        if let Some(letter) = self
            .dead_letters
            .iter_mut()
            .find(|letter| letter.dlq_id == dlq_id)
        {
            letter.replay_count = letter.replay_count.saturating_add(1);
            letter.replayed_est = Some(now_est);
        }
        Ok(seq)
    }

    /// Whether a delivered record already covers `event_id`.
    pub fn is_delivered(&self, event_id: &str) -> bool {
        self.records
            .iter()
            .any(|record| record.event_id == event_id && record.state == RecordState::Delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str) -> IntegrationEvent {
        IntegrationEvent::new(
            id,
            "reading.recorded",
            "acme",
            10,
            serde_json::json!({ "v": 1 }),
        )
    }

    #[test]
    fn submission_deduplicates_on_event_id() {
        let mut outbox = Outbox::new();
        assert_eq!(
            outbox.submit(&event("e-1"), "conn", 10).expect("queued"),
            SubmitOutcome::Queued(1)
        );
        assert_eq!(
            outbox.submit(&event("e-1"), "conn", 11).expect("dedupe"),
            SubmitOutcome::AlreadyQueued(1)
        );
        assert_eq!(outbox.records().len(), 1);
        outbox.mark_delivered(1, 12);
        assert_eq!(
            outbox.submit(&event("e-1"), "conn", 13).expect("dedupe"),
            SubmitOutcome::AlreadyDelivered(1)
        );
        assert_eq!(outbox.records().len(), 1);
        assert!(outbox.is_delivered("e-1"));
    }

    #[test]
    fn dead_letter_replay_keeps_the_idempotency_key_and_refuses_after_delivery() {
        let mut outbox = Outbox::new();
        outbox.submit(&event("e-1"), "conn", 10).expect("queued");
        outbox.begin_attempt(1, 10);
        let dlq = outbox.mark_dead_letter(1, 20, "exhausted").expect("dlq");
        assert_eq!(outbox.dead_letters().len(), 1);
        assert_eq!(outbox.dead_letter(&dlq).expect("letter").attempts, 1);
        assert!(outbox.mark_dead_letter(1, 21, "again").is_err());

        let seq = outbox.enqueue_replay(&dlq, 30).expect("replay");
        assert_ne!(seq, 1);
        let replayed = outbox.record(seq).expect("record");
        assert_eq!(
            replayed.idempotency_key,
            outbox.record(1).expect("original").idempotency_key
        );
        assert_eq!(outbox.dead_letter(&dlq).expect("letter").replay_count, 1);

        outbox.mark_delivered(seq, 31);
        assert!(matches!(
            outbox.enqueue_replay(&dlq, 32),
            Err(OutboxError::InvalidState { .. })
        ));
        assert!(matches!(
            outbox.enqueue_replay("dlq-99999999", 32),
            Err(OutboxError::UnknownDeadLetter(_))
        ));
    }

    #[test]
    fn backpressure_is_reported_not_swallowed() {
        let mut outbox = Outbox::with_limits(1, 1);
        outbox.submit(&event("e-1"), "conn", 10).expect("queued");
        assert!(matches!(
            outbox.submit(&event("e-2"), "conn", 10),
            Err(OutboxError::Backpressure { limit: 1, .. })
        ));
    }
}
