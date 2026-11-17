// SPDX-License-Identifier: Apache-2.0

//! The delivery engine: retries, dead letters, replay, logs, metrics and health.
//!
//! The engine is the only place that decides an outcome's consequences, so every
//! connector behaves the same under failure. It owns the outbox, asks the
//! connector to deliver one attempt at a time, and never advances a record
//! without the connector's answer.

use crate::connector::{Connector, DeliveryOutcome, DeliveryRequest, IntegrationEvent};
use crate::observability::{
    HealthResponse, HealthSnapshot, HealthStatus, LogRecord, LogSink, Metrics, MetricsSnapshot,
    MAX_RETAINED_LOGS,
};
use crate::outbox::{Outbox, OutboxError, RecordState, SubmitOutcome};
use crate::retry::RetryPolicy;

/// Most records one flush may attempt.
pub const MAX_FLUSH: usize = 1_000;

/// What one [`DeliveryEngine::submit`] call did.
pub type SubmitReport = SubmitOutcome;

/// Summary of one flush.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Records attempted.
    pub attempted: usize,
    /// Records accepted (delivered or duplicate).
    pub delivered: usize,
    /// Records recognised as duplicates.
    pub duplicates: usize,
    /// Records scheduled for another attempt.
    pub retried: usize,
    /// Records moved to the dead-letter queue.
    pub dead_lettered: usize,
}

/// Why the engine refused an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// The outbox refused it.
    Outbox(OutboxError),
    /// The event is already delivered; replay would duplicate it.
    AlreadyDelivered(String),
}

impl From<OutboxError> for EngineError {
    fn from(error: OutboxError) -> Self {
        EngineError::Outbox(error)
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Outbox(error) => write!(f, "{error}"),
            EngineError::AlreadyDelivered(event_id) => {
                write!(f, "event {event_id:?} is already delivered")
            }
        }
    }
}

impl std::error::Error for EngineError {}

/// Retry/dead-letter/replay engine for one connector.
pub struct DeliveryEngine {
    connector: Box<dyn Connector>,
    outbox: Outbox,
    retry: RetryPolicy,
    metrics: Metrics,
    logs: Vec<LogRecord>,
    sinks: Vec<Box<dyn LogSink>>,
    last_delivery_est: Option<i64>,
}

impl DeliveryEngine {
    /// Build an engine for `connector` with the default retry policy.
    pub fn new(connector: Box<dyn Connector>) -> Self {
        Self {
            connector,
            outbox: Outbox::new(),
            retry: RetryPolicy::default(),
            metrics: Metrics::default(),
            logs: Vec::new(),
            sinks: Vec::new(),
            last_delivery_est: None,
        }
    }

    /// Replace the retry policy.
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Replace the outbox (for a host restoring persisted state).
    pub fn with_outbox(mut self, outbox: Outbox) -> Self {
        self.outbox = outbox;
        self
    }

    /// Add a log sink.
    pub fn add_log_sink(&mut self, sink: Box<dyn LogSink>) {
        self.sinks.push(sink);
    }

    /// The connector.
    pub fn connector(&self) -> &dyn Connector {
        self.connector.as_ref()
    }

    /// The outbox.
    pub fn outbox(&self) -> &Outbox {
        &self.outbox
    }

    /// The retry policy.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// Retained log records.
    pub fn logs(&self) -> &[LogRecord] {
        &self.logs
    }

    /// Metric counters.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// When the last event was accepted.
    pub fn last_delivery_est(&self) -> Option<i64> {
        self.last_delivery_est
    }

    /// Queue an event for delivery.
    pub fn submit(
        &mut self,
        event: &IntegrationEvent,
        now_est: i64,
    ) -> Result<SubmitOutcome, EngineError> {
        Ok(self.outbox.submit(event, self.connector.name(), now_est)?)
    }

    /// Attempt every due record once.
    pub fn flush(&mut self, now_est: i64) -> FlushReport {
        let mut report = FlushReport::default();
        let due = self.outbox.due(now_est);
        for seq in due.into_iter().take(MAX_FLUSH) {
            let Some(attempt) = self.outbox.begin_attempt(seq, now_est) else {
                continue;
            };
            let Some(record) = self.outbox.record(seq) else {
                continue;
            };
            let request = DeliveryRequest {
                event_id: record.event_id.clone(),
                event_type: record.event_type.clone(),
                tenant: record.tenant.clone(),
                idempotency_key: record.idempotency_key.clone(),
                attempt,
                now_est,
                payload: record.payload.clone(),
            };
            let result = self.connector.deliver(&request);
            report.attempted += 1;
            self.metrics.record_attempt(result.outcome);
            self.log(LogRecord::new(
                now_est,
                self.connector.name(),
                &request.event_id,
                attempt,
                result.outcome,
                &result.detail,
            ));

            match result.outcome {
                DeliveryOutcome::Delivered => {
                    self.outbox.mark_delivered(seq, now_est);
                    self.last_delivery_est = Some(now_est);
                    report.delivered += 1;
                }
                DeliveryOutcome::Duplicate => {
                    self.outbox.mark_delivered(seq, now_est);
                    self.last_delivery_est = Some(now_est);
                    report.delivered += 1;
                    report.duplicates += 1;
                }
                DeliveryOutcome::Permanent => {
                    self.dead_letter(seq, now_est, &result.detail);
                    report.dead_lettered += 1;
                }
                DeliveryOutcome::Retryable => {
                    if self.retry.allows_attempt(attempt) {
                        let backoff = self.retry.delay_secs(attempt);
                        let delay = result
                            .retry_after_secs
                            .map(|after| after.max(backoff))
                            .unwrap_or(backoff);
                        let next = now_est.saturating_add(delay as i64);
                        self.outbox.mark_retry(seq, now_est, next, &result.detail);
                        report.retried += 1;
                    } else {
                        let reason = format!(
                            "retry budget of {} exhausted: {}",
                            self.retry.max_attempts, result.detail
                        );
                        self.dead_letter(seq, now_est, &reason);
                        report.dead_lettered += 1;
                    }
                }
            }
        }
        report
    }

    /// Re-enqueue a dead letter for delivery.
    ///
    /// Refused when the event has since been delivered, so replay cannot create a
    /// duplicate downstream record.
    pub fn replay(&mut self, dlq_id: &str, now_est: i64) -> Result<u64, EngineError> {
        match self.outbox.enqueue_replay(dlq_id, now_est) {
            Ok(seq) => {
                self.metrics.record_replay();
                Ok(seq)
            }
            Err(OutboxError::InvalidState {
                id,
                state: RecordState::Delivered,
            }) => Err(EngineError::AlreadyDelivered(id)),
            Err(error) => Err(EngineError::Outbox(error)),
        }
    }

    /// Replay every dead letter that is not already delivered.
    pub fn replay_all(&mut self, now_est: i64) -> usize {
        let pending_letters: Vec<String> = self
            .outbox
            .dead_letters()
            .iter()
            .filter(|letter| !self.outbox.is_delivered(&letter.event_id))
            .map(|letter| letter.dlq_id.clone())
            .collect();
        let mut replayed = 0;
        for dlq_id in pending_letters {
            if self.replay(&dlq_id, now_est).is_ok() {
                replayed += 1;
            }
        }
        replayed
    }

    /// Health document for this engine.
    pub fn health(&self) -> HealthSnapshot {
        let connector = self.connector.health();
        let pending = self.outbox.pending();
        // A dead letter that has since been replayed and accepted is history, not
        // an open failure; only unresolved dead letters make the engine unhealthy.
        let dead_letters = self
            .outbox
            .dead_letters()
            .iter()
            .filter(|letter| !self.outbox.is_delivered(&letter.event_id))
            .count();
        let metrics = self.metrics.snapshot();
        let status = if !connector.healthy || dead_letters > 0 {
            HealthStatus::Unhealthy
        } else if pending > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Ok
        };
        HealthSnapshot {
            status,
            connector: self.connector.name().to_string(),
            kind: self.connector.kind(),
            detail: connector.detail,
            pending,
            dead_letters,
            last_delivery_est: self.last_delivery_est,
            metrics,
        }
    }

    /// Health endpoint answer.
    pub fn health_response(&self) -> HealthResponse {
        self.health().response()
    }

    fn dead_letter(&mut self, seq: u64, now_est: i64, reason: &str) {
        match self.outbox.mark_dead_letter(seq, now_est, reason) {
            Ok(_) => self.metrics.record_dead_letter(),
            Err(error) => {
                // A full queue is itself a delivery failure; leave the record
                // pending so it is retried rather than silently dropped.
                self.log(LogRecord::new(
                    now_est,
                    self.connector.name(),
                    format!("seq-{seq}"),
                    0,
                    DeliveryOutcome::Permanent,
                    format!("dead-letter move failed: {error}"),
                ));
            }
        }
    }

    fn log(&mut self, record: LogRecord) {
        for sink in self.sinks.iter_mut() {
            sink.record(&record);
        }
        if self.logs.len() >= MAX_RETAINED_LOGS {
            self.logs.remove(0);
        }
        self.logs.push(record);
    }
}

impl std::fmt::Debug for DeliveryEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryEngine")
            .field("connector", &self.connector.name())
            .field("pending", &self.outbox.pending())
            .field("dead_letters", &self.outbox.dead_letters().len())
            .finish()
    }
}
