// SPDX-License-Identifier: Apache-2.0

//! POS operation runtime: idempotency, retries, dead letters, replay, logs.
//!
//! The runtime is the only place that decides what an outcome means, so every
//! connector behaves the same under failure. It owns the pending queue and the
//! dead-letter queue, validates an operation before each attempt, compares the
//! amount the vendor reports with the amount the operation asked for, and emits
//! one redacted log record per attempt.
//!
//! It is storage-agnostic and in-memory: [`PosRuntime::records`] and
//! [`PosRuntime::dead_letters`] are plain data a host can persist, and every
//! instant is supplied by the caller.

use std::collections::BTreeMap;

use crate::observability::LogRecord;
use crate::retry::RetryPolicy;

use super::contract::{OperationResult, PosConnector, PosOperation};
use super::pci::scrub_card_data;
use super::reconcile::{
    reconcile, LocalSettlement, ReconciliationPolicy, ReconciliationReport, ReconciliationSource,
};
use super::{Amount, PosError, PosFamily, PosOperationKind, PosOutcome};

/// Pending operations the runtime holds before refusing submissions.
pub const DEFAULT_MAX_PENDING: usize = 10_000;

/// Most operations one flush attempts.
pub const MAX_FLUSH: usize = 1_000;

/// Lifecycle of a queued operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosRecordState {
    /// Awaiting its next attempt.
    Pending,
    /// Accepted or replayed by the vendor.
    Settled,
    /// Moved to the dead-letter queue.
    DeadLettered,
}

impl PosRecordState {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            PosRecordState::Pending => "pending",
            PosRecordState::Settled => "settled",
            PosRecordState::DeadLettered => "dead_lettered",
        }
    }
}

/// One queued operation.
#[derive(Debug, Clone, PartialEq)]
pub struct PosRecord {
    /// Monotonic sequence within the runtime.
    pub seq: u64,
    /// Derived idempotency key.
    pub key: String,
    /// The operation.
    pub operation: PosOperation,
    /// Attempts made so far.
    pub attempts: u32,
    /// Earliest next attempt.
    pub next_attempt_est: i64,
    /// Last failure detail, scrubbed.
    pub last_error: Option<String>,
    /// Current state.
    pub state: PosRecordState,
}

/// A dead-lettered operation.
#[derive(Debug, Clone, PartialEq)]
pub struct PosDeadLetter {
    /// Dead-letter id.
    pub dlq_id: String,
    /// Original queue sequence.
    pub seq: u64,
    /// Idempotency key, preserved so a replay is a duplicate, not a second
    /// record.
    pub key: String,
    /// The operation.
    pub operation: PosOperation,
    /// Attempts made before dead-lettering.
    pub attempts: u32,
    /// Why it was dead-lettered.
    pub reason: String,
    /// When it happened.
    pub dead_lettered_est: i64,
    /// How many times it has been replayed.
    pub replay_count: u32,
    /// When it was last replayed.
    pub replayed_est: Option<i64>,
}

/// What one flush did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PosFlushReport {
    /// Operations attempted.
    pub attempted: usize,
    /// Operations the vendor accepted.
    pub accepted: usize,
    /// Operations the vendor recognised as duplicates.
    pub replayed: usize,
    /// Operations scheduled for another attempt.
    pub retried: usize,
    /// Operations moved to the dead-letter queue.
    pub dead_lettered: usize,
}

/// What a submission did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosSubmit {
    /// A new record was queued at this sequence.
    Queued(u64),
    /// The key is already pending or dead-lettered at this sequence.
    AlreadyQueued(u64),
    /// The key already settled at this sequence; replaying it would duplicate.
    AlreadySettled(u64),
}

impl PosSubmit {
    /// The sequence involved.
    pub fn seq(self) -> u64 {
        match self {
            PosSubmit::Queued(seq)
            | PosSubmit::AlreadyQueued(seq)
            | PosSubmit::AlreadySettled(seq) => seq,
        }
    }
}

/// Counters for a runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PosMetrics {
    /// Attempts made.
    pub attempts: u64,
    /// Operations accepted.
    pub accepted: u64,
    /// Operations recognised as duplicates.
    pub replayed: u64,
    /// Attempts scheduled for retry.
    pub retried: u64,
    /// Operations dead-lettered.
    pub dead_lettered: u64,
    /// Dead letters replayed.
    pub replays: u64,
    /// Settlements refused because the vendor reported a different amount.
    pub rejected: u64,
}

/// A vendor that recorded an amount different from the operation's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityViolation {
    /// Reference involved.
    pub reference: String,
    /// Amount the operation asked for.
    pub expected: Amount,
    /// Amount the vendor reported.
    pub got: Amount,
    /// When it was seen.
    pub at_est: i64,
}

#[derive(Debug, Clone, PartialEq)]
struct Settled {
    tenant: String,
    reference: String,
    family: PosFamily,
    kind: PosOperationKind,
    outcome: PosOutcome,
    amount: Option<Amount>,
    settled_est: i64,
    seq: u64,
}

/// Idempotency, retry, dead-letter and reconciliation runtime for one connector.
pub struct PosRuntime<C: PosConnector> {
    connector: C,
    retry: RetryPolicy,
    records: Vec<PosRecord>,
    dead_letters: Vec<PosDeadLetter>,
    settled: BTreeMap<String, Settled>,
    integrity: Vec<IntegrityViolation>,
    logs: Vec<LogRecord>,
    metrics: PosMetrics,
    next_seq: u64,
    max_pending: usize,
}

impl<C: PosConnector> PosRuntime<C> {
    /// Build a runtime with the default retry policy.
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            retry: RetryPolicy::default(),
            records: Vec::new(),
            dead_letters: Vec::new(),
            settled: BTreeMap::new(),
            integrity: Vec::new(),
            logs: Vec::new(),
            metrics: PosMetrics::default(),
            next_seq: 1,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }

    /// Replace the retry policy.
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Replace the pending ceiling.
    pub fn with_max_pending(mut self, max_pending: usize) -> Self {
        self.max_pending = max_pending.max(1);
        self
    }

    /// The connector.
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// The retry policy in force.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// Queued and settled records, in submission order.
    pub fn records(&self) -> &[PosRecord] {
        &self.records
    }

    /// Dead letters, in dead-letter order.
    pub fn dead_letters(&self) -> &[PosDeadLetter] {
        &self.dead_letters
    }

    /// Redacted log records, oldest first.
    pub fn logs(&self) -> &[LogRecord] {
        &self.logs
    }

    /// Counters.
    pub fn metrics(&self) -> PosMetrics {
        self.metrics
    }

    /// Settlements refused because the vendor reported a different amount.
    pub fn integrity_violations(&self) -> &[IntegrityViolation] {
        &self.integrity
    }

    /// Pending operations.
    pub fn pending(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.state == PosRecordState::Pending)
            .count()
    }

    /// The outcome recorded for `key`, if it has settled.
    pub fn settled_for(&self, key: &str) -> Option<PosOutcome> {
        self.settled.get(key).map(|settled| settled.outcome)
    }

    /// Queue an operation.
    ///
    /// The operation is validated first, so an invalid request never reaches the
    /// connector. A key that already settled reports
    /// [`PosSubmit::AlreadySettled`] and is not queued again, which is what makes
    /// a retry or a replay a duplicate rather than a second record.
    pub fn submit(&mut self, operation: PosOperation, now_est: i64) -> Result<PosSubmit, PosError> {
        operation.validate()?;
        let key = operation.idempotency_key().to_string();
        if let Some(settled) = self.settled.get(&key) {
            return Ok(PosSubmit::AlreadySettled(settled.seq));
        }
        if let Some(existing) = self
            .records
            .iter()
            .find(|record| record.key == key && record.state != PosRecordState::Settled)
        {
            return Ok(PosSubmit::AlreadyQueued(existing.seq));
        }
        let pending = self.pending();
        if pending >= self.max_pending {
            return Err(PosError::Backpressure {
                pending,
                limit: self.max_pending,
            });
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.records.push(PosRecord {
            seq,
            key,
            operation,
            attempts: 0,
            next_attempt_est: now_est,
            last_error: None,
            state: PosRecordState::Pending,
        });
        Ok(PosSubmit::Queued(seq))
    }

    /// Attempt every due operation once.
    pub fn flush(&mut self, now_est: i64) -> PosFlushReport {
        let mut report = PosFlushReport::default();
        let due: Vec<u64> = self
            .records
            .iter()
            .filter(|record| {
                record.state == PosRecordState::Pending && record.next_attempt_est <= now_est
            })
            .map(|record| record.seq)
            .take(MAX_FLUSH)
            .collect();

        for seq in due {
            let Some(index) = self.records.iter().position(|record| record.seq == seq) else {
                continue;
            };
            let operation = self.records[index].operation.clone();
            let key = self.records[index].key.clone();
            let reference = operation.reference().to_string();
            let attempt = {
                let record = &mut self.records[index];
                record.attempts = record.attempts.saturating_add(1);
                record.attempts
            };
            self.metrics.attempts += 1;
            report.attempted += 1;

            let mut result = match operation.validate() {
                Ok(()) => self.connector.execute(&operation),
                Err(error) => OperationResult::permanent(error.to_string()),
            };

            if result.is_settled() {
                if let (Some(expected), Some(got)) = (operation.amount(), result.amount.clone()) {
                    if !expected.matches(&got) {
                        self.metrics.rejected += 1;
                        self.integrity.push(IntegrityViolation {
                            reference: reference.clone(),
                            expected: expected.clone(),
                            got: got.clone(),
                            at_est: now_est,
                        });
                        result = OperationResult::permanent(format!(
                            "vendor reported {got} for an operation of {expected}"
                        ));
                    }
                }
            }

            self.record_log(now_est, &reference, attempt, &result);

            match result.outcome {
                PosOutcome::Accepted => {
                    self.metrics.accepted += 1;
                    report.accepted += 1;
                    self.settle(index, &operation, &result, now_est);
                }
                PosOutcome::Replayed => {
                    self.metrics.replayed += 1;
                    report.replayed += 1;
                    self.settle(index, &operation, &result, now_est);
                }
                PosOutcome::Retryable => {
                    if self.retry.allows_attempt(attempt) {
                        let backoff = self.retry.delay_secs(attempt);
                        let delay = result
                            .retry_after_secs
                            .map(|after| after.max(backoff))
                            .unwrap_or(backoff);
                        let next = now_est.saturating_add(i64::try_from(delay).unwrap_or(i64::MAX));
                        let record = &mut self.records[index];
                        record.next_attempt_est = next;
                        record.last_error = Some(scrub_card_data(&result.detail));
                        self.metrics.retried += 1;
                        report.retried += 1;
                    } else {
                        let reason = format!(
                            "retry budget of {} exhausted: {}",
                            self.retry.max_attempts, result.detail
                        );
                        self.dead_letter(index, key, &operation, now_est, &reason);
                        self.metrics.dead_lettered += 1;
                        report.dead_lettered += 1;
                    }
                }
                PosOutcome::Permanent => {
                    let reason = result.detail.clone();
                    self.dead_letter(index, key, &operation, now_est, &reason);
                    self.metrics.dead_lettered += 1;
                    report.dead_lettered += 1;
                }
            }
        }
        report
    }

    /// Re-enqueue a dead letter with its original key.
    ///
    /// Refused once the operation has settled, so a replay cannot create a
    /// second vendor record.
    pub fn replay(&mut self, dlq_id: &str, now_est: i64) -> Result<u64, PosError> {
        let Some(position) = self
            .dead_letters
            .iter()
            .position(|letter| letter.dlq_id == dlq_id)
        else {
            return Err(PosError::Invariant {
                field: "dlq_id".to_string(),
                detail: format!("unknown dead letter {dlq_id:?}"),
            });
        };
        let letter = self.dead_letters[position].clone();
        if self.settled.contains_key(&letter.key) {
            return Err(PosError::Invariant {
                field: "dlq_id".to_string(),
                detail: "the operation has since settled; replay would duplicate it".to_string(),
            });
        }
        if let Some(existing) = self
            .records
            .iter()
            .find(|record| record.key == letter.key && record.state == PosRecordState::Pending)
        {
            return Ok(existing.seq);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.records.push(PosRecord {
            seq,
            key: letter.key.clone(),
            operation: letter.operation.clone(),
            attempts: 0,
            next_attempt_est: now_est,
            last_error: None,
            state: PosRecordState::Pending,
        });
        let letter = &mut self.dead_letters[position];
        letter.replay_count = letter.replay_count.saturating_add(1);
        letter.replayed_est = Some(now_est);
        self.metrics.replays += 1;
        Ok(seq)
    }

    /// Replay every dead letter that has not settled.
    pub fn replay_all(&mut self, now_est: i64) -> usize {
        let ids: Vec<String> = self
            .dead_letters
            .iter()
            .filter(|letter| !self.settled.contains_key(&letter.key))
            .map(|letter| letter.dlq_id.clone())
            .collect();
        let mut replayed = 0;
        for dlq_id in ids {
            if self.replay(&dlq_id, now_est).is_ok() {
                replayed += 1;
            }
        }
        replayed
    }

    /// Reconcile this register's settlements against `source`.
    ///
    /// Payment intents are netted (captures minus refunds) so the local side
    /// matches a settlement line; other families use their latest settled amount.
    pub fn reconcile(
        &self,
        tenant: &str,
        source: &dyn ReconciliationSource,
        policy: &ReconciliationPolicy,
        now_est: i64,
    ) -> ReconciliationReport {
        let mut local: BTreeMap<String, LocalSettlement> = BTreeMap::new();
        for settled in self.settled.values() {
            if settled.tenant != tenant {
                continue;
            }
            let Some(amount) = &settled.amount else {
                continue;
            };
            let signed = match (settled.family, settled.kind) {
                (PosFamily::Payment, PosOperationKind::Refund) => -amount.minor,
                (PosFamily::Payment, PosOperationKind::Authorize)
                | (PosFamily::Payment, PosOperationKind::Capture) => amount.minor,
                _ => {
                    local.insert(
                        settled.reference.clone(),
                        LocalSettlement {
                            reference: settled.reference.clone(),
                            amount: amount.clone(),
                            settled_est: settled.settled_est,
                        },
                    );
                    continue;
                }
            };
            let entry = local
                .entry(settled.reference.clone())
                .or_insert_with(|| LocalSettlement {
                    reference: settled.reference.clone(),
                    amount: Amount::zero(&amount.currency).unwrap_or(amount.clone()),
                    settled_est: settled.settled_est,
                });
            entry.amount.minor = entry.amount.minor.saturating_add(signed);
            entry.settled_est = entry.settled_est.max(settled.settled_est);
        }
        let local: Vec<LocalSettlement> = local.into_values().collect();
        let remote = source.settlements(tenant);
        reconcile(tenant, &local, &remote, policy, now_est)
    }

    fn settle(
        &mut self,
        index: usize,
        operation: &PosOperation,
        result: &OperationResult,
        now_est: i64,
    ) {
        let seq = self.records[index].seq;
        let key = self.records[index].key.clone();
        self.records[index].state = PosRecordState::Settled;
        self.records[index].last_error = None;
        self.settled.insert(
            key,
            Settled {
                tenant: operation.tenant().to_string(),
                reference: operation.reference().to_string(),
                family: operation.family(),
                kind: operation.kind(),
                outcome: result.outcome,
                amount: result.amount.clone().or_else(|| operation.amount()),
                settled_est: now_est,
                seq,
            },
        );
    }

    fn dead_letter(
        &mut self,
        index: usize,
        key: String,
        operation: &PosOperation,
        now_est: i64,
        reason: &str,
    ) {
        let seq = self.records[index].seq;
        let attempts = self.records[index].attempts;
        self.records[index].state = PosRecordState::DeadLettered;
        self.records[index].last_error = Some(scrub_card_data(reason));
        self.dead_letters.push(PosDeadLetter {
            dlq_id: format!("pos-dlq-{seq:08}"),
            seq,
            key,
            operation: operation.clone(),
            attempts,
            reason: scrub_card_data(reason),
            dead_lettered_est: now_est,
            replay_count: 0,
            replayed_est: None,
        });
    }

    fn record_log(
        &mut self,
        now_est: i64,
        reference: &str,
        attempt: u32,
        result: &OperationResult,
    ) {
        let record = LogRecord::new(
            now_est,
            self.connector.name(),
            reference,
            attempt,
            result.outcome.delivery_outcome(),
            scrub_card_data(&result.detail),
        );
        if self.logs.len() >= crate::observability::MAX_RETAINED_LOGS {
            self.logs.remove(0);
        }
        self.logs.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pos::mock::MockPaymentTerminal;
    use crate::pos::{pos_idempotency_key, AuthorizeRequest, PaymentMethodToken, PosConnector};

    fn authorize(connector: &str, intent: &str, minor: i64) -> PosOperation {
        PosOperation::Authorize(AuthorizeRequest::new(
            connector,
            "acme",
            intent,
            PaymentMethodToken::new("tok_terminal_1").expect("valid token"),
            Amount::new("EUR", minor).expect("valid amount"),
            true,
            10,
        ))
    }

    #[test]
    fn a_submitted_operation_flushes_once_and_deduplicates() {
        let mut runtime = PosRuntime::new(MockPaymentTerminal::new("terminal"));
        assert_eq!(
            runtime.submit(authorize("terminal", "intent-1", 500), 10),
            Ok(PosSubmit::Queued(1))
        );
        assert_eq!(
            runtime.submit(authorize("terminal", "intent-1", 500), 11),
            Ok(PosSubmit::AlreadyQueued(1))
        );
        let report = runtime.flush(12);
        assert_eq!(report.accepted, 1);
        assert_eq!(
            runtime.submit(authorize("terminal", "intent-1", 500), 13),
            Ok(PosSubmit::AlreadySettled(1))
        );
        assert_eq!(runtime.records().len(), 1);
        assert_eq!(runtime.logs().len(), 1);
    }

    #[test]
    fn a_transient_failure_is_retried_then_dead_lettered_and_replayed() {
        let terminal = MockPaymentTerminal::new("terminal");
        terminal.set_failures(10);
        let mut runtime =
            PosRuntime::new(terminal).with_retry_policy(RetryPolicy::new(2, 5, 2, 30));
        runtime
            .submit(authorize("terminal", "intent-2", 500), 10)
            .expect("queued");
        assert_eq!(runtime.flush(11).retried, 1);
        assert_eq!(runtime.flush(100).dead_lettered, 1);
        assert_eq!(runtime.dead_letters().len(), 1);
        let dlq = runtime.dead_letters()[0].dlq_id.clone();
        let key = runtime.dead_letters()[0].key.clone();
        assert_eq!(
            key,
            pos_idempotency_key("terminal", "authorize", "intent-2")
        );
        // The vendor recovers, then the operator replays the dead letter.
        runtime.connector().set_failures(0);
        let seq = runtime.replay(&dlq, 200).expect("replayed");
        assert_ne!(seq, 1);
        assert_eq!(runtime.flush(201).accepted, 1);
        assert!(runtime.replay(&dlq, 202).is_err());
        assert_eq!(PosConnector::name(runtime.connector()), "terminal");
    }
}
