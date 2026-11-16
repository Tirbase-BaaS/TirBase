// SPDX-License-Identifier: AGPL-3.0-only

//! Domain-event sink for the lineage ledger (CC-14).
//!
//! [`LedgerSink`] is the seam the lot registry (CC-12) and the excursion
//! workflow (CC-11) append through. It owns one [`LineageLedger`] and the actor
//! DID that gets attributed for events whose domain object carries no operator
//! of its own (lot registration and lot operations are keyed by lot and
//! operation id, not by a signer).
//!
//! Every caller supplies a *stable* entry id derived from the domain object it
//! is recording — `lot-registered:<lot_id>`, `lot-op:<operation_id>`,
//! `excursion-disposition:<record_id>`, `excursion-resolution:<record_id>` — so a
//! retried operation, or one replayed after a crash between the domain write and
//! the ledger append, appends nothing new: [`LineageLedger::append`] returns
//! [`AppendOutcome::Duplicate`].
//!
//! Share one sink between the registries that must write to the same chain by
//! putting it behind an [`Arc`](std::sync::Arc).
//!
//! [`LineageLedger::append`]: crate::lineage_ledger::LineageLedger::append
//! [`AppendOutcome::Duplicate`]: crate::lineage_ledger::AppendOutcome::Duplicate

use std::sync::{Mutex, MutexGuard};

use crate::lineage_ledger::{AppendOutcome, AppendRequest, LedgerError, LineageLedger};

/// The ledger plus the actor attributed to domain events.
///
/// The ledger sits behind a mutex so one sink can be shared (`Arc`) by the
/// registries that write the same chain, including across gateway threads: the
/// SQLite connection is `Send` but not `Sync`, and a single writer keeps the
/// sequence assignment unambiguous.
#[derive(Debug)]
pub struct LedgerSink {
    ledger: Mutex<LineageLedger>,
    actor_did: String,
}

impl LedgerSink {
    /// Wrap `ledger` so domain events are attributed to `actor_did`.
    pub fn new(ledger: LineageLedger, actor_did: impl Into<String>) -> Result<Self, LedgerError> {
        let actor_did = actor_did.into();
        if actor_did.trim().is_empty() {
            return Err(LedgerError::InvalidRequest(
                "lineage ledger sink needs a non-empty actor DID".to_string(),
            ));
        }
        Ok(Self {
            ledger: Mutex::new(ledger),
            actor_did,
        })
    }

    /// The underlying ledger, for reads, checkpoints and export.
    ///
    /// Poisons are ignored on purpose: every write is a single transaction, so a
    /// panicking reader cannot leave the chain half-written.
    pub fn ledger(&self) -> MutexGuard<'_, LineageLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The DID attributed to events that carry no operator of their own.
    pub fn actor_did(&self) -> &str {
        &self.actor_did
    }

    /// Append an event attributed to the sink's actor.
    pub fn record(
        &self,
        entry_id: impl Into<String>,
        event_type: impl Into<String>,
        payload: serde_json::Value,
        recorded_est: i64,
    ) -> Result<AppendOutcome, LedgerError> {
        self.append(AppendRequest::new(
            entry_id,
            self.actor_did.clone(),
            event_type,
            payload,
            recorded_est,
        ))
    }

    /// Append a fully-built request, defaulting an empty actor to the sink's.
    ///
    /// Idempotent exactly like [`LineageLedger::append`]: a retry with the same
    /// entry id and payload returns [`AppendOutcome::Duplicate`] and writes
    /// nothing, while the same id with a different payload is
    /// [`LedgerError::Conflict`].
    pub fn append(&self, request: AppendRequest) -> Result<AppendOutcome, LedgerError> {
        let mut request = request;
        if request.actor_did.trim().is_empty() {
            request.actor_did = self.actor_did.clone();
        }
        self.ledger().append(request)
    }
}
