//! Gateway security event log sink (PV-7.1, CLAIM-5.4, 19.4, INV-4).
//!
//! The gateway installs one [`GatewaySecurityEventLog`] as the process-wide
//! [`SecurityEventSink`] at boot.  Every typed event emitted by
//! `tirbase-core` (CRDT hardening, revocation, transport, migration) and by
//! the gateway itself lands in this log.
//!
//! Task 19.4 (PV-15.4): `High`/`Critical` severity events bypass the
//! group-commit batcher and are flushed immediately; lower-severity events
//! are buffered for the configured window (default 50ms) before flush.
//! Task 25.1 replaces the backend with the hash-chained, device-signed
//! `SecurityEventLog`.

use std::sync::{Arc, RwLock};

use tirbase_core::events::SecurityEvent;
use tirbase_core::traits::SecurityEventSink;

use crate::event_batcher::{GroupCommitBatcher, RecordingBatchBackend, DEFAULT_BATCH_WINDOW};

/// In-memory security event log used by the gateway.
///
/// Bounded by [`MAX_EVENTS`] so a flood of events cannot exhaust gateway
/// memory before the hash-chained log from task 25.1 lands.
#[derive(Debug)]
pub struct GatewaySecurityEventLog {
    events: RwLock<Vec<SecurityEvent>>,
    /// 19.4 group-commit batcher: LOW/MEDIUM buffered, HIGH/CRITICAL bypass.
    batcher: Option<Arc<GroupCommitBatcher>>,
}

/// Upper bound on retained events in the skeleton log.
pub const MAX_EVENTS: usize = 10_000;

impl Default for GatewaySecurityEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewaySecurityEventLog {
    /// Construct an empty event log (immediate, non-batched) for compatibility.
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            batcher: None,
        }
    }

    /// Construct a batched event log (19.4, PV-15.4). HIGH/CRITICAL bypass.
    pub fn new_batched() -> Self {
        let backend = Arc::new(RecordingBatchBackend::default());
        let batcher = GroupCommitBatcher::with_window(backend, DEFAULT_BATCH_WINDOW);
        Self {
            events: RwLock::new(Vec::new()),
            batcher: Some(batcher),
        }
    }

    /// Install this log as the process-wide sink, returning a shared handle.
    pub fn install(self) -> Arc<Self> {
        let log = Arc::new(self);
        tirbase_core::events::install_security_event_sink(log.clone());
        log
    }

    /// Number of recorded events.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of all recorded events, oldest first.
    pub fn events(&self) -> Vec<SecurityEvent> {
        self.read().clone()
    }

    /// Expose batcher for tests/diagnostics (19.4).
    pub fn batcher(&self) -> Option<&Arc<GroupCommitBatcher>> {
        self.batcher.as_ref()
    }

    /// Flush pending batched events (test/shutdown helper).
    pub fn flush(&self) {
        if let Some(b) = &self.batcher {
            b.stop();
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<SecurityEvent>> {
        match self.events.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl SecurityEventSink for GatewaySecurityEventLog {
    fn emit(&self, event: SecurityEvent) {
        {
            let mut events = match self.events.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if events.len() >= MAX_EVENTS {
                events.remove(0);
            }
            events.push(event.clone());
        }
        if let Some(batcher) = &self.batcher {
            // 19.4 production caller path: SecurityEventLog::emit() routes through
            // the group-commit batcher; HIGH/CRITICAL bypass inside batcher.
            batcher.emit(event);
        } else {
            // Immediate path (compatibility). HIGH/CRITICAL are effectively immediate here.
            let _ = event.severity;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use tirbase_core::crdt::CrdtEngine;
    use tirbase_core::events::{ReasonCode, SecurityEventCategory, Severity};
    use tirbase_core::schema::hash::compute_schema_identifier_hash;
    use tirbase_core::store::sqlite;

    #[test]
    fn core_events_are_routed_into_the_gateway_log() {
        let _guard = crate::EVENT_SINK_TEST_LOCK.lock().unwrap();
        let log = GatewaySecurityEventLog::new().install();

        tirbase_core::events::emit(
            SecurityEvent::new(
                SecurityEventCategory::Startup,
                Severity::Low,
                ReasonCode::BootCompleted,
            )
            .with_detail("gateway started"),
        );

        let events = log.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category, SecurityEventCategory::Startup);
        assert_eq!(events[0].reason_code, ReasonCode::BootCompleted);
    }

    #[test]
    fn crdt_rejection_in_core_reaches_the_gateway_event_log() {
        let _guard = crate::EVENT_SINK_TEST_LOCK.lock().unwrap();
        let log = GatewaySecurityEventLog::new().install();

        let (secret, public) =
            tirbase_core::identity::keypair::generate_keypair().expect("keypair");
        let did = tirbase_core::identity::did::derive_did(&public);
        let schema_hash =
            compute_schema_identifier_hash(&[("readings", &[("id", "TEXT"), ("value", "TEXT")])]);
        let conn = sqlite::open(":memory:").expect("in-memory sqlite");
        let conn = std::sync::Arc::new(Mutex::new(conn));
        let mut engine = CrdtEngine::new(secret, public, did.clone(), schema_hash, conn);

        let delta = Delta {
            id: [0x42; 32],
            author_did: did,
            signature: Ed25519Signature::default(),
            schema_hash,
            automerge_bytes: b"not-a-real-changeset".to_vec(),
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };
        let outcome = engine.apply(&delta).expect("apply returns an outcome");
        assert!(matches!(
            outcome,
            tirbase_core::crdt::merge::MergeOutcome::Rejected { .. }
        ));

        let events = log.events();
        assert!(
            events
                .iter()
                .any(|e| e.category == SecurityEventCategory::CrdtHardening),
            "expected a CrdtHardening event, got {events:?}"
        );
    }
}
