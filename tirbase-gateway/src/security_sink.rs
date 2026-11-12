//! Gateway security event sink (PV-7.1, 19.4, INV-4, compatibility).
//!
//! replaces the skeleton log with [`crate::security_log::SecurityEventLog`].
//! [`GatewaySecurityEventLog`] remains as a compatibility wrapper used by older
//! tests and lightweight boot paths.

use std::sync::Arc;

use tirbase_core::events::SecurityEvent;
use tirbase_core::traits::SecurityEventSink;

pub use crate::event_batcher::GroupCommitBatcher;
pub use crate::security_log::SecurityEventLog;

/// Upper bound on retained events in in-memory views/ring.
pub const MAX_EVENTS: usize = 10_000;

/// Compatibility wrapper around the hash-chained [`SecurityEventLog`].
#[derive(Debug)]
pub struct GatewaySecurityEventLog {
    inner: Arc<SecurityEventLog>,
}

impl Default for GatewaySecurityEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewaySecurityEventLog {
 /// Construct an immediate/in-memory chained log.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SecurityEventLog::new_memory()),
        }
    }

 /// Construct a batched log (19.4 compatibility). Persistence is not wired
 /// through this constructor; use [`SecurityEventLog::new_persistent`].
    pub fn new_batched() -> Self {
        Self {
            inner: Arc::new(SecurityEventLog::with_options_compat(true)),
        }
    }

 /// Install this log as the process-wide sink.
    pub fn install(self) -> Arc<SecurityEventLog> {
        let log = self.inner.clone();
        tirbase_core::events::install_security_event_sink(log.clone());
        log
    }

    pub fn into_inner(self) -> Arc<SecurityEventLog> {
        self.inner
    }
}

impl SecurityEventSink for GatewaySecurityEventLog {
    fn emit(&self, event: SecurityEvent) {
        self.inner.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let conn = std::sync::Arc::new(std::sync::Mutex::new(conn));
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
