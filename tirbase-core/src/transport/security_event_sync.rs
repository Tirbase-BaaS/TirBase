// SPDX-License-Identifier: AGPL-3.0-only

//! Security event mesh sync (PV-7.9, PV-7.12, CLAIM-28.3).
//!
//! Production caller: sync handler in `tirbase-core/src/transport/`.
//! Append-only collection semantics (`compaction=none`): received records are
//! applied only when their seq is unseen for the origin segment key.
//! Per-peer inbound rate limit: 500 events/minute. On sync failure a local
//! `SyncFailure` event is recorded by the gateway sink/bridge and retry is
//! scheduled after 30 seconds.

use crate::crdt::delta::Did;
use crate::events::{emit, ReasonCode, SecurityEvent as Payload, SecurityEventCategory, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// PV-7.12: max security events accepted from a peer per minute.
pub const SECURITY_EVENT_SYNC_MAX_PER_PEER_PER_MIN: usize = 500;
/// PV-7.9: retry delay after sync failure.
pub const SECURITY_EVENT_SYNC_RETRY_SECS: u64 = 30;
pub const SECURITY_EVENT_SYNC_TOPIC_SUFFIX: &str = "security-events";

/// Wire record for a synced security event (append-only, compaction=none).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEventSyncRecord {
    pub origin_did: Did,
    pub seq: u64,
    pub segment_id: u64,
    pub category: String,
    pub severity: String,
    pub actor_did: Option<String>,
    pub target: Option<String>,
    pub reason_code: String,
    pub best_effort_wall_time: i64,
    pub time_source_flag: String,
    pub prev_hash: [u8; 32],
    pub is_checkpoint: bool,
    #[serde(default)]
    pub personal_commitments: Vec<(String, [u8; 32])>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEventSyncBatch {
    pub sender_did: Did,
    pub records: Vec<SecurityEventSyncRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncInboundDecision {
    Accepted(Vec<SecurityEventSyncRecord>),
    RateLimited {
        accepted: Vec<SecurityEventSyncRecord>,
        dropped: usize,
    },
    RetryScheduled {
        after_secs: u64,
    },
}

/// Per-peer inbound rate limiter (500 events/min, PV-7.12).
///
/// Time is the [`crate::traits::monotonic_now`] domain in microseconds so the
/// limiter never reads the system clock directly (PV-3.12).
#[derive(Debug, Default)]
pub struct PeerSecurityEventSyncLimiter {
    windows: BTreeMap<String, VecDeque<u64>>,
}

pub const SECURITY_EVENT_SYNC_WINDOW_MICROS: u64 = 60_000_000;

impl PeerSecurityEventSyncLimiter {
    pub fn allow(&mut self, peer_did: &str, count: usize, now_micros: u64) -> (usize, usize) {
        let q = self.windows.entry(peer_did.to_string()).or_default();
        while let Some(front) = q.front() {
            if now_micros.saturating_sub(*front) >= SECURITY_EVENT_SYNC_WINDOW_MICROS {
                q.pop_front();
            } else {
                break;
            }
        }
        let room = SECURITY_EVENT_SYNC_MAX_PER_PEER_PER_MIN.saturating_sub(q.len());
        let accepted = room.min(count);
        for _ in 0..accepted {
            q.push_back(now_micros);
        }
        (accepted, count.saturating_sub(accepted))
    }
}

/// Append-only collection (`compaction=none`): dedupe by (origin_did, segment_id, seq).
#[derive(Debug, Default)]
pub struct AppendOnlySecurityEventCollection {
    seen: std::collections::HashSet<(String, u64, u64)>,
}

impl AppendOnlySecurityEventCollection {
    pub fn ingest(
        &mut self,
        records: Vec<SecurityEventSyncRecord>,
    ) -> Vec<SecurityEventSyncRecord> {
        let mut out = Vec::new();
        for r in records {
            let key = (r.origin_did.clone(), r.segment_id, r.seq);
            if self.seen.insert(key) {
                out.push(r);
            }
        }
        out
    }
}

/// Transport sync handler (CLAIM-28.3 production caller).
#[derive(Debug, Default)]
pub struct SecurityEventSyncHandler {
    limiter: PeerSecurityEventSyncLimiter,
    collection: AppendOnlySecurityEventCollection,
}

impl SecurityEventSyncHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle_inbound(
        &mut self,
        batch: SecurityEventSyncBatch,
        now_micros: u64,
    ) -> SyncInboundDecision {
        let (accepted_n, dropped_n) =
            self.limiter
                .allow(&batch.sender_did, batch.records.len(), now_micros);
        if dropped_n > 0 {
            emit(
                Payload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Low,
                    ReasonCode::SyncRateLimitReached,
                )
                .with_actor(batch.sender_did.clone())
                .with_target(format!("accepted={accepted_n} dropped={dropped_n}"))
                .with_detail(format!(
                    "peer security-event sync rate limit {SECURITY_EVENT_SYNC_MAX_PER_PEER_PER_MIN}/min exceeded (CLAIM-28.3, PV-7.12)"
                )),
            );
        }
        if accepted_n == 0 {
            return SyncInboundDecision::RateLimited {
                accepted: Vec::new(),
                dropped: dropped_n,
            };
        }
        let mut accepted = batch.records;
        accepted.truncate(accepted_n);
        let ingested = self.collection.ingest(accepted);
        if dropped_n > 0 {
            SyncInboundDecision::RateLimited {
                accepted: ingested,
                dropped: dropped_n,
            }
        } else {
            SyncInboundDecision::Accepted(ingested)
        }
    }

    pub fn on_sync_failure(&self, peer: &str, detail: impl Into<String>) -> SyncInboundDecision {
        emit(
            Payload::new(
                SecurityEventCategory::SecurityLog,
                Severity::Medium,
                ReasonCode::SyncFailure,
            )
            .with_actor(peer.to_string())
            .with_detail(format!(
                "{}; retry in {}s (CLAIM-28.3, PV-7.9)",
                detail.into(),
                SECURITY_EVENT_SYNC_RETRY_SECS
            )),
        );
        SyncInboundDecision::RetryScheduled {
            after_secs: SECURITY_EVENT_SYNC_RETRY_SECS,
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn rec(i: u64) -> SecurityEventSyncRecord {
        SecurityEventSyncRecord {
            origin_did: "did:test:o".into(),
            seq: i,
            segment_id: 1,
            category: "CommandDecision".into(),
            severity: "Low".into(),
            actor_did: None,
            target: Some(format!("t{i}")),
            reason_code: "CommandAccepted".into(),
            best_effort_wall_time: 0,
            time_source_flag: "LogicalFallback".into(),
            prev_hash: [0; 32],
            is_checkpoint: false,
            personal_commitments: vec![],
        }
    }

    #[test]
    fn per_peer_rate_limit_is_500_per_min() {
        let mut h = SecurityEventSyncHandler::new();
        let now = crate::traits::monotonic_now();
        let batch = SecurityEventSyncBatch {
            sender_did: "did:peer:a".into(),
            records: (1..=700).map(rec).collect(),
        };
        match h.handle_inbound(batch, now) {
            SyncInboundDecision::RateLimited { accepted, dropped } => {
                assert_eq!(accepted.len() + dropped, 700);
                assert!(accepted.len() <= 500);
                assert!(dropped >= 200);
            }
            _ => panic!("expected rate limited"),
        }
    }

    #[test]
    fn append_only_compaction_none_dedupes() {
        let mut h = SecurityEventSyncHandler::new();
        let now = crate::traits::monotonic_now();
        let b = SecurityEventSyncBatch {
            sender_did: "did:peer:a".into(),
            records: vec![rec(1), rec(1), rec(2)],
        };
        let d = h.handle_inbound(b, now);
        match d {
            SyncInboundDecision::Accepted(v) => assert_eq!(v.len(), 2),
            _ => panic!("expected accepted"),
        }
    }
}
