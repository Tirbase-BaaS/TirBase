// SPDX-License-Identifier: AGPL-3.0-only

//! Simulated network with deterministic fault injection (CLAIM-38.3,
//! PV-12.1).
//!
//! The network is virtual-time based: [`SimNetwork::send`] never delivers
//! synchronously. It schedules a [`DeliveredMessage`] at a virtual millisecond
//! offset and [`SimNetwork::deliver`] releases everything due at the current
//! clock value. All randomness (drop decisions and reorder keys) comes from a
//! `ChaCha8Rng` seeded from the scenario seed, so a run is exactly reproducible.
//!
//! Fault modes (PV-12.1):
//!
//! | Fault | Behaviour |
//! |---|---|
//! | [`NetworkFault::Partition`] | no delivery in either direction between the two nodes |
//! | [`NetworkFault::Delay`] | every message on the link arrives `ms` later (1–30,000 ms) |
//! | [`NetworkFault::Drop`] | each message on the link is dropped with probability `rate` |
//! | [`NetworkFault::Reorder`] | consecutive messages on a link are delivered in reverse order |
//! | [`NetworkFault::Duplicate`] | each message is delivered as `copies` copies (≤ 5) |
//!
//! Faults are additive per directed link, except `Partition`, which applies to
//! both directions. A message dropped by `Drop` is counted and never delivered.

use std::collections::BTreeMap;
use std::fmt;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Smallest injectable delay in milliseconds (PV-12.1).
pub const MIN_DELAY_MS: u64 = 1;
/// Largest injectable delay in milliseconds (PV-12.1).
pub const MAX_DELAY_MS: u64 = 30_000;
/// Largest number of copies a message may be duplicated into (PV-12.1).
pub const MAX_DUPLICATE_COPIES: u8 = 5;
/// Default virtual link latency when no `Delay` fault is configured.
pub const DEFAULT_LINK_DELAY_MS: u64 = 10;

/// Stable node identifier inside a simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u16);

impl NodeId {
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node-{}", self.0)
    }
}

/// Monotonic message identifier assigned by [`SimNetwork::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub u64);

impl MessageId {
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "msg-{}", self.0)
    }
}

/// A controllable fault applied to the simulated network (PV-12.1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkFault {
 /// Bidirectional partition between `src` and `dst`.
    Partition { src: NodeId, dst: NodeId },
 /// Add `ms` of latency to every message from `src` to `dst` (1–30,000 ms).
    Delay { src: NodeId, dst: NodeId, ms: u64 },
 /// Drop each message from `src` to `dst` with probability `rate` (0.0–1.0).
    Drop { src: NodeId, dst: NodeId, rate: f64 },
 /// Deliver consecutive messages from `src` to `dst` in reverse order.
    Reorder { src: NodeId, dst: NodeId },
 /// Deliver `copies` copies of each message from `src` to `dst` (1–5).
    Duplicate {
        src: NodeId,
        dst: NodeId,
        copies: u8,
    },
}

/// Fault configuration/validation failures.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkError {
 /// Delay outside the 1–30,000 ms range from PV-12.1.
    DelayOutOfRange { ms: u64 },
 /// Drop probability outside `0.0..=1.0` or NaN.
    InvalidDropRate { rate: f64 },
 /// Duplicate copies outside 1–5 (PV-12.1 allows at most 5 per message).
    TooManyCopies { copies: u8 },
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::DelayOutOfRange { ms } => write!(
                f,
                "delay {ms} ms outside the supported range {MIN_DELAY_MS}..={MAX_DELAY_MS} ms"
            ),
            NetworkError::InvalidDropRate { rate } => {
                write!(f, "drop rate {rate} is not a probability in [0.0, 1.0]")
            }
            NetworkError::TooManyCopies { copies } => write!(
                f,
                "duplicate copies {copies} exceeds the maximum of {MAX_DUPLICATE_COPIES} per message"
            ),
        }
    }
}

impl std::error::Error for NetworkError {}

/// A message released by the network at the current virtual time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredMessage {
    pub id: MessageId,
    pub src: NodeId,
    pub dst: NodeId,
    pub payload: Vec<u8>,
 /// Virtual time at which the message was put on the wire.
    pub sent_at_ms: u64,
 /// Virtual time at which the message became deliverable.
    pub deliver_at_ms: u64,
 /// Zero-based copy index; non-zero for duplicates.
    pub copy: u8,
}

/// One queued (not yet due) message.
#[derive(Debug, Clone)]
struct QueuedMessage {
    delivered: DeliveredMessage,
 /// Deterministic ordering key inside a `(deliver_at_ms)` bucket.
    order_key: u64,
}

/// Deterministic in-memory network with fault injection (CLAIM-38.3).
#[derive(Debug)]
pub struct SimNetwork {
    rng: ChaCha8Rng,
    faults: Vec<NetworkFault>,
    queue: Vec<QueuedMessage>,
    next_id: u64,
 /// Per-link send counter, used to reverse delivery order under `Reorder`.
    link_seq: BTreeMap<(NodeId, NodeId), u64>,
    log: Vec<DeliveredMessage>,
    sent_messages: u64,
    delivered_messages: u64,
    dropped_messages: u64,
}

impl SimNetwork {
 /// Create a network whose random decisions derive from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
 // Domain-separate the network stream from the scenario RNG.
            rng: ChaCha8Rng::seed_from_u64(seed ^ 0x5349_4D4E_4554_0001),
            faults: Vec::new(),
            queue: Vec::new(),
            next_id: 1,
            link_seq: BTreeMap::new(),
            log: Vec::new(),
            sent_messages: 0,
            delivered_messages: 0,
            dropped_messages: 0,
        }
    }

 /// Currently configured faults.
    pub fn faults(&self) -> &[NetworkFault] {
        &self.faults
    }

 /// Install a fault, validating its parameters (PV-12.1 bounds).
    pub fn add_fault(&mut self, fault: NetworkFault) -> Result<(), NetworkError> {
        match fault {
            NetworkFault::Delay { ms, .. } if !(MIN_DELAY_MS..=MAX_DELAY_MS).contains(&ms) => {
                Err(NetworkError::DelayOutOfRange { ms })
            }
            NetworkFault::Drop { rate, .. } if !(0.0..=1.0).contains(&rate) || rate.is_nan() => {
                Err(NetworkError::InvalidDropRate { rate })
            }
            NetworkFault::Duplicate { copies, .. }
                if !(1..=MAX_DUPLICATE_COPIES).contains(&copies) =>
            {
                Err(NetworkError::TooManyCopies { copies })
            }
            other => {
                self.faults.push(other);
                Ok(())
            }
        }
    }

 /// Remove every configured fault (the link returns to healthy behaviour).
    pub fn heal_all(&mut self) {
        self.faults.clear();
        self.link_seq.clear();
    }

 /// True when a partition is active between `a` and `b` in either direction.
    pub fn is_partitioned(&self, a: NodeId, b: NodeId) -> bool {
        self.faults.iter().any(|f| match *f {
            NetworkFault::Partition { src, dst } => {
                (src == a && dst == b) || (src == b && dst == a)
            }
            _ => false,
        })
    }

 /// Effective one-way latency for `src -> dst` (validated delay fault wins;
 /// otherwise the default link latency).
    pub fn latency_ms(&self, src: NodeId, dst: NodeId) -> u64 {
        self.faults
            .iter()
            .rev()
            .find_map(|f| match *f {
                NetworkFault::Delay { src: s, dst: d, ms } if s == src && d == dst => Some(ms),
                _ => None,
            })
            .unwrap_or(DEFAULT_LINK_DELAY_MS)
    }

    fn drop_rate(&self, src: NodeId, dst: NodeId) -> f64 {
        self.faults
            .iter()
            .rev()
            .find_map(|f| match *f {
                NetworkFault::Drop {
                    src: s,
                    dst: d,
                    rate,
                } if s == src && d == dst => Some(rate),
                _ => None,
            })
            .unwrap_or(0.0)
    }

    fn copies(&self, src: NodeId, dst: NodeId) -> u8 {
        self.faults
            .iter()
            .rev()
            .find_map(|f| match *f {
                NetworkFault::Duplicate {
                    src: s,
                    dst: d,
                    copies,
                } if s == src && d == dst => Some(copies.clamp(1, MAX_DUPLICATE_COPIES)),
                _ => None,
            })
            .unwrap_or(1)
    }

    fn reorders(&self, src: NodeId, dst: NodeId) -> bool {
        self.faults.iter().any(|f| match *f {
            NetworkFault::Reorder { src: s, dst: d } => s == src && d == dst,
            _ => false,
        })
    }

 /// Send `payload` from `src` to `dst` at virtual time `now_ms`.
 ///
 /// Returns the message ids that were accepted onto the wire (empty when the
 /// link is partitioned or the message is dropped).
    pub fn send(
        &mut self,
        now_ms: u64,
        src: NodeId,
        dst: NodeId,
        payload: impl Into<Vec<u8>>,
    ) -> Vec<MessageId> {
        self.sent_messages += 1;
        if self.is_partitioned(src, dst) {
            self.dropped_messages += 1;
            return Vec::new();
        }

        let rate = self.drop_rate(src, dst);
        if rate >= 1.0 || (rate > 0.0 && self.rng.gen_bool(rate)) {
            self.dropped_messages += 1;
            return Vec::new();
        }

        let id = MessageId(self.next_id);
        self.next_id += 1;
        let payload = payload.into();
        let deliver_at_ms = now_ms.saturating_add(self.latency_ms(src, dst));

        let reorders = self.reorders(src, dst);
        let seq = self.link_seq.entry((src, dst)).or_insert(0);
        *seq += 1;
 // Under `Reorder`, later sends sort *before* earlier sends inside the
 // same delivery bucket, so the last message sent arrives first.
        let order_key = if reorders { u64::MAX - *seq } else { *seq };

        let copies = self.copies(src, dst);
        let mut ids = Vec::with_capacity(copies as usize);
        for copy in 0..copies {
            ids.push(id);
            self.queue.push(QueuedMessage {
                delivered: DeliveredMessage {
                    id,
                    src,
                    dst,
                    payload: payload.clone(),
                    sent_at_ms: now_ms,
                    deliver_at_ms,
                    copy,
                },
                order_key,
            });
        }
        ids
    }

 /// Release every message due at `now_ms`, in deterministic order.
    pub fn deliver(&mut self, now_ms: u64) -> Vec<DeliveredMessage> {
        let mut due: Vec<QueuedMessage> = Vec::new();
        let mut pending: Vec<QueuedMessage> = Vec::with_capacity(self.queue.len());
        for queued in self.queue.drain(..) {
            if queued.delivered.deliver_at_ms <= now_ms {
                due.push(queued);
            } else {
                pending.push(queued);
            }
        }
        self.queue = pending;

        due.sort_by_key(|q| {
            (
                q.delivered.deliver_at_ms,
                q.order_key,
                q.delivered.id,
                q.delivered.copy,
            )
        });

        let mut out = Vec::with_capacity(due.len());
        for queued in due {
            self.delivered_messages += 1;
            self.log.push(queued.delivered.clone());
            out.push(queued.delivered);
        }
        out
    }

 /// Number of messages queued but not yet delivered.
    pub fn in_flight(&self) -> usize {
        self.queue.len()
    }

 /// Number of `send` calls observed (including dropped sends).
    pub fn sent_messages(&self) -> u64 {
        self.sent_messages
    }

 /// Number of message copies delivered so far.
    pub fn delivered_messages(&self) -> u64 {
        self.delivered_messages
    }

 /// Number of sends dropped by partition or `Drop`.
    pub fn dropped_messages(&self) -> u64 {
        self.dropped_messages
    }

 /// Complete delivery log, in delivery order.
    pub fn delivery_log(&self) -> &[DeliveredMessage] {
        &self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: NodeId = NodeId::new(0);
    const B: NodeId = NodeId::new(1);

    fn network() -> SimNetwork {
        SimNetwork::new(0xDEAD_BEEF)
    }

    #[test]
    fn healthy_link_delivers_once_after_default_latency() {
        let mut net = network();
        let ids = net.send(0, A, B, b"hello".to_vec());
        assert_eq!(ids.len(), 1);
        assert!(
            net.deliver(0).is_empty(),
            "not due before the latency elapses"
        );
        let delivered = net.deliver(DEFAULT_LINK_DELAY_MS);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].payload, b"hello");
        assert_eq!(delivered[0].src, A);
        assert_eq!(delivered[0].dst, B);
        assert_eq!(net.in_flight(), 0);
    }

    #[test]
    fn partition_drops_both_directions() {
        let mut net = network();
        net.add_fault(NetworkFault::Partition { src: A, dst: B })
            .unwrap();
        assert!(net.send(0, A, B, b"x".to_vec()).is_empty());
        assert!(net.send(0, B, A, b"y".to_vec()).is_empty());
        assert!(net.send(0, A, NodeId::new(2), b"z".to_vec()).len() == 1);
        assert!(net.deliver(MAX_DELAY_MS).len() == 1);
        assert_eq!(net.dropped_messages(), 2);
    }

    #[test]
    fn delay_is_applied_and_bounds_are_enforced() {
        let mut net = network();
        net.add_fault(NetworkFault::Delay {
            src: A,
            dst: B,
            ms: 250,
        })
        .unwrap();
        net.send(1_000, A, B, b"slow".to_vec());
        assert!(net.deliver(1_249).is_empty());
        assert_eq!(net.deliver(1_250).len(), 1);

        assert_eq!(
            net.add_fault(NetworkFault::Delay {
                src: A,
                dst: B,
                ms: 0
            }),
            Err(NetworkError::DelayOutOfRange { ms: 0 })
        );
        assert_eq!(
            net.add_fault(NetworkFault::Delay {
                src: A,
                dst: B,
                ms: MAX_DELAY_MS + 1
            }),
            Err(NetworkError::DelayOutOfRange {
                ms: MAX_DELAY_MS + 1
            })
        );
        net.add_fault(NetworkFault::Delay {
            src: A,
            dst: B,
            ms: MAX_DELAY_MS,
        })
        .unwrap();
    }

    #[test]
    fn drop_rate_is_deterministic_and_bounded() {
        let mut net = network();
        net.add_fault(NetworkFault::Drop {
            src: A,
            dst: B,
            rate: 1.0,
        })
        .unwrap();
        for _ in 0..10 {
            assert!(net.send(0, A, B, b"lost".to_vec()).is_empty());
        }
        assert_eq!(net.dropped_messages(), 10);

 // Same seed => same drop pattern at an intermediate rate.
        let runs: Vec<Vec<u64>> = (0..2)
            .map(|_| {
                let mut net = SimNetwork::new(7);
                net.add_fault(NetworkFault::Drop {
                    src: A,
                    dst: B,
                    rate: 0.5,
                })
                .unwrap();
                (0..64)
                    .filter(|i| !net.send(*i, A, B, b"m".to_vec()).is_empty())
                    .collect()
            })
            .collect();
        assert_eq!(
            runs[0], runs[1],
            "drop decisions must be seed-deterministic"
        );

        assert_eq!(
            net.add_fault(NetworkFault::Drop {
                src: A,
                dst: B,
                rate: 1.5
            }),
            Err(NetworkError::InvalidDropRate { rate: 1.5 })
        );
    }

    #[test]
    fn reorder_delivers_later_messages_first() {
        let mut net = network();
        net.add_fault(NetworkFault::Reorder { src: A, dst: B })
            .unwrap();
        net.send(0, A, B, b"first".to_vec());
        net.send(0, A, B, b"second".to_vec());
        let delivered = net.deliver(DEFAULT_LINK_DELAY_MS);
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].payload, b"second");
        assert_eq!(delivered[1].payload, b"first");
    }

    #[test]
    fn duplicate_produces_the_requested_number_of_copies() {
        for copies in 1..=MAX_DUPLICATE_COPIES {
            let mut net = network();
            net.add_fault(NetworkFault::Duplicate {
                src: A,
                dst: B,
                copies,
            })
            .unwrap();
            assert_eq!(
                net.send(0, A, B, b"fan-out".to_vec()).len(),
                copies as usize
            );
            assert_eq!(net.deliver(DEFAULT_LINK_DELAY_MS).len(), copies as usize);
        }

        let mut net = network();
        assert_eq!(
            net.add_fault(NetworkFault::Duplicate {
                src: A,
                dst: B,
                copies: 6,
            }),
            Err(NetworkError::TooManyCopies { copies: 6 })
        );
    }

    #[test]
    fn deliver_is_ordered_and_drains_exactly_once() {
        let mut net = network();
        net.send(0, A, B, b"1".to_vec());
        net.send(0, A, B, b"2".to_vec());
        let first = net.deliver(DEFAULT_LINK_DELAY_MS);
        assert_eq!(first.len(), 2);
        assert!(net.deliver(DEFAULT_LINK_DELAY_MS).is_empty());
    }
}
