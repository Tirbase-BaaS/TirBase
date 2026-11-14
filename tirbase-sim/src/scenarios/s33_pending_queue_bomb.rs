// SPDX-License-Identifier: AGPL-3.0-only

//! Scenario S33 (Pending-queue memory bomb, PV-6.1, CLAIM-23.1, CLAIM-23.2).
//!
//! An attacker injects deltas with missing causal dependencies to inflate memory.
//! The pending queue must enforce per-peer/global byte caps and age-out, producing
//! bounded behavior and overflow/timeout quarantine events.

use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use tirbase_core::crdt::pending_queue::PendingQueue;
use tirbase_core::events::ReasonCode;

pub const S33_SEED: u64 = 0x00C1_0CC0_0000_0033;

fn mk(n: u16, payload: usize, author: &str) -> Delta {
    let mut id = [0u8; 32];
    id[0] = (n & 0xff) as u8;
    id[1] = (n >> 8) as u8;
    Delta {
        id,
        author_did: author.to_string(),
        signature: Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: vec![0xAB; payload],
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport: n as u64,
        created_at: 0,
    }
}

pub fn run_s33(seed: u64) -> Result<(), String> {
 // Tiny caps to model boundedness deterministically.
    let mut q = PendingQueue::new(100, 5_000, 2_200);
    let mut overflow = 0usize;
    let base = seed as u16;
    for i in 0u16..30 {
        let ev = q.enqueue(
            mk(base.wrapping_add(i), 700, "did:key:attacker"),
            i as u64,
            "did:key:attacker".into(),
        );
        overflow += ev
            .iter()
            .filter(|e| e.reason == ReasonCode::PendingQueueOverflow)
            .count();
    }
    if overflow == 0 {
        return Err(format!(
            "seed={seed} S33 FAIL: expected PendingQueueOverflow under byte cap pressure"
        ));
    }
    if q.total_bytes() > 5_000 {
        return Err(format!(
            "seed={seed} S33 FAIL: global byte cap violated: {}",
            q.total_bytes()
        ));
    }

 // age-out -> MissingDependencyTimeout
    let mut q2 = PendingQueue::new(50, 1024 * 1024, 1024 * 1024);
    q2.enqueue(
        mk(base.wrapping_add(999), 10, "did:key:a"),
        1,
        "did:key:a".into(),
    );
    let ev = q2.evict_timed_out(100);
    if ev.len() != 1 || ev[0].reason != ReasonCode::MissingDependencyTimeout {
        return Err(format!(
            "seed={seed} S33 FAIL: age-out must produce MissingDependencyTimeout: {ev:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s33_pending_queue_bomb_bounded() {
        if let Err(e) = run_s33(S33_SEED) {
            panic!("S33 failed (seed={S33_SEED}): {e}");
        }
    }

    #[test]
    fn s33_pending_queue_bomb_seeded_sweep() {
        for seed in 0u64..8 {
            let s = S33_SEED.wrapping_add(seed);
            if let Err(e) = run_s33(s) {
                panic!("S33 failed (seed={s}): {e}");
            }
        }
    }
}
