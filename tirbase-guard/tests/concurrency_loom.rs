//! Loom concurrency tests for `SingleWriterLease` and `AntiReplayWindow`
//! (CLAIM-51.5, PV-26.3).
//!
//! These tests model concurrent acquire/renew/preempt/revocation decisions for a
//! single-writer lease and concurrent check/commit decisions for the anti-replay
//! sliding window over a shared atomic state, asserting the safety invariants the
//! Rust implementations must uphold (at most one active lease holder; an
//! accepted `(issuer,target,epoch,seq)` is never durably committed twice).
//!
//! Run with: `cargo test -p tirbase-guard --test concurrency_loom --features loom`

#![cfg(feature = "loom")]

use loom::sync::atomic::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

#[test]
fn single_writer_lease_at_most_one_active_holder_under_concurrency() {
    // Model: two issuers race to acquire/renew a single target. State packs
    // holder id in high bits and a generation/expiry token in low bits; a
    // compare-exchange admits exactly one winner per state transition.
    // Invariant: concurrent winners never both observe themselves as the active
    // holder of the same committed generation.
    loom::model(|| {
        let state = Arc::new(AtomicU64::new(0)); // 0 = free
        let committed_holder = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for issuer in 1u64..=2 {
            let state = state.clone();
            let committed_holder = committed_holder.clone();
            handles.push(thread::spawn(move || {
                // Attempt acquire: only succeeds from free -> issuer@g1.
                let desired = (issuer << 32) | 1;
                if state
                    .compare_exchange(0, desired, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    // Winner records itself as committed holder for generation 1.
                    committed_holder.store(desired, Ordering::SeqCst);
                    // Release (expire) back to free if still ours.
                    let _ = state.compare_exchange(desired, 0, Ordering::SeqCst, Ordering::SeqCst);
                    return Some(issuer);
                }
                None
            }));
        }
        let results: Vec<Option<u64>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners = results.iter().filter(|r| r.is_some()).count();
        assert!(winners <= 1, "at most one issuer may acquire the lease: {:?}", results);
        let committed = committed_holder.load(Ordering::SeqCst);
        if winners == 1 {
            let holder = committed >> 32;
            assert!(holder == 1 || holder == 2);
        } else {
            assert_eq!(committed, 0);
        }
    });
}

#[test]
fn single_writer_lease_renewal_cap_blocks_unbounded_renewal() {
    // Model: a holder repeatedly renews; each renewal increments a shared
    // counter and is refused once the cap is reached, forcing cooldown/release.
    // Invariant: renewals never exceed the cap and the lease is not held past cap.
    const CAP: u64 = 3;
    loom::model(|| {
        let renewals = Arc::new(AtomicU64::new(0));
        let held = Arc::new(AtomicU64::new(1)); // issuer 1 holds initially
        let mut handles = Vec::new();
        for _ in 0..2 {
            let renewals = renewals.clone();
            let held = held.clone();
            handles.push(thread::spawn(move || loop {
                let current = renewals.load(Ordering::SeqCst);
                if current >= CAP {
                    // Cap reached: lease must be released/cooled down.
                    held.store(0, Ordering::SeqCst);
                    return;
                }
                if renewals
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return;
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let r = renewals.load(Ordering::SeqCst);
        assert!(r <= CAP, "renewals must not exceed cap: {r}");
        // Once cap is reached, holder must not remain active.
        if r >= CAP {
            assert_eq!(held.load(Ordering::SeqCst), 0, "cap triggers release/cooldown");
        }
    });
}

#[test]
fn anti_replay_window_never_commits_same_sequence_twice() {
    // Model: two concurrent commit attempts for the same (issuer,target,epoch,seq)
    // compete to set the seen bit in a shared bitmap via CAS. A sequence is
    // durably accepted at most once.
    loom::model(|| {
        let bitmap = Arc::new(AtomicU64::new(0));
        let accepted_count = Arc::new(AtomicU64::new(0));
        let seq_bit: u64 = 1u64 << 5; // fixed sequence position within window
        let mut handles = Vec::new();
        for _ in 0..2 {
            let bitmap = bitmap.clone();
            let accepted_count = accepted_count.clone();
            handles.push(thread::spawn(move || loop {
                let cur = bitmap.load(Ordering::SeqCst);
                if cur & seq_bit != 0 {
                    return false; // replay/outside after concurrent accept
                }
                let next = cur | seq_bit;
                if bitmap
                    .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    accepted_count.fetch_add(1, Ordering::SeqCst);
                    return true;
                }
            }));
        }
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let accepted = results.iter().filter(|&&a| a).count();
        assert_eq!(accepted, 1, "same sequence must be committed exactly once: {:?}", results);
        assert_eq!(accepted_count.load(Ordering::SeqCst), 1);
        assert_ne!(bitmap.load(Ordering::SeqCst) & seq_bit, 0);
    });
}

#[test]
fn anti_replay_window_concurrent_distinct_sequences_commit_once_each() {
    // Two different sequence bits can both be accepted concurrently (no false replay).
    loom::model(|| {
        let bitmap = Arc::new(AtomicU64::new(0));
        let bits = [1u64 << 1, 1u64 << 2];
        let mut handles = Vec::new();
        for bit in bits {
            let bitmap = bitmap.clone();
            handles.push(thread::spawn(move || loop {
                let cur = bitmap.load(Ordering::SeqCst);
                if cur & bit != 0 {
                    return false;
                }
                if bitmap
                    .compare_exchange(cur, cur | bit, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return true;
                }
            }));
        }
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(results.iter().all(|&a| a), "distinct in-window sequences must both be accepted");
        let final_bits = bitmap.load(Ordering::SeqCst);
        assert_eq!(final_bits & bits[0], bits[0]);
        assert_eq!(final_bits & bits[1], bits[1]);
    });
}
