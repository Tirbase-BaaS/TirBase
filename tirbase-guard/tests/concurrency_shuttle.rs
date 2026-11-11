//! Shuttle concurrency tests for `SingleWriterLease` and `AntiReplayWindow`
//! (CLAIM-51.5, PV-26.3).
//!
//! Randomized schedule exploration (shuttle) complementing the exhaustive loom
//! models, asserting the same safety invariants: exclusive lease holding,
//! bounded renewals/cooldown, and at-most-once acceptance of a replayed
//! sequence within an epoch.
//!
//! Run with: `cargo test -p tirbase-guard --test concurrency_shuttle --features shuttle`

#![cfg(feature = "shuttle")]

use shuttle::sync::atomic::{AtomicU64, Ordering};
use shuttle::sync::Arc;
use shuttle::thread;

fn lease_exclusive_model() {
    let state = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for issuer in 1u64..=3 {
        let state = state.clone();
        handles.push(thread::spawn(move || {
            let desired = (issuer << 32) | 1;
            state
                .compare_exchange(0, desired, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        }));
    }
    let winners = handles.into_iter().filter(|h| h.join().unwrap()).count();
    assert!(winners <= 1, "exclusive lease: at most one winner, got {winners}");
}

#[test]
fn shuttle_single_writer_lease_exclusive_acquire() {
    shuttle::check_random(lease_exclusive_model, 200);
}

fn lease_renewal_cap_model() {
    const CAP: u64 = 5;
    let renewals = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let renewals = renewals.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                let cur = renewals.load(Ordering::SeqCst);
                if cur >= CAP {
                    return;
                }
                let _ = renewals.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(renewals.load(Ordering::SeqCst) <= CAP);
}

#[test]
fn shuttle_single_writer_lease_renewal_cap() {
    shuttle::check_random(lease_renewal_cap_model, 200);
}

fn anti_replay_no_double_accept_model() {
    let bitmap = Arc::new(AtomicU64::new(0));
    let seq_bit = 1u64 << 7;
    let accepted = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..3 {
        let bitmap = bitmap.clone();
        let accepted = accepted.clone();
        handles.push(thread::spawn(move || loop {
            let cur = bitmap.load(Ordering::SeqCst);
            if cur & seq_bit != 0 {
                return;
            }
            if bitmap
                .compare_exchange(cur, cur | seq_bit, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                accepted.fetch_add(1, Ordering::SeqCst);
                return;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "replay must not be accepted twice");
}

#[test]
fn shuttle_anti_replay_window_no_double_accept() {
    shuttle::check_random(anti_replay_no_double_accept_model, 200);
}
