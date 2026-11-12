//! Shuttle concurrency tests for `SingleWriterLease` and `AntiReplayWindow`
//! (CLAIM-51.5, PV-26.3).
//!
//! Shuttle explores randomised thread schedules over the same real guard types
//! (`SingleWriterLease::is_expired`/`in_cooldown` for acquisition, and
//! `AntiReplayWindow::check`/`apply_accepted` for commit), giving a second
//! scheduler independent of loom.
//!
//! Run: `cargo test -p tirbase-guard --features shuttle --test concurrency_shuttle`

#![cfg(feature = "shuttle")]

use std::sync::Arc;

use shuttle::sync::{Mutex, MutexGuard};
use shuttle::thread;
use tirbase_guard::anti_replay::{AntiReplayDecision, AntiReplayWindow};
use tirbase_guard::single_writer_lease::SingleWriterLease;
use tirbase_types::Did;

const SCHEDULES: usize = 200;

fn lease(issuer: &str, target: &str, expires: i64) -> SingleWriterLease {
    SingleWriterLease {
        issuer_did: Did::new(issuer),
        target_id: target.to_string(),
        expires_mono_secs: expires,
        consecutive_renewals: 0,
        cooldown_until_mono_secs: None,
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    }
}

fn try_acquire(
    slot: &Mutex<Option<SingleWriterLease>>,
    issuer: &str,
    target: &str,
    now: i64,
) -> Result<(), &'static str> {
    let mut guard = lock(slot);
    if let Some(current) = guard.as_ref() {
        if !current.is_expired(now) && !current.in_cooldown(now) {
            return Err("target busy");
        }
    }
    *guard = Some(lease(issuer, target, now + 10));
    Ok(())
}

#[test]
fn shuttle_single_writer_lease_mutual_exclusion() {
    shuttle::check_random(
        || {
            let slot = Arc::new(Mutex::new(None::<SingleWriterLease>));
            let outcomes = Arc::new(Mutex::new(Vec::<Result<(), &'static str>>::new()));
            let mut handles = Vec::new();
            for issuer in ["did:key:zAlice", "did:key:zBob"] {
                let slot = slot.clone();
                let outcomes = outcomes.clone();
                handles.push(thread::spawn(move || {
                    let outcome = try_acquire(&slot, issuer, "target-1", 100);
                    lock(&outcomes).push(outcome);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }

            let results = lock(&outcomes).clone();
            let winners = results.iter().filter(|r| r.is_ok()).count();
            assert!(
                winners <= 1,
                "two issuers must not both hold a live lease: {results:?}"
            );
            for r in &results {
                if let Err(e) = r {
                    assert_eq!(*e, "target busy");
                }
            }
            let holder = lock(&slot);
            assert!(holder.as_ref().is_some(), "a lease must be committed");
            assert!(!holder.as_ref().unwrap().is_expired(100));
        },
        SCHEDULES,
    );
}

#[test]
fn shuttle_anti_replay_window_rejects_concurrent_duplicate_commit() {
    shuttle::check_random(
        || {
            let window = Arc::new(Mutex::new(AntiReplayWindow::new(
                "did:key:zIssuer".into(),
                "target-1".into(),
                0,
            )));
            let outcomes = Arc::new(Mutex::new(Vec::<AntiReplayDecision>::new()));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let window = window.clone();
                let outcomes = outcomes.clone();
                handles.push(thread::spawn(move || {
                    let mut guard = lock(&window);
                    let decision = guard.check(5);
                    if decision.is_accepted() {
                        guard.apply_accepted(decision);
                    }
                    lock(&outcomes).push(decision);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }

            let results = lock(&outcomes).clone();
            let accepted = results.iter().filter(|d| d.is_accepted()).count();
            let replays = results
                .iter()
                .filter(|d| matches!(d, AntiReplayDecision::Replay))
                .count();
            assert_eq!(accepted, 1, "sequence must commit exactly once: {results:?}");
            assert_eq!(replays, 1, "the duplicate must be rejected: {results:?}");
        },
        SCHEDULES,
    );
}

#[test]
fn shuttle_anti_replay_window_admits_distinct_sequences_once() {
    shuttle::check_random(
        || {
            let window = Arc::new(Mutex::new(AntiReplayWindow::new(
                "did:key:zIssuer".into(),
                "target-1".into(),
                0,
            )));
            let outcomes = Arc::new(Mutex::new(Vec::<AntiReplayDecision>::new()));
            let mut handles = Vec::new();
            for seq in [3u64, 4u64] {
                let window = window.clone();
                let outcomes = outcomes.clone();
                handles.push(thread::spawn(move || {
                    let mut guard = lock(&window);
                    let decision = guard.check(seq);
                    if decision.is_accepted() {
                        guard.apply_accepted(decision);
                    }
                    lock(&outcomes).push(decision);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            let results = lock(&outcomes).clone();
            assert!(
                results.iter().all(|d| d.is_accepted()),
                "distinct sequences must both commit: {results:?}"
            );
        },
        SCHEDULES,
    );
}
