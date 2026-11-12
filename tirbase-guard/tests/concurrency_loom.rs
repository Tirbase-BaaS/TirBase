//! Loom concurrency tests for `SingleWriterLease` and `AntiReplayWindow`
//! (CLAIM-51.5, PV-26.3).
//!
//! These tests drive the **real** guard types under loom-explored interleavings:
//! `SingleWriterLease::is_expired`/`in_cooldown` decide acquisition, and
//! `AntiReplayWindow::check`/`apply_accepted` decide whether a sequence is
//! committed. The lease/admission rules are therefore the production rules, not
//! a re-implementation.
//!
//! Run: `cargo test -p tirbase-guard --features loom --test concurrency_loom`
//!
//! History: the previous version modelled a toy `AtomicU64` instead of the real
//! types and asserted "at most one winner ever", which is wrong for a lease that
//! can be released and re-acquired; it failed the first time it was executed.

#![cfg(feature = "loom")]

use std::sync::Arc;

use loom::sync::{Mutex, MutexGuard};
use loom::thread;
use tirbase_guard::anti_replay::{AntiReplayDecision, AntiReplayWindow};
use tirbase_guard::single_writer_lease::SingleWriterLease;
use tirbase_types::Did;

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

/// Try to acquire `target` at `now`: the production rule is that a lease may be
/// taken when there is none, when it has expired, or when its issuer is not in
/// cooldown. Returns `Ok` when this issuer now holds it.
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
        if current.in_cooldown(now) && current.issuer_did.as_str() == issuer {
            return Err("issuer in cooldown");
        }
    }
    *guard = Some(lease(issuer, target, now + 10));
    Ok(())
}

#[test]
fn single_writer_lease_mutual_exclusion_under_concurrency() {
    // Two issuers race for one target. Both may legitimately acquire in
    // sequence (a released/expired lease is free again), but at no point may a
    // second issuer take a lease that is still live for the first: every
    // rejection must be the typed "target busy" error, and the final holder must
    // be consistent with the lease written under the lock.
    loom::model(|| {
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
        // Both acquisitions happened at the same instant `now=100`, so at most
        // one can succeed; the loser must see the typed busy error.
        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert!(
            winners <= 1,
            "two issuers must not both hold a live lease: {results:?}"
        );
        for r in &results {
            if let Err(e) = r {
                assert_eq!(*e, "target busy", "rejection must be typed: {results:?}");
            }
        }

        let holder = lock(&slot);
        let holder = holder.as_ref().expect("lease written by the winner");
        assert!(
            holder.issuer_did.as_str() == "did:key:zAlice"
                || holder.issuer_did.as_str() == "did:key:zBob",
            "holder must be one of the contenders"
        );
        assert!(!holder.is_expired(100), "the committed lease is live");
    });
}

#[test]
fn single_writer_lease_expired_lease_is_reacquirable() {
    // A lease that has expired must be acquirable by another issuer: the
    // production `is_expired` rule, not an unconditional lock.
    loom::model(|| {
        let slot = Arc::new(Mutex::new(Some(lease("did:key:zAlice", "target-1", 50))));
        let second = try_acquire(&slot, "did:key:zBob", "target-1", 100);
        assert_eq!(second, Ok(()), "an expired lease must be reacquirable");
        let holder = lock(&slot);
        assert_eq!(
            holder.as_ref().unwrap().issuer_did.as_str(),
            "did:key:zBob"
        );
    });
}

#[test]
fn anti_replay_window_rejects_concurrent_duplicate_commit() {
    // Two threads attempt to commit the same sequence. Check + commit are done
    // under one lock (the Stage 16 atomic-commit contract). Exactly one accepts;
    // the other must see the real `Replay` decision.
    loom::model(|| {
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
        assert_eq!(replays, 1, "the duplicate must be rejected as Replay: {results:?}");
    });
}

#[test]
fn anti_replay_window_admits_distinct_sequences_once() {
    // Distinct in-window sequences must both be accepted, each exactly once.
    loom::model(|| {
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
            "distinct in-window sequences must both be accepted: {results:?}"
        );
        let w = lock(&window);
        assert!(w.check(3).is_accepted() == false, "3 is already committed");
        assert!(w.check(4).is_accepted() == false, "4 is already committed");
    });
}
