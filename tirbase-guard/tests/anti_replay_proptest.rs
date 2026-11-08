//! Property tests for anti-replay window (task 20.6, CLAIM-20.6, PV-5.5).
//! P7: sequence numbers outside the window are always rejected.
//! P8: accepted sequence numbers are never re-accepted within the same enrollment epoch.

use proptest::prelude::*;
use tirbase_guard::anti_replay::{
    AntiReplayDecision, AntiReplayWindow, DEFAULT_FORWARD_GAP_G, DEFAULT_WINDOW_W,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// P7: any seq outside [highest_seen - W, highest_seen + G] is rejected.
    #[test]
    fn p7_sequences_outside_window_always_rejected(
        highest in 1u64..10_000,
        outside_low in prop::bool::ANY,
        delta in (DEFAULT_WINDOW_W + 1)..5000u64,
        epoch in 0u64..4,
    ) {
        let mut w = AntiReplayWindow::new("issuer".into(), "target".into(), epoch);
        w.apply_accepted(w.check(highest));
        let seq = if outside_low {
            highest.saturating_sub(delta)
        } else {
            highest.saturating_add(DEFAULT_FORWARD_GAP_G + delta)
        };
        // Only assert "outside" when it truly is (saturating_sub can collapse).
        let lower = highest.saturating_sub(DEFAULT_WINDOW_W);
        let upper = highest.saturating_add(DEFAULT_FORWARD_GAP_G);
        if seq < lower || seq > upper {
            prop_assert_eq!(
                w.check(seq),
                AntiReplayDecision::OutsideWindow,
                "P7: seq outside window must be rejected (seq={}, lower={}, upper={})", seq, lower, upper
            );
        }
    }

    /// P8: once accepted in an epoch, the same (issuer,target,seq,epoch) is never re-accepted.
    /// It may be reported as `Replay` (still in bitmap) or `OutsideWindow` (window slid past);
    /// both satisfy INV-10's "accepted at most once".
    #[test]
    fn p8_accepted_sequence_never_reaccepted_same_epoch(
        seqs in prop::collection::vec(1u64..500, 1..32),
        epoch in 0u64..3,
    ) {
        let mut w = AntiReplayWindow::new("issuer".into(), "target".into(), epoch);
        let mut accepted = std::collections::BTreeSet::<u64>::new();
        for seq in seqs {
            let d = w.check(seq);
            if d.is_accepted() {
                prop_assert!(!accepted.contains(&seq), "P8: impl returned Accept for already accepted {}", seq);
                w.apply_accepted(d);
                accepted.insert(seq);
            } else if accepted.contains(&seq) {
                prop_assert!(
                    matches!(d, AntiReplayDecision::Replay | AntiReplayDecision::OutsideWindow),
                    "P8: accepted seq must never be re-accepted (seq={}, got={:?})", seq, d
                );
            }
            // Re-check every accepted seq: must never be accepted again.
            for &a in &accepted {
                prop_assert!(!w.check(a).is_accepted(), "P8: accepted seq re-accepted in same epoch (seq={})", a);
            }
        }
    }

    /// Enrollment epoch scoping: same seq in a different epoch window instance is independent.
    #[test]
    fn epoch_scoping_independent_windows(
        seq in 1u64..200,
        epoch_a in 0u64..3,
        epoch_b in 0u64..3,
    ) {
        prop_assume!(epoch_a != epoch_b);
        let mut wa = AntiReplayWindow::new("i".into(), "t".into(), epoch_a);
        let wb = AntiReplayWindow::new("i".into(), "t".into(), epoch_b);
        let da = wa.check(seq);
        wa.apply_accepted(da);
        prop_assert!(da.is_accepted());
        let db = wb.check(seq);
        prop_assert!(db.is_accepted(), "same seq in different epoch must be acceptable in its own window");
    }
}
