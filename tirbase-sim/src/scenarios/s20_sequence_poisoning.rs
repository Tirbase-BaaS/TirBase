// SPDX-License-Identifier: AGPL-3.0-only

//! Scenario S20 — Sequence-number poisoning (CLAIM-20.8, PV-5.5, INV-10).
//!
//! A compromised/rejected issuer attempt with a sequence number far beyond the
//! forward gap must not advance the anti-replay window. Legitimate sequential
//! commands remain accepted.

use tirbase_guard::anti_replay::{AntiReplayDecision, AntiReplayWindow, DEFAULT_FORWARD_GAP_G};

/// S20: rejected/far-future sequence does not advance `highest_seen`; legitimate
/// issuer is not stranded.
pub fn scenario_s20_sequence_poisoning_rejected_cmd_does_not_advance_window() {
    let mut w = AntiReplayWindow::new("did:key:zIssuer".into(), "pump-1".into(), 0);
 // Legitimate issuer establishes baseline.
    let d1 = w.check(10);
    assert!(d1.is_accepted(), "baseline seq 10 accepted");
    w.apply_accepted(d1);

    let before = w.highest_seen;
 // Attacker sends far-future seq beyond [highest_seen - W, highest_seen + G].
    let poison = before + DEFAULT_FORWARD_GAP_G + 50_000;
    let decision = w.check(poison);
    assert_eq!(
        decision,
        AntiReplayDecision::OutsideWindow,
        "S20: far-future poisoned seq must be rejected"
    );
 // Critical invariant: rejected command does NOT advance highest_seen.
 // (Caller must not call apply_accepted on rejection; state is unchanged.)
    assert_eq!(
        w.highest_seen, before,
        "S20: rejected command must not advance highest_seen"
    );

 // Legitimate issuer continues with sequential numbers.
    for seq in 11u64..=20 {
        let d = w.check(seq);
        assert!(
            d.is_accepted(),
            "S20: legitimate seq {seq} must remain accepted; got {d:?}"
        );
        w.apply_accepted(d);
    }
    assert_eq!(w.highest_seen, 20);

 // Replay of an accepted seq is rejected.
    assert_eq!(w.check(15), AntiReplayDecision::Replay);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s20_sequence_poisoning_claim_20_8() {
        scenario_s20_sequence_poisoning_rejected_cmd_does_not_advance_window();
    }
}
