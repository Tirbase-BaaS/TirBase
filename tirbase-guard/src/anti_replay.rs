//! Anti-replay sliding window (task 20.1/20.2/20.3, CLAIM-20.1–20.3, PV-5.5, INV-10).
//!
//! Per `(issuer_did, target_id, enrollment_epoch)`, a sliding bitmap of width
//! `W` (default 64) tracks accepted sequence numbers. The window slides to the
//! highest authenticated sequence number seen. A sequence number is accepted if
//! it falls within `[highest_seen - W, highest_seen + G]` (where `G` is the
//! forward gap, default 1024) and has not been seen before.
//!
//! **S20 (sequence-number poisoning):** only a fully authenticated and
//! committed command may advance state. Rejected/unauthenticated commands must
//! never advance `highest_seen`; callers must not persist the result of
//! [`AntiReplayWindow::check`] unless Stage 16 commits atomically.

use serde::{Deserialize, Serialize};
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};

use crate::signed_operation::{
    SignatureEntry, SignedOperation, SignedOperationError, SignedOperationPayload,
};

/// Domain-separation context for PolicyAuthority-signed anti-replay window reset
/// (CLAIM-20.3, PV-5.5).
pub const CONTEXT_ANTI_REPLAY_WINDOW_RESET: &str = "TirBase/v1/AntiReplayWindowReset";

/// Default sliding window width W.
pub const DEFAULT_WINDOW_W: u64 = 64;
/// Default forward gap G (tolerates reordering in store-and-forward meshes).
pub const DEFAULT_FORWARD_GAP_G: u64 = 1024;

/// Outcome of a non-mutating anti-replay check (CLAIM-20.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiReplayDecision {
    /// Sequence is acceptable; commit should persist `new_highest`/`new_bitmap`.
    Accept { new_highest: u64, new_bitmap: u64 },
    /// Sequence was already seen in the current window.
    Replay,
    /// Sequence is outside `[highest_seen - W, highest_seen + G]`.
    OutsideWindow,
}

impl AntiReplayDecision {
    pub fn is_accepted(self) -> bool {
        matches!(self, AntiReplayDecision::Accept { .. })
    }
}

/// Sliding bitmap anti-replay window state (CLAIM-20.1).
///
/// In-memory representation mirrors the durable row in `anti_replay_windows`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiReplayWindow {
    pub issuer_did: String,
    pub target_id: String,
    pub enrollment_epoch: u64,
    pub highest_seen: u64,
    /// Little-endian u64 bitmap over `[highest_seen - (W-1), highest_seen]`.
    pub seen_bitmap: u64,
    pub forward_gap: u64,
    pub window_w: u64,
}

impl AntiReplayWindow {
    pub fn new(issuer_did: String, target_id: String, enrollment_epoch: u64) -> Self {
        Self::with_params(
            issuer_did,
            target_id,
            enrollment_epoch,
            DEFAULT_WINDOW_W,
            DEFAULT_FORWARD_GAP_G,
        )
    }

    pub fn with_params(
        issuer_did: String,
        target_id: String,
        enrollment_epoch: u64,
        window_w: u64,
        forward_gap: u64,
    ) -> Self {
        Self {
            issuer_did,
            target_id,
            enrollment_epoch,
            highest_seen: 0,
            seen_bitmap: 0,
            forward_gap: forward_gap.max(DEFAULT_FORWARD_GAP_G.min(forward_gap)),
            window_w: window_w.max(1),
        }
    }

    /// Rehydrate from persisted fields.
    pub fn from_persisted(
        issuer_did: String,
        target_id: String,
        enrollment_epoch: u64,
        highest_seen: u64,
        seen_bitmap: u64,
        forward_gap: u64,
        window_w: u64,
    ) -> Self {
        Self {
            issuer_did,
            target_id,
            enrollment_epoch,
            highest_seen,
            seen_bitmap,
            forward_gap,
            window_w: window_w.max(1),
        }
    }

    /// Non-mutating check (CLAIM-20.2). Does **not** modify `self`.
    pub fn check(&self, seq: u64) -> AntiReplayDecision {
        check_sequence(
            self.highest_seen,
            self.seen_bitmap,
            seq,
            self.window_w,
            self.forward_gap,
            self.is_empty_state(),
        )
    }

    fn is_empty_state(&self) -> bool {
        self.highest_seen == 0 && self.seen_bitmap == 0
    }

    /// Apply an accepted decision (call only after Stage 16 atomic commit).
    pub fn apply_accepted(&mut self, decision: AntiReplayDecision) {
        if let AntiReplayDecision::Accept {
            new_highest,
            new_bitmap,
        } = decision
        {
            self.highest_seen = new_highest;
            self.seen_bitmap = new_bitmap;
        }
    }

    /// PolicyAuthority-signed sequence-window reset for issuer re-enrollment or
    /// wrap-around (CLAIM-20.3, PV-5.5). Advances the baseline; clears the bitmap
    /// below the new baseline.
    pub fn reset_to_baseline(&mut self, new_baseline: u64) {
        self.highest_seen = new_baseline;
        self.seen_bitmap = 1;
        emit(
            SecurityEvent::new(
                SecurityEventCategory::AntiReplay,
                Severity::Medium,
                ReasonCode::WindowReset,
            )
            .with_actor(self.issuer_did.as_str())
            .with_target(self.target_id.as_str())
            .with_detail(format!(
                "anti-replay window reset baseline={new_baseline} epoch={}",
                self.enrollment_epoch
            )),
        );
    }
}

/// Pure sliding-bitmap check. `empty` means no prior persisted state.
pub fn check_sequence(
    highest_seen: u64,
    seen_bitmap: u64,
    seq: u64,
    window_w: u64,
    forward_gap: u64,
    empty: bool,
) -> AntiReplayDecision {
    let w = window_w.max(1);
    let g = forward_gap.max(1);
    if empty {
        return AntiReplayDecision::Accept {
            new_highest: seq,
            new_bitmap: 1,
        };
    }
    let lower = highest_seen.saturating_sub(w);
    let upper = highest_seen.saturating_add(g);
    if seq < lower || seq > upper {
        return AntiReplayDecision::OutsideWindow;
    }
    if bitmap_get(seen_bitmap, highest_seen, seq, w) {
        return AntiReplayDecision::Replay;
    }
    match bitmap_set(seen_bitmap, highest_seen, seq, w) {
        Some((new_highest, new_bitmap)) => AntiReplayDecision::Accept {
            new_highest,
            new_bitmap,
        },
        None => AntiReplayDecision::Replay,
    }
}

fn bitmap_get(bitmap: u64, highest: u64, seq: u64, w: u64) -> bool {
    if seq > highest {
        return false;
    }
    let delta = highest - seq;
    if delta >= w || delta >= 64 {
        return false;
    }
    (bitmap & (1u64 << delta)) != 0
}

fn bitmap_set(bitmap: u64, highest: u64, seq: u64, w: u64) -> Option<(u64, u64)> {
    if seq > highest {
        let shift = seq - highest;
        let new_bitmap = if shift >= 64 {
            1u64
        } else {
            (bitmap << shift) | 1u64
        };
        return Some((seq, new_bitmap));
    }
    let delta = highest - seq;
    if delta >= w || delta >= 64 {
        return None;
    }
    let mask = 1u64 << delta;
    if (bitmap & mask) != 0 {
        return None;
    }
    Some((highest, bitmap | mask))
}

/// Payload for a PolicyAuthority-signed sequence-window reset (CLAIM-20.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiReplayWindowReset {
    pub issuer_did: String,
    pub target_id: String,
    pub enrollment_epoch: u64,
    pub new_baseline_sequence: u64,
    /// Replay-protection / audit timestamp (authenticated estimate seconds).
    pub requested_at_est: i64,
    pub reason: String,
}

impl SignedOperationPayload for AntiReplayWindowReset {
    const CONTEXT: &'static str = CONTEXT_ANTI_REPLAY_WINDOW_RESET;
}

/// Verify and apply a signed anti-replay window reset.
///
/// Caller is responsible for persisting the resulting baseline in the same
/// administrative transaction boundary as audit logging.
pub fn verify_and_apply_window_reset(
    window: &mut AntiReplayWindow,
    operation: &SignedOperation<AntiReplayWindowReset>,
    payload: &AntiReplayWindowReset,
    resolve: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<(), SignedOperationError> {
    operation.verify(payload, resolve)?;
    if payload.issuer_did != window.issuer_did
        || payload.target_id != window.target_id
        || payload.enrollment_epoch != window.enrollment_epoch
    {
        return Err(SignedOperationError::Serialization(
            "window reset payload does not match target window".to_string(),
        ));
    }
    window.reset_to_baseline(payload.new_baseline_sequence);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_first_seq_and_rejects_replay() {
        let mut w = AntiReplayWindow::new("i".into(), "t".into(), 0);
        let d = w.check(5);
        assert!(matches!(
            d,
            AntiReplayDecision::Accept { new_highest: 5, .. }
        ));
        w.apply_accepted(d);
        assert_eq!(w.check(5), AntiReplayDecision::Replay);
    }

    #[test]
    fn rejects_outside_window_s20_far_future_does_not_advance_without_commit() {
        let mut w = AntiReplayWindow::new("i".into(), "t".into(), 0);
        let d = w.check(10);
        w.apply_accepted(d);
        let before = w.highest_seen;
        // Far future beyond forward gap G=1024 is rejected and must not advance.
        assert_eq!(
            w.check(before + DEFAULT_FORWARD_GAP_G + 1),
            AntiReplayDecision::OutsideWindow
        );
        assert_eq!(
            w.highest_seen, before,
            "rejected command must not advance highest_seen (S20)"
        );
    }

    #[test]
    fn accepts_reordered_within_window() {
        let mut w = AntiReplayWindow::new("i".into(), "t".into(), 0);
        w.apply_accepted(w.check(100));
        let d = w.check(90);
        assert!(d.is_accepted());
        w.apply_accepted(d);
        assert_eq!(w.check(90), AntiReplayDecision::Replay);
    }

    #[test]
    fn rejects_below_window() {
        let mut w = AntiReplayWindow::new("i".into(), "t".into(), 0);
        w.apply_accepted(w.check(200));
        assert_eq!(
            w.check(200 - DEFAULT_WINDOW_W - 1),
            AntiReplayDecision::OutsideWindow
        );
    }

    #[test]
    fn reset_allows_previously_rejected_sequence() {
        let mut w = AntiReplayWindow::new("i".into(), "t".into(), 0);
        w.apply_accepted(w.check(200));
        // 1 is now below window
        assert_eq!(w.check(1), AntiReplayDecision::OutsideWindow);
        w.reset_to_baseline(0);
        let d = w.check(1);
        assert!(
            d.is_accepted(),
            "reset baseline must allow sequence 1 again"
        );
    }
}
