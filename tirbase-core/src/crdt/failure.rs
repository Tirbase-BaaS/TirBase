//! Structured Delta rejection failure records — Req 7.4 / 7.5.
//!
//! When the CRDT merge gate discards an inbound Delta (revoked author,
//! missing signature, unresolvable sender DID, failed Ed25519 verification),
//! [`CrdtEngine::apply`](crate::crdt::CrdtEngine::apply) emits a typed
//! [`DeltaRejectionRecord`] instead of an unstructured `eprintln!` line.
//!
//! Every record carries the sender DID and a UTC timestamp, satisfying the
//! spec conjuncts of:
//! - Req 7.4 — "IF Delta signature verification fails, THEN THE Rust_Core
//!   SHALL discard the Delta and emit a failure record containing the sender
//!   DID and UTC timestamp without merging any data";
//! - Req 7.5 — "IF the sender's DID cannot be resolved to a public key, THEN
//!   THE Rust_Core SHALL discard the Delta and emit a distinct
//!   unresolvable-DID failure record containing the unresolved DID and UTC
//!   timestamp."
//!
//! Records are retained (bounded) on the engine so operators and in-crate
//! callers can introspect recent rejections, and a copy is forwarded to the
//! host listener registered by [`CoreHandle::init`](crate::api::CoreHandle::init)
//! (which relays each record onto a broadcast channel for subscribers —
//! Subphase 6.2).  On native builds the record is also rendered to stderr as
//! the v1 observability channel; on the WASM build `eprintln!` is a silent
//! no-op, so the retained record is the observable.

use crate::crdt::delta::{DeltaId, Did};

// ─── Rejection code ───────────────────────────────────────────────────────────

/// Why an inbound Delta was rejected by the merge gate.
///
/// Discriminates the Req 7.4 signature-verification failure record from the
/// distinct Req 7.5 unresolvable-DID failure record (and from the other
/// rejection causes the gate enforces ahead of signature verification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeltaRejectionCode {
    /// The author DID is in the engine's REVOKED set — the Req 8.6
    /// revocation gate (a revocation-gate rejection, not a crypto failure).
    RevokedAuthor,
    /// The Delta carries no signature at all (malformed-signature guard).
    MissingSignature,
    /// The sender's DID could not be resolved to an Ed25519 public key
    /// (Req 7.5 — the distinct unresolvable-DID failure record).
    DidResolutionFailed,
    /// The Ed25519 signature did not verify against the sender's resolved
    /// public key over the Delta's canonical bytes (Req 7.4).
    SignatureVerificationFailed,
}

impl DeltaRejectionCode {
    /// Stable machine-readable code string carried by the record's renderings.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DeltaRejectionCode::RevokedAuthor => "REVOKED_AUTHOR",
            DeltaRejectionCode::MissingSignature => "MISSING_SIGNATURE",
            DeltaRejectionCode::DidResolutionFailed => "DID_RESOLUTION_FAILED",
            DeltaRejectionCode::SignatureVerificationFailed => {
                "SIGNATURE_VERIFICATION_FAILED"
            }
        }
    }
}

// ─── Rejection record ─────────────────────────────────────────────────────────

/// A structured failure record emitted when the merge gate rejects an inbound
/// Delta (Req 7.4 / 7.5).
///
/// This is the typed replacement for the former `eprintln!` rejection logs:
/// the record — not a log string — is the thing that is emitted, and every
/// record carries the sender DID (`author_did`) and a UTC timestamp
/// (`occurred_at_utc`) per Req 7.4/7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeltaRejectionRecord {
    /// Why the Delta was rejected; discriminates the distinct Req 7.5
    /// unresolvable-DID record from the Req 7.4 signature-verification record.
    pub code: DeltaRejectionCode,
    /// DID of the Delta's sender.
    ///
    /// For a Req 7.5 rejection this IS the unresolved DID — resolution failed
    /// *for this string* — so the record carries exactly the DID the spec
    /// requires the distinct record to contain.
    pub author_did: Did,
    /// The rejected Delta's ID (SHA-256 of its canonical bytes).
    pub delta_id: DeltaId,
    /// Human-readable rejection reason (mirrors `MergeOutcome::Rejected`).
    pub reason: String,
    /// UTC wall-clock time when the rejection occurred, in microseconds since
    /// the Unix epoch (same clock convention as Delta `created_at` and the
    /// contamination engine's `utc_timestamp`).
    pub occurred_at_utc: i64,
}

impl DeltaRejectionRecord {
    /// Canonical single-line rendering for the v1 native stderr observability
    /// channel.  Key/value structured so operators can parse it; the typed
    /// record itself remains the authoritative artifact.
    pub(crate) fn render_line(&self) -> String {
        format!(
            "[CRDT] Delta rejected code={} author={} delta={} occurred_at_utc={} reason={}",
            self.code.as_str(),
            self.author_did,
            hex::encode(self.delta_id),
            self.occurred_at_utc,
            self.reason,
        )
    }
}

// ─── Host listener ────────────────────────────────────────────────────────────

/// Application-layer callback invoked for every rejection record the engine
/// emits.
///
/// `Send + Sync` so the engine (and the `CoreHandle` hosting it) can be shared
/// across the production background loops.  The listener is invoked while the
/// engine is locked (inside `CrdtEngine::apply`), so it must not re-enter the
/// engine — [`CoreHandle::init`](crate::api::CoreHandle::init) registers a
/// listener that only forwards onto a non-blocking broadcast channel.
pub(crate) type DeltaRejectionListener =
    Box<dyn Fn(&DeltaRejectionRecord) + Send + Sync>;

// ─── Notification ─────────────────────────────────────────────────────────────

/// Notify the v1 observability channel of a rejection record.
///
/// Native builds render the structured record to stderr (the native
/// diagnostics channel in v1).  WASM builds have no stderr sink — the
/// retained engine record (and any host listener) is the observable, exactly
/// as `eprintln!` was a silent no-op on that target before this module.
pub(crate) fn notify_delta_rejection(record: &DeltaRejectionRecord) {
    #[cfg(feature = "native")]
    {
        eprintln!("{}", record.render_line());
    }
    #[cfg(not(feature = "native"))]
    {
        let _ = record;
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_code_stable_strings_are_distinct() {
        let codes = [
            DeltaRejectionCode::RevokedAuthor.as_str(),
            DeltaRejectionCode::MissingSignature.as_str(),
            DeltaRejectionCode::DidResolutionFailed.as_str(),
            DeltaRejectionCode::SignatureVerificationFailed.as_str(),
        ];
        // The two spec-mandated records must carry distinct, stable codes.
        assert_ne!(codes[2], codes[3]);
        for code in codes {
            assert!(!code.is_empty());
        }
    }

    #[test]
    fn record_render_line_carries_code_did_delta_and_utc_timestamp() {
        let record = DeltaRejectionRecord {
            code: DeltaRejectionCode::SignatureVerificationFailed,
            author_did: "did:key:z6Mkpeer".to_string(),
            delta_id: [0xAB; 32],
            reason: "signature mismatch".to_string(),
            occurred_at_utc: 1_720_000_000_123_456,
        };
        let line = record.render_line();
        assert!(line.contains("SIGNATURE_VERIFICATION_FAILED"), "line: {line}");
        assert!(line.contains("did:key:z6Mkpeer"), "line: {line}");
        assert!(line.contains(&hex::encode([0xAB; 32])), "line: {line}");
        assert!(line.contains("occurred_at_utc=1720000000123456"), "line: {line}");
        assert!(line.contains("signature mismatch"), "line: {line}");
    }
}
