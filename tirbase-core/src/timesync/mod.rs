// SPDX-License-Identifier: AGPL-3.0-only

//! F-06 — time sources, time confidence, signed time evidence, and site time
//! zones.
//!
//! # Two clock domains
//!
//! * **Monotonic** (`TimeSource::monotonic_now`, `CLOCK_BOOTTIME`) is the only
//!   clock used for expiry and anti-replay. It cannot be moved by changing the
//!   system clock and it survives suspend.
//! * **Wall clock** is for human-facing records only. It may jump, so every
//!   record that carries a wall time also carries a [`TimeConfidence`] marker
//!   and, for exports/audit, a [`SignedTimeEvidence`] signature.
//!
//! Authenticated expiry stays with the guard's `TimeRatchet`
//! (`tirbase_guard::time`), which derives `now_est` from a signed beacon plus
//! elapsed monotonic time. This module provides the pieces that surround it:
//!
//! * [`TimeSourceKind`] / [`TimeSample`] / [`select_sample`] — a uniform
//!   admission path for NTP (NTS-vetted), gateway beacons, and GPS (OSNMA)
//!   readings, with replay, boot, age, and forward-jump checks.
//! * [`DriftBound`] — the documented uncertainty growth used for offline
//!   records.
//! * [`TimeEvidence`] / [`SignedTimeEvidence`] — the verifiable
//!   time-confidence marker attached to offline records, exports, and audit
//!   entries.
//! * [`zone`] — per-site UTC offset and DST rules plus a schedule evaluator
//!   that produces exactly one occurrence per local date across a DST
//!   transition.
//!
//! # External sources never set time directly
//!
//! A source reading is a *sample*, not a clock. It is admitted only if it is
//! authenticated, from the current boot, within the configured sample age,
//! not below the persisted ratchet floor, and within the maximum single-jump
//! bound. Larger jumps require the M-of-N `TimeAnchor` path in the guard, and
//! a replayed or rolled-back sample is rejected outright.

pub mod zone;

pub use zone::{
    CivilDate, DstRule, DstTransition, LocalResolution, ScheduledEvent,
    ScheduledOccurrence, SiteTimeZone, TimeZoneRegistry,
};

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_types::DeviceSignature;

use crate::crdt::delta::Ed25519Signature;
use crate::identity::{did as did_identity, keypair};
use crate::traits::KeyProvider;

/// Domain separation for [`TimeEvidence`] signatures.
pub const CONTEXT_TIME_EVIDENCE: &str = "TirBase/v1/TimeEvidence";

/// Documented default drift bound for an offline record: 50 ppm plus 250 ms of
/// absolute uncertainty at the last authenticated anchor.
pub const DEFAULT_DRIFT: DriftBound = DriftBound {
    max_ppm: 50,
    max_absolute_ms: 250,
};

/// Clock sources that can feed the authenticated-time path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSourceKind {
    /// Network Time Protocol, admitted only when NTS-authenticated.
    Ntp,
    /// A signed TirBase gateway `TimeAnchor` beacon.
    GatewayBeacon,
    /// GNSS time with message authentication (for example Galileo OSNMA).
    Gps,
    /// The local monotonic clock, with no external attestation.
    Monotonic,
}

impl TimeSourceKind {
    /// Canonical name used in confidence markers and audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            TimeSourceKind::Ntp => "ntp",
            TimeSourceKind::GatewayBeacon => "gateway-beacon",
            TimeSourceKind::Gps => "gps",
            TimeSourceKind::Monotonic => "monotonic",
        }
    }

    /// Relative preference when uncertainty ties.
    fn priority(self) -> u8 {
        match self {
            TimeSourceKind::GatewayBeacon => 3,
            TimeSourceKind::Gps => 2,
            TimeSourceKind::Ntp => 1,
            TimeSourceKind::Monotonic => 0,
        }
    }
}

impl fmt::Display for TimeSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a sample carries cryptographic authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleAttestation {
    /// Signature- or MAC-protected at the source (signed beacon, OSNMA, NTS).
    Authenticated,
    /// Plain NTP or any other unauthenticated reading; usable only as a
    /// wall-clock hint, never admitted to the authenticated-time path.
    Unauthenticated,
}

/// One reading from an external or local source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSample {
    /// Which source produced the reading.
    pub source: TimeSourceKind,
    /// Wall-clock seconds claimed by the source.
    pub wall_time_secs: i64,
    /// Source-reported uncertainty in milliseconds.
    pub uncertainty_ms: u64,
    /// Authentication of the reading.
    pub attestation: SampleAttestation,
    /// Monotonic value when the reading was taken.
    pub mono_secs: u64,
    /// Boot identifier when the reading was taken.
    pub boot_id: u64,
}

impl TimeSample {
    /// An authenticated sample.
    pub fn authenticated(
        source: TimeSourceKind,
        wall_time_secs: i64,
        uncertainty_ms: u64,
        mono_secs: u64,
        boot_id: u64,
    ) -> Self {
        TimeSample {
            source,
            wall_time_secs,
            uncertainty_ms,
            attestation: SampleAttestation::Authenticated,
            mono_secs,
            boot_id,
        }
    }

    /// An unauthenticated sample (plain NTP or a local hint).
    pub fn unauthenticated(
        source: TimeSourceKind,
        wall_time_secs: i64,
        uncertainty_ms: u64,
        mono_secs: u64,
        boot_id: u64,
    ) -> Self {
        TimeSample {
            source,
            wall_time_secs,
            uncertainty_ms,
            attestation: SampleAttestation::Unauthenticated,
            mono_secs,
            boot_id,
        }
    }
}

/// Failure modes when admitting a time sample (all fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeSourceError {
    /// No samples were offered.
    NoSamples,
    /// Every sample was unauthenticated.
    NoAuthenticatedSource,
    /// A sample comes from a previous boot and cannot be trusted.
    BootMismatch {
        /// Boot identifier in the sample.
        sample_boot: u64,
        /// Current boot identifier.
        current_boot: u64,
    },
    /// A sample is older than the allowed age.
    SampleTooOld {
        /// Age in seconds.
        age_secs: i64,
        /// Configured maximum.
        max_age_secs: i64,
    },
    /// A sample would move time below the persisted floor.
    Rollback {
        /// Wall time claimed by the sample.
        wall_time_secs: i64,
        /// Persisted ratchet floor.
        floor_secs: i64,
    },
    /// A sample would jump further forward than a single source may.
    ForwardJump {
        /// Requested jump in seconds.
        jump_secs: i64,
        /// Configured maximum.
        max_jump_secs: i64,
    },
}

impl fmt::Display for TimeSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeSourceError::NoSamples => f.write_str("no time samples were offered"),
            TimeSourceError::NoAuthenticatedSource => {
                f.write_str("no authenticated time source is available")
            }
            TimeSourceError::BootMismatch {
                sample_boot,
                current_boot,
            } => write!(
                f,
                "time sample is from boot {sample_boot}, current boot is {current_boot}"
            ),
            TimeSourceError::SampleTooOld {
                age_secs,
                max_age_secs,
            } => write!(
                f,
                "time sample is {age_secs}s old (maximum {max_age_secs}s)"
            ),
            TimeSourceError::Rollback {
                wall_time_secs,
                floor_secs,
            } => write!(
                f,
                "time sample {wall_time_secs} is below the persisted floor {floor_secs}"
            ),
            TimeSourceError::ForwardJump {
                jump_secs,
                max_jump_secs,
            } => write!(
                f,
                "time sample jumps {jump_secs}s forward (maximum {max_jump_secs}s without quorum)"
            ),
        }
    }
}

impl std::error::Error for TimeSourceError {}

/// Select the best admissible sample from a set of readings.
///
/// A sample is admissible when it is authenticated, from the current boot, no
/// older than `max_sample_age_secs`, not below `floor_secs`, and no more than
/// `max_forward_jump_secs` ahead of the floor. Among admissible samples the
/// lowest uncertainty wins; ties break by source priority (gateway beacon,
/// GPS, NTP).
pub fn select_sample(
    samples: &[TimeSample],
    floor_secs: i64,
    max_forward_jump_secs: i64,
    mono_now_secs: u64,
    current_boot: u64,
    max_sample_age_secs: i64,
) -> Result<TimeSample, TimeSourceError> {
    if samples.is_empty() {
        return Err(TimeSourceError::NoSamples);
    }

    let mut best: Option<TimeSample> = None;
    let mut saw_authenticated = false;

    for sample in samples {
        if sample.attestation != SampleAttestation::Authenticated {
            continue;
        }
        saw_authenticated = true;

        if sample.boot_id != current_boot {
            return Err(TimeSourceError::BootMismatch {
                sample_boot: sample.boot_id,
                current_boot,
            });
        }
        if sample.mono_secs > mono_now_secs {
            return Err(TimeSourceError::SampleTooOld {
                age_secs: 0,
                max_age_secs: max_sample_age_secs,
            });
        }
        let age_secs = (mono_now_secs - sample.mono_secs) as i64;
        if age_secs > max_sample_age_secs {
            return Err(TimeSourceError::SampleTooOld {
                age_secs,
                max_age_secs: max_sample_age_secs,
            });
        }
        if sample.wall_time_secs < floor_secs {
            return Err(TimeSourceError::Rollback {
                wall_time_secs: sample.wall_time_secs,
                floor_secs,
            });
        }
        let jump_secs = sample.wall_time_secs.saturating_sub(floor_secs);
        if jump_secs > max_forward_jump_secs {
            return Err(TimeSourceError::ForwardJump {
                jump_secs,
                max_jump_secs: max_forward_jump_secs,
            });
        }

        let replace = match &best {
            None => true,
            Some(current) => {
                (sample.uncertainty_ms, std::cmp::Reverse(sample.source.priority()))
                    < (
                        current.uncertainty_ms,
                        std::cmp::Reverse(current.source.priority()),
                    )
            }
        };
        if replace {
            best = Some(sample.clone());
        }
    }

    if !saw_authenticated {
        return Err(TimeSourceError::NoAuthenticatedSource);
    }
    best.ok_or(TimeSourceError::NoSamples)
}

/// Documented drift bound for offline time confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftBound {
    /// Oscillator drift in parts per million.
    pub max_ppm: u32,
    /// Absolute uncertainty already present at the last anchor.
    pub max_absolute_ms: u64,
}

impl DriftBound {
    /// Uncertainty after `elapsed_secs` without an authenticated anchor.
    pub fn uncertainty_after(&self, elapsed_secs: i64) -> u64 {
        let elapsed = elapsed_secs.max(0) as u128;
        let drift_ms = elapsed * u128::from(self.max_ppm) / 1_000;
        self.max_absolute_ms
            .saturating_add(u64::try_from(drift_ms).unwrap_or(u64::MAX))
    }
}

impl Default for DriftBound {
    fn default() -> Self {
        DEFAULT_DRIFT
    }
}

/// Why a wall-clock reading has no authenticated or bounded confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnverifiedReason {
    /// The device rebooted and no new anchor has arrived.
    Rebooted,
    /// No authenticated source has ever been admitted.
    NoAuthenticatedSource,
    /// A rollback or invalid jump was detected.
    ClockAnomaly,
}

/// Confidence in the wall time carried by a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TimeConfidence {
    /// Backed by an authenticated source inside its uncertainty bound.
    Verified {
        /// Source of the anchor.
        source: TimeSourceKind,
        /// Reported uncertainty in milliseconds.
        uncertainty_ms: u64,
    },
    /// No authenticated source is reachable; the wall time is derived from the
    /// monotonic ratchet plus the documented [`DriftBound`].
    Offline {
        /// Seconds since the last authenticated anchor.
        elapsed_since_anchor_secs: i64,
        /// Bound on accumulated drift at that elapsed time, in milliseconds.
        drift_bound_ms: u64,
    },
    /// No trustworthy wall time: the record must not be used for a security
    /// decision without a challenge/freshness check.
    Unverified {
        /// Why confidence is absent.
        reason: UnverifiedReason,
    },
}

impl TimeConfidence {
    /// Stable marker string for audit records and exports.
    pub fn marker(&self) -> &'static str {
        match self {
            TimeConfidence::Verified { .. } => "verified",
            TimeConfidence::Offline { .. } => "offline",
            TimeConfidence::Unverified { .. } => "unverified",
        }
    }

    /// Whether the wall time may be treated as authenticated.
    pub fn is_verified(&self) -> bool {
        matches!(self, TimeConfidence::Verified { .. })
    }

    /// Whether the record carries a bounded offline confidence.
    pub fn is_offline_bounded(&self) -> bool {
        matches!(self, TimeConfidence::Offline { .. })
    }

    /// Bound on the wall-time error in milliseconds, if one exists.
    pub fn uncertainty_ms(&self) -> Option<u64> {
        match self {
            TimeConfidence::Verified { uncertainty_ms, .. } => Some(*uncertainty_ms),
            TimeConfidence::Offline { drift_bound_ms, .. } => Some(*drift_bound_ms),
            TimeConfidence::Unverified { .. } => None,
        }
    }
}

/// Domain-separated bytes signed for a [`TimeEvidence`] record.
fn evidence_signing_bytes(evidence: &TimeEvidence) -> Result<Vec<u8>, TimeEvidenceError> {
    let body = serde_json::to_vec(evidence).map_err(|_| TimeEvidenceError::Encoding)?;
    let digest = Sha256::digest(&body);
    let mut bytes = Vec::with_capacity(CONTEXT_TIME_EVIDENCE.len() + 1 + 32);
    bytes.extend_from_slice(CONTEXT_TIME_EVIDENCE.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

/// The time-confidence marker attached to offline records, exports, and audit
/// entries.
///
/// The evidence binds the wall time to the monotonic reading and the persisted
/// floor at capture time, so a verifier can tell that the record came from a
/// bounded offline estimate rather than an unchecked clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeEvidence {
    /// Wall-clock seconds recorded.
    pub wall_time_secs: i64,
    /// Monotonic seconds at capture.
    pub mono_secs: u64,
    /// Boot identifier at capture.
    pub boot_id: u64,
    /// Ratchet floor at capture (never decreases).
    pub ratchet_floor_secs: i64,
    /// Confidence marker.
    pub confidence: TimeConfidence,
}

impl TimeEvidence {
    /// Evidence backed by an authenticated source.
    pub fn verified(
        wall_time_secs: i64,
        mono_secs: u64,
        boot_id: u64,
        ratchet_floor_secs: i64,
        source: TimeSourceKind,
        uncertainty_ms: u64,
    ) -> Self {
        TimeEvidence {
            wall_time_secs,
            mono_secs,
            boot_id,
            ratchet_floor_secs,
            confidence: TimeConfidence::Verified {
                source,
                uncertainty_ms,
            },
        }
    }

    /// Evidence derived from the monotonic ratchet with no live source.
    pub fn offline(
        wall_time_secs: i64,
        mono_secs: u64,
        boot_id: u64,
        ratchet_floor_secs: i64,
        elapsed_since_anchor_secs: i64,
        drift: DriftBound,
    ) -> Self {
        TimeEvidence {
            wall_time_secs,
            mono_secs,
            boot_id,
            ratchet_floor_secs,
            confidence: TimeConfidence::Offline {
                elapsed_since_anchor_secs,
                drift_bound_ms: drift.uncertainty_after(elapsed_since_anchor_secs),
            },
        }
    }

    /// Evidence with no trustworthy wall time.
    pub fn unverified(
        wall_time_secs: i64,
        mono_secs: u64,
        boot_id: u64,
        ratchet_floor_secs: i64,
        reason: UnverifiedReason,
    ) -> Self {
        TimeEvidence {
            wall_time_secs,
            mono_secs,
            boot_id,
            ratchet_floor_secs,
            confidence: TimeConfidence::Unverified { reason },
        }
    }

    /// Sign this evidence with a device/export key.
    pub fn sign(&self, provider: &dyn KeyProvider) -> Result<SignedTimeEvidence, TimeEvidenceError> {
        let bytes = evidence_signing_bytes(self)?;
        let signature = provider
            .sign(&bytes)
            .map_err(|_| TimeEvidenceError::SignatureInvalid)?;
        Ok(SignedTimeEvidence {
            evidence: self.clone(),
            signer_did: provider.did().to_string(),
            signature,
        })
    }
}

/// A signed [`TimeEvidence`] record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTimeEvidence {
    /// The evidence that was signed.
    pub evidence: TimeEvidence,
    /// DID of the signer.
    pub signer_did: String,
    /// Signature over the domain-separated evidence bytes.
    pub signature: DeviceSignature,
}

impl SignedTimeEvidence {
    /// Verify the signature and that `signer_did` derives from `public_key`.
    pub fn verify(&self, public_key: &[u8]) -> Result<(), TimeEvidenceError> {
        let key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| TimeEvidenceError::InvalidPublicKey)?;
        if did_identity::derive_did(&key) != self.signer_did {
            return Err(TimeEvidenceError::SignerMismatch {
                signer_did: self.signer_did.clone(),
            });
        }
        let bytes = evidence_signing_bytes(&self.evidence)?;
        let DeviceSignature::Ed25519(signature) = &self.signature else {
            return Err(TimeEvidenceError::SignatureInvalid);
        };
        keypair::verify(&key, &bytes, &Ed25519Signature::from_bytes(*signature))
            .map_err(|_| TimeEvidenceError::SignatureInvalid)
    }

    /// The confidence marker carried by the evidence.
    pub fn confidence(&self) -> &TimeConfidence {
        &self.evidence.confidence
    }
}

/// Time-evidence failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeEvidenceError {
    /// The evidence body could not be encoded deterministically.
    Encoding,
    /// The supplied public key is not a 32-byte Ed25519 key.
    InvalidPublicKey,
    /// The signer DID does not derive from the supplied public key.
    SignerMismatch {
        /// DID claimed by the evidence.
        signer_did: String,
    },
    /// The signature did not verify over the evidence bytes.
    SignatureInvalid,
}

impl fmt::Display for TimeEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeEvidenceError::Encoding => f.write_str("time evidence could not be encoded"),
            TimeEvidenceError::InvalidPublicKey => {
                f.write_str("time evidence public key is not Ed25519")
            }
            TimeEvidenceError::SignerMismatch { signer_did } => {
                write!(f, "time evidence signer {signer_did} does not match the public key")
            }
            TimeEvidenceError::SignatureInvalid => {
                f.write_str("time evidence signature did not verify")
            }
        }
    }
}

impl std::error::Error for TimeEvidenceError {}

/// An approval with an authenticated expiry and the boot it was issued in.
///
/// Expiry is always evaluated against `now_est` from the ratchet, never the
/// wall clock, so setting the system clock backwards cannot revive it. The
/// boot binding handles the other direction: after a reboot the ratchet is
/// floored and cannot prove how much time elapsed, so a pre-reboot approval is
/// invalidated rather than silently revived. It must be re-issued under the
/// new boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalExpiry {
    /// Approval identifier (audit correlation).
    pub approval_id: String,
    /// Authenticated-time expiry (`now_est > expires_at_est` is expired).
    pub expires_at_est: i64,
    /// Boot identifier the approval was issued in.
    pub issued_boot_id: u64,
}

impl ApprovalExpiry {
    /// Whether the approval is numerically expired at this authenticated time.
    pub fn is_expired(&self, now_est: i64) -> bool {
        now_est > self.expires_at_est
    }

    /// Fail-closed check used before acting on an approval.
    ///
    /// Rejects when the authenticated time has passed the expiry, or when the
    /// device rebooted since the approval was issued (the ratchet cannot
    /// prove elapsed time across the reboot).
    pub fn check(&self, now_est: i64, current_boot_id: u64) -> Result<(), ApprovalRejection> {
        if self.is_expired(now_est) {
            return Err(ApprovalRejection::Expired(ApprovalExpired {
                approval_id: self.approval_id.clone(),
                expires_at_est: self.expires_at_est,
                now_est,
            }));
        }
        if self.issued_boot_id != current_boot_id {
            return Err(ApprovalRejection::InvalidatedByReboot {
                approval_id: self.approval_id.clone(),
                issued_boot_id: self.issued_boot_id,
                current_boot_id,
            });
        }
        Ok(())
    }
}

/// Returned when an approval has passed its authenticated expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalExpired {
    /// Approval identifier.
    pub approval_id: String,
    /// Expiry that was passed.
    pub expires_at_est: i64,
    /// Authenticated time at the check.
    pub now_est: i64,
}

impl fmt::Display for ApprovalExpired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "approval '{}' expired at {} (now_est {})",
            self.approval_id, self.expires_at_est, self.now_est
        )
    }
}

impl std::error::Error for ApprovalExpired {}

/// Why an approval may not be acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalRejection {
    /// Authenticated time passed the expiry.
    Expired(ApprovalExpired),
    /// The device rebooted since the approval was issued.
    InvalidatedByReboot {
        /// Approval identifier.
        approval_id: String,
        /// Boot the approval was issued in.
        issued_boot_id: u64,
        /// Boot observed at the check.
        current_boot_id: u64,
    },
}

impl fmt::Display for ApprovalRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalRejection::Expired(expired) => expired.fmt(f),
            ApprovalRejection::InvalidatedByReboot {
                approval_id,
                issued_boot_id,
                current_boot_id,
            } => write!(
                f,
                "approval '{approval_id}' was issued in boot {issued_boot_id} and cannot be used after reboot to boot {current_boot_id}"
            ),
        }
    }
}

impl std::error::Error for ApprovalRejection {}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::identity::file_key_provider::InMemoryKeyProvider;

    #[test]
    fn admitted_sample_is_authenticated_and_within_bounds() {
        let samples = vec![
            TimeSample::unauthenticated(TimeSourceKind::Ntp, 1_000, 5, 100, 7),
            TimeSample::authenticated(TimeSourceKind::Gps, 1_001, 40, 100, 7),
            TimeSample::authenticated(TimeSourceKind::GatewayBeacon, 1_000, 10, 100, 7),
        ];
        let selected =
            select_sample(&samples, 900, 300, 100, 7, 60).expect("select best sample");
        assert_eq!(selected.source, TimeSourceKind::GatewayBeacon);
        assert_eq!(selected.wall_time_secs, 1_000);
    }

    #[test]
    fn unauthenticated_only_sources_are_refused() {
        let samples = vec![TimeSample::unauthenticated(
            TimeSourceKind::Ntp,
            1_000,
            5,
            100,
            7,
        )];
        assert_eq!(
            select_sample(&samples, 900, 300, 100, 7, 60),
            Err(TimeSourceError::NoAuthenticatedSource)
        );
    }

    #[test]
    fn rollback_and_forward_jump_samples_are_rejected() {
        let old = TimeSample::authenticated(TimeSourceKind::GatewayBeacon, 800, 10, 100, 7);
        assert_eq!(
            select_sample(&[old], 900, 300, 100, 7, 60),
            Err(TimeSourceError::Rollback {
                wall_time_secs: 800,
                floor_secs: 900
            })
        );

        let far = TimeSample::authenticated(TimeSourceKind::Gps, 5_000, 10, 100, 7);
        assert_eq!(
            select_sample(&[far], 900, 300, 100, 7, 60),
            Err(TimeSourceError::ForwardJump {
                jump_secs: 4_100,
                max_jump_secs: 300
            })
        );
    }

    #[test]
    fn stale_and_previous_boot_samples_are_rejected() {
        let stale = TimeSample::authenticated(TimeSourceKind::Ntp, 1_000, 10, 10, 7);
        assert_eq!(
            select_sample(&[stale], 900, 300, 500, 7, 60),
            Err(TimeSourceError::SampleTooOld {
                age_secs: 490,
                max_age_secs: 60
            })
        );

        let previous_boot = TimeSample::authenticated(TimeSourceKind::Gps, 1_000, 10, 100, 6);
        assert_eq!(
            select_sample(&[previous_boot], 900, 300, 100, 7, 60),
            Err(TimeSourceError::BootMismatch {
                sample_boot: 6,
                current_boot: 7
            })
        );
    }

    #[test]
    fn drift_bound_grows_with_elapsed_time() {
        let drift = DriftBound::default();
        assert_eq!(drift.uncertainty_after(0), 250);
        assert_eq!(drift.uncertainty_after(1_000), 300); // 50 ppm * 1000 s = 50 ms
        assert_eq!(drift.uncertainty_after(86_400), 4_570); // +4_320 ms per day
    }

    #[test]
    fn offline_evidence_signs_verifies_and_carries_its_marker() {
        let provider = InMemoryKeyProvider::generate().expect("key");
        let evidence = TimeEvidence::offline(
            1_800_003_600,
            5_000,
            7,
            1_800_000_000,
            3_600,
            DriftBound::default(),
        );
        assert!(evidence.confidence.is_offline_bounded());
        assert_eq!(evidence.confidence.marker(), "offline");

        let signed = evidence.sign(&provider).expect("sign");
        signed
            .verify(&provider.public_key_bytes())
            .expect("verify with the signer key");

        // A different key cannot verify the record.
        let other = InMemoryKeyProvider::generate().expect("other");
        assert_eq!(
            signed.verify(&other.public_key_bytes()),
            Err(TimeEvidenceError::SignerMismatch {
                signer_did: provider.did().to_string()
            })
        );
    }

    #[test]
    fn tampered_confidence_breaks_the_evidence_signature() {
        let provider = InMemoryKeyProvider::generate().expect("key");
        let evidence = TimeEvidence::verified(1_800_000_000, 5_000, 7, 1_800_000_000, TimeSourceKind::GatewayBeacon, 10);
        let mut signed = evidence.sign(&provider).expect("sign");
        signed.evidence.wall_time_secs += 86_400;
        assert_eq!(
            signed.verify(&provider.public_key_bytes()),
            Err(TimeEvidenceError::SignatureInvalid)
        );
    }

    #[test]
    fn approval_expiry_is_strict_and_fails_closed() {
        let approval = ApprovalExpiry {
            approval_id: "APR-7".to_string(),
            expires_at_est: 1_800_000_060,
            issued_boot_id: 7,
        };
        assert!(approval.check(1_800_000_060, 7).is_ok());
        assert!(matches!(
            approval.check(1_800_000_061, 7),
            Err(ApprovalRejection::Expired(_))
        ));
        assert!(matches!(
            approval.check(1_700_000_000, 8),
            Err(ApprovalRejection::InvalidatedByReboot { .. })
        ));
    }
}
