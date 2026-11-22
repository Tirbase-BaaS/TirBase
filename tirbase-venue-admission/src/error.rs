// SPDX-License-Identifier: AGPL-3.0-only

//! Errors for the replay store and revocation deltas.

use std::fmt;

/// Replay-store configuration or persistence error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    InvalidConfig(&'static str),
    CorruptStore(&'static str),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::InvalidConfig(reason) => write!(f, "invalid replay config: {reason}"),
            ReplayError::CorruptStore(reason) => write!(f, "corrupt replay store: {reason}"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Why a revocation delta or ledger operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationError {
    /// The delta is structurally invalid.
    InvalidDelta(&'static str),
    /// A signed delta could not be encoded deterministically.
    InvalidEncoding(&'static str),
    /// The delta's own expiry has passed at verification time.
    Expired { expires_at_utc_us: i64 },
    /// A signature did not verify under its key.
    Signature { key_id: String },
    /// The same key signed twice.
    DuplicateSigner { key_id: String },
    /// Fewer valid signatures than the required M-of-N threshold.
    InsufficientApprovals { provided: u32, required: u32 },
    /// An emergency delta's lifetime exceeds the policy maximum.
    EmergencyTtlTooLong { ttl_us: i64 },
    /// The delta does not chain onto the applied version.
    Gap { expected: u64, offered: u64 },
    /// The pending offline queue is full.
    PendingFull { capacity: usize },
    /// A queued version arrived twice with different contents.
    ConflictingVersion { version: u64 },
    /// Policy configuration is invalid.
    InvalidConfig(&'static str),
    /// A persisted ledger or guard could not be read.
    CorruptStore(&'static str),
}

impl fmt::Display for RevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RevocationError::InvalidDelta(reason) => write!(f, "invalid revocation delta: {reason}"),
            RevocationError::InvalidEncoding(reason) => {
                write!(f, "cannot encode revocation delta: {reason}")
            }
            RevocationError::Expired { expires_at_utc_us } => {
                write!(f, "revocation delta expired at {expires_at_utc_us}")
            }
            RevocationError::Signature { key_id } => {
                write!(f, "revocation delta signature does not verify for {key_id}")
            }
            RevocationError::DuplicateSigner { key_id } => {
                write!(f, "revocation delta was signed twice by {key_id}")
            }
            RevocationError::InsufficientApprovals { provided, required } => write!(
                f,
                "revocation delta has {provided} approval(s), {required} required"
            ),
            RevocationError::EmergencyTtlTooLong { ttl_us } => {
                write!(f, "emergency revocation delta lasts {ttl_us} us, over policy")
            }
            RevocationError::Gap { expected, offered } => {
                write!(f, "delta builds on v{offered}, ledger is at v{expected}")
            }
            RevocationError::PendingFull { capacity } => {
                write!(f, "pending revocation queue is full ({capacity})")
            }
            RevocationError::ConflictingVersion { version } => {
                write!(f, "a different delta for v{version} is already queued")
            }
            RevocationError::InvalidConfig(reason) => {
                write!(f, "invalid revocation policy: {reason}")
            }
            RevocationError::CorruptStore(reason) => write!(f, "corrupt revocation store: {reason}"),
        }
    }
}

impl std::error::Error for RevocationError {}
