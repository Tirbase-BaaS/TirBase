// SPDX-License-Identifier: AGPL-3.0-only

//! Errors raised by the access-control crate.

use std::fmt;

use tirbase_venue::{ReaderId, VenueError};

use crate::credential::{CardholderId, CredentialId, ReaderKeyId};
use crate::crypto::CryptoError;
#[cfg(feature = "desfire")]
use crate::desfire::DesfireError;
#[cfg(feature = "osdp")]
use crate::osdp::OsdpError;
#[cfg(feature = "wiegand")]
use crate::wiegand::WiegandError;

/// A rejected access-control operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessError {
    /// An identifier was empty, oversized or contained control characters.
    InvalidIdentifier(&'static str),
    /// A cryptographic primitive rejected its input.
    Crypto(CryptoError),
    /// An OSDP frame or secure channel operation failed.
    #[cfg(feature = "osdp")]
    Osdp(OsdpError),
    /// A Wiegand capture failed decoding.
    #[cfg(feature = "wiegand")]
    Wiegand(WiegandError),
    /// A DESFire exchange failed.
    #[cfg(feature = "desfire")]
    Desfire(DesfireError),
    /// The venue domain model rejected the resolution.
    Venue(VenueError),
    /// No credential is registered for the presented card material.
    UnknownCredential(String),
    /// The card material is already registered to another credential.
    DuplicateCredential(String),
    /// The credential is outside its validity window.
    CredentialExpired,
    /// The credential is not valid yet.
    CredentialNotYetValid,
    /// The credential has been revoked.
    CredentialRevoked(CredentialId),
    /// The cardholder is unknown or inactive.
    UnknownCardholder(CardholderId),
    /// The reader has a latched tamper and refuses credentials.
    ReaderTampered(ReaderId),
    /// The reader is offline and holds no matching cached grant.
    NoCachedGrant,
    /// The reader is offline.
    ReaderOffline,
    /// The key handle is unknown.
    UnknownKey(ReaderKeyId),
    /// A revocation delta would roll the version backwards.
    RevocationRegression { current: u64, offered: u64 },
    /// A revocation delta does not build on the current version.
    RevocationOutOfOrder { expected: u64, offered: u64 },
    /// A persisted cache could not be read.
    CacheCorrupt(&'static str),
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessError::InvalidIdentifier(what) => write!(f, "invalid identifier: {what}"),
            AccessError::Crypto(error) => write!(f, "crypto: {error}"),
            #[cfg(feature = "osdp")]
            AccessError::Osdp(error) => write!(f, "osdp: {error}"),
            #[cfg(feature = "wiegand")]
            AccessError::Wiegand(error) => write!(f, "wiegand: {error}"),
            #[cfg(feature = "desfire")]
            AccessError::Desfire(error) => write!(f, "desfire: {error}"),
            AccessError::Venue(error) => write!(f, "venue: {error}"),
            AccessError::UnknownCredential(fingerprint) => {
                write!(f, "unknown credential fingerprint: {fingerprint}")
            }
            AccessError::DuplicateCredential(fingerprint) => {
                write!(f, "credential already registered: {fingerprint}")
            }
            AccessError::CredentialExpired => write!(f, "credential has expired"),
            AccessError::CredentialNotYetValid => write!(f, "credential is not valid yet"),
            AccessError::CredentialRevoked(id) => write!(f, "credential revoked: {id}"),
            AccessError::UnknownCardholder(id) => write!(f, "unknown cardholder: {id}"),
            AccessError::ReaderTampered(id) => write!(f, "reader {id} has a latched tamper"),
            AccessError::NoCachedGrant => {
                write!(f, "reader is offline and holds no cached grant")
            }
            AccessError::ReaderOffline => write!(f, "reader is offline"),
            AccessError::UnknownKey(id) => write!(f, "unknown reader key handle: {id}"),
            AccessError::RevocationRegression { current, offered } => write!(
                f,
                "revocation version would regress from {current} to {offered}"
            ),
            AccessError::RevocationOutOfOrder { expected, offered } => write!(
                f,
                "revocation delta builds on {offered}, current version is {expected}"
            ),
            AccessError::CacheCorrupt(reason) => write!(f, "offline cache corrupt: {reason}"),
        }
    }
}

impl std::error::Error for AccessError {}

impl From<CryptoError> for AccessError {
    fn from(error: CryptoError) -> Self {
        AccessError::Crypto(error)
    }
}

#[cfg(feature = "osdp")]
impl From<OsdpError> for AccessError {
    fn from(error: OsdpError) -> Self {
        AccessError::Osdp(error)
    }
}

#[cfg(feature = "wiegand")]
impl From<WiegandError> for AccessError {
    fn from(error: WiegandError) -> Self {
        AccessError::Wiegand(error)
    }
}

#[cfg(feature = "desfire")]
impl From<DesfireError> for AccessError {
    fn from(error: DesfireError) -> Self {
        AccessError::Desfire(error)
    }
}

impl From<VenueError> for AccessError {
    fn from(error: VenueError) -> Self {
        AccessError::Venue(error)
    }
}
