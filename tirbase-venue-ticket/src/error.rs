// SPDX-License-Identifier: AGPL-3.0-only

//! Errors from construction, encoding and signing.

use std::fmt;

/// A ticket kernel input error (not a validation decision).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TicketError {
    /// An identifier or digest was empty, oversized or contained control bytes.
    InvalidIdentifier(&'static str),
    /// A payload was structurally invalid or used an unsupported version.
    InvalidEncoding(&'static str),
    /// A configuration value was outside its documented bound.
    InvalidConfig(&'static str),
    /// A key id was already registered.
    DuplicateIssuerKey { key_id: String },
    /// A public key was not a valid Ed25519 point encoding.
    InvalidPublicKey,
    /// A signature was not 64 bytes encoded as 128 hex characters.
    InvalidSignatureEncoding,
    /// No active issuer key exists.
    NoActiveKey,
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TicketError::InvalidIdentifier(what) => write!(f, "invalid identifier: {what}"),
            TicketError::InvalidEncoding(reason) => write!(f, "invalid ticket encoding: {reason}"),
            TicketError::InvalidConfig(reason) => write!(f, "invalid configuration: {reason}"),
            TicketError::DuplicateIssuerKey { key_id } => {
                write!(f, "issuer key already registered: {key_id}")
            }
            TicketError::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            TicketError::InvalidSignatureEncoding => write!(f, "invalid signature encoding"),
            TicketError::NoActiveKey => write!(f, "no active issuer key"),
        }
    }
}

impl std::error::Error for TicketError {}
