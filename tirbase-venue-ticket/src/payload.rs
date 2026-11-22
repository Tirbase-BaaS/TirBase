// SPDX-License-Identifier: AGPL-3.0-only

//! Ticket payload, venue scope, holder binding and canonical encoding.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, TicketId, VenueId, ZoneId};

use crate::error::TicketError;

/// Current payload version.
pub const TICKET_VERSION: u8 = 1;
/// Domain separator for ticket signatures.
pub const TICKET_DOMAIN: &str = "TirBase/v1/VenueTicket";
/// Domain separator for revocation-list signatures.
pub const REVOCATION_DOMAIN: &str = "TirBase/v1/VenueTicketRevocation";

/// Maximum identifier length, in bytes.
pub const MAX_ID_LEN: usize = 128;

/// Identifies an event (a match, concert, session) inside a venue's calendar.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EventId(String);

impl EventId {
    pub fn new(value: impl Into<String>) -> Result<Self, TicketError> {
        let value = value.into();
        validate_id(&value, "event id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventId {
    type Err = TicketError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn validate_id(value: &str, what: &'static str) -> Result<(), TicketError> {
    if value.is_empty() || value.len() > MAX_ID_LEN || value.chars().any(char::is_control) {
        return Err(TicketError::InvalidIdentifier(what));
    }
    Ok(())
}

/// Where a ticket admits its holder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueScope {
    pub event_id: EventId,
    pub venue_id: VenueId,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
}

impl VenueScope {
    pub fn new(
        event_id: EventId,
        venue_id: VenueId,
        gate_id: GateId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            event_id,
            venue_id,
            gate_id,
            zone_id,
        }
    }

    fn push_canonical(&self, out: &mut Vec<u8>) -> Result<(), TicketError> {
        push_str(out, self.event_id.as_str())?;
        push_str(out, self.venue_id.as_str())?;
        push_str(out, self.gate_id.as_str())?;
        push_str(out, self.zone_id.as_str())?;
        Ok(())
    }
}

/// What a holder binding is derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    /// Fingerprint of the holder's access credential (ST-03).
    CredentialFingerprint,
    /// One-way digest of a biometric template; the template is never stored.
    BiometricDigest,
    /// Pseudonymous wallet subject.
    WalletSubject,
}

impl HolderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HolderKind::CredentialFingerprint => "credential_fingerprint",
            HolderKind::BiometricDigest => "biometric_digest",
            HolderKind::WalletSubject => "wallet_subject",
        }
    }

    fn code(self) -> u8 {
        match self {
            HolderKind::CredentialFingerprint => 1,
            HolderKind::BiometricDigest => 2,
            HolderKind::WalletSubject => 3,
        }
    }

}

/// Proof that a ticket belongs to a particular holder.
///
/// Only a digest is carried: the credential, biometric or wallet reference
/// itself never appears in the ticket.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HolderBinding {
    pub kind: HolderKind,
    pub digest: String,
}

impl HolderBinding {
    /// Build a binding, rejecting an empty or over-long digest.
    pub fn new(kind: HolderKind, digest: impl Into<String>) -> Result<Self, TicketError> {
        let digest = digest.into();
        if digest.is_empty()
            || digest.len() > MAX_ID_LEN
            || digest.chars().any(char::is_control)
        {
            return Err(TicketError::InvalidIdentifier("holder digest"));
        }
        Ok(Self { kind, digest })
    }
}

/// The signed part of a venue ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketPayload {
    pub version: u8,
    pub ticket_id: TicketId,
    pub scope: VenueScope,
    /// Inclusive start of validity, UTC microseconds.
    pub valid_from_utc_us: i64,
    /// Exclusive end of validity, UTC microseconds.
    pub valid_until_utc_us: i64,
    /// Per-ticket nonce; a second presentation of the same value is a replay.
    pub nonce: u64,
    /// Present when the issuer bound the ticket to a holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<HolderBinding>,
}

impl TicketPayload {
    /// Build a payload and validate its shape.
    pub fn new(
        ticket_id: TicketId,
        scope: VenueScope,
        valid_from_utc_us: i64,
        valid_until_utc_us: i64,
        nonce: u64,
    ) -> Result<Self, TicketError> {
        let payload = Self {
            version: TICKET_VERSION,
            ticket_id,
            scope,
            valid_from_utc_us,
            valid_until_utc_us,
            nonce,
            holder: None,
        };
        payload.check_shape()?;
        Ok(payload)
    }

    /// Bind the ticket to a holder.
    pub fn with_holder(mut self, holder: HolderBinding) -> Self {
        self.holder = Some(holder);
        self
    }

    /// True when `at_utc_us` is inside `[valid_from, valid_until)`.
    pub fn is_valid_at(&self, at_utc_us: i64) -> bool {
        at_utc_us >= self.valid_from_utc_us && at_utc_us < self.valid_until_utc_us
    }

    /// Deterministic, allocation-stable encoding of the payload.
    ///
    /// Field order, integer width and length prefixes are fixed here so a
    /// signature covers exactly the bytes this function produces.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TicketError> {
        let mut out = Vec::with_capacity(128);
        out.push(self.version);
        push_str(&mut out, self.ticket_id.as_str())?;
        self.scope.push_canonical(&mut out)?;
        out.extend_from_slice(&self.valid_from_utc_us.to_le_bytes());
        out.extend_from_slice(&self.valid_until_utc_us.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        match &self.holder {
            None => out.push(0),
            Some(binding) => {
                out.push(1);
                out.push(binding.kind.code());
                push_str(&mut out, &binding.digest)?;
            }
        }
        Ok(out)
    }

    /// Bytes covered by the issuer signature, including the key id and domain.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, TicketError> {
        let mut out = Vec::with_capacity(24 + key_id.len() + 128);
        out.extend_from_slice(TICKET_DOMAIN.as_bytes());
        out.push(0);
        push_str(&mut out, key_id)?;
        out.extend_from_slice(&self.canonical_bytes()?);
        Ok(out)
    }

    /// Stable key for the anti-replay store: one signed ticket, one entry.
    pub fn replay_key(&self) -> String {
        format!("{}#{}", self.ticket_id, self.nonce)
    }

    /// Structural validation, independent of the verification context.
    pub fn check_shape(&self) -> Result<(), TicketError> {
        if self.version != TICKET_VERSION {
            return Err(TicketError::InvalidEncoding("unsupported ticket version"));
        }
        validate_id(self.ticket_id.as_str(), "ticket id")?;
        validate_id(self.scope.event_id.as_str(), "event id")?;
        validate_id(self.scope.venue_id.as_str(), "venue id")?;
        validate_id(self.scope.gate_id.as_str(), "gate id")?;
        validate_id(self.scope.zone_id.as_str(), "zone id")?;
        if self.valid_until_utc_us <= self.valid_from_utc_us {
            return Err(TicketError::InvalidEncoding("validity window is empty"));
        }
        if let Some(holder) = &self.holder {
            HolderBinding::new(holder.kind, holder.digest.clone())?;
        }
        Ok(())
    }
}

pub(crate) fn push_str(out: &mut Vec<u8>, value: &str) -> Result<(), TicketError> {
    if value.len() > u16::MAX as usize {
        return Err(TicketError::InvalidEncoding("string too long"));
    }
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
