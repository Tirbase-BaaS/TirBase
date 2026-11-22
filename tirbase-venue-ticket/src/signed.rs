// SPDX-License-Identifier: AGPL-3.0-only

//! Signed ticket envelope and signed revocation lists.

use serde::{Deserialize, Serialize};
use tirbase_venue::TicketId;

use crate::decision::Denial;
use crate::error::TicketError;
use crate::keys::{IssuerKeyRing, TicketSigner};
use crate::payload::{push_str, TicketPayload, REVOCATION_DOMAIN};

/// A signed ticket payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTicket {
    pub payload: TicketPayload,
    pub key_id: String,
    /// Hex-encoded Ed25519 signature over [`TicketPayload::signing_bytes`].
    pub signature: String,
}

impl SignedTicket {
    /// Sign a payload with a custodian-backed signer.
    pub fn sign(payload: TicketPayload, signer: &dyn TicketSigner) -> Result<Self, TicketError> {
        payload.check_shape()?;
        let message = payload.signing_bytes(signer.key_id())?;
        let signature = signer.sign(&message);
        Ok(Self {
            payload,
            key_id: signer.key_id().to_owned(),
            signature: hex::encode(signature),
        })
    }

    /// Verify the issuer signature and key state at `at_utc_us`.
    ///
    /// This does not check scope, time or revocation; the validator does that.
    pub fn verify_signature(&self, ring: &IssuerKeyRing, at_utc_us: i64) -> Result<(), Denial> {
        let message = self
            .payload
            .signing_bytes(&self.key_id)
            .map_err(|_| Denial::Malformed("payload encoding"))?;
        ring.verify(&self.key_id, &message, &self.signature, at_utc_us)
    }

    pub fn to_json(&self) -> Result<String, TicketError> {
        serde_json::to_string(self).map_err(|_| TicketError::InvalidEncoding("serialize failed"))
    }

    pub fn from_json(json: &str) -> Result<Self, TicketError> {
        let ticket: Self = serde_json::from_str(json)
            .map_err(|_| TicketError::InvalidEncoding("parse failed"))?;
        ticket.payload.check_shape()?;
        Ok(ticket)
    }
}

/// A revocation list, distributed and signed by the issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketRevocationList {
    /// Monotonic list version.
    pub version: u64,
    pub issued_at_utc_us: i64,
    /// After this instant the list must not be trusted.
    pub expires_at_utc_us: i64,
    pub tickets: Vec<TicketId>,
}

impl TicketRevocationList {
    /// Build a list. The expiry must be after the issue time.
    pub fn new(
        version: u64,
        issued_at_utc_us: i64,
        expires_at_utc_us: i64,
        mut tickets: Vec<TicketId>,
    ) -> Result<Self, TicketError> {
        if expires_at_utc_us <= issued_at_utc_us {
            return Err(TicketError::InvalidConfig(
                "revocation list expiry must be after issue time",
            ));
        }
        tickets.sort();
        tickets.dedup();
        Ok(Self {
            version,
            issued_at_utc_us,
            expires_at_utc_us,
            tickets,
        })
    }

    pub fn is_revoked(&self, ticket_id: &TicketId) -> bool {
        // A list may arrive from storage in any order, so do not rely on the
        // sorted order `new` establishes.
        self.tickets.iter().any(|entry| entry == ticket_id)
    }

    pub fn len(&self) -> usize {
        self.tickets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }

    /// Deterministic bytes covered by the list signature.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, TicketError> {
        let mut out = Vec::with_capacity(32 + key_id.len() + self.tickets.len() * 16);
        out.extend_from_slice(REVOCATION_DOMAIN.as_bytes());
        out.push(0);
        push_str(&mut out, key_id)?;
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.issued_at_utc_us.to_le_bytes());
        out.extend_from_slice(&self.expires_at_utc_us.to_le_bytes());
        out.extend_from_slice(&(self.tickets.len() as u32).to_le_bytes());
        for ticket in &self.tickets {
            push_str(&mut out, ticket.as_str())?;
        }
        Ok(out)
    }
}

/// A signed revocation list as distributed to readers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocationList {
    pub list: TicketRevocationList,
    pub key_id: String,
    pub signature: String,
}

impl SignedRevocationList {
    /// Sign a list with the issuer's signer.
    pub fn sign(
        list: TicketRevocationList,
        signer: &dyn TicketSigner,
    ) -> Result<Self, TicketError> {
        let message = list.signing_bytes(signer.key_id())?;
        Ok(Self {
            list,
            key_id: signer.key_id().to_owned(),
            signature: hex::encode(signer.sign(&message)),
        })
    }

    /// Verify the list's own signature and key state.
    pub fn verify(&self, ring: &IssuerKeyRing, at_utc_us: i64) -> Result<(), Denial> {
        let message = self
            .list
            .signing_bytes(&self.key_id)
            .map_err(|_| Denial::Malformed("revocation list encoding"))?;
        ring.verify(&self.key_id, &message, &self.signature, at_utc_us)
            .map_err(|_| Denial::RevocationListSignature)
    }

    pub fn to_json(&self) -> Result<String, TicketError> {
        serde_json::to_string(self).map_err(|_| TicketError::InvalidEncoding("serialize failed"))
    }

    pub fn from_json(json: &str) -> Result<Self, TicketError> {
        serde_json::from_str(json).map_err(|_| TicketError::InvalidEncoding("parse failed"))
    }
}
