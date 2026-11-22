// SPDX-License-Identifier: AGPL-3.0-only

//! Credential and cardholder mapping.
//!
//! A credential is stored as a **fingerprint** of the card material plus the
//! ticket type it grants. Raw card identifiers are used only long enough to
//! compute the fingerprint; reader keys are never stored at all — a
//! [`KeyHandle`] records a key id, its purpose and a one-way fingerprint.

use std::collections::BTreeMap;
use std::fmt;

use tirbase_venue::TicketTypeId;

use crate::crypto::{digest_hex, AesKey};
use crate::error::AccessError;
pub use crate::ids::{CardholderId, CredentialId, ReaderKeyId};

/// Fingerprint domain for card material.
const CREDENTIAL_DOMAIN: &str = "TirBase/v1/CredentialMaterial";
/// Fingerprint domain for reader key handles.
const KEY_DOMAIN: &str = "TirBase/v1/ReaderKey";

/// Which reader produced a credential presentation.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Card data delivered over an OSDP secure channel.
    Osdp,
    /// Wiegand pulse capture, with its bit length.
    Wiegand { bits: u8 },
    /// MIFARE DESFire EV2/EV3 application.
    Desfire,
}

impl CredentialSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialSource::Osdp => "osdp",
            CredentialSource::Wiegand { .. } => "wiegand",
            CredentialSource::Desfire => "desfire",
        }
    }

    /// Source discriminator mixed into the fingerprint, so the same bytes from
    /// two different readers never share an identity.
    fn digest_domain(&self) -> String {
        match self {
            CredentialSource::Wiegand { bits } => format!("{CREDENTIAL_DOMAIN}/wiegand/{bits}"),
            other => format!("{CREDENTIAL_DOMAIN}/{}", other.as_str()),
        }
    }
}

/// One card presented at a reader, before it is mapped to a credential.
///
/// `material` is the card identifier (UID, Wiegand payload) — never a key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresentedCredential {
    pub source: CredentialSource,
    pub material: Vec<u8>,
}

impl PresentedCredential {
    pub fn new(source: CredentialSource, material: impl Into<Vec<u8>>) -> Self {
        Self {
            source,
            material: material.into(),
        }
    }

    /// Fingerprint of the presented material under its source domain.
    pub fn fingerprint(&self) -> String {
        digest_hex(&self.source.digest_domain(), &self.material)
    }
}

/// A registered credential, keyed by card-material fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub id: CredentialId,
    pub holder_id: CardholderId,
    /// ST-01 ticket type this credential is allowed to present.
    pub ticket_type_id: TicketTypeId,
    pub source: CredentialSource,
    /// Hex SHA-256 of the card material. The material itself is not stored.
    pub fingerprint: String,
    pub valid_from_utc_us: Option<i64>,
    pub valid_until_utc_us: Option<i64>,
}

impl Credential {
    fn is_valid_at(&self, ts_utc_us: i64) -> Result<(), AccessError> {
        if let Some(from) = self.valid_from_utc_us {
            if ts_utc_us < from {
                return Err(AccessError::CredentialNotYetValid);
            }
        }
        if let Some(until) = self.valid_until_utc_us {
            if ts_utc_us >= until {
                return Err(AccessError::CredentialExpired);
            }
        }
        Ok(())
    }
}

/// A person who may hold credentials.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cardholder {
    pub id: CardholderId,
    pub name: String,
    pub active: bool,
}

/// Credential and cardholder directory.
///
/// Cards are looked up by fingerprint, so a lost card cannot be recovered from
/// the registry and an audit log never contains card numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialRegistry {
    holders: BTreeMap<CardholderId, Cardholder>,
    by_fingerprint: BTreeMap<String, Credential>,
}

impl CredentialRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cardholder. Names must be non-empty.
    pub fn add_holder(&mut self, id: CardholderId, name: impl Into<String>) -> Result<(), AccessError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(AccessError::InvalidIdentifier("cardholder name"));
        }
        if self.holders.contains_key(&id) {
            return Err(AccessError::InvalidIdentifier("duplicate cardholder id"));
        }
        self.holders.insert(
            id.clone(),
            Cardholder {
                id,
                name,
                active: true,
            },
        );
        Ok(())
    }

    pub fn set_holder_active(&mut self, id: &CardholderId, active: bool) -> Result<(), AccessError> {
        let holder = self
            .holders
            .get_mut(id)
            .ok_or_else(|| AccessError::UnknownCardholder(id.clone()))?;
        holder.active = active;
        Ok(())
    }

    pub fn holder(&self, id: &CardholderId) -> Option<&Cardholder> {
        self.holders.get(id)
    }

    pub fn credentials(&self) -> impl Iterator<Item = &Credential> {
        self.by_fingerprint.values()
    }

    pub fn get(&self, id: &CredentialId) -> Option<&Credential> {
        self.by_fingerprint.values().find(|credential| &credential.id == id)
    }

    /// Register a card. The credential id is derived from the fingerprint so
    /// re-registering the same card is detected rather than duplicated.
    pub fn register(
        &mut self,
        holder_id: CardholderId,
        ticket_type_id: TicketTypeId,
        source: CredentialSource,
        material: &[u8],
    ) -> Result<Credential, AccessError> {
        if !self.holders.contains_key(&holder_id) {
            return Err(AccessError::UnknownCardholder(holder_id));
        }
        if material.is_empty() {
            return Err(AccessError::InvalidIdentifier("credential material"));
        }
        let presented = PresentedCredential::new(source.clone(), material.to_vec());
        let fingerprint = presented.fingerprint();
        if self.by_fingerprint.contains_key(&fingerprint) {
            return Err(AccessError::DuplicateCredential(fingerprint));
        }
        let id = CredentialId::new(format!("cred-{}", &fingerprint[..16]))?;
        let credential = Credential {
            id,
            holder_id,
            ticket_type_id,
            source,
            fingerprint: fingerprint.clone(),
            valid_from_utc_us: None,
            valid_until_utc_us: None,
        };
        self.by_fingerprint.insert(fingerprint, credential.clone());
        Ok(credential)
    }

    /// Look up a presented card. Returns `None` for an unregistered card.
    pub fn lookup(&self, presented: &PresentedCredential) -> Option<&Credential> {
        self.by_fingerprint.get(&presented.fingerprint())
    }

    /// Look up by fingerprint, for cache and audit paths.
    pub fn lookup_fingerprint(&self, fingerprint: &str) -> Option<&Credential> {
        self.by_fingerprint.get(fingerprint)
    }

    /// Check the credential and cardholder are usable at `ts_utc_us`.
    pub fn validate(
        &self,
        presented: &PresentedCredential,
        ts_utc_us: i64,
    ) -> Result<&Credential, AccessError> {
        let credential = self
            .lookup(presented)
            .ok_or_else(|| AccessError::UnknownCredential(presented.fingerprint()))?;
        credential.is_valid_at(ts_utc_us)?;
        let holder = self
            .holders
            .get(&credential.holder_id)
            .ok_or_else(|| AccessError::UnknownCardholder(credential.holder_id.clone()))?;
        if !holder.active {
            return Err(AccessError::UnknownCardholder(credential.holder_id.clone()));
        }
        Ok(credential)
    }
}

/// What a reader key is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// OSDP secure channel base key (SCBK).
    OsdpSecureChannel,
    /// DESFire application authentication key.
    DesfireApplication,
    /// DESFire file read key.
    DesfireFile,
}

impl KeyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyPurpose::OsdpSecureChannel => "osdp_secure_channel",
            KeyPurpose::DesfireApplication => "desfire_application",
            KeyPurpose::DesfireFile => "desfire_file",
        }
    }
}

/// A reference to a reader key: identity and fingerprint, never the key.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyHandle {
    pub key_id: ReaderKeyId,
    pub purpose: KeyPurpose,
    /// Hex SHA-256 of the key material.
    pub fingerprint: String,
}

impl fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHandle")
            .field("key_id", &self.key_id)
            .field("purpose", &self.purpose)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl KeyHandle {
    /// Derive a handle for a key without retaining the key bytes.
    pub fn from_key(key_id: ReaderKeyId, purpose: KeyPurpose, key: &AesKey) -> Self {
        Self {
            key_id,
            purpose,
            fingerprint: digest_hex(
                &format!("{KEY_DOMAIN}/{}", purpose.as_str()),
                key.bytes(),
            ),
        }
    }
}

/// Registry of key handles, so audit records can name a key without holding it.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyRegistry {
    handles: BTreeMap<ReaderKeyId, KeyHandle>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a key handle. The key itself is dropped by the caller.
    pub fn register(&mut self, handle: KeyHandle) -> Result<(), AccessError> {
        if self.handles.contains_key(&handle.key_id) {
            return Err(AccessError::UnknownKey(handle.key_id));
        }
        self.handles.insert(handle.key_id.clone(), handle);
        Ok(())
    }

    pub fn get(&self, id: &ReaderKeyId) -> Option<&KeyHandle> {
        self.handles.get(id)
    }

    pub fn handles(&self) -> impl Iterator<Item = &KeyHandle> {
        self.handles.values()
    }

    /// True when a key with this purpose and material is already registered.
    pub fn contains_fingerprint(&self, purpose: KeyPurpose, fingerprint: &str) -> bool {
        self.handles
            .values()
            .any(|handle| handle.purpose == purpose && handle.fingerprint == fingerprint)
    }
}
