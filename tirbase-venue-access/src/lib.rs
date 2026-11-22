// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-access — Venue access-control credential ingest (ST-03)
//!
//! Bridges physical credentials into the ST-01 venue model:
//!
//! * OSDP reader links with an AES secure channel (SCS12/SCS13), polling,
//!   local status and tamper reporting;
//! * Wiegand captures decoded with parity and timing validation;
//! * MIFARE DESFire EV2/EV3 AES authentication and authenticated file read;
//! * credential/cardholder mapping that stores only card fingerprints, and key
//!   handles that store only a key id and a one-way fingerprint;
//! * reader health with a tamper latch, an offline grant cache and monotonic
//!   revocation versions that survive a restart;
//! * deterministic simulators, recorded frames and fuzz targets for every
//!   decoder.
//!
//! Depends on ST-01 (`tirbase-venue`) for topology, ticket types, access
//! policies, anti-passback and capacity. Device I/O belongs to the caller: this
//! crate decodes and decides, it does not open sockets or serial ports.
//!
//! # Reading, never writing
//!
//! DESFire support is limited to authentication and `ReadData`; no write,
//! delete, key-change or configuration command is implemented. OSDP support
//! has no LED, buzzer, output or mode command. Both protocols reject frames
//! that would only be meaningful on a write path.

#![forbid(unsafe_code)]

pub mod credential;
pub mod crypto;
#[cfg(feature = "desfire")]
pub mod desfire;
pub mod error;
pub mod ids;
#[cfg(feature = "osdp")]
pub mod osdp;
pub mod reader;
pub mod revocation;
pub mod sim;
#[cfg(feature = "wiegand")]
pub mod wiegand;

pub use credential::{
    Cardholder, Credential, CredentialRegistry, CredentialSource, KeyHandle, KeyPurpose,
    KeyRegistry, PresentedCredential,
};
pub use crypto::{AesKey, CryptoError};
#[cfg(feature = "desfire")]
pub use desfire::{DesfireError, DesfireReader, DesfireSession};
pub use error::AccessError;
pub use ids::{CardholderId, CredentialId, ReaderKeyId};
#[cfg(feature = "osdp")]
pub use osdp::{
    CardRead, OsdpError, OsdpFrame, OsdpPoller, OsdpReply, PdStatus, Scs, SecureChannel,
};
pub use reader::{
    AccessController, AccessGrant, HealthEvent, HealthEventRecord, LinkState, ReaderHealth,
    TamperState,
};
pub use revocation::{
    AppliedRevocation, CachedGrant, OfflineCache, RevocationDelta, RevocationList,
};
#[cfg(feature = "wiegand")]
pub use wiegand::{
    DataLine, WiegandCredential, WiegandError, WiegandPulse, WiegandTiming,
};
