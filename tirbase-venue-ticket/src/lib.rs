// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-ticket — Offline ticket validation kernel (ST-05)
//!
//! A gate that cannot reach the back office still has to decide, safely, in
//! bounded space and time:
//!
//! * a **signed payload** — ticket id, event, venue, gate, zone, validity
//!   window, nonce and an optional holder binding — with a fixed canonical
//!   encoding and Ed25519 signature over a domain-separated message;
//! * a **signed revocation list** carrying a monotonic version and an expiry;
//! * a **bounded anti-replay store** with a capacity and a retention window;
//! * an **offline decision API** returning either an admission or a typed
//!   [`Denial`], never a free-text reason;
//! * **issuer key rotation** with an overlap window and per-key revocation, and
//!   revocation **refresh** that refuses rollback and expired lists;
//! * property tests for replay, expiry, wrong scope and corrupted signatures.
//!
//! # F-05 boundary
//!
//! Private key material belongs to the deployment's F-05 custodian. This crate
//! holds verification keys only and signs through the [`TicketSigner`] seam
//! ([`Ed25519Signer`] exists for tooling and tests), so an HSM can sign without
//! exporting anything. Key ids, domain separation (`TirBase/v1/...`), rotation
//! overlap and revocation semantics follow F-05 conventions.
//!
//! # Fail-closed revocation
//!
//! A missing, expired, rolled-back or unverifiable revocation list never
//! permits a ticket. [`StaleRevocationPolicy::FailClosed`] refuses silently;
//! [`StaleRevocationPolicy::Alarm`] refuses *and* raises an operator alarm
//! ([`OfflineValidator::take_alarm`]).

#![forbid(unsafe_code)]

pub mod decision;
pub mod error;
pub mod keys;
pub mod payload;
pub mod replay;
pub mod signed;
pub mod validator;

pub use decision::{Denial, scope_denial};
pub use error::TicketError;
pub use keys::{
    Ed25519Signer, IssuerKey, IssuerKeyRing, IssuerKeyState, IssuerRotation, TicketSigner,
};
pub use payload::{
    EventId, HolderBinding, HolderKind, TicketPayload, VenueScope, MAX_ID_LEN, REVOCATION_DOMAIN,
    TICKET_DOMAIN, TICKET_VERSION,
};
pub use replay::{ReplayStore, MAX_REPLAY_CAPACITY, MAX_RETENTION_US};
pub use signed::{SignedRevocationList, SignedTicket, TicketRevocationList};
pub use validator::{
    Admission, HolderPolicy, OfflineValidator, RevocationStatus, StaleListAlarm,
    StaleRevocationPolicy, ValidationRequest, ValidatorPolicy,
};
