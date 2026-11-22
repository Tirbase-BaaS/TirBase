// SPDX-License-Identifier: Apache-2.0

//! # tirbase-venue-connectors — generic venue integration framework (ST-10)
//!
//! This crate is Apache-2.0 and links only the Apache-2.0
//! [`tirbase_integrations`] framework. A closed venue connector can be built,
//! tested and shipped against this crate alone: nothing here reaches the AGPL
//! venue runtime (`tirbase-venue*`), and the `agpl_free` test proves it from
//! `Cargo.lock`.
//!
//! The framework supplies:
//!
//! * **event schemas** — ticket scan, access decision, alarm and announcement,
//!   strict on the wire and validated before delivery;
//! * **connector interfaces** — one generic [`VenueConnector`] plus typed
//!   [`domain::TicketingConnector`], [`domain::AccessConnector`],
//!   [`domain::BmsConnector`], [`domain::CctvConnector`] and
//!   [`domain::PaConnector`] surfaces;
//! * **mapping config** — a versioned TOML [`ConnectorProfile`] embedding the
//!   CC-20 mapping document, privacy config and retry policy;
//! * **idempotency, retries and dead letters** — [`VenueDispatcher`] derives a
//!   deterministic event id and key from the native scan/announcement id and
//!   drives the CC-20 [`tirbase_integrations::DeliveryEngine`], so a replay is a
//!   downstream duplicate rather than a second scan or announcement;
//! * **webhook verification** — signed inbound callbacks with timestamp skew,
//!   rotation-tolerant HMAC-SHA256 and an explicit refusal of unsigned bodies;
//! * **redaction and privacy** — holder references are pseudonymised, personal
//!   fields never leave the venue, announcement text is scrubbed, and camera
//!   media/biometric data cannot be represented;
//! * **mocks and conformance** — [`mock::MockVenueApi`] vendor fixtures and
//!   [`conformance::certify`], which fails a connector that pages twice or
//!   accepts an unsigned webhook.
//!
//! ```no_run
//! use tirbase_venue_connectors::{
//!     event::{Announcement, AnnouncementSeverity, VenueEvent},
//!     idempotency::VenueDispatcher,
//!     mock::MockVenueApi,
//!     privacy::PrivacyPolicy,
//!     domain::VenueDomain,
//! };
//!
//! let mock = MockVenueApi::new("venue-pa", "venue-1", vec![VenueDomain::Pa]);
//! let mut dispatcher = VenueDispatcher::new(
//!     Box::new(mock),
//!     PrivacyPolicy::standard("deployment-salt"),
//!     Default::default(),
//! );
//! let announcement = Announcement::new(
//!     "ann-1", "venue-1", vec!["zone-north".into()],
//!     AnnouncementSeverity::Info, "Gates open in ten minutes.", 1_000,
//! )?;
//! let event = VenueEvent::announcement(announcement);
//! dispatcher.submit(&event, 1_000)?;
//! dispatcher.flush(1_000);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

pub mod conformance;
pub mod domain;
pub mod event;
pub mod idempotency;
pub mod mapping;
pub mod mock;
pub mod privacy;
pub mod webhook;

pub use conformance::{certify, VenueCertificationReport, VenueCheck};
pub use domain::{
    AccessConnector, BmsConnector, BmsPointWrite, BmsValue, CameraContext, CctvConnector,
    PaConnector, TicketingConnector, VenueCapabilities, VenueConnector, VenueDomain,
};
pub use event::{
    AccessDecision, AccessOutcome, AlarmKind, AlarmSeverity, Announcement, AnnouncementSeverity,
    DenyReason, ScanDirection, SchemaError, TicketScan, VenueAlarm, VenueEvent, VenueEventKind,
};
pub use idempotency::{
    announcement_idempotency_key, event_id, scan_idempotency_key, VenueDispatcher, VenueError,
    VenueSubmit,
};
pub use mapping::{CompiledProfile, ConnectorProfile, ProfileError};
pub use mock::{MockVenueApi, MockVenueConfig};
pub use privacy::{HolderDisclosure, PrivacyError, PrivacyPolicy};
pub use webhook::{
    InboundOutcome, InboundVenueEvents, VenueWebhookVerifier, VerifiedWebhook, WebhookError,
    DEFAULT_SIGNATURE_HEADER, DEFAULT_TIMESTAMP_HEADER, DEFAULT_TOLERANCE_SECS,
};

pub use tirbase_integrations::{FlushReport, RetryPolicy};

/// Crate version from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
