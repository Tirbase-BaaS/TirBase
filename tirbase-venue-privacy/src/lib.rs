// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-privacy — ST-13 privacy runtime
//!
//! This crate is the open, enforceable part of the venue privacy programme:
//! metadata-only CCTV events, role-scoped access, enforced retention, legal
//! holds, subject access/deletion and the embedded field register. The
//! commercial compliance kit supplies customer-completion templates and review
//! records; it does not replace this runtime.
//!
//! ```no_run
//! use tirbase_venue_privacy::{CctvActor, CctvEvent, CctvEventKind, CctvRole, CctvStore};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut store = CctvStore::new();
//! let officer = CctvActor::new("dpo-1", CctvRole::PrivacyOfficer, "venue-1")?;
//! let event = CctvEvent::new("cctv-1", "venue-1", "cam-n1", "zone-north",
//!     CctvEventKind::Security, 1_000)?;
//! store.insert(&officer, event)?;
//! let visible = store.read(&officer, "cctv-1", 2_000)?;
//! assert_eq!(visible.event_id(), "cctv-1");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod store;

pub use store::{
    parse_register, privacy_register, CctvAccessRecord, CctvActor, CctvDeletionReport, CctvError,
    CctvEvent, CctvEventKind, CctvHoldScope, CctvLegalHold, CctvRetentionClass,
    CctvRetentionReport, CctvRole, CctvStore, CctvSubjectAccessReport, PersonalData, PrivacyField,
    RegisterError, ACCESS_RETENTION_SECS, CCTV_OPERATIONAL_SECS, CCTV_SAFETY_SECS,
    CCTV_SECURITY_SECS, DSAR_RECORD_RETENTION_SECS, REGISTER_CSV, RETENTION_CODES, SECONDS_PER_DAY,
    TICKET_RETENTION_SECS,
};
