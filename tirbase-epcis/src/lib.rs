// SPDX-License-Identifier: Apache-2.0

//! # TirBase EPCIS 2.0 adapter
//!
//! Maps a signed TirBase lineage ledger bundle (CC-14) to GS1 EPCIS 2.0 events,
//! as JSON-LD and XML, and validates the JSON against the vendored official
//! EPCIS 2.0 JSON Schema.
//!
//! The crate is Apache-2.0 and depends on nothing from the AGPL half of the
//! repository: it reads the bundle's *JSON* and never links the ledger crate.
//! See `tests/licence.rs` for the dependency-graph proof and
//! `docs/epcis-adapter.md` for the field mappings and the fields the adapter
//! deliberately does not emit.
//!
//! ```
//! use tirbase_epcis::{map_bundle, parse_bundle};
//!
//! let bundle = parse_bundle(r#"{
//!   "manifest": {
//!     "format_version": 1, "created_est": 10, "signer_did": "did:key:z6MkTest",
//!     "signer_public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
//!     "range_start": 1, "range_end": 1,
//!     "range_prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
//!     "entry_count": 1,
//!     "root_hash": "1111111111111111111111111111111111111111111111111111111111111111",
//!     "checkpoints": [], "attachments": []
//!   },
//!   "entries": [{
//!     "seq": 1, "entry_id": "lot-registered:LOT-A",
//!     "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
//!     "entry_hash": "1111111111111111111111111111111111111111111111111111111111111111",
//!     "recorded_est": 9, "actor_did": "did:key:z6MkTest",
//!     "lot_id": "LOT-A", "event_type": "lot_registered",
//!     "payload_hash": "2222222222222222222222222222222222222222222222222222222222222222",
//!     "payload": {"lot_id": "LOT-A", "site_id": "site-1", "location_id": "loc-1"}
//!   }]
//! }"#).expect("bundle");
//!
//! let mapped = map_bundle(&bundle, None);
//! assert_eq!(mapped.document.events.len(), 1);
//! ```

pub mod bundle;
pub mod json;
pub mod mapping;
pub mod model;
pub mod schema;
pub mod time;
pub mod xml;

pub use bundle::{parse_bundle, Bundle, BundleSignature, LedgerEntry, Manifest};
pub use mapping::{map_bundle, MappedBundle, MappedDocument, UnsupportedEntry};
pub use model::{
    AggregationEvent, AssociationEvent, EpcisAction, EpcisDocument, EpcisEvent, EventBase,
    ObjectEvent, TransformationEvent,
};
pub use schema::{validate_document, Schema, Violation};

/// Error raised while reading, verifying or mapping a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// The bundle JSON could not be parsed or serialised.
    Json(String),
    /// The detached signature did not verify.
    Signature(String),
    /// The bundle is structurally invalid for mapping.
    InvalidBundle(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::Json(detail) => write!(f, "bundle json: {detail}"),
            AdapterError::Signature(detail) => write!(f, "bundle signature: {detail}"),
            AdapterError::InvalidBundle(detail) => write!(f, "invalid bundle: {detail}"),
        }
    }
}

impl std::error::Error for AdapterError {}
