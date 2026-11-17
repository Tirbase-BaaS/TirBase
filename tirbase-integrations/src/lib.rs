// SPDX-License-Identifier: Apache-2.0

//! TirBase generic integration framework.
//!
//! This crate is Apache-2.0 and deliberately links nothing from the AGPL
//! runtime, so a vendor connector can be written, tested and shipped against it
//! alone. A connector implements [`Connector`]; everything else — retries,
//! dead letters, replay, metrics, health, the mapping DSL, the mock vendor and
//! the conformance suite — is supplied here.
//!
//! ```no_run
//! use tirbase_integrations::auth::ApiKey;
//! use tirbase_integrations::connector::IntegrationEvent;
//! use tirbase_integrations::connectors::{HttpConnector, HttpConnectorConfig};
//! use tirbase_integrations::engine::DeliveryEngine;
//! use tirbase_integrations::mapping::Mapping;
//!
//! let mapping = Mapping::from_toml(
//!     "schema_version = 1\n[[field]]\ntarget = \"device.serial\"\nsource = \"payload.serial\"\n",
//! )?;
//! let config = HttpConnectorConfig::new("vendor", "https://vendor.example/api/events")
//!     .with_auth(tirbase_integrations::auth::Auth::ApiKey(
//!         ApiKey::new("x-api-key", "…")?,
//!     ));
//! let connector = HttpConnector::with_default_client(config, Some(mapping))?;
//! let mut engine = DeliveryEngine::new(Box::new(connector));
//! engine.submit(
//!     &IntegrationEvent::new("e-1", "reading.recorded", "acme", 1, serde_json::json!({"serial": "SN-1"})),
//!     1,
//! )?;
//! let report = engine.flush(1);
//! assert_eq!(report.delivered, 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Guarantees
//!
//! - **One record per event.** The outbox deduplicates on event id, and replay
//!   reuses the original idempotency key, so a replayed event is a duplicate
//!   downstream rather than a second record.
//! - **Deterministic.** No connector, retry policy or engine reads the clock;
//!   every instant is supplied by the caller.
//! - **Redacted.** Secrets never print, log records carry no payload, and
//!   credential-shaped keys are masked in structured output.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod conformance;
pub mod connector;
pub mod connectors;
pub mod engine;
pub mod mapping;
pub mod mock;
pub mod observability;
pub mod outbox;
pub mod retry;

pub use auth::{ApiKey, Auth, HmacWebhook, MutualTls, OAuth2Client, SecretString};
pub use conformance::{certify, CertificationReport, ContractCase, ContractHarness};
pub use connector::{
    AuthKind, Connector, ConnectorCapabilities, ConnectorHealth, ConnectorKind, DeliveryOutcome,
    DeliveryRequest, DeliveryResult, IntegrationEvent,
};
pub use engine::{DeliveryEngine, EngineError, FlushReport};
pub use mapping::{Mapping, MappingError};
pub use mock::{MockRequest, MockVendorConfig, MockVendorServer};
pub use observability::{HealthResponse, HealthSnapshot, HealthStatus, LogRecord};
pub use outbox::{DeadLetter, Outbox, OutboxRecord, RecordState};
pub use retry::RetryPolicy;

/// Crate version from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
