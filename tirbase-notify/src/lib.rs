// SPDX-License-Identifier: Apache-2.0

//! Generic alert-delivery connectors for TirBase (CC-17).
//!
//! This crate is the *integration surface* for alert delivery. It is
//! Apache-2.0 and depends on no AGPL crate, so a vendor can implement
//! [`transport::NotifyTransport`] in a closed-source plugin, link this crate
//! (and only this crate), and have the AGPL gateway deliver alerts through it.
//!
//! What ships here:
//!
//! * [`message`] — the wire-level alert model ([`message::AlertMessage`]) and
//!   its deterministic renderings (JSON payload, email body, console line).
//! * [`secrets`] — secrets **by reference**: a [`secrets::SecretRef`] names a
//!   secret, and a [`secrets::SecretStore`] resolves it at delivery time. No
//!   connector configuration ever carries a secret value.
//! * [`transport`] — the connector interface ([`transport::NotifyTransport`])
//!   and its outcome types ([`transport::DeliveryReceipt`],
//!   [`transport::DeliveryFailure`], with `retriable` deciding whether the
//!   runtime retries or dead-letters).
//! * [`webhook`] — HTTPS webhook connector: deterministic JSON payload, HMAC
//!   signature headers, idempotency key, and status classification.
//! * [`smtp`] — SMTP connector: a scriptable session driver plus MIME message
//!   rendering, dot-stuffing and `AUTH PLAIN`.
//! * [`console`] — the local console/test sink.
//! * [`backoff`] — the deterministic retry schedule the runtime uses.
//! * [`oncall`] — on-call rotation arithmetic used for routing.
//!
//! Vendor SaaS connectors (Slack, Teams, PagerDuty, SMS gateways) are **not**
//! in this repository: they are closed commercial plugins that implement
//! [`transport::NotifyTransport`]. Routing, deduplication, retries, dead
//! letters, acknowledgement, escalation and the delivery audit live in the AGPL
//! runtime (`tirbase-gateway::alerts`), which is the only code that decides who
//! gets paged and whether an alert escalated.

#![forbid(unsafe_code)]

pub mod backoff;
pub mod conformance;
pub mod console;
pub mod message;
pub mod oncall;
pub mod secrets;
pub mod smtp;
pub mod transport;
pub mod webhook;

pub use conformance::{certify, NotifierCheck, NotifierReport};
pub use message::{AlertMessage, Severity};
pub use secrets::{
    FileSecretStore, MemorySecretStore, SecretError, SecretRef, SecretStore, SecretValue,
};
pub use transport::{
    ConnectorKind, DeliveryFailure, DeliveryReceipt, DeliveryTarget, NotifyTransport,
};
