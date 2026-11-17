// SPDX-License-Identifier: Apache-2.0

//! The generic connectors.
//!
//! | Module | Transport | Idempotency mechanism |
//! | --- | --- | --- |
//! | [`http`] | HTTP/REST | `Idempotency-Key` header |
//! | [`webhook`] | HTTP webhook | HMAC signature + `Idempotency-Key` |
//! | [`mqtt`] | MQTT 3.1.1 publish | idempotency key in the payload |
//! | [`csv`] | CSV drop | one file per idempotency key |
//! | [`sftp`] | SFTP upload | one file per idempotency key, put-if-absent |
//!
//! Each connector only classifies one attempt; retries, dead letters and replay
//! live in [`crate::engine`].

pub mod csv;
pub mod http;
pub mod mqtt;
pub mod sftp;
pub mod webhook;

pub use csv::CsvConnector;
pub use http::{classify_status, HttpConnector, HttpConnectorConfig};
pub use mqtt::{encode_publish, MqttConnector, MqttPublish, MqttTransport, MqttTransportError};
pub use sftp::{SftpConnector, SftpPut, SftpSession, SftpTransportError};
pub use webhook::{WebhookConnector, WebhookConnectorConfig};
