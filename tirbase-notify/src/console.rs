// SPDX-License-Identifier: Apache-2.0

//! Local console/test sink.
//!
//! One line per delivery, tab-separated and stable, so a test can assert exactly
//! what was paged and a local operator can watch alerts without a network. This
//! is the connector a deployment uses when no relay is configured: a silent
//! alerting system is worse than a noisy one.

use std::sync::Mutex;

use crate::message::AlertMessage;
use crate::transport::{DeliveryReceipt, DeliveryTarget, NotifyTransport};

/// One deterministic console line for `message`.
pub fn render_line(message: &AlertMessage) -> String {
    format!(
        "{}\t{}\t{}\t{}\tlevel={}\t{}\t{}\t{}",
        message.occurred_est,
        message.severity.label(),
        message.site_id,
        message.role,
        message.escalation_level,
        if message.is_acknowledged() {
            "ACKED"
        } else if message.ack_required {
            "UNACKED"
        } else {
            "-"
        },
        message.alert_id,
        message.title
    )
}

/// Writes each delivery to a writer (a file, `stdout`, or a `Vec<u8>` in tests).
#[derive(Debug)]
pub struct ConsoleSink<W: std::io::Write + Send + std::fmt::Debug> {
    channel: String,
    out: Mutex<W>,
}

impl<W: std::io::Write + Send + std::fmt::Debug> ConsoleSink<W> {
    /// A sink writing to `out`, registered as `channel`.
    pub fn new(channel: impl Into<String>, out: W) -> Self {
        Self {
            channel: channel.into(),
            out: Mutex::new(out),
        }
    }
}

impl ConsoleSink<std::io::Stdout> {
    /// A sink writing to standard output as channel `console`.
    pub fn stdout() -> Self {
        Self::new("console", std::io::stdout())
    }
}

impl<W: std::io::Write + Send + std::fmt::Debug> NotifyTransport for ConsoleSink<W> {
    fn channel(&self) -> &str {
        &self.channel
    }

    fn deliver(
        &self,
        message: &AlertMessage,
        _target: &DeliveryTarget,
    ) -> Result<DeliveryReceipt, crate::transport::DeliveryFailure> {
        let mut out = self.out.lock().map_err(|_| {
            crate::transport::DeliveryFailure::retriable("console sink lock poisoned")
        })?;
        writeln!(out, "{}", render_line(message)).map_err(|error| {
            crate::transport::DeliveryFailure::permanent(format!("console write: {error}"))
        })?;
        out.flush().map_err(|error| {
            crate::transport::DeliveryFailure::permanent(format!("console flush: {error}"))
        })?;
        Ok(DeliveryReceipt { provider_id: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Severity;

    #[test]
    fn a_delivery_is_one_stable_line() {
        let message = AlertMessage::new("alert-1", "dedup-1", Severity::Critical, "too warm");
        assert_eq!(
            render_line(&message),
            "0\tCRITICAL\tunknown\ton-call\tlevel=1\tUNACKED\talert-1\ttoo warm"
        );
    }

    #[test]
    fn the_sink_writes_every_delivery() {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::fmt::Debug for Shared {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("Shared")
            }
        }
        impl std::io::Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = ConsoleSink::new("console", Shared(shared.clone()));
        let target = DeliveryTarget {
            channel: "console".into(),
            address: "-".into(),
            secret_ref: None,
        };
        let mut message = AlertMessage::new("a1", "d1", Severity::Warning, "door open");
        message.site_id = "site-1".to_string();
        sink.deliver(&message, &target).expect("delivered");
        let written = String::from_utf8(shared.lock().unwrap().clone()).expect("utf8");
        assert_eq!(
            written,
            "0\tWARNING\tsite-1\ton-call\tlevel=1\t-\ta1\tdoor open\n"
        );
    }
}
