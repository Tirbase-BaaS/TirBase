// SPDX-License-Identifier: AGPL-3.0-only

//! Shared byte transport for the POS-08 device guards.
//!
//! Drivers are codecs: they turn bytes into typed readings and back. They never
//! own a port, a clock or a retry policy. The guard-owned endpoints
//! ([`crate::scale::ScaleEndpoint`], [`crate::scanner::SerialScanner`] and
//! [`crate::kds::KdsEndpoint`]) own the transport and enforce the bounded
//! buffer, timeout and idempotency rules.

use crate::printer::TransportError;

/// A synchronous byte pipe to a peripheral.
///
/// `read` fills at most the supplied slice and returns the number of bytes
/// written into it. It must never allocate on behalf of the device. A zero
/// return means "no bytes are available right now"; a device that does not
/// answer within its deadline returns [`TransportError::Timeout`].
pub trait DeviceTransport {
    /// Write the complete byte slice.
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// Read up to `buf.len()` bytes into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Flush buffered output.
    fn flush(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
