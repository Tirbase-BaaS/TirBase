// SPDX-License-Identifier: AGPL-3.0-only

//! BACnet/IP read bridge (CC-04).
//!
//! Read-only MVP: Who-Is/I-Am discovery and ReadProperty against analog and
//! binary inputs/values. The transport is behind the `bacnet-ip` feature; the
//! pure codec lives in Apache-2.0 `tirbase_driver_api::bacnet_codec`.
//!
//! # Safety properties
//!
//! * **Read-only.** [`BacnetIpClient::write_property`] returns
//!   [`BacnetError::WriteRejected`] before any socket operation. No encoder in
//!   the codec can produce a WriteProperty frame.
//! * **Bounded.** Every request carries one UDP datagram; retries and timeouts
//!   are clamped to [`MAX_RETRIES`] and the caller-supplied timeout. Discovery
//!   reports at most [`MAX_DISCOVERED_DEVICES`] devices and only broadcasts the
//!   single global Who-Is frame in [`BacnetIpClient::discover_broadcast`].
//! * **No clock reads.** Deadlines use the caller-supplied monotonic clock,
//!   consistent with the other transports in this crate.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use tirbase_driver_api::bacnet_codec::{
    encode_read_property, encode_who_is, encode_who_is_unicast, parse_message, BacnetError,
    BacnetMessage, BacnetResult, BacnetValue, ObjectIdentifier, PropertyId, BACNET_IP_PORT,
    MAX_BVLC_LENGTH, MAX_DISCOVERED_DEVICES, MAX_OBJECT_INSTANCE, MAX_RETRIES,
};

/// Caller-supplied monotonic millisecond clock shared with the other drivers.
pub type MonotonicMillisFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Transport configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetIpConfig {
    /// Local bind address (`0.0.0.0:0` binds an ephemeral port).
    pub local_addr: String,
    /// Per-attempt response deadline.
    pub timeout: Duration,
    /// Retries after a bounded timeout. Clamped to [`MAX_RETRIES`].
    pub retries: u8,
    /// Devices reported per discovery pass. Clamped to
    /// [`MAX_DISCOVERED_DEVICES`].
    pub max_devices: usize,
}

impl Default for BacnetIpConfig {
    fn default() -> Self {
        Self {
            local_addr: format!("0.0.0.0:{BACNET_IP_PORT}"),
            timeout: Duration::from_secs(1),
            retries: 1,
            max_devices: 64,
        }
    }
}

/// One device discovered by Who-Is/I-Am.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub device: ObjectIdentifier,
    pub address: SocketAddr,
    pub max_apdu: u16,
    pub segmentation: u8,
    pub vendor_id: u16,
}

/// BACnet/IP read client.
pub struct BacnetIpClient {
    socket: UdpSocket,
    timeout: Duration,
    retries: u8,
    max_devices: usize,
    clock: MonotonicMillisFn,
    next_invoke: u8,
}

impl BacnetIpClient {
    /// Binds a local UDP socket. No discovery or device traffic is sent here.
    pub fn bind(config: &BacnetIpConfig, clock: MonotonicMillisFn) -> BacnetResult<Self> {
        let socket = UdpSocket::bind(&config.local_addr)
            .map_err(|error| BacnetError::Transport(format!("bind: {error}")))?;
        Ok(Self::from_socket(socket, config, clock))
    }

    /// Wraps an already-bound socket (used by tests and the simulator).
    pub fn from_socket(
        socket: UdpSocket,
        config: &BacnetIpConfig,
        clock: MonotonicMillisFn,
    ) -> Self {
        Self {
            socket,
            timeout: config.timeout,
            retries: config.retries.min(MAX_RETRIES),
            max_devices: config.max_devices.clamp(1, MAX_DISCOVERED_DEVICES),
            clock,
            next_invoke: 1,
        }
    }

    /// Local socket address.
    pub fn local_addr(&self) -> BacnetResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| BacnetError::Transport(format!("local_addr: {error}")))
    }

    /// Directed Who-Is discovery: one unicast Who-Is per attempt, bounded
    /// retries, bounded device count. No broadcast is emitted.
    pub fn discover(&self, target: SocketAddr) -> BacnetResult<Vec<DiscoveredDevice>> {
        self.discover_with(
            target,
            encode_who_is_unicast(),
            false,
            0,
            MAX_OBJECT_INSTANCE,
        )
    }

    /// Directed Who-Is discovery limited to an inclusive device-instance range.
    pub fn discover_range(
        &self,
        target: SocketAddr,
        low: u32,
        high: u32,
    ) -> BacnetResult<Vec<DiscoveredDevice>> {
        let frame = tirbase_driver_api::bacnet_codec::encode_who_is_range_unicast(low, high)?;
        self.discover_with(target, frame, false, low, high)
    }

    /// Global-broadcast Who-Is discovery on the BACnet/IP port.
    ///
    /// This emits exactly one Who-Is datagram per bounded attempt and stops
    /// once the device cap is reached.
    pub fn discover_broadcast(&self) -> BacnetResult<Vec<DiscoveredDevice>> {
        let target = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.discover_with(target, encode_who_is(), true, 0, MAX_OBJECT_INSTANCE)
    }

    fn discover_with(
        &self,
        target: SocketAddr,
        frame: Vec<u8>,
        broadcast: bool,
        low: u32,
        high: u32,
    ) -> BacnetResult<Vec<DiscoveredDevice>> {
        if self.max_devices == 0 || self.max_devices > MAX_DISCOVERED_DEVICES {
            return Err(BacnetError::DiscoveryLimit {
                max: MAX_DISCOVERED_DEVICES,
            });
        }
        self.socket
            .set_broadcast(broadcast)
            .map_err(|error| BacnetError::Transport(format!("set_broadcast: {error}")))?;

        let mut found: BTreeMap<u32, DiscoveredDevice> = BTreeMap::new();
        let attempts = u16::from(self.retries) + 1;
        for _ in 0..attempts {
            self.socket
                .send_to(&frame, target)
                .map_err(|error| BacnetError::Transport(format!("discovery send: {error}")))?;
            let deadline = self.deadline();
            while found.len() < self.max_devices {
                let Some((datagram, address)) = self.recv_until(deadline, "discovery")? else {
                    break;
                };
                let Ok(BacnetMessage::IAm(i_am)) = parse_message(&datagram) else {
                    continue;
                };
                if !(low..=high).contains(&i_am.device.instance) {
                    continue;
                }
                found
                    .entry(i_am.device.instance)
                    .or_insert(DiscoveredDevice {
                        device: i_am.device,
                        address,
                        max_apdu: i_am.max_apdu,
                        segmentation: i_am.segmentation,
                        vendor_id: i_am.vendor_id,
                    });
            }
            if !found.is_empty() {
                break;
            }
        }
        Ok(found.into_values().collect())
    }

    /// Reads a property from one object. Retries only bounded timeouts.
    pub fn read_property(
        &mut self,
        target: SocketAddr,
        object: ObjectIdentifier,
        property: PropertyId,
    ) -> BacnetResult<BacnetValue> {
        if !object.object_type.is_readable() {
            return Err(BacnetError::UnsupportedObjectType(
                object.object_type.code(),
            ));
        }
        let invoke_id = self.alloc_invoke();
        let frame = encode_read_property(invoke_id, object, property)?;
        let attempts = u16::from(self.retries) + 1;
        for _ in 0..attempts {
            self.socket
                .send_to(&frame, target)
                .map_err(|error| BacnetError::Transport(format!("read send: {error}")))?;
            let deadline = self.deadline();
            while let Some((datagram, address)) = self.recv_until(deadline, "read_property")? {
                if address != target {
                    continue;
                }
                match parse_message(&datagram) {
                    Ok(BacnetMessage::ReadPropertyAck {
                        invoke_id: reply,
                        value,
                    }) if reply == invoke_id => return Ok(value),
                    Ok(BacnetMessage::Error {
                        invoke_id: reply,
                        error_class,
                        error_code,
                        ..
                    }) if reply == invoke_id => {
                        return Err(BacnetError::ErrorPdu {
                            invoke_id: reply,
                            error_class,
                            error_code,
                        })
                    }
                    Ok(BacnetMessage::Reject {
                        invoke_id: reply,
                        reason,
                    }) if reply == invoke_id => {
                        return Err(BacnetError::Reject {
                            invoke_id: reply,
                            reason,
                        })
                    }
                    Ok(BacnetMessage::Abort {
                        invoke_id: reply,
                        reason,
                    }) if reply == invoke_id => {
                        return Err(BacnetError::Abort {
                            invoke_id: reply,
                            reason,
                        })
                    }
                    _ => continue,
                }
            }
        }
        Err(BacnetError::Timeout {
            operation: "read_property",
            limit_ms: self.timeout.as_millis() as u64,
        })
    }

    /// Reads the Present-Value of an analog or binary object.
    pub fn read_present_value(
        &mut self,
        target: SocketAddr,
        object: ObjectIdentifier,
    ) -> BacnetResult<BacnetValue> {
        self.read_property(target, object, PropertyId::PRESENT_VALUE)
    }

    /// Read-only MVP: writes are rejected before any socket operation.
    ///
    /// Always returns [`BacnetError::WriteRejected`].
    pub fn write_property(
        &mut self,
        _target: SocketAddr,
        object: ObjectIdentifier,
        property: PropertyId,
        _value: &BacnetValue,
    ) -> BacnetResult<()> {
        Err(BacnetError::WriteRejected { object, property })
    }

    fn alloc_invoke(&mut self) -> u8 {
        let invoke = self.next_invoke;
        self.next_invoke = self.next_invoke.wrapping_add(1).max(1);
        invoke
    }

    fn deadline(&self) -> u64 {
        (self.clock)().saturating_add(self.timeout.as_millis() as u64)
    }

    /// Receives one datagram before `deadline`; `None` means the deadline
    /// expired.
    fn recv_until(
        &self,
        deadline: u64,
        operation: &'static str,
    ) -> BacnetResult<Option<(Vec<u8>, SocketAddr)>> {
        loop {
            let now = (self.clock)();
            if now >= deadline {
                return Ok(None);
            }
            let remaining = deadline - now;
            let slice = Duration::from_millis(remaining.clamp(1, 100));
            self.socket
                .set_read_timeout(Some(slice))
                .map_err(|error| BacnetError::Transport(format!("read timeout: {error}")))?;
            let mut buffer = [0u8; MAX_BVLC_LENGTH];
            match self.socket.recv_from(&mut buffer) {
                Ok((len, address)) => return Ok(Some((buffer[..len].to_vec(), address))),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(BacnetError::Transport(format!(
                        "{operation} receive: {error}"
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // `tirbase-drivers` must not depend on `tirbase-core`'s TimeSource (layering).
    #[allow(clippy::disallowed_methods)]
    fn real_clock() -> MonotonicMillisFn {
        let start = Instant::now();
        Arc::new(move || start.elapsed().as_millis() as u64)
    }

    #[test]
    fn write_is_rejected_without_touching_the_socket() {
        let config = BacnetIpConfig {
            local_addr: "127.0.0.1:0".into(),
            timeout: Duration::from_millis(50),
            retries: 0,
            max_devices: 1,
        };
        let mut client = BacnetIpClient::bind(&config, real_clock()).unwrap();
        let target: SocketAddr = "127.0.0.1:47808".parse().unwrap();
        let object =
            ObjectIdentifier::new(tirbase_driver_api::bacnet_codec::ObjectType::AnalogValue, 1)
                .unwrap();
        let error = client
            .write_property(
                target,
                object,
                PropertyId::PRESENT_VALUE,
                &BacnetValue::Real(1.0),
            )
            .unwrap_err();
        assert!(matches!(error, BacnetError::WriteRejected { .. }));
    }

    #[test]
    fn retries_are_clamped() {
        let config = BacnetIpConfig {
            retries: u8::MAX,
            ..BacnetIpConfig::default()
        };
        let client = BacnetIpClient::bind(&config, real_clock()).unwrap();
        assert_eq!(client.retries, MAX_RETRIES);
    }
}
