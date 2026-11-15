// SPDX-License-Identifier: AGPL-3.0-only

//! Minimal BACnet/IP device simulator for CC-04 tests (F-13).
//!
//! Serves Who-Is/I-Am discovery and ReadProperty from an in-memory object
//! table over UDP. WriteProperty requests are answered with a BACnet Error PDU
//! and counted, so tests can prove the client never sends writes. No physical
//! device or broadcast network is required: tests bind loopback and use
//! directed Who-Is.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tirbase_driver_api::bacnet_codec::{
    decode_read_property_apdu, encode_error_pdu, encode_i_am, encode_read_property_ack, parse_bvlc,
    BacnetValue, IAm, ObjectType, PropertyId, MAX_BVLC_LENGTH,
};

const SERVICE_WRITE_PROPERTY: u8 = 0x0F;
const SERVICE_WRITE_PROPERTY_MULTIPLE: u8 = 0x10;
const ERROR_CLASS_PROPERTY: u32 = 2;
const ERROR_CODE_UNKNOWN_PROPERTY: u32 = 32;
const ERROR_CLASS_OBJECT: u32 = 1;
const ERROR_CODE_UNKNOWN_OBJECT: u32 = 31;
const ERROR_CLASS_WRITE_ACCESS_DENIED: u32 = 1;
const ERROR_CODE_WRITE_ACCESS_DENIED: u32 = 40;

/// One simulated BACnet device.
#[derive(Debug, Clone)]
pub struct BacnetSimDevice {
    pub device_instance: u32,
    pub vendor_id: u16,
    pub max_apdu: u16,
    pub segmentation: u8,
    /// Present values keyed by `(object type, instance)`.
    pub values: BTreeMap<(ObjectType, u32), BacnetValue>,
}

impl BacnetSimDevice {
    /// Creates a device with no objects.
    pub fn new(device_instance: u32) -> Self {
        Self {
            device_instance,
            vendor_id: 0x0021,
            max_apdu: 480,
            segmentation: 0,
            values: BTreeMap::new(),
        }
    }

    /// Adds or replaces an object's Present-Value.
    pub fn set_present_value(
        &mut self,
        object_type: ObjectType,
        instance: u32,
        value: BacnetValue,
    ) {
        self.values.insert((object_type, instance), value);
    }
}

/// Failure-injection options.
#[derive(Debug, Clone, Copy, Default)]
pub struct BacnetSimServerOptions {
    /// Ignore the first Who-Is datagram, forcing a client retry.
    pub drop_first_who_is: bool,
    /// Ignore the first ReadProperty request, forcing a client retry.
    pub drop_first_read: bool,
}

/// Running simulator handle.
#[derive(Clone)]
pub struct BacnetSimServerHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    write_attempts: Arc<AtomicUsize>,
    who_is_requests: Arc<AtomicUsize>,
    read_requests: Arc<AtomicUsize>,
}

impl BacnetSimServerHandle {
    /// Number of WriteProperty requests received (expected to stay zero).
    pub fn write_attempts(&self) -> usize {
        self.write_attempts.load(Ordering::SeqCst)
    }

    /// Number of Who-Is datagrams received.
    pub fn who_is_requests(&self) -> usize {
        self.who_is_requests.load(Ordering::SeqCst)
    }

    /// Number of ReadProperty requests received.
    pub fn read_requests(&self) -> usize {
        self.read_requests.load(Ordering::SeqCst)
    }

    /// Stops the background loop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for BacnetSimServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// BACnet/IP server bound to a loopback ephemeral port.
pub struct BacnetSimServer;

impl BacnetSimServer {
    /// Binds `127.0.0.1:0` and serves `devices`.
    pub fn spawn(devices: Vec<BacnetSimDevice>) -> std::io::Result<BacnetSimServerHandle> {
        Self::spawn_with_options(devices, BacnetSimServerOptions::default())
    }

    /// Binds `127.0.0.1:0` with failure injection.
    pub fn spawn_with_options(
        devices: Vec<BacnetSimDevice>,
        options: BacnetSimServerOptions,
    ) -> std::io::Result<BacnetSimServerHandle> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        let addr = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let write_attempts = Arc::new(AtomicUsize::new(0));
        let who_is_requests = Arc::new(AtomicUsize::new(0));
        let read_requests = Arc::new(AtomicUsize::new(0));
        let drop_who_is = Arc::new(AtomicBool::new(options.drop_first_who_is));
        let drop_read = Arc::new(AtomicBool::new(options.drop_first_read));

        let thread_stop = Arc::clone(&stop);
        let thread_writes = Arc::clone(&write_attempts);
        let thread_who_is = Arc::clone(&who_is_requests);
        let thread_reads = Arc::clone(&read_requests);
        thread::spawn(move || {
            let mut buffer = [0u8; MAX_BVLC_LENGTH];
            while !thread_stop.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buffer) {
                    Ok((len, peer)) => {
                        if let Some(reply) = serve(
                            &buffer[..len],
                            &devices,
                            &thread_writes,
                            &thread_who_is,
                            &thread_reads,
                            &drop_who_is,
                            &drop_read,
                        ) {
                            let _ = socket.send_to(&reply, peer);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(BacnetSimServerHandle {
            addr,
            stop,
            write_attempts,
            who_is_requests,
            read_requests,
        })
    }
}

fn serve(
    datagram: &[u8],
    devices: &[BacnetSimDevice],
    write_attempts: &AtomicUsize,
    who_is_requests: &AtomicUsize,
    read_requests: &AtomicUsize,
    drop_who_is: &AtomicBool,
    drop_read: &AtomicBool,
) -> Option<Vec<u8>> {
    let bvlc = parse_bvlc(datagram).ok()?;
    let apdu = bvlc.apdu;
    let header = *apdu.first()?;
    match header & 0xF0 {
        // Unconfirmed-Request: Who-Is (0x08).
        0x10 if apdu.get(1) == Some(&0x08) => {
            who_is_requests.fetch_add(1, Ordering::SeqCst);
            if drop_who_is.swap(false, Ordering::SeqCst) {
                return None;
            }
            let (low, high) = who_is_range(apdu);
            // One reply per matching device; encode the first match, since a
            // test client discovers one simulated device per port.
            let device = devices
                .iter()
                .find(|device| (low..=high).contains(&device.device_instance))?;
            let i_am = IAm::new(
                device.device_instance,
                device.max_apdu,
                device.segmentation,
                device.vendor_id,
            );
            encode_i_am(&i_am).ok()
        }
        // Confirmed-Request: ReadProperty or a write service.
        0x00 => {
            let service = *apdu.get(2)?;
            let invoke_id = *apdu.get(1)?;
            match service {
                0x0C => {
                    read_requests.fetch_add(1, Ordering::SeqCst);
                    if drop_read.swap(false, Ordering::SeqCst) {
                        return None;
                    }
                    let request = decode_read_property_apdu(apdu).ok()?;
                    if request.property != PropertyId::PRESENT_VALUE {
                        return Some(encode_error_pdu(
                            invoke_id,
                            service,
                            ERROR_CLASS_PROPERTY,
                            ERROR_CODE_UNKNOWN_PROPERTY,
                        ));
                    }
                    let key = (request.object.object_type, request.object.instance);
                    let Some(value) = devices.iter().find_map(|device| device.values.get(&key))
                    else {
                        return Some(encode_error_pdu(
                            invoke_id,
                            service,
                            ERROR_CLASS_OBJECT,
                            ERROR_CODE_UNKNOWN_OBJECT,
                        ));
                    };
                    Some(encode_read_property_ack(invoke_id, value))
                }
                SERVICE_WRITE_PROPERTY | SERVICE_WRITE_PROPERTY_MULTIPLE => {
                    write_attempts.fetch_add(1, Ordering::SeqCst);
                    Some(encode_error_pdu(
                        invoke_id,
                        service,
                        ERROR_CLASS_WRITE_ACCESS_DENIED,
                        ERROR_CODE_WRITE_ACCESS_DENIED,
                    ))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn who_is_range(apdu: &[u8]) -> (u32, u32) {
    if apdu.len() >= 8 {
        let low = ((apdu[2] as u32) << 16) | ((apdu[3] as u32) << 8) | apdu[4] as u32;
        let high = ((apdu[5] as u32) << 16) | ((apdu[6] as u32) << 8) | apdu[7] as u32;
        (low, high)
    } else {
        (0, 0x3F_FFFF)
    }
}
