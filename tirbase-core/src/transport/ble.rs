//! BLE transport bridge — cross-platform Bluetooth Low Energy transport for
//! TirBase mesh Deltas (native-only, gated behind `#[cfg(feature = "native")]`).
//!
//! Deltas are serialised, fragmented into ≤ 512-byte BLE chunks, written to a
//! custom TirBase GATT characteristic, and reassembled on the receiver using
//! the existing `ReassemblyBuffer`.

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;
use crate::transport::fragment::{reassemble, DeltaFragment, ReassemblyBuffer};

use btleplug::api::{Central, Manager as _, Peripheral, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral as PlatformPeripheral};
use std::time::Duration;
use tokio::time::timeout;
use libp2p::futures::StreamExt;

// ─── TirBase BLE service/characteristic UUIDs ─────────────────────────────────

pub const TIRBASE_BLE_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x0000beef_0000_1000_8000_00805f9b34fb);

pub const TIRBASE_BLE_CHAR_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x0000cafe_0000_1000_8000_00805f9b34fb);

// ─── BLE chunk framing ────────────────────────────────────────────────────────

/// Maximum bytes per BLE ATT write (BLE 4.x limit).
pub const BLE_MAX_CHUNK_SIZE: usize = 512;

/// Header prepended to each BLE chunk: 32-byte delta_id + 4-byte fragment_index + 4-byte total.
pub const BLE_CHUNK_HEADER_SIZE: usize = 40;

/// Maximum payload per BLE chunk after header overhead.
pub const BLE_MAX_PAYLOAD: usize = BLE_MAX_CHUNK_SIZE - BLE_CHUNK_HEADER_SIZE;

/// Fragment serialised Delta bytes into BLE-compatible chunks.
///
/// Each chunk is a `Vec<u8>` with the layout:
/// ```text
/// [  0.. 32) delta_id (32 bytes)
/// [ 32.. 36) fragment_index (u32 LE)
/// [ 36.. 40) total_fragments (u32 LE)
/// [ 40..   ) payload bytes (≤ BLE_MAX_PAYLOAD)
/// ```
pub fn fragment_for_ble(delta_id: [u8; 32], data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![];
    }

    let chunks: Vec<&[u8]> = data.chunks(BLE_MAX_PAYLOAD).collect();
    let total = chunks.len() as u32;

    chunks
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let mut buf = Vec::with_capacity(BLE_CHUNK_HEADER_SIZE + payload.len());
            buf.extend_from_slice(&delta_id);
            buf.extend_from_slice(&(i as u32).to_le_bytes());
            buf.extend_from_slice(&total.to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        })
        .collect()
}

/// Parse a single BLE chunk into a `DeltaFragment`.
pub fn parse_ble_chunk(chunk: &[u8]) -> Result<DeltaFragment, TirBaseError> {
    if chunk.len() < BLE_CHUNK_HEADER_SIZE {
        return Err(TirBaseError::FragmentReassemblyFailed {
            sender_did: "ble".to_string(),
            expected: 0,
        });
    }

    let mut delta_id = [0u8; 32];
    delta_id.copy_from_slice(&chunk[0..32]);
    let fragment_index = u32::from_le_bytes(chunk[32..36].try_into().unwrap());
    let total_fragments = u32::from_le_bytes(chunk[36..40].try_into().unwrap());
    let payload = chunk[40..].to_vec();

    Ok(DeltaFragment {
        delta_id,
        fragment_index,
        total_fragments,
        payload,
    })
}

/// Reassemble BLE chunks into the original Delta bytes using the `ReassemblyBuffer`.
pub fn reassemble_ble_chunks(
    chunks: Vec<Vec<u8>>,
    sender_did: &Did,
) -> Result<Vec<u8>, TirBaseError> {
    if chunks.is_empty() {
        return Err(TirBaseError::FragmentReassemblyFailed {
            sender_did: sender_did.clone(),
            expected: 0,
        });
    }

    let first = parse_ble_chunk(&chunks[0])?;
    let total = first.total_fragments as usize;

    if chunks.len() != total {
        return Err(TirBaseError::FragmentReassemblyFailed {
            sender_did: sender_did.clone(),
            expected: first.total_fragments,
        });
    }

    let mut fragments = Vec::with_capacity(total);
    for chunk in chunks {
        fragments.push(parse_ble_chunk(&chunk)?);
    }

    // Delegate to the canonical reassemble() for validation + concatenation.
    reassemble(fragments, sender_did)
}

// ─── BleAdapter ───────────────────────────────────────────────────────────────

/// Wraps a platform BLE adapter and manages a single BLE peer connection.
pub struct BleAdapter {
    pub adapter: Adapter,
    pub peripheral: Option<PlatformPeripheral>,
    pub connected: bool,
    pub local_did: Did,
    pub peer_did: Did,
    pub char_handle: Option<btleplug::api::Characteristic>,
}

impl BleAdapter {
    /// Create a new `BleAdapter` from the first available platform BLE adapter.
    pub async fn new(local_did: Did, peer_did: Did) -> Result<Self, TirBaseError> {
        let manager = Manager::new()
            .await
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("BLE manager init failed: {e}"),
            })?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("BLE adapter enumeration failed: {e}"),
            })?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "no BLE adapter found".to_string(),
            })?;

        Ok(Self {
            adapter,
            peripheral: None,
            connected: false,
            local_did,
            peer_did,
            char_handle: None,
        })
    }

    /// Scan for the TirBase BLE service and connect to the first matching peripheral (central role).
    pub async fn scan_and_connect(&mut self, scan_timeout_secs: u64) -> Result<(), TirBaseError> {
        self.adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("BLE scan start failed: {e}"),
            })?;

        let result = timeout(Duration::from_secs(scan_timeout_secs), async {
            loop {
                let peripherals = self.adapter.peripherals().await.map_err(|e| {
                    TirBaseError::MeshUnavailable {
                        reason: format!("BLE peripherals enumeration failed: {e}"),
                    }
                })?;

                for p in peripherals {
                    let props = p.properties().await.map_err(|e| {
                        TirBaseError::MeshUnavailable {
                            reason: format!("BLE peripheral properties failed: {e}"),
                        }
                    })?;

                    if let Some(props) = props {
                    if props
                        .services
                        .iter()
                        .any(|s| *s == TIRBASE_BLE_SERVICE_UUID)
                        {
                            p.connect()
                                .await
                                .map_err(|e| TirBaseError::MeshUnavailable {
                                    reason: format!("BLE connect failed: {e}"),
                                })?;

                            p.discover_services()
                                .await
                                .map_err(|e| TirBaseError::MeshUnavailable {
                                    reason: format!("BLE discover services failed: {e}"),
                                })?;

                            let services = p.services();
                            let chr = services
                                .iter()
                                .flat_map(|s| &s.characteristics)
                                .find(|c| c.uuid == TIRBASE_BLE_CHAR_UUID)
                                .cloned()
                                .ok_or_else(|| TirBaseError::MeshUnavailable {
                                    reason: "BLE characteristic not found".to_string(),
                                })?;

                            self.peripheral = Some(p);
                            self.connected = true;
                            self.char_handle = Some(chr);
                            return Ok(());
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await;

        self.adapter
            .stop_scan()
            .await
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("BLE scan stop failed: {e}"),
            })?;

        result.unwrap_or(Err(TirBaseError::MeshUnavailable {
            reason: format!("BLE scan timed out after {scan_timeout_secs}s"),
        }))
    }

    /// Send a list of BLE chunks to the connected peer.
    pub async fn send_chunks(&mut self, chunks: &[Vec<u8>]) -> Result<(), TirBaseError> {
        let chr = self
            .char_handle
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "BLE not connected — no characteristic".to_string(),
            })?;

        let peripheral = self
            .peripheral
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "BLE not connected — no peripheral".to_string(),
            })?;

        for chunk in chunks {
            peripheral
                .write(chr, chunk, WriteType::WithResponse)
                .await
                .map_err(|e| TirBaseError::MeshUnavailable {
                    reason: format!("BLE write failed: {e}"),
                })?;
        }
        Ok(())
    }

    /// Subscribe to notifications on the TirBase characteristic and return
    /// an async stream of received `Vec<u8>` chunks.
    pub async fn subscribe_notifications(
        &mut self,
    ) -> Result<tokio::sync::mpsc::Receiver<Vec<u8>>, TirBaseError> {
        let chr = self
            .char_handle
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "BLE not connected — no characteristic".to_string(),
            })?;

        let peripheral = self
            .peripheral
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "BLE not connected — no peripheral".to_string(),
            })?;

        peripheral
            .subscribe(chr)
            .await
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("BLE subscribe failed: {e}"),
            })?;

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        let peripheral = self.peripheral.take().unwrap();
        let peripheral_clone = peripheral.clone();
        let chr_clone = chr.clone();

        tokio::spawn(async move {
            let mut notifications = match peripheral_clone.notifications().await {
                Ok(stream) => stream,
                Err(_) => return,
            };

            loop {
                match notifications.next().await {
                    Some(notification) => {
                        if notification.uuid == chr_clone.uuid {
                            let _ = tx.send(notification.value).await;
                        }
                    }
                    None => break,
                }
            }
        });

        self.peripheral = Some(peripheral);
        Ok(rx)
    }

    /// Disconnect from the peer.
    pub async fn disconnect(&mut self) -> Result<(), TirBaseError> {
        if let Some(peripheral) = &self.peripheral {
            peripheral
                .disconnect()
                .await
                .map_err(|e| TirBaseError::MeshUnavailable {
                    reason: format!("BLE disconnect failed: {e}"),
                })?;
        }
        self.connected = false;
        self.peripheral = None;
        self.char_handle = None;
        Ok(())
    }
}
