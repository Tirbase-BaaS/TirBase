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
use libp2p::futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;

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
/// [ 0.. 32) delta_id (32 bytes)
/// [ 32.. 36) fragment_index (u32 LE)
/// [ 36.. 40) total_fragments (u32 LE)
/// [ 40.. ) payload bytes (≤ BLE_MAX_PAYLOAD)
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

/// Stable chunk-group id for a framed `GossipMessage` payload.
///
/// BLE chunks are grouped by this 32-byte id so several Deltas can be in
/// flight on the same characteristic without interleaving. It is derived from
/// the payload itself (SHA-256), so both ends agree without a side channel and
/// two different payloads can never share an assembly slot.
pub fn chunk_id_for(payload: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut id = [0u8; 32];
    id.copy_from_slice(Sha256::digest(payload).as_slice());
    id
}

/// The radio half of the BLE bridge.
///
/// `run_ble_bridge` owns all framing, chunking, assembly and dispatch; a
/// `BleLink` only moves already-framed chunks. The production implementation
/// ([`BleAdapter`]) writes GATT characteristics; tests supply an in-memory
/// link, so the CI proof exercises the same framing/bridge code as the radio
/// path rather than a parallel implementation.
#[async_trait::async_trait]
pub trait BleLink: Send {
    /// Write one framed chunk to the peer characteristic.
    async fn send_chunk(&mut self, chunk: &[u8]) -> Result<(), TirBaseError>;

    /// Receive the next framed chunk, or `Ok(None)` once the link is closed.
    async fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>, TirBaseError>;
}

/// In-progress BLE chunk assemblies, keyed by [`chunk_id_for`].
///
/// Out-of-order chunks are accepted, duplicate chunk indices are idempotent
/// (the later copy replaces the earlier one), inconsistent `total_fragments`
/// for the same id is a clean failure, and a finished assembly is handed to
/// the canonical `fragment::reassemble` for validation.
#[derive(Debug, Default)]
pub struct BleChunkAssembler {
    pending: std::collections::BTreeMap<[u8; 32], Vec<DeltaFragment>>,
    /// Recently completed chunk groups (a retransmitted chunk is a no-op).
    completed: std::collections::VecDeque<[u8; 32]>,
}

impl BleChunkAssembler {
    /// Feed one chunk. Returns the complete payload bytes once every fragment
    /// of that group has arrived, `None` while still incomplete.
    pub fn push_chunk(&mut self, chunk: Vec<u8>) -> Result<Option<Vec<u8>>, TirBaseError> {
        let fragment = parse_ble_chunk(&chunk)?;
        let id = fragment.delta_id;
        let total = fragment.total_fragments;

        if self.completed.contains(&id) {
            return Ok(None);
        }

        let sender_did = format!("ble-{}", hex::encode(id));

        if total == 0 || fragment.fragment_index >= total {
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did,
                expected: total,
            });
        }

        // Reject a group whose chunks disagree about the fragment count; drop
        // the whole assembly so a malformed stream cannot wedge the slot.
        if let Some(existing) = self.pending.get(&id) {
            if existing.iter().any(|f| f.total_fragments != total) {
                self.pending.remove(&id);
                return Err(TirBaseError::FragmentReassemblyFailed {
                    sender_did,
                    expected: total,
                });
            }
        }

        let entry = self.pending.entry(id).or_default();
        if let Some(slot) = entry
            .iter_mut()
            .find(|f| f.fragment_index == fragment.fragment_index)
        {
            *slot = fragment;
        } else {
            entry.push(fragment);
        }

        let complete = self
            .pending
            .get(&id)
            .map(|frags| frags.len() == total as usize)
            .unwrap_or(false);
        if !complete {
            return Ok(None);
        }

        let fragments = self.pending.remove(&id).expect("checked above");
        let bytes = reassemble(fragments, &sender_did)?;
        self.completed.push_back(id);
        while self.completed.len() > crate::transport::fragment::MAX_COMPLETED_ASSEMBLIES {
            self.completed.pop_front();
        }
        Ok(Some(bytes))
    }

    /// Number of groups still incomplete (bounded by the link's in-flight set).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Drive the BLE bridge until the outbound channel closes or the link ends.
///
/// Outbound: every framed `GossipMessage` received on `outbound_rx` is split
/// into BLE chunks ([`fragment_for_ble`]) and written to the link.
///
/// Inbound: every notified chunk is fed to [`BleChunkAssembler`]; a completed
/// payload is parsed as a `GossipMessage` and pushed to `inbound_tx`, which the
/// transport drains through `poll_ble_inbound` → `process_wire_message`.
///
/// Production caller: `MeshTransport::start` spawns this with the platform
/// [`BleAdapter`]; CI passes an emulated link through
/// `MeshTransport::bind_ble_link`.
pub async fn run_ble_bridge<L: BleLink>(
    mut link: L,
    mut outbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    inbound_tx: tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>,
) {
    use crate::transport::message::GossipMessage;

    let mut assembler = BleChunkAssembler::default();

    loop {
        tokio::select! {
            outbound = outbound_rx.recv() => {
                let Some(payload) = outbound else {
                    // Transport dropped its sender: nothing more will be sent.
                    return;
                };
                let chunks = fragment_for_ble(chunk_id_for(&payload), &payload);
                for chunk in &chunks {
                    if let Err(e) = link.send_chunk(chunk).await {
                        crate::events::emit_transport(
                            crate::events::Severity::Medium,
                            crate::events::ReasonCode::HandshakeFailed,
                            None,
                            format!("[transport] BLE send failed: {e}"),
                        );
                        return;
                    }
                }
            }
            received = link.recv_chunk() => {
                match received {
                    Ok(Some(chunk)) => match assembler.push_chunk(chunk) {
                        Ok(Some(bytes)) => match GossipMessage::from_bytes(&bytes) {
                            Some(msg) => {
                                if inbound_tx.send(msg).await.is_err() {
                                    return;
                                }
                            }
                            None => crate::events::emit_transport(
                                crate::events::Severity::Medium,
                                crate::events::ReasonCode::FragmentReassemblyFailed,
                                None,
                                "[transport] BLE reassembly produced a non-GossipMessage payload".to_string(),
                            ),
                        },
                        Ok(None) => {}
                        Err(e) => crate::events::emit_transport(
                            crate::events::Severity::Medium,
                            crate::events::ReasonCode::FragmentReassemblyFailed,
                            None,
                            format!("[transport] BLE reassembly failed: {e}"),
                        ),
                    },
                    Ok(None) => return,
                    Err(e) => {
                        crate::events::emit_transport(
                            crate::events::Severity::Medium,
                            crate::events::ReasonCode::HandshakeFailed,
                            None,
                            format!("[transport] BLE receive failed: {e}"),
                        );
                        return;
                    }
                }
            }
        }
    }
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
    /// Notification stream receiver installed by `subscribe_notifications`.
    notify_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
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
            notify_rx: None,
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
                    let props =
                        p.properties()
                            .await
                            .map_err(|e| TirBaseError::MeshUnavailable {
                                reason: format!("BLE peripheral properties failed: {e}"),
                            })?;

                    if let Some(props) = props {
                        if props.services.contains(&TIRBASE_BLE_SERVICE_UUID) {
                            p.connect()
                                .await
                                .map_err(|e| TirBaseError::MeshUnavailable {
                                    reason: format!("BLE connect failed: {e}"),
                                })?;

                            p.discover_services().await.map_err(|e| {
                                TirBaseError::MeshUnavailable {
                                    reason: format!("BLE discover services failed: {e}"),
                                }
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

 /// Subscribe to notifications on the TirBase characteristic.
 ///
 /// Received chunks are delivered through [`BleAdapter::take_notifications`]
 /// (the bridge runner owns receive scheduling); the subscription itself is a
 /// radio operation, not part of the framing loop.
    pub async fn subscribe_notifications(&mut self) -> Result<(), TirBaseError> {
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

            while let Some(notification) = notifications.next().await {
                if notification.uuid == chr_clone.uuid {
                    let _ = tx.send(notification.value).await;
                }
            }
        });

        self.peripheral = Some(peripheral);
        self.notify_rx = Some(rx);
        Ok(())
    }

 /// Move the notification receiver out of the adapter (used by the bridge
 /// runner, which owns receive scheduling).
    pub fn take_notifications(&mut self) -> Option<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        self.notify_rx.take()
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
        self.notify_rx = None;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BleLink for BleAdapter {
    async fn send_chunk(&mut self, chunk: &[u8]) -> Result<(), TirBaseError> {
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
            .write(chr, chunk, WriteType::WithResponse)
            .await
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("BLE write failed: {e}"),
            })
    }

    async fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>, TirBaseError> {
        match self.notify_rx.as_mut() {
            Some(rx) => Ok(rx.recv().await),
            None => Ok(None),
        }
    }
}
