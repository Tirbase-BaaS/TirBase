// SPDX-License-Identifier: AGPL-3.0-only

//! OSDP: frame codec, secure channel (SCS12/SCS13), polling and status.
//!
//! # Frames
//!
//! `SOM 0x53 | ADDR | LEN(LE, whole packet) | CTRL | payload | CRC-16(LE)`.
//! `CTRL` bits: 0–1 sequence, 2 = 16-bit CRC (set; the 8-bit checksum form is
//! refused), 3 = security control block present. The CRC is CRC-16/AUG-CCITT
//! (poly `0x1021`, init `0x1FFF`).
//!
//! # Secure channel
//!
//! Implemented types are **SCS12** (AES-128, 4-byte CMAC) and **SCS13**
//! (AES-256, 8-byte CMAC). Both sides derive
//!
//! ```text
//! S-ENC  = CMAC(K, 0x01 || RND.C || RND.PD)
//! S-MAC  = CMAC(K, 0x02 || RND.C || RND.PD)
//! C-MAC  = CMAC(S-MAC, RND.C || RND.PD)[..8]
//! R-MAC  = CMAC(S-MAC, RND.PD || RND.C)
//! ```
//!
//! and start MAC chaining at `R-MAC`. Each secure block carries the SCS code
//! and a SID (`0` clear payload, `1` encrypted payload); the payload is
//! AES-CBC encrypted under `S-ENC` with the complement of the current chain as
//! IV and authenticated with a CMAC over the chain, the frame header and the
//! ciphertext. One chain is advanced by every frame in both directions, so a
//! dropped, reordered or replayed block fails the next MAC check.
//!
//! Device I/O is the caller's: this module only builds and consumes bytes.

use std::fmt;

use crate::crypto::{
    cbc_decrypt, cbc_encrypt, cmac, constant_time_eq, CryptoError,
};

/// Start of message.
pub const SOM: u8 = 0x53;
/// Set in `ADDR` on a reply.
pub const ADDR_REPLY_FLAG: u8 = 0x80;
/// Broadcast address.
pub const BROADCAST_ADDRESS: u8 = 0x7F;
/// Largest accepted frame, including header and CRC.
pub const MAX_FRAME_LEN: usize = 2048;

/// Poll.
pub const CMD_POLL: u8 = 0x60;
/// Local status report request.
pub const CMD_LSTAT: u8 = 0x64;
/// Reader status tamper report request.
pub const CMD_RSTAT: u8 = 0x67;
/// Encryption key set.
pub const CMD_KEYSET: u8 = 0x75;
/// Challenge / secure session initialisation.
pub const CMD_CHLNG: u8 = 0x76;
/// Server random number and cryptogram.
pub const CMD_SCRYPT: u8 = 0x77;

/// Acknowledged.
pub const REPLY_ACK: u8 = 0x40;
/// Negative acknowledgement.
pub const REPLY_NAK: u8 = 0x41;
/// Local status report.
pub const REPLY_LSTATR: u8 = 0x48;
/// Raw card data.
pub const REPLY_RAW: u8 = 0x50;
/// Challenge reply (secure channel step 2).
pub const REPLY_CCRYPT: u8 = 0x76;
/// Initial reply MAC (secure channel step 4).
pub const REPLY_RMAC_I: u8 = 0x78;

const CTRL_SEQUENCE_MASK: u8 = 0x03;
const CTRL_CRC: u8 = 0x04;
const CTRL_SCB: u8 = 0x08;

/// A rejected OSDP frame or secure-channel operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsdpError {
    FrameTooShort(usize),
    FrameTooLong(usize),
    BadSom(u8),
    BadLength { declared: usize, actual: usize },
    UnsupportedChecksum,
    BadCrc,
    InvalidAddress(u8),
    ScbTooShort(usize),
    ScbLengthMismatch { declared: usize, actual: usize },
    UnsupportedScs(u8),
    ScsMismatch { expected: u8, found: u8 },
    MacMismatch,
    NotSecure,
    AlreadySecure,
    NoHandshake,
    UnexpectedSecure,
    UnexpectedReply(u8),
    BadChallenge,
    Crypto(CryptoError),
}

impl fmt::Display for OsdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsdpError::FrameTooShort(len) => write!(f, "osdp frame too short: {len} bytes"),
            OsdpError::FrameTooLong(len) => write!(f, "osdp frame too long: {len} bytes"),
            OsdpError::BadSom(byte) => write!(f, "bad osdp start of message: 0x{byte:02X}"),
            OsdpError::BadLength { declared, actual } => {
                write!(f, "osdp length {declared} does not match {actual} bytes")
            }
            OsdpError::UnsupportedChecksum => {
                write!(f, "osdp 8-bit checksum frames are refused; CRC is required")
            }
            OsdpError::BadCrc => write!(f, "osdp CRC mismatch"),
            OsdpError::InvalidAddress(address) => write!(f, "invalid osdp address: 0x{address:02X}"),
            OsdpError::ScbTooShort(len) => write!(f, "osdp security block too short: {len} bytes"),
            OsdpError::ScbLengthMismatch { declared, actual } => {
                write!(f, "osdp security block length {declared} does not match {actual}")
            }
            OsdpError::UnsupportedScs(code) => {
                write!(f, "unsupported osdp secure channel type: 0x{code:02X}")
            }
            OsdpError::ScsMismatch { expected, found } => {
                write!(f, "osdp secure channel type {found} != {expected}")
            }
            OsdpError::MacMismatch => write!(f, "osdp MAC mismatch"),
            OsdpError::NotSecure => write!(f, "osdp secure channel is not established"),
            OsdpError::AlreadySecure => write!(f, "osdp secure channel is already established"),
            OsdpError::NoHandshake => write!(f, "no osdp secure-channel handshake in progress"),
            OsdpError::UnexpectedSecure => write!(f, "expected a plain osdp frame"),
            OsdpError::UnexpectedReply(code) => {
                write!(f, "unexpected osdp reply code: 0x{code:02X}")
            }
            OsdpError::BadChallenge => write!(f, "osdp challenge did not match"),
            OsdpError::Crypto(error) => write!(f, "crypto: {error}"),
        }
    }
}

impl std::error::Error for OsdpError {}

impl From<CryptoError> for OsdpError {
    fn from(error: CryptoError) -> Self {
        OsdpError::Crypto(error)
    }
}

/// CRC-16/AUG-CCITT used by OSDP (init `0x1FFF`, poly `0x1021`).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0x1FFFu16;
    for byte in data {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// A decoded command or reply frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsdpFrame {
    pub address: u8,
    pub sequence: u8,
    /// True when a security control block is present.
    pub secure: bool,
    /// Command/reply code and data (or a security control block).
    pub payload: Vec<u8>,
}

impl OsdpFrame {
    /// Encode a plain (non-secured) frame.
    pub fn encode(&self) -> Result<Vec<u8>, OsdpError> {
        let total = 5 + self.payload.len() + 2;
        if total > MAX_FRAME_LEN {
            return Err(OsdpError::FrameTooLong(total));
        }
        let mut out = Vec::with_capacity(total);
        out.push(SOM);
        out.push(self.address);
        out.extend_from_slice(&(total as u16).to_le_bytes());
        out.push(self.control());
        out.extend_from_slice(&self.payload);
        let crc = crc16(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    fn control(&self) -> u8 {
        (self.sequence & CTRL_SEQUENCE_MASK)
            | CTRL_CRC
            | if self.secure { CTRL_SCB } else { 0 }
    }

    /// Decode and validate a frame: SOM, length, CRC mode and CRC.
    pub fn decode(bytes: &[u8]) -> Result<Self, OsdpError> {
        if bytes.len() < 8 {
            return Err(OsdpError::FrameTooShort(bytes.len()));
        }
        if bytes[0] != SOM {
            return Err(OsdpError::BadSom(bytes[0]));
        }
        let declared = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        if declared > MAX_FRAME_LEN {
            return Err(OsdpError::FrameTooLong(declared));
        }
        if declared != bytes.len() {
            return Err(OsdpError::BadLength {
                declared,
                actual: bytes.len(),
            });
        }
        let ctrl = bytes[4];
        if ctrl & CTRL_CRC == 0 {
            return Err(OsdpError::UnsupportedChecksum);
        }
        let expected = u16::from_le_bytes([bytes[declared - 2], bytes[declared - 1]]);
        if crc16(&bytes[..declared - 2]) != expected {
            return Err(OsdpError::BadCrc);
        }
        Ok(Self {
            address: bytes[1],
            sequence: ctrl & CTRL_SEQUENCE_MASK,
            secure: ctrl & CTRL_SCB != 0,
            payload: bytes[5..declared - 2].to_vec(),
        })
    }
}

/// Supported OSDP secure channel types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scs {
    /// AES-128 with a 4-byte CMAC.
    Scs12,
    /// AES-256 with an 8-byte CMAC.
    Scs13,
}

impl Scs {
    pub fn code(self) -> u8 {
        match self {
            Scs::Scs12 => 0x12,
            Scs::Scs13 => 0x13,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, OsdpError> {
        match code {
            0x12 => Ok(Scs::Scs12),
            0x13 => Ok(Scs::Scs13),
            other => Err(OsdpError::UnsupportedScs(other)),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Scs::Scs12 => 16,
            Scs::Scs13 => 32,
        }
    }

    pub fn mac_len(self) -> usize {
        match self {
            Scs::Scs12 => 4,
            Scs::Scs13 => 8,
        }
    }
}

/// Derived secure-channel state for one reader.
#[derive(Clone, Debug)]
pub struct SecureChannel {
    scs: Scs,
    s_enc: crate::crypto::AesKey,
    s_mac: crate::crypto::AesKey,
    mac_chain: [u8; 16],
    sealed: u32,
}

impl SecureChannel {
    /// Derive session keys and the initial MAC chain from a base key and the
    /// two random values.
    pub(crate) fn derive(
        scs: Scs,
        master: &crate::crypto::AesKey,
        rnd_c: &[u8; 8],
        rnd_pd: &[u8; 8],
    ) -> Result<(Self, [u8; 8], [u8; 16]), OsdpError> {
        if master.len() != scs.key_len() {
            return Err(OsdpError::Crypto(CryptoError::InvalidKeyLength(master.len())));
        }
        let mut input = Vec::with_capacity(17);
        input.push(0x01);
        input.extend_from_slice(rnd_c);
        input.extend_from_slice(rnd_pd);
        let s_enc = crate::crypto::AesKey::new(&cmac(master, &input))?;
        input[0] = 0x02;
        let s_mac = crate::crypto::AesKey::new(&cmac(master, &input))?;

        let mut cp = Vec::with_capacity(16);
        cp.extend_from_slice(rnd_c);
        cp.extend_from_slice(rnd_pd);
        let c_mac_full = cmac(&s_mac, &cp);
        let mut pc = Vec::with_capacity(16);
        pc.extend_from_slice(rnd_pd);
        pc.extend_from_slice(rnd_c);
        let r_mac = cmac(&s_mac, &pc);

        let mut c_mac = [0u8; 8];
        c_mac.copy_from_slice(&c_mac_full[..8]);
        Ok((
            Self {
                scs,
                s_enc,
                s_mac,
                mac_chain: r_mac,
                sealed: 0,
            },
            c_mac,
            r_mac,
        ))
    }

    pub fn scs(&self) -> Scs {
        self.scs
    }

    pub fn mac_chain(&self) -> [u8; 16] {
        self.mac_chain
    }

    pub fn sealed_blocks(&self) -> u32 {
        self.sealed
    }

    pub(crate) fn set_chain(&mut self, chain: [u8; 16]) {
        self.mac_chain = chain;
    }

    /// Seal a payload into a complete frame.
    pub fn seal(
        &mut self,
        address: u8,
        sequence: u8,
        payload: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>, OsdpError> {
        let sid = u8::from(encrypt);
        let body = if encrypt {
            let mut plain = payload.to_vec();
            crate::crypto::pad_eom(&mut plain);
            let mut iv = self.mac_chain;
            for byte in iv.iter_mut() {
                *byte = !*byte;
            }
            cbc_encrypt(&self.s_enc, &iv, &plain)?
        } else {
            payload.to_vec()
        };

        let mac_len = self.scs.mac_len();
        let scb_len = 3 + body.len() + mac_len;
        if scb_len > u8::MAX as usize {
            return Err(OsdpError::FrameTooLong(scb_len));
        }
        let total = 5 + scb_len + 2;
        let control = (sequence & CTRL_SEQUENCE_MASK) | CTRL_CRC | CTRL_SCB;

        let mut out = Vec::with_capacity(total);
        out.push(SOM);
        out.push(address);
        out.extend_from_slice(&(total as u16).to_le_bytes());
        out.push(control);
        out.push(scb_len as u8);
        out.push(self.scs.code());
        out.push(sid);
        out.extend_from_slice(&body);

        let mut mac_input = Vec::with_capacity(16 + out.len());
        mac_input.extend_from_slice(&self.mac_chain);
        mac_input.extend_from_slice(&out[1..]);
        let mac = cmac(&self.s_mac, &mac_input);
        self.mac_chain = mac;
        out.extend_from_slice(&mac[..mac_len]);

        let crc = crc16(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        self.sealed = self.sealed.saturating_add(1);
        Ok(out)
    }

    /// Verify and open a secured frame.
    pub fn open(&mut self, frame: &OsdpFrame) -> Result<Vec<u8>, OsdpError> {
        if !frame.secure {
            return Err(OsdpError::UnexpectedSecure);
        }
        let payload = &frame.payload;
        let mac_len = self.scs.mac_len();
        if payload.len() < 3 + mac_len {
            return Err(OsdpError::ScbTooShort(payload.len()));
        }
        let scb_len = usize::from(payload[0]);
        if scb_len != payload.len() {
            return Err(OsdpError::ScbLengthMismatch {
                declared: scb_len,
                actual: payload.len(),
            });
        }
        if payload[1] != self.scs.code() {
            return Err(OsdpError::ScsMismatch {
                expected: self.scs.code(),
                found: payload[1],
            });
        }
        let sid = payload[2];
        let body_end = payload.len() - mac_len;
        let body = &payload[3..body_end];
        let mac_field = &payload[body_end..];

        let chain_before = self.mac_chain;
        let total = 5 + payload.len() + 2;
        let control = (frame.sequence & CTRL_SEQUENCE_MASK) | CTRL_CRC | CTRL_SCB;
        let mut mac_input = Vec::with_capacity(16 + 1 + 2 + 1 + body_end);
        mac_input.extend_from_slice(&chain_before);
        mac_input.push(frame.address);
        mac_input.extend_from_slice(&(total as u16).to_le_bytes());
        mac_input.push(control);
        mac_input.extend_from_slice(&payload[..body_end]);
        let mac = cmac(&self.s_mac, &mac_input);
        if !constant_time_eq(mac_field, &mac[..mac_len]) {
            return Err(OsdpError::MacMismatch);
        }
        self.mac_chain = mac;

        match sid {
            0 => Ok(body.to_vec()),
            1 => {
                let mut iv = chain_before;
                for byte in iv.iter_mut() {
                    *byte = !*byte;
                }
                let plain = cbc_decrypt(&self.s_enc, &iv, body)?;
                Ok(crate::crypto::unpad_eom(&plain)?.to_vec())
            }
            other => Err(OsdpError::ScbLengthMismatch {
                declared: usize::from(other),
                actual: body.len(),
            }),
        }
    }
}

/// PD local status: tamper, power and supervised inputs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdStatus {
    pub tamper: bool,
    pub power_cycle: bool,
    pub power_fault: bool,
    pub battery_low: bool,
    pub rex: bool,
    pub aux_input: bool,
}

impl PdStatus {
    /// Decode a 3-byte LSTATR body.
    pub fn decode(body: &[u8]) -> Result<Self, OsdpError> {
        if body.len() < 3 {
            return Err(OsdpError::FrameTooShort(body.len()));
        }
        Ok(Self {
            tamper: body[0] & 0x01 != 0,
            power_cycle: body[0] & 0x02 != 0,
            power_fault: body[1] & 0x01 != 0 || body[1] & 0x08 != 0,
            battery_low: body[1] & 0x02 != 0,
            rex: body[2] & 0x01 != 0,
            aux_input: body[2] & 0x02 != 0,
        })
    }

    /// Encode the 3-byte LSTATR body.
    pub(crate) fn encode(&self) -> [u8; 3] {
        let mut body = [0u8; 3];
        if self.tamper {
            body[0] |= 0x01;
        }
        if self.power_cycle {
            body[0] |= 0x02;
        }
        if self.power_fault {
            body[1] |= 0x01;
        }
        if self.battery_low {
            body[1] |= 0x02;
        }
        if self.rex {
            body[2] |= 0x01;
        }
        if self.aux_input {
            body[2] |= 0x02;
        }
        body
    }
}

/// Card data delivered in a RAW reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardRead {
    pub reader_no: u8,
    pub format: u8,
    pub bit_count: u16,
    pub data: Vec<u8>,
}

impl CardRead {
    pub(crate) fn decode(body: &[u8]) -> Result<Self, OsdpError> {
        if body.len() < 4 {
            return Err(OsdpError::FrameTooShort(body.len()));
        }
        let bit_count = u16::from_le_bytes([body[2], body[3]]);
        let expected = usize::from(bit_count).div_ceil(8);
        if body.len() < 4 + expected {
            return Err(OsdpError::FrameTooShort(body.len()));
        }
        Ok(Self {
            reader_no: body[0],
            format: body[1],
            bit_count,
            data: body[4..4 + expected].to_vec(),
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + self.data.len());
        body.push(self.reader_no);
        body.push(self.format);
        body.extend_from_slice(&self.bit_count.to_le_bytes());
        body.extend_from_slice(&self.data);
        body
    }
}

/// A parsed reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsdpReply {
    Ack,
    Nak(u8),
    Status(PdStatus),
    Card(CardRead),
    RmacI([u8; 16]),
    Ccrypt([u8; 16]),
    Other { code: u8, data: Vec<u8> },
}

impl OsdpReply {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, OsdpError> {
        let Some(code) = payload.first().copied() else {
            return Err(OsdpError::FrameTooShort(0));
        };
        let body = &payload[1..];
        Ok(match code {
            REPLY_ACK => OsdpReply::Ack,
            REPLY_NAK => OsdpReply::Nak(body.first().copied().unwrap_or(0)),
            REPLY_LSTATR => OsdpReply::Status(PdStatus::decode(body)?),
            REPLY_RAW => OsdpReply::Card(CardRead::decode(body)?),
            REPLY_CCRYPT => {
                if body.len() < 16 {
                    return Err(OsdpError::FrameTooShort(body.len()));
                }
                let mut cryptogram = [0u8; 16];
                cryptogram.copy_from_slice(&body[..16]);
                OsdpReply::Ccrypt(cryptogram)
            }
            REPLY_RMAC_I => {
                if body.len() < 16 {
                    return Err(OsdpError::FrameTooShort(body.len()));
                }
                let mut mac = [0u8; 16];
                mac.copy_from_slice(&body[..16]);
                OsdpReply::RmacI(mac)
            }
            other => OsdpReply::Other {
                code: other,
                data: body.to_vec(),
            },
        })
    }
}

struct Handshake {
    master: crate::crypto::AesKey,
    scs: Scs,
    rnd_c: [u8; 8],
    c_mac: [u8; 8],
    r_mac: [u8; 16],
}

/// Control-panel side of one OSDP reader link.
pub struct OsdpPoller {
    address: u8,
    sequence: u8,
    channel: Option<SecureChannel>,
    handshake: Option<Handshake>,
    tamper_events: u32,
    status: Option<PdStatus>,
    secure_failures: u32,
}

impl OsdpPoller {
    /// Create a poller for a PD address (0x00–0x7E).
    pub fn new(address: u8) -> Result<Self, OsdpError> {
        if address > 0x7E {
            return Err(OsdpError::InvalidAddress(address));
        }
        Ok(Self {
            address,
            sequence: 0,
            channel: None,
            handshake: None,
            tamper_events: 0,
            status: None,
            secure_failures: 0,
        })
    }

    pub fn address(&self) -> u8 {
        self.address
    }

    pub fn is_secure(&self) -> bool {
        self.channel.is_some()
    }

    pub fn scs(&self) -> Option<Scs> {
        self.channel.as_ref().map(SecureChannel::scs)
    }

    pub fn last_status(&self) -> Option<PdStatus> {
        self.status
    }

    /// Number of status reports that showed tamper.
    pub fn tamper_events(&self) -> u32 {
        self.tamper_events
    }

    /// Number of secure frames rejected by the MAC.
    pub fn secure_failures(&self) -> u32 {
        self.secure_failures
    }

    fn next_sequence(&mut self) -> u8 {
        let sequence = self.sequence;
        self.sequence = (self.sequence + 1) & CTRL_SEQUENCE_MASK;
        sequence
    }

    fn plain_frame(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, OsdpError> {
        let sequence = self.next_sequence();
        OsdpFrame {
            address: self.address,
            sequence,
            secure: false,
            payload,
        }
        .encode()
    }

    /// Step 1: send `CHLNG` with the caller's 8-byte client random.
    pub fn begin_secure_channel(
        &mut self,
        scs: Scs,
        master: &crate::crypto::AesKey,
        rnd_c: [u8; 8],
    ) -> Result<Vec<u8>, OsdpError> {
        if self.channel.is_some() {
            return Err(OsdpError::AlreadySecure);
        }
        if master.len() != scs.key_len() {
            return Err(OsdpError::Crypto(CryptoError::InvalidKeyLength(master.len())));
        }
        let mut payload = Vec::with_capacity(9);
        payload.push(CMD_CHLNG);
        payload.extend_from_slice(&rnd_c);
        self.handshake = Some(Handshake {
            master: master.duplicate(),
            scs,
            rnd_c,
            c_mac: [0u8; 8],
            r_mac: [0u8; 16],
        });
        self.plain_frame(payload)
    }

    /// Step 2: verify `CCRYPT` and derive session keys.
    pub fn accept_ccrypt(&mut self, bytes: &[u8]) -> Result<(), OsdpError> {
        let frame = OsdpFrame::decode(bytes)?;
        if frame.secure {
            return Err(OsdpError::UnexpectedSecure);
        }
        let code = frame.payload.first().copied().unwrap_or(0);
        if code != REPLY_CCRYPT {
            return Err(OsdpError::UnexpectedReply(code));
        }
        let body = &frame.payload[1..];
        if body.len() < 24 {
            return Err(OsdpError::FrameTooShort(body.len()));
        }
        let mut handshake = self.handshake.take().ok_or(OsdpError::NoHandshake)?;
        let zero_iv = [0u8; 16];
        let plain = cbc_decrypt(&handshake.master, &zero_iv, &body[..16])?;
        if !constant_time_eq(&plain[..8], &handshake.rnd_c) {
            self.handshake = Some(handshake);
            return Err(OsdpError::BadChallenge);
        }
        let mut rnd_pd = [0u8; 8];
        rnd_pd.copy_from_slice(&plain[8..16]);
        let (channel, c_mac, r_mac) =
            SecureChannel::derive(handshake.scs, &handshake.master, &handshake.rnd_c, &rnd_pd)?;
        if !constant_time_eq(&body[16..24], &r_mac[..8]) {
            self.handshake = Some(handshake);
            self.secure_failures = self.secure_failures.saturating_add(1);
            return Err(OsdpError::MacMismatch);
        }
        handshake.c_mac = c_mac;
        handshake.r_mac = r_mac;
        self.channel = Some(channel);
        self.handshake = Some(handshake);
        Ok(())
    }

    /// Step 3: send `SCRYPT` proving possession of the derived MAC key.
    pub fn scrypt_frame(&mut self) -> Result<Vec<u8>, OsdpError> {
        let handshake = self.handshake.as_ref().ok_or(OsdpError::NoHandshake)?;
        if self.channel.is_none() {
            return Err(OsdpError::NotSecure);
        }
        let mut payload = Vec::with_capacity(9);
        payload.push(CMD_SCRYPT);
        payload.extend_from_slice(&handshake.c_mac);
        self.plain_frame(payload)
    }

    /// Step 4: verify `RMAC_I` and start MAC chaining.
    pub fn accept_rmac(&mut self, bytes: &[u8]) -> Result<(), OsdpError> {
        let frame = OsdpFrame::decode(bytes)?;
        let code = frame.payload.first().copied().unwrap_or(0);
        if code != REPLY_RMAC_I {
            return Err(OsdpError::UnexpectedReply(code));
        }
        let body = &frame.payload[1..];
        if body.len() < 16 {
            return Err(OsdpError::FrameTooShort(body.len()));
        }
        let handshake = self.handshake.take().ok_or(OsdpError::NoHandshake)?;
        let channel = self.channel.as_mut().ok_or(OsdpError::NotSecure)?;
        if !constant_time_eq(&body[..16], &handshake.r_mac) {
            self.secure_failures = self.secure_failures.saturating_add(1);
            return Err(OsdpError::MacMismatch);
        }
        channel.set_chain(handshake.r_mac);
        Ok(())
    }

    /// Send a secured command payload.
    pub fn secure_command(&mut self, payload: &[u8]) -> Result<Vec<u8>, OsdpError> {
        let sequence = self.next_sequence();
        let channel = self.channel.as_mut().ok_or(OsdpError::NotSecure)?;
        channel.seal(self.address, sequence, payload, true)
    }

    /// Secured `POLL`.
    pub fn poll_frame(&mut self) -> Result<Vec<u8>, OsdpError> {
        self.secure_command(&[CMD_POLL])
    }

    /// Secured local status request.
    pub fn status_request_frame(&mut self) -> Result<Vec<u8>, OsdpError> {
        self.secure_command(&[CMD_LSTAT])
    }

    /// Decode a reply, opening it when secured, and fold status into counters.
    pub fn accept(&mut self, bytes: &[u8]) -> Result<OsdpReply, OsdpError> {
        let frame = OsdpFrame::decode(bytes)?;
        let plain = if frame.secure {
            let channel = self.channel.as_mut().ok_or(OsdpError::NotSecure)?;
            match channel.open(&frame) {
                Ok(plain) => plain,
                Err(error) => {
                    if matches!(error, OsdpError::MacMismatch) {
                        self.secure_failures = self.secure_failures.saturating_add(1);
                    }
                    return Err(error);
                }
            }
        } else {
            frame.payload.clone()
        };
        let reply = OsdpReply::parse(&plain)?;
        if let OsdpReply::Status(status) = &reply {
            self.status = Some(*status);
            if status.tamper {
                self.tamper_events = self.tamper_events.saturating_add(1);
            }
        }
        Ok(reply)
    }
}

/// Build a secured `KEYSET` payload for a new base key (16 or 32 bytes).
///
/// The key bytes are placed in the command payload as OSDP requires; they are
/// not retained by this crate.
pub fn keyset_payload(new_key: &crate::crypto::AesKey) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + new_key.len());
    payload.push(CMD_KEYSET);
    payload.extend_from_slice(new_key.bytes());
    payload
}

