// SPDX-License-Identifier: AGPL-3.0-only

//! MIFARE DESFire EV2/EV3: `AuthenticateEV2First` and authenticated file read.
//!
//! # Scope
//!
//! This is the read-only subset a venue reader needs: AES-128 application
//! authentication on EV2/EV3 (command `0x71`, additional frame `0xAF`) and
//! `ReadData` (`0xBD`) in `CommMode.Full` (encrypted data plus CMAC).
//!
//! Session keys follow the published EV2 derivation:
//!
//! ```text
//! SV1 = 0x01 || RndA[0..2] || RndB[0..8] || RndA[2..8] || RndB[8..16]
//! SV2 = 0x02 || RndA[0..2] || RndB[0..8] || RndA[2..8] || RndB[8..16]
//! SesAuthENCKey = CMAC(Kx, SV1)
//! SesAuthMACKey = CMAC(Kx, SV2)
//! ```
//!
//! Command and response data use the `A55Ah` IV label with the transaction
//! identifier and command counter, and MACs are the leading 8 bytes of
//! `CMAC(SesAuthMACKey, 0x00 || Cmd || CmdCtr || [Status] || Data)`. EV3 is
//! wire-compatible with this subset; both are covered by the tests.
//!
//! No command that changes card state is implemented or parsed: the reader can
//! authenticate and read, never write, delete or change a key.

use std::fmt;

use crate::crypto::{
    cbc_decrypt, cbc_encrypt, cmac, constant_time_eq, encrypt_block, unpad_eom, AesKey,
    CryptoError, BLOCK_LEN,
};

/// `AuthenticateEV2First`.
pub const CMD_AUTHENTICATE_EV2_FIRST: u8 = 0x71;
/// Additional frame.
pub const CMD_ADDITIONAL_FRAME: u8 = 0xAF;
/// `ReadData`.
pub const CMD_READ_DATA: u8 = 0xBD;

/// ISO 7816 status byte 1.
pub const SW1: u8 = 0x91;
/// Success.
pub const SW_OK: u8 = 0x00;
/// Additional frame expected.
pub const SW_ADDITIONAL: u8 = 0xAF;

/// Truncated CMAC length in EV2 secure messaging.
pub const MAC_LEN: usize = 8;

/// IV label for encryption in EV2 secure messaging.
pub const IV_LABEL_ENC: [u8; 2] = [0xA5, 0x5A];

/// A rejected DESFire exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DesfireError {
    ApduTooShort(usize),
    MalformedApdu(&'static str),
    BadStatus(u8),
    UnexpectedStatus { expected: u8, found: u8 },
    MacMismatch,
    BadRandom,
    NotAuthenticated,
    AlreadyAuthenticated,
    BadLength(usize),
    UnknownCommand(u8),
    FileOutOfRange { file_no: u8, offset: u32, length: u32 },
    BadKeyNumber(u8),
    CounterExhausted,
    Crypto(CryptoError),
}

impl fmt::Display for DesfireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DesfireError::ApduTooShort(len) => write!(f, "desfire APDU too short: {len} bytes"),
            DesfireError::MalformedApdu(reason) => write!(f, "malformed desfire APDU: {reason}"),
            DesfireError::BadStatus(status) => {
                write!(f, "desfire status byte 1 was 0x{status:02X}")
            }
            DesfireError::UnexpectedStatus { expected, found } => {
                write!(f, "desfire status {found:#04X} != {expected:#04X}")
            }
            DesfireError::MacMismatch => write!(f, "desfire MAC mismatch"),
            DesfireError::BadRandom => write!(f, "desfire random challenge mismatch"),
            DesfireError::NotAuthenticated => write!(f, "desfire session is not authenticated"),
            DesfireError::AlreadyAuthenticated => {
                write!(f, "desfire session is already authenticated")
            }
            DesfireError::BadLength(len) => write!(f, "bad desfire length: {len}"),
            DesfireError::UnknownCommand(code) => {
                write!(f, "unknown or unsupported desfire command: 0x{code:02X}")
            }
            DesfireError::FileOutOfRange {
                file_no,
                offset,
                length,
            } => write!(
                f,
                "desfire file {file_no} read {length} bytes at {offset} is out of range"
            ),
            DesfireError::BadKeyNumber(key_no) => write!(f, "unexpected desfire key number: {key_no}"),
            DesfireError::CounterExhausted => write!(f, "desfire command counter exhausted"),
            DesfireError::Crypto(error) => write!(f, "crypto: {error}"),
        }
    }
}

impl std::error::Error for DesfireError {}

impl From<CryptoError> for DesfireError {
    fn from(error: CryptoError) -> Self {
        DesfireError::Crypto(error)
    }
}

fn zero_iv() -> [u8; BLOCK_LEN] {
    [0u8; BLOCK_LEN]
}

/// Encode a native command in an ISO 7816-4 APDU (`90 INS 00 00 Lc DATA 00`).
pub(crate) fn encode_apdu(ins: u8, data: &[u8]) -> Result<Vec<u8>, DesfireError> {
    if data.len() > u8::MAX as usize {
        return Err(DesfireError::BadLength(data.len()));
    }
    let mut out = Vec::with_capacity(6 + data.len());
    out.extend_from_slice(&[0x90, ins, 0x00, 0x00, data.len() as u8]);
    out.extend_from_slice(data);
    out.push(0x00);
    Ok(out)
}

/// Split a response into status byte 2 and data.
pub(crate) fn decode_apdu(response: &[u8]) -> Result<(u8, &[u8]), DesfireError> {
    if response.len() < 2 {
        return Err(DesfireError::ApduTooShort(response.len()));
    }
    let sw1 = response[response.len() - 2];
    let sw2 = response[response.len() - 1];
    if sw1 != SW1 {
        return Err(DesfireError::BadStatus(sw1));
    }
    Ok((sw2, &response[..response.len() - 2]))
}

/// Parse a request APDU into command and data (used by the card simulator).
pub(crate) fn decode_command(apdu: &[u8]) -> Result<(u8, &[u8]), DesfireError> {
    if apdu.len() < 6 {
        return Err(DesfireError::ApduTooShort(apdu.len()));
    }
    if apdu[0] != 0x90 || apdu[2] != 0x00 || apdu[3] != 0x00 {
        return Err(DesfireError::MalformedApdu("unexpected APDU header"));
    }
    let ins = apdu[1];
    let length = usize::from(apdu[4]);
    if apdu.len() != 6 + length {
        return Err(DesfireError::MalformedApdu("Lc does not match APDU length"));
    }
    if apdu[apdu.len() - 1] != 0x00 {
        return Err(DesfireError::MalformedApdu("missing Le"));
    }
    Ok((ins, &apdu[5..5 + length]))
}

/// EV2 session-key derivation vector for `label`.
pub(crate) fn session_vector(label: u8, rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> Vec<u8> {
    let mut input = Vec::with_capacity(25);
    input.push(label);
    input.extend_from_slice(&rnd_a[..2]);
    input.extend_from_slice(&rnd_b[..8]);
    input.extend_from_slice(&rnd_a[2..8]);
    input.extend_from_slice(&rnd_b[8..]);
    input
}

/// Derive `(SesAuthENCKey, SesAuthMACKey)`.
pub(crate) fn derive_session_keys(
    key: &AesKey,
    rnd_a: &[u8; 16],
    rnd_b: &[u8; 16],
) -> Result<(AesKey, AesKey), DesfireError> {
    let enc = AesKey::new(&cmac(key, &session_vector(0x01, rnd_a, rnd_b)))?;
    let mac = AesKey::new(&cmac(key, &session_vector(0x02, rnd_a, rnd_b)))?;
    Ok((enc, mac))
}

/// EV2 secure-messaging IV for `command`/`response` data.
pub(crate) fn session_iv(s_enc: &AesKey, ti: &[u8; 4], cmd_ctr: u16) -> [u8; BLOCK_LEN] {
    let mut input = [0u8; BLOCK_LEN];
    input[0] = IV_LABEL_ENC[0];
    input[1] = IV_LABEL_ENC[1];
    input[2..6].copy_from_slice(ti);
    input[6..8].copy_from_slice(&cmd_ctr.to_le_bytes());
    encrypt_block(s_enc, input)
}

/// Truncated command MAC: `CMAC(SesAuthMACKey, 0x00 || Cmd || CmdCtr || Data)`.
pub(crate) fn command_mac(s_mac: &AesKey, ins: u8, cmd_ctr: u16, data: &[u8]) -> [u8; MAC_LEN] {
    let mut input = Vec::with_capacity(4 + data.len());
    input.push(0x00);
    input.push(ins);
    input.extend_from_slice(&cmd_ctr.to_le_bytes());
    input.extend_from_slice(data);
    let full = cmac(s_mac, &input);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&full[..MAC_LEN]);
    mac
}

/// Truncated response MAC:
/// `CMAC(SesAuthMACKey, 0x00 || Cmd || CmdCtr || Status || Data)`.
pub(crate) fn response_mac(
    s_mac: &AesKey,
    ins: u8,
    cmd_ctr: u16,
    status: u8,
    data: &[u8],
) -> [u8; MAC_LEN] {
    let mut input = Vec::with_capacity(5 + data.len());
    input.push(0x00);
    input.push(ins);
    input.extend_from_slice(&cmd_ctr.to_le_bytes());
    input.push(status);
    input.extend_from_slice(data);
    let full = cmac(s_mac, &input);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&full[..MAC_LEN]);
    mac
}

fn rotate_left_one(block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    out.rotate_left(1);
    out
}

/// Decrypted session state.
#[derive(Clone, Debug)]
pub struct DesfireSession {
    s_enc: AesKey,
    s_mac: AesKey,
    ti: [u8; 4],
    cmd_ctr: u16,
}

impl DesfireSession {
    pub fn transaction_id(&self) -> [u8; 4] {
        self.ti
    }

    pub fn command_counter(&self) -> u16 {
        self.cmd_ctr
    }

    fn next_counter(&mut self) -> Result<u16, DesfireError> {
        self.cmd_ctr = self
            .cmd_ctr
            .checked_add(1)
            .ok_or(DesfireError::CounterExhausted)?;
        Ok(self.cmd_ctr)
    }
}

/// Reader side of an EV2/EV3 authentication and read sequence.
pub struct DesfireReader {
    key_no: u8,
    key: AesKey,
    rnd_a: [u8; 16],
    rnd_b: Option<[u8; 16]>,
    session: Option<DesfireSession>,
    pending_read: Option<(u16, u32)>,
}

impl DesfireReader {
    /// Create a reader for an application key number and AES-128 key.
    pub fn new(key_no: u8, key: AesKey) -> Result<Self, DesfireError> {
        if key_no > 0x0D {
            return Err(DesfireError::BadKeyNumber(key_no));
        }
        if key.len() != 16 {
            return Err(DesfireError::Crypto(CryptoError::InvalidKeyLength(key.len())));
        }
        Ok(Self {
            key_no,
            key,
            rnd_a: [0u8; 16],
            rnd_b: None,
            session: None,
            pending_read: None,
        })
    }

    pub fn key_no(&self) -> u8 {
        self.key_no
    }

    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// Step 1: build `AuthenticateEV2First` with the caller's 16-byte random.
    pub fn start_authentication(&mut self, rnd_a: [u8; 16]) -> Result<Vec<u8>, DesfireError> {
        if self.session.is_some() {
            return Err(DesfireError::AlreadyAuthenticated);
        }
        self.rnd_a = rnd_a;
        // Key number plus a zero-length PCDcap2.
        encode_apdu(CMD_AUTHENTICATE_EV2_FIRST, &[self.key_no, 0x00])
    }

    /// Step 2: consume `E(Kx, RndB)` and build the second authentication frame.
    pub fn complete_authentication(
        &mut self,
        response: &[u8],
    ) -> Result<Vec<u8>, DesfireError> {
        let (sw2, data) = decode_apdu(response)?;
        if sw2 != SW_ADDITIONAL {
            return Err(DesfireError::UnexpectedStatus {
                expected: SW_ADDITIONAL,
                found: sw2,
            });
        }
        if data.len() != 16 {
            return Err(DesfireError::BadLength(data.len()));
        }
        let plain = cbc_decrypt(&self.key, &zero_iv(), data)?;
        let mut rnd_b = [0u8; 16];
        rnd_b.copy_from_slice(&plain);

        let mut part_two = Vec::with_capacity(32);
        part_two.extend_from_slice(&self.rnd_a);
        part_two.extend_from_slice(&rotate_left_one(&rnd_b));
        let ciphertext = cbc_encrypt(&self.key, &zero_iv(), &part_two)?;

        let (s_enc, s_mac) = derive_session_keys(&self.key, &self.rnd_a, &rnd_b)?;
        self.rnd_b = Some(rnd_b);
        self.session = Some(DesfireSession {
            s_enc,
            s_mac,
            ti: [0u8; 4],
            cmd_ctr: 0,
        });
        encode_apdu(CMD_ADDITIONAL_FRAME, &ciphertext)
    }

    /// Step 3: verify `E(Kx, TI || RndA' || caps)` and mark the session usable.
    pub fn finish_authentication(&mut self, response: &[u8]) -> Result<(), DesfireError> {
        let session = self.session.as_mut().ok_or(DesfireError::NotAuthenticated)?;
        let (sw2, data) = decode_apdu(response)?;
        if sw2 != SW_OK {
            return Err(DesfireError::UnexpectedStatus {
                expected: SW_OK,
                found: sw2,
            });
        }
        if data.len() != 32 {
            return Err(DesfireError::BadLength(data.len()));
        }
        let plain = cbc_decrypt(&self.key, &zero_iv(), data)?;
        let mut ti = [0u8; 4];
        ti.copy_from_slice(&plain[..4]);
        let mut rnd_a_prime = [0u8; 16];
        rnd_a_prime.copy_from_slice(&plain[4..20]);
        if !constant_time_eq(&rnd_a_prime, &rotate_left_one(&self.rnd_a)) {
            return Err(DesfireError::BadRandom);
        }
        session.ti = ti;
        Ok(())
    }

    /// Build an encrypted, MACed `ReadData`.
    pub fn read_file(
        &mut self,
        file_no: u8,
        offset: u32,
        length: u32,
    ) -> Result<Vec<u8>, DesfireError> {
        if offset > 0x00FF_FFFF || length > 0x00FF_FFFF {
            return Err(DesfireError::BadLength(length as usize));
        }
        let session = self.session.as_mut().ok_or(DesfireError::NotAuthenticated)?;
        let cmd_ctr = session.next_counter()?;
        let offset_bytes = offset.to_le_bytes();
        let length_bytes = length.to_le_bytes();
        let mut header = Vec::with_capacity(7);
        header.push(file_no);
        header.extend_from_slice(&offset_bytes[..3]);
        header.extend_from_slice(&length_bytes[..3]);
        let mac = command_mac(&session.s_mac, CMD_READ_DATA, cmd_ctr, &header);
        header.extend_from_slice(&mac);
        self.pending_read = Some((cmd_ctr, length));
        encode_apdu(CMD_READ_DATA, &header)
    }

    /// Verify and decrypt a `ReadData` response.
    pub fn accept_file_data(&mut self, response: &[u8]) -> Result<Vec<u8>, DesfireError> {
        let (cmd_ctr, expected_len) = self.pending_read.ok_or(DesfireError::NotAuthenticated)?;
        let session = self.session.as_ref().ok_or(DesfireError::NotAuthenticated)?;
        let (sw2, data) = decode_apdu(response)?;
        if sw2 != SW_OK {
            return Err(DesfireError::UnexpectedStatus {
                expected: SW_OK,
                found: sw2,
            });
        }
        if data.len() < MAC_LEN {
            return Err(DesfireError::BadLength(data.len()));
        }
        let split = data.len() - MAC_LEN;
        let ciphertext = &data[..split];
        let mac_field = &data[split..];
        let mac = response_mac(&session.s_mac, CMD_READ_DATA, cmd_ctr, SW_OK, ciphertext);
        if !constant_time_eq(mac_field, &mac) {
            return Err(DesfireError::MacMismatch);
        }
        let iv = session_iv(&session.s_enc, &session.ti, cmd_ctr);
        let plain = cbc_decrypt(&session.s_enc, &iv, ciphertext)?;
        let unpadded = unpad_eom(&plain)?;
        if unpadded.len() as u32 != expected_len {
            return Err(DesfireError::BadLength(unpadded.len()));
        }
        self.pending_read = None;
        Ok(unpadded.to_vec())
    }
}
