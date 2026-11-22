// SPDX-License-Identifier: AGPL-3.0-only

//! AES block primitives, CMAC (RFC 4493), CBC and constant-time comparison.
//!
//! Only the AES block cipher comes from a dependency; CMAC, CBC mode, the key
//! wrapper and all framing are implemented here so the constructions used by
//! OSDP secure channel and DESFire EV2/EV3 are reviewable in one place.
//!
//! [`AesKey`] never prints key bytes: `Debug` is redacted and the buffer is
//! zeroized on drop. Callers record a [`AesKey::fingerprint`] instead of the
//! key itself.

use std::fmt;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES block size in bytes.
pub const BLOCK_LEN: usize = 16;

/// A rejected cryptographic operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The key was neither 16 nor 32 bytes.
    InvalidKeyLength(usize),
    /// The input was not a whole number of AES blocks.
    InvalidBlockLength(usize),
    /// A MAC did not match in constant time.
    MacMismatch,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength(len) => {
                write!(f, "invalid AES key length: {len} bytes")
            }
            CryptoError::InvalidBlockLength(len) => {
                write!(f, "invalid block length: {len} bytes")
            }
            CryptoError::MacMismatch => write!(f, "message authentication code mismatch"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// An AES-128 or AES-256 key held in a zeroizing buffer.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesKey {
    bytes: Vec<u8>,
}

impl AesKey {
    /// Build a key from exactly 16 or 32 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if !matches!(bytes.len(), 16 | 32) {
            return Err(CryptoError::InvalidKeyLength(bytes.len()));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Build a key from a fixed-size array (16 or 32 bytes).
    pub fn from_array<const N: usize>(bytes: [u8; N]) -> Self {
        Self::new(&bytes).expect("array length is 16 or 32")
    }

    /// Key length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: a key buffer is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// A second in-process copy, used while a handshake keeps a master key.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }

    /// Recorded key identity: a SHA-256 over a domain separator and the key.
    ///
    /// This is the only value that may be logged or persisted; it cannot be
    /// used to recover the key.
    pub fn fingerprint(&self) -> String {
        digest_hex("TirBase/v1/AesKey", &self.bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for AesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AesKey(<redacted>; {} bytes)", self.bytes.len())
    }
}

impl Clone for AesKey {
    fn clone(&self) -> Self {
        self.duplicate()
    }
}

fn block_cipher_encrypt(key: &AesKey, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut buffer = GenericArray::clone_from_slice(block);
    match key.len() {
        16 => Aes128::new_from_slice(key.bytes())
            .expect("key length checked")
            .encrypt_block(&mut buffer),
        32 => Aes256::new_from_slice(key.bytes())
            .expect("key length checked")
            .encrypt_block(&mut buffer),
        _ => unreachable!("AesKey only holds 16 or 32 bytes"),
    }
    let mut out = [0u8; BLOCK_LEN];
    out.copy_from_slice(&buffer);
    out
}

fn block_cipher_decrypt(key: &AesKey, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut buffer = GenericArray::clone_from_slice(block);
    match key.len() {
        16 => Aes128::new_from_slice(key.bytes())
            .expect("key length checked")
            .decrypt_block(&mut buffer),
        32 => Aes256::new_from_slice(key.bytes())
            .expect("key length checked")
            .decrypt_block(&mut buffer),
        _ => unreachable!("AesKey only holds 16 or 32 bytes"),
    }
    let mut out = [0u8; BLOCK_LEN];
    out.copy_from_slice(&buffer);
    out
}

/// Encrypt a single block with the key (AES-ECB on one block).
pub(crate) fn encrypt_block(key: &AesKey, block: [u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    block_cipher_encrypt(key, &block)
}

fn xor_block(target: &mut [u8; BLOCK_LEN], other: &[u8; BLOCK_LEN]) {
    for (a, b) in target.iter_mut().zip(other.iter()) {
        *a ^= b;
    }
}

fn double_block(input: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut out = [0u8; BLOCK_LEN];
    let carry = input[0] & 0x80 != 0;
    for i in 0..BLOCK_LEN - 1 {
        out[i] = (input[i] << 1) | (input[i + 1] >> 7);
    }
    out[BLOCK_LEN - 1] = input[BLOCK_LEN - 1] << 1;
    if carry {
        out[BLOCK_LEN - 1] ^= 0x87;
    }
    out
}

/// AES-CMAC over an arbitrary-length message (RFC 4493).
pub fn cmac(key: &AesKey, message: &[u8]) -> [u8; BLOCK_LEN] {
    let zero = [0u8; BLOCK_LEN];
    let l = block_cipher_encrypt(key, &zero);
    let k1 = double_block(&l);
    let k2 = double_block(&k1);

    let blocks = message.len().div_ceil(BLOCK_LEN).max(1);
    let complete = !message.is_empty() && message.len() % BLOCK_LEN == 0;

    let mut last = [0u8; BLOCK_LEN];
    let tail_start = (blocks - 1) * BLOCK_LEN;
    if complete {
        last.copy_from_slice(&message[tail_start..tail_start + BLOCK_LEN]);
        xor_block(&mut last, &k1);
    } else {
        let tail = &message[tail_start..];
        last[..tail.len()].copy_from_slice(tail);
        last[tail.len()] = 0x80;
        xor_block(&mut last, &k2);
    }

    let mut state = [0u8; BLOCK_LEN];
    for index in 0..blocks - 1 {
        let offset = index * BLOCK_LEN;
        xor_block(&mut state, &message[offset..offset + BLOCK_LEN].try_into().expect("block"));
        state = block_cipher_encrypt(key, &state);
    }
    xor_block(&mut state, &last);
    block_cipher_encrypt(key, &state)
}

/// AES-CBC encryption. `plaintext` must be a whole number of blocks.
pub fn cbc_encrypt(
    key: &AesKey,
    iv: &[u8; BLOCK_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() % BLOCK_LEN != 0 {
        return Err(CryptoError::InvalidBlockLength(plaintext.len()));
    }
    let mut previous = *iv;
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks_exact(BLOCK_LEN) {
        let mut block: [u8; BLOCK_LEN] = chunk.try_into().expect("chunk size");
        xor_block(&mut block, &previous);
        previous = block_cipher_encrypt(key, &block);
        out.extend_from_slice(&previous);
    }
    Ok(out)
}

/// AES-CBC decryption. `ciphertext` must be a whole number of blocks.
pub fn cbc_decrypt(
    key: &AesKey,
    iv: &[u8; BLOCK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() % BLOCK_LEN != 0 {
        return Err(CryptoError::InvalidBlockLength(ciphertext.len()));
    }
    let mut previous = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(BLOCK_LEN) {
        let block: [u8; BLOCK_LEN] = chunk.try_into().expect("chunk size");
        let mut plain = block_cipher_decrypt(key, &block);
        xor_block(&mut plain, &previous);
        previous = block;
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

/// Append the OSDP/DESFire end-of-message marker and zero padding.
pub(crate) fn pad_eom(data: &mut Vec<u8>) {
    data.push(0x80);
    while data.len() % BLOCK_LEN != 0 {
        data.push(0x00);
    }
}

/// Remove and validate the end-of-message marker padding.
pub(crate) fn unpad_eom(data: &[u8]) -> Result<&[u8], CryptoError> {
    let Some(position) = data.iter().rposition(|byte| *byte != 0x00) else {
        return Err(CryptoError::InvalidBlockLength(data.len()));
    };
    if data[position] != 0x80 {
        return Err(CryptoError::InvalidBlockLength(data.len()));
    }
    Ok(&data[..position])
}

/// Constant-time byte comparison.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Hex SHA-256 over `domain || 0x00 || bytes`, so digests from different
/// purposes never collide.
pub fn digest_hex(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
