// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic reader simulators for recorded-frame and fuzz tests.
//!
//! Each simulator builds the exact bytes a reader or card emits, with no
//! sockets, clocks or randomness, so tests are byte-for-byte reproducible.

#[cfg(feature = "desfire")]
pub use desfire_sim::DesfireSim;
#[cfg(feature = "osdp")]
pub use osdp_sim::OsdpSim;
#[cfg(feature = "wiegand")]
pub use wiegand_sim::WiegandSim;

#[cfg(feature = "wiegand")]
mod wiegand_sim {
    use crate::wiegand::{DataLine, WiegandPulse};

    /// Builds Wiegand pulse captures for the supported formats.
    pub struct WiegandSim;

    impl WiegandSim {
        /// Capture with nominal timing (50 us pulses, 1 ms gaps, 25 ms frame
        /// separator).
        pub fn pulses(facility: u32, card: u32, bits: u8) -> Vec<WiegandPulse> {
            Self::pulses_with(facility, card, bits, 50, 1_000)
        }

        /// Capture with explicit pulse width and inter-pulse gap.
        pub fn pulses_with(
            facility: u32,
            card: u32,
            bits: u8,
            width_us: u32,
            gap_us: u32,
        ) -> Vec<WiegandPulse> {
            let frame = Self::frame_bits(facility, card, bits);
            let last = frame.len();
            frame
                .into_iter()
                .enumerate()
                .map(|(index, bit)| {
                    let gap = if index + 1 == last { 25_000 } else { gap_us };
                    WiegandPulse::new(
                        if bit { DataLine::One } else { DataLine::Zero },
                        width_us,
                        gap,
                    )
                })
                .collect()
        }

        /// Capture whose leading parity bit is inverted.
        pub fn bad_parity(facility: u32, card: u32, bits: u8) -> Vec<WiegandPulse> {
            let mut pulses = Self::pulses(facility, card, bits);
            pulses[0].line = match pulses[0].line {
                DataLine::Zero => DataLine::One,
                DataLine::One => DataLine::Zero,
            };
            pulses
        }

        /// Parity-correct bits for a card: leading even parity, data, trailing
        /// odd parity.
        pub fn frame_bits(facility: u32, card: u32, bits: u8) -> Vec<bool> {
            let half = (usize::from(bits) - 2) / 2;
            let facility_width = match bits {
                26 => 8usize,
                34 => 16usize,
                // Unknown formats still produce a capture so the decoder can
                // reject the length rather than the simulator panicking.
                _ => half,
            };
            let card_width = half * 2 - facility_width;
            let raw = ((u64::from(facility) & ((1u64 << facility_width) - 1)) << card_width)
                | (u64::from(card) & ((1u64 << card_width) - 1));
            let mut data = Vec::with_capacity(facility_width + card_width);
            for index in (0..facility_width + card_width).rev() {
                data.push((raw >> index) & 1 == 1);
            }
            let ones = |slice: &[bool]| slice.iter().filter(|bit| **bit).count() % 2;
            let mut frame = Vec::with_capacity(usize::from(bits));
            frame.push(ones(&data[..half]) == 1);
            frame.extend_from_slice(&data);
            frame.push(ones(&data[half..]) == 0);
            frame
        }
    }
}

#[cfg(feature = "osdp")]
mod osdp_sim {
    use crate::crypto::{cbc_encrypt, constant_time_eq, AesKey};
    use crate::osdp::{
        CardRead, OsdpError, OsdpFrame, PdStatus, Scs, SecureChannel, CMD_CHLNG, CMD_LSTAT,
        CMD_POLL, CMD_RSTAT, CMD_SCRYPT, REPLY_ACK, REPLY_CCRYPT, REPLY_LSTATR, REPLY_RAW,
        REPLY_RMAC_I,
    };

    /// Peripheral-device side of an OSDP link.
    pub struct OsdpSim {
        address: u8,
        master: AesKey,
        channel: Option<SecureChannel>,
        rnd_pd: [u8; 8],
        pending: Option<([u8; 8], [u8; 8], [u8; 16])>,
        tamper: bool,
        power_fault: bool,
        card: Option<CardRead>,
    }

    impl OsdpSim {
        /// Create a PD holding the secure-channel base key.
        pub fn new(address: u8, master: &AesKey) -> Result<Self, OsdpError> {
            if address > 0x7E {
                return Err(OsdpError::InvalidAddress(address));
            }
            Ok(Self {
                address,
                master: master.duplicate(),
                channel: None,
                rnd_pd: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                pending: None,
                tamper: false,
                power_fault: false,
                card: None,
            })
        }

        pub fn set_tamper(&mut self, tamper: bool) {
            self.tamper = tamper;
        }

        pub fn set_power_fault(&mut self, fault: bool) {
            self.power_fault = fault;
        }

        /// Queue a card event delivered on the next poll.
        pub fn queue_card(&mut self, data: Vec<u8>, bit_count: u16) {
            self.card = Some(CardRead {
                reader_no: 0,
                format: 1,
                bit_count,
                data,
            });
        }

        fn plain_reply(&self, sequence: u8, payload: &[u8]) -> Result<Vec<u8>, OsdpError> {
            OsdpFrame {
                address: self.address | 0x80,
                sequence,
                secure: false,
                payload: payload.to_vec(),
            }
            .encode()
        }

        fn secure_reply(&mut self, sequence: u8, payload: &[u8]) -> Result<Vec<u8>, OsdpError> {
            let channel = self.channel.as_mut().ok_or(OsdpError::NotSecure)?;
            channel.seal(self.address | 0x80, sequence, payload, true)
        }

        /// Consume one command frame and produce the reply.
        pub fn handle(&mut self, bytes: &[u8]) -> Result<Vec<u8>, OsdpError> {
            let frame = OsdpFrame::decode(bytes)?;
            if frame.address & 0x7F != self.address {
                return Err(OsdpError::InvalidAddress(frame.address));
            }
            let plain = if frame.secure {
                let channel = self.channel.as_mut().ok_or(OsdpError::NotSecure)?;
                channel.open(&frame)?
            } else {
                frame.payload.clone()
            };
            let code = plain.first().copied().unwrap_or(0);
            match code {
                CMD_CHLNG => {
                    let body = &plain[1..];
                    if body.len() < 8 {
                        return Err(OsdpError::FrameTooShort(body.len()));
                    }
                    let mut rnd_c = [0u8; 8];
                    rnd_c.copy_from_slice(&body[..8]);
                    let mut seed = Vec::with_capacity(16);
                    seed.extend_from_slice(&rnd_c);
                    seed.extend_from_slice(&self.rnd_pd);
                    let cryptogram = cbc_encrypt(&self.master, &[0u8; 16], &seed)?;
                    let (channel, c_mac, r_mac) =
                        SecureChannel::derive(Scs::Scs12, &self.master, &rnd_c, &self.rnd_pd)?;
                    self.pending = Some((rnd_c, c_mac, r_mac));
                    self.channel = Some(channel);
                    let mut payload = Vec::with_capacity(25);
                    payload.push(REPLY_CCRYPT);
                    payload.extend_from_slice(&cryptogram);
                    payload.extend_from_slice(&r_mac[..8]);
                    self.plain_reply(frame.sequence, &payload)
                }
                CMD_SCRYPT => {
                    let (_, c_mac, r_mac) = self.pending.ok_or(OsdpError::NoHandshake)?;
                    let body = &plain[1..];
                    if body.len() < 8 {
                        return Err(OsdpError::FrameTooShort(body.len()));
                    }
                    if !constant_time_eq(&body[..8], &c_mac) {
                        self.channel = None;
                        return Err(OsdpError::MacMismatch);
                    }
                    if let Some(channel) = self.channel.as_mut() {
                        channel.set_chain(r_mac);
                    }
                    let mut payload = Vec::with_capacity(17);
                    payload.push(REPLY_RMAC_I);
                    payload.extend_from_slice(&r_mac);
                    self.plain_reply(frame.sequence, &payload)
                }
                CMD_POLL => {
                    let payload = if let Some(card) = self.card.take() {
                        let mut payload = vec![REPLY_RAW];
                        payload.extend_from_slice(&card.encode());
                        payload
                    } else {
                        vec![REPLY_ACK]
                    };
                    self.secure_reply(frame.sequence, &payload)
                }
                CMD_LSTAT => {
                    let status = PdStatus {
                        tamper: self.tamper,
                        power_fault: self.power_fault,
                        ..PdStatus::default()
                    };
                    let mut payload = vec![REPLY_LSTATR];
                    payload.extend_from_slice(&status.encode());
                    self.secure_reply(frame.sequence, &payload)
                }
                CMD_RSTAT => self.secure_reply(frame.sequence, &[REPLY_ACK]),
                _ => self.secure_reply(frame.sequence, &[0x41, 0x01]),
            }
        }
    }
}

#[cfg(feature = "desfire")]
mod desfire_sim {
    use std::collections::BTreeMap;

    use crate::crypto::{cbc_decrypt, cbc_encrypt, constant_time_eq, pad_eom, AesKey};
    use crate::desfire::{
        command_mac, decode_command, derive_session_keys, response_mac, session_iv,
        CMD_ADDITIONAL_FRAME, CMD_AUTHENTICATE_EV2_FIRST, CMD_READ_DATA, DesfireError, MAC_LEN,
        SW1, SW_ADDITIONAL, SW_OK,
    };

    struct SimSession {
        s_enc: AesKey,
        s_mac: AesKey,
        ti: [u8; 4],
        cmd_ctr: u16,
    }

    impl SimSession {
        fn next_counter(&mut self) -> Result<u16, DesfireError> {
            self.cmd_ctr = self.cmd_ctr.checked_add(1).ok_or(DesfireError::CounterExhausted)?;
            Ok(self.cmd_ctr)
        }
    }

    /// Card side of an EV2/EV3 authentication and read sequence.
    pub struct DesfireSim {
        key_no: u8,
        key: AesKey,
        uid: [u8; 7],
        rnd_b: [u8; 16],
        files: BTreeMap<u8, Vec<u8>>,
        session: Option<SimSession>,
    }

    impl DesfireSim {
        /// Create a card holding an AES-128 application key.
        pub fn new(key_no: u8, key: AesKey, uid: [u8; 7]) -> Result<Self, DesfireError> {
            if key.len() != 16 {
                return Err(DesfireError::Crypto(
                    crate::crypto::CryptoError::InvalidKeyLength(key.len()),
                ));
            }
            Ok(Self {
                key_no,
                key,
                uid,
                rnd_b: [
                    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC,
                    0xAD, 0xAE, 0xAF,
                ],
                files: BTreeMap::new(),
                session: None,
            })
        }

        /// Add a standard-data file.
        pub fn with_file(mut self, file_no: u8, data: impl Into<Vec<u8>>) -> Self {
            self.files.insert(file_no, data.into());
            self
        }

        pub fn uid(&self) -> [u8; 7] {
            self.uid
        }

        /// Build a response APDU (`data || 91 || status`).
        fn response(status: u8, data: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(data.len() + 2);
            out.extend_from_slice(data);
            out.push(SW1);
            out.push(status);
            out
        }

        /// Consume one request APDU and produce the response.
        pub fn handle(&mut self, apdu: &[u8]) -> Result<Vec<u8>, DesfireError> {
            let (ins, data) = decode_command(apdu)?;
            match ins {
                CMD_AUTHENTICATE_EV2_FIRST => {
                    if data.is_empty() {
                        return Err(DesfireError::BadLength(0));
                    }
                    if data[0] != self.key_no {
                        return Err(DesfireError::BadKeyNumber(data[0]));
                    }
                    let cryptogram = cbc_encrypt(&self.key, &[0u8; 16], &self.rnd_b)?;
                    Ok(Self::response(SW_ADDITIONAL, &cryptogram))
                }
                CMD_ADDITIONAL_FRAME => {
                    if data.len() != 32 {
                        return Err(DesfireError::BadLength(data.len()));
                    }
                    let plain = cbc_decrypt(&self.key, &[0u8; 16], data)?;
                    let mut rnd_a = [0u8; 16];
                    rnd_a.copy_from_slice(&plain[..16]);
                    let mut rnd_b_prime = [0u8; 16];
                    rnd_b_prime.copy_from_slice(&plain[16..]);
                    let mut expected = self.rnd_b;
                    expected.rotate_left(1);
                    if !constant_time_eq(&rnd_b_prime, &expected) {
                        return Err(DesfireError::BadRandom);
                    }
                    let (s_enc, s_mac) = derive_session_keys(&self.key, &rnd_a, &self.rnd_b)?;
                    let ti = [0x54, 0x49, 0x00, 0x01];
                    let mut rnd_a_prime = rnd_a;
                    rnd_a_prime.rotate_left(1);
                    let mut body = Vec::with_capacity(32);
                    body.extend_from_slice(&ti);
                    body.extend_from_slice(&rnd_a_prime);
                    body.extend_from_slice(&[0u8; 12]);
                    let ciphertext = cbc_encrypt(&self.key, &[0u8; 16], &body)?;
                    self.session = Some(SimSession {
                        s_enc,
                        s_mac,
                        ti,
                        cmd_ctr: 0,
                    });
                    Ok(Self::response(SW_OK, &ciphertext))
                }
                CMD_READ_DATA => {
                    let session = self.session.as_mut().ok_or(DesfireError::NotAuthenticated)?;
                    if data.len() != 7 + MAC_LEN {
                        return Err(DesfireError::BadLength(data.len()));
                    }
                    let header = &data[..7];
                    let mac_field = &data[7..];
                    let cmd_ctr = session.next_counter()?;
                    let expected = command_mac(&session.s_mac, CMD_READ_DATA, cmd_ctr, header);
                    if !constant_time_eq(mac_field, &expected) {
                        return Err(DesfireError::MacMismatch);
                    }
                    let file_no = header[0];
                    let offset = u24(&header[1..4]);
                    let length = u24(&header[4..7]);
                    let file = self.files.get(&file_no).ok_or(DesfireError::FileOutOfRange {
                        file_no,
                        offset,
                        length,
                    })?;
                    let end = offset
                        .checked_add(length)
                        .ok_or(DesfireError::FileOutOfRange {
                            file_no,
                            offset,
                            length,
                        })?;
                    if usize::try_from(end).map(|end| end > file.len()).unwrap_or(true) {
                        return Err(DesfireError::FileOutOfRange {
                            file_no,
                            offset,
                            length,
                        });
                    }
                    let plain = &file[offset as usize..end as usize];
                    let mut padded = plain.to_vec();
                    pad_eom(&mut padded);
                    let iv = session_iv(&session.s_enc, &session.ti, cmd_ctr);
                    let ciphertext = cbc_encrypt(&session.s_enc, &iv, &padded)?;
                    let mac = response_mac(&session.s_mac, CMD_READ_DATA, cmd_ctr, SW_OK, &ciphertext);
                    let mut body = ciphertext;
                    body.extend_from_slice(&mac);
                    Ok(Self::response(SW_OK, &body))
                }
                other => Err(DesfireError::UnknownCommand(other)),
            }
        }
    }

    fn u24(bytes: &[u8]) -> u32 {
        u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16)
    }
}
