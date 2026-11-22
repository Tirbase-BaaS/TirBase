// SPDX-License-Identifier: AGPL-3.0-only

//! Wiegand capture decoding with parity and timing checks.
//!
//! A capture is a list of pulses, one per bit, each carrying the line that
//! pulsed, its width and the quiet gap that follows it. Decoding rejects:
//!
//! * a pulse narrower or wider than the configured window;
//! * an inter-pulse gap shorter than the minimum (contact bounce) or longer
//!   than the maximum (a dropped bit);
//! * a trailing gap shorter than the frame separator, which would let two
//!   cards merge into one capture;
//! * a capture whose length is not a supported format;
//! * a frame whose even or odd parity bit does not match;
//! * an all-zero (blank) card.
//!
//! Supported formats are 26-bit (8-bit facility, 16-bit card) and 34-bit
//! (16-bit facility, 16-bit card), both HID-shaped.

use std::fmt;

use crate::credential::{CredentialSource, PresentedCredential};

/// 26-bit Wiegand frame.
pub const BITS_26: u8 = 26;
/// 34-bit Wiegand frame.
pub const BITS_34: u8 = 34;

/// Which data line pulsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataLine {
    /// D0: a zero bit.
    Zero,
    /// D1: a one bit.
    One,
}

impl DataLine {
    pub fn bit(self) -> bool {
        matches!(self, DataLine::One)
    }
}

/// One pulse in a capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WiegandPulse {
    pub line: DataLine,
    /// Pulse width in microseconds.
    pub width_us: u32,
    /// Quiet time after this pulse before the next pulse or frame end.
    pub gap_after_us: u32,
}

impl WiegandPulse {
    pub fn new(line: DataLine, width_us: u32, gap_after_us: u32) -> Self {
        Self {
            line,
            width_us,
            gap_after_us,
        }
    }
}

/// Accepted pulse timing envelope, in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WiegandTiming {
    pub min_width_us: u32,
    pub max_width_us: u32,
    pub min_gap_us: u32,
    pub max_gap_us: u32,
    /// Minimum quiet time after the last bit before another frame may start.
    pub min_frame_gap_us: u32,
}

impl Default for WiegandTiming {
    fn default() -> Self {
        Self {
            min_width_us: 20,
            max_width_us: 200,
            min_gap_us: 100,
            max_gap_us: 20_000,
            min_frame_gap_us: 20_000,
        }
    }
}

/// A decoded Wiegand card.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WiegandCredential {
    pub bits: u8,
    pub facility_code: u32,
    pub card_number: u32,
    /// Raw data bits (parity excluded), most significant bit first.
    pub raw: u64,
}

impl WiegandCredential {
    /// Canonical bytes for credential fingerprinting.
    pub fn material(&self) -> Vec<u8> {
        let mut material = Vec::with_capacity(7);
        material.push(self.bits);
        material.extend_from_slice(&self.raw.to_be_bytes());
        material
    }

    /// Present this card to the credential registry.
    pub fn presented(&self) -> PresentedCredential {
        PresentedCredential::new(
            CredentialSource::Wiegand { bits: self.bits },
            self.material(),
        )
    }
}

/// A rejected Wiegand capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WiegandError {
    /// The capture contained no pulses.
    NoPulses,
    /// The capture length is not a supported format.
    UnsupportedLength(usize),
    /// A pulse was outside the width window.
    BadPulseWidth { index: usize, width_us: u32 },
    /// A gap was outside the gap window.
    BadGap { index: usize, gap_us: u32 },
    /// The capture did not end with a frame separator.
    BadFrameGap { gap_us: u32 },
    /// A parity bit did not match its covered bits.
    BadParity { which: &'static str },
    /// Every data bit was zero.
    BlankCard,
    /// The timing envelope itself is invalid.
    InvalidTiming(&'static str),
}

impl fmt::Display for WiegandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WiegandError::NoPulses => write!(f, "wiegand capture contained no pulses"),
            WiegandError::UnsupportedLength(len) => {
                write!(f, "unsupported wiegand length: {len} bits")
            }
            WiegandError::BadPulseWidth { index, width_us } => write!(
                f,
                "pulse {index} width {width_us} us is outside the accepted window"
            ),
            WiegandError::BadGap { index, gap_us } => {
                write!(f, "gap after pulse {index} is {gap_us} us")
            }
            WiegandError::BadFrameGap { gap_us } => {
                write!(f, "trailing gap {gap_us} us is shorter than a frame separator")
            }
            WiegandError::BadParity { which } => write!(f, "wiegand {which} parity failed"),
            WiegandError::BlankCard => write!(f, "wiegand frame carried no card data"),
            WiegandError::InvalidTiming(reason) => write!(f, "invalid timing envelope: {reason}"),
        }
    }
}

impl std::error::Error for WiegandError {}

impl WiegandTiming {
    fn validate(&self) -> Result<(), WiegandError> {
        if self.min_width_us == 0 || self.max_width_us < self.min_width_us {
            return Err(WiegandError::InvalidTiming("pulse width window"));
        }
        if self.min_gap_us == 0 || self.max_gap_us < self.min_gap_us {
            return Err(WiegandError::InvalidTiming("gap window"));
        }
        if self.min_frame_gap_us < self.max_gap_us {
            return Err(WiegandError::InvalidTiming(
                "frame separator must be at least the maximum gap",
            ));
        }
        Ok(())
    }
}

fn parity_of(bits: &[bool]) -> u32 {
    bits.iter().filter(|bit| **bit).count() as u32 % 2
}

/// Decode a Wiegand capture, enforcing timing and parity.
pub fn decode(
    pulses: &[WiegandPulse],
    timing: &WiegandTiming,
) -> Result<WiegandCredential, WiegandError> {
    timing.validate()?;
    if pulses.is_empty() {
        return Err(WiegandError::NoPulses);
    }
    match pulses.len() {
        26 => decode_format(pulses, timing, BITS_26),
        34 => decode_format(pulses, timing, BITS_34),
        other => Err(WiegandError::UnsupportedLength(other)),
    }
}

fn decode_format(
    pulses: &[WiegandPulse],
    timing: &WiegandTiming,
    bits: u8,
) -> Result<WiegandCredential, WiegandError> {
    for (index, pulse) in pulses.iter().enumerate() {
        if pulse.width_us < timing.min_width_us || pulse.width_us > timing.max_width_us {
            return Err(WiegandError::BadPulseWidth {
                index,
                width_us: pulse.width_us,
            });
        }
        // The trailing gap is the frame separator, checked below rather than
        // against the inter-pulse window.
        if index + 1 == pulses.len() {
            continue;
        }
        if pulse.gap_after_us < timing.min_gap_us || pulse.gap_after_us > timing.max_gap_us {
            return Err(WiegandError::BadGap {
                index,
                gap_us: pulse.gap_after_us,
            });
        }
    }
    let last = pulses.last().expect("non-empty capture");
    if last.gap_after_us < timing.min_frame_gap_us {
        return Err(WiegandError::BadFrameGap {
            gap_us: last.gap_after_us,
        });
    }

    let frame: Vec<bool> = pulses.iter().map(|pulse| pulse.line.bit()).collect();
    let length = frame.len();
    let data = &frame[1..length - 1];
    let half = data.len() / 2;

    // Leading bit: even parity over the first half of the data bits.
    let even_expected = parity_of(&data[..half]) == 1;
    if frame[0] != even_expected {
        return Err(WiegandError::BadParity { which: "even" });
    }
    // Trailing bit: odd parity over the second half.
    let odd_expected = parity_of(&data[half..]) == 0;
    if frame[length - 1] != odd_expected {
        return Err(WiegandError::BadParity { which: "odd" });
    }

    let mut raw = 0u64;
    for bit in data {
        raw = (raw << 1) | u64::from(*bit);
    }
    // HID field layout: 26-bit is 8 facility + 16 card bits; 34-bit is 16 + 16.
    // The parity halves are always equal, the field split is not.
    let facility_width = match bits {
        BITS_26 => 8usize,
        BITS_34 => 16usize,
        _ => return Err(WiegandError::UnsupportedLength(usize::from(bits))),
    };
    let card_width = data.len() - facility_width;
    let facility_code = (raw >> card_width) as u32;
    let card_number = (raw & ((1u64 << card_width) - 1)) as u32;

    if facility_code == 0 && card_number == 0 {
        return Err(WiegandError::BlankCard);
    }

    Ok(WiegandCredential {
        bits,
        facility_code,
        card_number,
        raw,
    })
}
