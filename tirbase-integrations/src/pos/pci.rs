// SPDX-License-Identifier: Apache-2.0

//! PCI-safe primitives: opaque payment tokens and card-data scrubbing.
//!
//! A POS connector must never see a PAN, an expiry, a CVV or track data. The
//! framework therefore models the payment instrument as an opaque
//! [`PaymentMethodToken`] produced by the terminal SDK, refuses a token that is
//! shaped like a PAN, and scrubs every error and log detail through
//! [`scrub_card_data`]. [`contains_card_data`] is the check the conformance
//! suite and the fixture test use.

use serde::{Deserialize, Serialize};

use super::PosError;

/// Shortest digit run treated as card-number shaped.
pub const PAN_MIN_DIGITS: usize = 13;

/// Longest digit run treated as card-number shaped.
pub const PAN_MAX_DIGITS: usize = 19;

/// Replacement text for a scrubbed card number.
pub const REDACTED_CARD: &str = "[redacted-card]";

/// Field names that denote card data rather than a token.
const CARD_FIELD_MARKERS: [&str; 8] = [
    "card_number",
    "cardnumber",
    "pan",
    "cvv",
    "cvc",
    "cvn",
    "track2",
    "pin_block",
];

/// Whether `key` names a card-data field.
pub fn is_card_field(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    CARD_FIELD_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// Count digits in a run, ignoring grouping spaces and dashes.
fn digit_count(text: &str) -> usize {
    text.chars().filter(char::is_ascii_digit).count()
}

/// End (exclusive) of the digit run that starts at `start`.
///
/// A grouping space or dash continues the run only when a digit follows it, so
/// `2026-11-18` is one run of eight digits and `2500 EUR` stops at the space.
fn digit_run_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() {
        let byte = bytes[end];
        let grouped =
            matches!(byte, b' ' | b'-') && end + 1 < bytes.len() && bytes[end + 1].is_ascii_digit();
        if byte.is_ascii_digit() || grouped {
            end += 1;
        } else {
            break;
        }
    }
    end
}

/// Whether `text` contains something shaped like a PAN.
///
/// The check is deliberately conservative: any 13–19 digit run, with or without
/// grouping spaces or dashes, counts, whether or not it passes the Luhn check.
/// A false positive costs a rejected token; a false negative costs a card
/// number in a log.
pub fn contains_card_data(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let end = digit_run_end(bytes, start);
        let digits = digit_count(&text[start..end]);
        if (PAN_MIN_DIGITS..=PAN_MAX_DIGITS).contains(&digits) {
            return true;
        }
        index = end.max(start + 1);
    }
    false
}

/// Mask card-shaped digit runs and card-named `key=value` fields.
pub fn scrub_card_data(text: &str) -> String {
    let masked = mask_card_fields(text);
    let bytes = masked.as_bytes();
    let mut output = String::with_capacity(masked.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            let end = digit_run_end(bytes, start);
            let digits = digit_count(&masked[start..end]);
            if digits >= PAN_MIN_DIGITS {
                output.push_str(REDACTED_CARD);
            } else {
                output.push_str(&masked[start..end]);
            }
            index = end.max(start + 1);
            continue;
        }
        let length = masked[index..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1);
        output.push_str(&masked[index..index + length]);
        index += length;
    }
    output
}

/// Replace the value of every card-named `key=value` pair with a marker.
fn mask_card_fields(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for (position, token) in text.split_whitespace().enumerate() {
        if position > 0 {
            output.push(' ');
        }
        match token.split_once('=') {
            Some((key, _value)) if is_card_field(key) => {
                output.push_str(key);
                output.push('=');
                output.push_str(REDACTED_CARD);
            }
            _ => output.push_str(token),
        }
    }
    output
}

/// An opaque payment-instrument token produced by the terminal SDK.
///
/// The type is a claim: a value in it is a token, never card data. [`Self::new`]
/// enforces the claim, [`std::fmt::Debug`] prints `***`, and the wire form is a
/// bare string because a token is only useful to the vendor that issued it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PaymentMethodToken(String);

impl PaymentMethodToken {
    /// Validate and wrap a token.
    ///
    /// Accepts 6–64 characters from `[A-Za-z0-9_.:-]`. Values that are all
    /// digits, or that contain a 13–19 digit run, are refused as card data.
    pub fn new(raw: impl Into<String>) -> Result<Self, PosError> {
        let raw = raw.into();
        let trimmed = raw.trim();
        if trimmed.len() < 6 || trimmed.len() > 64 {
            return Err(PosError::Invariant {
                field: "payment_method_token".to_string(),
                detail: "must be 6..=64 characters".to_string(),
            });
        }
        if !trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':' | '-')
        }) {
            return Err(PosError::Invariant {
                field: "payment_method_token".to_string(),
                detail: "may contain only letters, digits, '_', '.', ':' and '-'".to_string(),
            });
        }
        if contains_card_data(trimmed)
            || trimmed.chars().all(|character| character.is_ascii_digit())
        {
            return Err(PosError::CardDataDetected {
                field: "payment_method_token".to_string(),
            });
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Wrap a value without validation.
    ///
    /// Only for the conformance suite and tests, which must be able to present a
    /// malformed token and prove the framework refuses it. Never call this with
    /// a value that came from a customer.
    #[doc(hidden)]
    pub fn unchecked_for_tests(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The token as the vendor issued it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the value is a well-formed token.
    pub fn is_valid(&self) -> bool {
        let value = self.0.trim();
        value.len() >= 6
            && value.len() <= 64
            && !contains_card_data(value)
            && !value.chars().all(|character| character.is_ascii_digit())
    }
}

impl std::fmt::Debug for PaymentMethodToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaymentMethodToken(***)")
    }
}

/// Refuse a text field that carries card data.
pub fn assert_no_card_data(field: &str, text: &str) -> Result<(), PosError> {
    if contains_card_data(text) {
        return Err(PosError::CardDataDetected {
            field: field.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_refuse_pan_shaped_values() {
        assert!(PaymentMethodToken::new("1234567890123456").is_err());
        assert!(PaymentMethodToken::new("1234 5678 9012 3456").is_err());
        assert!(PaymentMethodToken::new("411111111111").is_err());
        assert!(PaymentMethodToken::new("tok_test_5f2c1a").is_ok());
        assert_eq!(
            format!(
                "{:?}",
                PaymentMethodToken::new("tok_test_5f2c1a").expect("valid")
            ),
            "PaymentMethodToken(***)"
        );
    }

    #[test]
    fn scrubbing_masks_number_runs_and_card_fields() {
        let scrubbed = scrub_card_data("pan 1234 5678 9012 3456 cvv=123 amount 2500");
        assert!(!scrubbed.contains("1234"));
        assert!(scrubbed.contains("amount 2500"));
        let named = scrub_card_data("cvv=123 ok");
        assert_eq!(named, "cvv=[redacted-card] ok");
        assert!(contains_card_data("1234-5678-9012-3456"));
        assert!(!contains_card_data("2500 EUR"));
        assert!(!contains_card_data("2026-11-18"));
    }
}
