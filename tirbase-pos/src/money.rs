// SPDX-License-Identifier: AGPL-3.0-only

//! ISO 4217 currency, integer minor-unit money, decimal quantity and rates.
//!
//! Money is an `i64` count of **minor units** (cents, fils, yen, …) tagged with
//! an ISO 4217 currency. There is deliberately no `f64` constructor, no `From`
//! implementation for a float, and no rounding that happens implicitly: the
//! caller must name a [`RoundingMode`] whenever a division is not exact.
//!
//! Currencies are data, not a default. The crate has no jurisdiction default,
//! matching the POS-00 gate record's approved scope.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::PosError;
use crate::rounding::{div_round, RoundingMode};

/// Decimal places used by one line quantity: 3 (`0.001` of a unit).
pub const QUANTITY_SCALE: i128 = 1_000;

/// Parts per million used by tax rates and percentage discounts.
pub const RATE_SCALE: i128 = 1_000_000;

/// Minor units per major unit for each supported ISO 4217 code.
///
/// The table follows the ISO 4217 list of active currencies. Precious-metal and
/// testing codes with no minor unit are included as data where they are part of
/// the standard; they are never selected by default.
const CURRENCY_MINOR_UNITS: &[(&str, u8)] = &[
    ("AED", 2),
    ("AFN", 2),
    ("ALL", 2),
    ("AMD", 2),
    ("ANG", 2),
    ("AOA", 2),
    ("ARS", 2),
    ("AUD", 2),
    ("AWG", 2),
    ("AZN", 2),
    ("BAM", 2),
    ("BBD", 2),
    ("BDT", 2),
    ("BGN", 2),
    ("BHD", 3),
    ("BIF", 0),
    ("BMD", 2),
    ("BND", 2),
    ("BOB", 2),
    ("BOV", 2),
    ("BRL", 2),
    ("BSD", 2),
    ("BTN", 2),
    ("BWP", 2),
    ("BYN", 2),
    ("BZD", 2),
    ("CAD", 2),
    ("CDF", 2),
    ("CHE", 2),
    ("CHF", 2),
    ("CHW", 2),
    ("CLF", 4),
    ("CLP", 0),
    ("CNY", 2),
    ("COP", 2),
    ("COU", 2),
    ("CRC", 2),
    ("CUP", 2),
    ("CVE", 2),
    ("CZK", 2),
    ("DJF", 0),
    ("DKK", 2),
    ("DOP", 2),
    ("DZD", 2),
    ("EGP", 2),
    ("ERN", 2),
    ("ETB", 2),
    ("EUR", 2),
    ("FJD", 2),
    ("FKP", 2),
    ("GBP", 2),
    ("GEL", 2),
    ("GHS", 2),
    ("GIP", 2),
    ("GMD", 2),
    ("GNF", 0),
    ("GTQ", 2),
    ("GYD", 2),
    ("HKD", 2),
    ("HNL", 2),
    ("HTG", 2),
    ("HUF", 2),
    ("IDR", 2),
    ("ILS", 2),
    ("INR", 2),
    ("IQD", 3),
    ("IRR", 2),
    ("ISK", 0),
    ("JMD", 2),
    ("JOD", 3),
    ("JPY", 0),
    ("KES", 2),
    ("KGS", 2),
    ("KHR", 2),
    ("KMF", 0),
    ("KPW", 2),
    ("KRW", 0),
    ("KWD", 3),
    ("KYD", 2),
    ("KZT", 2),
    ("LAK", 2),
    ("LBP", 2),
    ("LKR", 2),
    ("LRD", 2),
    ("LSL", 2),
    ("LYD", 3),
    ("MAD", 2),
    ("MDL", 2),
    ("MGA", 2),
    ("MKD", 2),
    ("MMK", 2),
    ("MNT", 2),
    ("MOP", 2),
    ("MRU", 2),
    ("MUR", 2),
    ("MVR", 2),
    ("MWK", 2),
    ("MXN", 2),
    ("MXV", 2),
    ("MYR", 2),
    ("MZN", 2),
    ("NAD", 2),
    ("NGN", 2),
    ("NIO", 2),
    ("NOK", 2),
    ("NPR", 2),
    ("NZD", 2),
    ("OMR", 3),
    ("PAB", 2),
    ("PEN", 2),
    ("PGK", 2),
    ("PHP", 2),
    ("PKR", 2),
    ("PLN", 2),
    ("PYG", 0),
    ("QAR", 2),
    ("RON", 2),
    ("RSD", 2),
    ("RUB", 2),
    ("RWF", 0),
    ("SAR", 2),
    ("SBD", 2),
    ("SCR", 2),
    ("SDG", 2),
    ("SEK", 2),
    ("SGD", 2),
    ("SHP", 2),
    ("SLE", 2),
    ("SOS", 2),
    ("SRD", 2),
    ("SSP", 2),
    ("STN", 2),
    ("SVC", 2),
    ("SYP", 2),
    ("SZL", 2),
    ("THB", 2),
    ("TJS", 2),
    ("TMT", 2),
    ("TND", 3),
    ("TOP", 2),
    ("TRY", 2),
    ("TTD", 2),
    ("TWD", 2),
    ("TZS", 2),
    ("UAH", 2),
    ("UGX", 0),
    ("USD", 2),
    ("USN", 2),
    ("UYI", 0),
    ("UYU", 2),
    ("UYW", 4),
    ("UZS", 2),
    ("VED", 2),
    ("VES", 2),
    ("VND", 0),
    ("VUV", 0),
    ("WST", 2),
    ("XAF", 0),
    ("XCD", 2),
    ("XDR", 0),
    ("XOF", 0),
    ("XPF", 0),
    ("XSU", 0),
    ("XUA", 0),
    ("XXX", 0),
    ("YER", 2),
    ("ZAR", 2),
    ("ZMW", 2),
    ("ZWG", 2),
];

/// An ISO 4217 currency and its minor-unit precision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Currency {
    code: &'static str,
    minor_units: u8,
}

impl Currency {
    /// Look up an ISO 4217 alphabetic code. Case is normalised to upper case.
    ///
    /// # Errors
    ///
    /// [`PosError::UnknownCurrency`] when the input is not exactly three ASCII
    /// letters or is not in the supported ISO 4217 table.
    pub fn from_code(code: &str) -> Result<Self, PosError> {
        let bytes = code.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_alphabetic) {
            return Err(PosError::UnknownCurrency(code.to_owned()));
        }
        let upper = [
            bytes[0].to_ascii_uppercase(),
            bytes[1].to_ascii_uppercase(),
            bytes[2].to_ascii_uppercase(),
        ];
        let normalised = std::str::from_utf8(&upper).expect("ASCII bytes are valid UTF-8");
        // The table owns `'static` strings, so the returned currency borrows
        // from the table rather than from the caller's input.
        let (code, minor_units) = CURRENCY_MINOR_UNITS
            .iter()
            .find(|(known, _)| *known == normalised)
            .ok_or_else(|| PosError::UnknownCurrency(code.to_owned()))?;
        Ok(Self {
            code,
            minor_units: *minor_units,
        })
    }

    /// The upper-case alphabetic code, e.g. `"USD"`.
    pub fn code(self) -> &'static str {
        self.code
    }

    /// Number of decimal digits in one major unit (0, 2, 3 or 4).
    pub fn minor_units(self) -> u8 {
        self.minor_units
    }

    /// One major unit expressed in minor units, e.g. 100 for USD, 1 for JPY.
    pub fn minor_units_per_major(self) -> i64 {
        10_i64.pow(u32::from(self.minor_units))
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl Serialize for Currency {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = String::deserialize(deserializer)?;
        Currency::from_code(&code).map_err(serde::de::Error::custom)
    }
}

/// A quantity in thousandths of a unit.
///
/// A line quantity is always positive; corrections are made by removing or
/// replacing the line, not by a negative quantity. Weight-based goods use the
/// same type (`2.500 kg` is `2_500` thousandths).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quantity {
    thousandths: i64,
}

impl Quantity {
    /// Construct from thousandths of a unit. Must be strictly positive.
    pub fn from_thousandths(thousandths: i64) -> Result<Self, PosError> {
        if thousandths <= 0 {
            return Err(PosError::InvalidQuantity);
        }
        Ok(Self { thousandths })
    }

    /// Construct from whole units. Overflows are rejected.
    pub fn from_units(units: i64) -> Result<Self, PosError> {
        if units <= 0 {
            return Err(PosError::InvalidQuantity);
        }
        let thousandths = units
            .checked_mul(QUANTITY_SCALE as i64)
            .ok_or(PosError::ArithmeticOverflow)?;
        Ok(Self { thousandths })
    }

    /// The raw value, in thousandths of a unit.
    pub fn thousandths(self) -> i64 {
        self.thousandths
    }
}

impl std::fmt::Display for Quantity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sign = if self.thousandths < 0 { "-" } else { "" };
        let magnitude = self.thousandths.unsigned_abs();
        write!(f, "{sign}{}.{:03}", magnitude / 1_000, magnitude % 1_000)
    }
}

/// A non-negative rate in parts per million (1_000_000 = 100%).
///
/// Integer parts per million represent common percentage rates exactly,
/// including sub-basis-point rates such as 8.875% (88_750 ppm).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rate {
    ppm: i32,
}

impl Rate {
    /// Zero percent.
    pub const ZERO: Rate = Rate { ppm: 0 };
    /// One hundred percent.
    pub const ONE_HUNDRED_PERCENT: Rate = Rate { ppm: 1_000_000 };

    /// Construct directly from parts per million, `0 ..= 1_000_000`.
    pub fn from_ppm(ppm: i32) -> Result<Self, PosError> {
        if !(0..=1_000_000).contains(&ppm) {
            return Err(PosError::InvalidRate);
        }
        Ok(Self { ppm })
    }

    /// Construct from basis points (1 bp = 0.01%), `0 ..= 10_000`.
    pub fn from_basis_points(basis_points: i32) -> Result<Self, PosError> {
        if !(0..=10_000).contains(&basis_points) {
            return Err(PosError::InvalidRate);
        }
        Self::from_ppm(basis_points * 100)
    }

    /// Construct from a whole percentage, `0 ..= 100`.
    pub fn from_percent(percent: i32) -> Result<Self, PosError> {
        Self::from_basis_points(percent * 100)
    }

    /// The rate in parts per million.
    pub fn ppm(self) -> i32 {
        self.ppm
    }

    /// The rate in basis points, rounded down (the value is always an exact
    /// multiple of 100 ppm when constructed with `from_basis_points`).
    pub fn basis_points(self) -> i32 {
        self.ppm / 100
    }
}

impl std::fmt::Display for Rate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ppm", self.ppm)
    }
}

/// An amount of money: an integer number of minor units in one currency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Money {
    currency: Currency,
    minor: i64,
}

impl Money {
    /// Construct an amount from an exact integer count of minor units.
    pub const fn new(currency: Currency, minor: i64) -> Self {
        Self { currency, minor }
    }

    /// Zero in `currency`.
    pub const fn zero(currency: Currency) -> Self {
        Self::new(currency, 0)
    }

    /// The currency tag.
    pub const fn currency(self) -> Currency {
        self.currency
    }

    /// The exact integer minor-unit amount.
    pub const fn minor(self) -> i64 {
        self.minor
    }

    /// `true` when the amount is exactly zero.
    pub const fn is_zero(self) -> bool {
        self.minor == 0
    }

    /// `true` when the amount is greater than zero.
    pub const fn is_positive(self) -> bool {
        self.minor > 0
    }

    /// `true` when the amount is less than zero.
    pub const fn is_negative(self) -> bool {
        self.minor < 0
    }

    /// Checked addition; currencies must match.
    pub fn checked_add(self, other: Money) -> Result<Money, PosError> {
        self.require_same_currency(other)?;
        let minor = self
            .minor
            .checked_add(other.minor)
            .ok_or(PosError::ArithmeticOverflow)?;
        Ok(Money::new(self.currency, minor))
    }

    /// Checked subtraction; currencies must match.
    pub fn checked_sub(self, other: Money) -> Result<Money, PosError> {
        self.require_same_currency(other)?;
        let minor = self
            .minor
            .checked_sub(other.minor)
            .ok_or(PosError::ArithmeticOverflow)?;
        Ok(Money::new(self.currency, minor))
    }

    /// Checked negation.
    pub fn checked_neg(self) -> Result<Money, PosError> {
        let minor = self
            .minor
            .checked_neg()
            .ok_or(PosError::ArithmeticOverflow)?;
        Ok(Money::new(self.currency, minor))
    }

    /// Absolute value, rejecting `i64::MIN`.
    pub fn checked_abs(self) -> Result<Money, PosError> {
        let minor = self
            .minor
            .checked_abs()
            .ok_or(PosError::ArithmeticOverflow)?;
        Ok(Money::new(self.currency, minor))
    }

    /// Sum amounts that must all share `currency`.
    pub fn checked_sum(
        currency: Currency,
        amounts: impl IntoIterator<Item = Money>,
    ) -> Result<Money, PosError> {
        let mut total = Money::zero(currency);
        for amount in amounts {
            total = total.checked_add(amount)?;
        }
        Ok(total)
    }

    /// Multiply by a decimal quantity and round the minor units with `mode`.
    ///
    /// The multiplication and division use `i128`; only the final rounded
    /// quotient is stored.
    pub fn mul_quantity(self, quantity: Quantity, mode: RoundingMode) -> Result<Money, PosError> {
        let numerator = i128::from(self.minor) * i128::from(quantity.thousandths());
        let minor = div_round(numerator, QUANTITY_SCALE, mode)?;
        Ok(Money::new(self.currency, minor))
    }

    /// Apply a rate (tax or percentage discount) and round with `mode`.
    pub fn mul_rate(self, rate: Rate, mode: RoundingMode) -> Result<Money, PosError> {
        let numerator = i128::from(self.minor) * i128::from(rate.ppm());
        let minor = div_round(numerator, RATE_SCALE, mode)?;
        Ok(Money::new(self.currency, minor))
    }

    fn require_same_currency(self, other: Money) -> Result<(), PosError> {
        if self.currency != other.currency {
            return Err(PosError::CurrencyMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Display for Money {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            format_minor(self.minor, self.currency.minor_units),
            self.currency.code()
        )
    }
}

fn format_minor(minor: i64, digits: u8) -> String {
    if digits == 0 {
        return minor.to_string();
    }
    let divisor = 10_u64.pow(u32::from(digits));
    let magnitude = minor.unsigned_abs();
    let whole = magnitude / divisor;
    let fraction = magnitude % divisor;
    let sign = if minor < 0 { "-" } else { "" };
    format!(
        "{sign}{whole}.{fraction:0width$}",
        width = usize::from(digits)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd(minor: i64) -> Money {
        Money::new(Currency::from_code("USD").unwrap(), minor)
    }

    #[test]
    fn currency_lookup_normalises_case_and_has_minor_units() {
        assert_eq!(Currency::from_code("usd").unwrap().code(), "USD");
        assert_eq!(Currency::from_code("JPY").unwrap().minor_units(), 0);
        assert_eq!(Currency::from_code("BHD").unwrap().minor_units(), 3);
        assert_eq!(Currency::from_code("CLF").unwrap().minor_units(), 4);
        assert_eq!(
            Currency::from_code("USD").unwrap().minor_units_per_major(),
            100
        );
        assert_eq!(
            Currency::from_code("JPY").unwrap().minor_units_per_major(),
            1
        );
    }

    #[test]
    fn currency_lookup_rejects_unknown_and_malformed_codes() {
        assert_eq!(
            Currency::from_code("us"),
            Err(PosError::UnknownCurrency("us".into()))
        );
        assert_eq!(
            Currency::from_code("US1"),
            Err(PosError::UnknownCurrency("US1".into()))
        );
        assert_eq!(
            Currency::from_code("ABC"),
            Err(PosError::UnknownCurrency("ABC".into()))
        );
    }

    #[test]
    fn currency_serde_roundtrip_uses_the_alphabetic_code() {
        let currency = Currency::from_code("EUR").unwrap();
        let json = serde_json::to_string(&currency).unwrap();
        assert_eq!(json, "\"EUR\"");
        assert_eq!(serde_json::from_str::<Currency>(&json).unwrap(), currency);
        assert!(serde_json::from_str::<Currency>("\"ABC\"").is_err());
    }

    #[test]
    fn money_display_uses_the_currency_precision() {
        assert_eq!(usd(123).to_string(), "1.23 USD");
        assert_eq!(usd(-5).to_string(), "-0.05 USD");
        assert_eq!(usd(0).to_string(), "0.00 USD");
        let jpy = Money::new(Currency::from_code("JPY").unwrap(), 1200);
        assert_eq!(jpy.to_string(), "1200 JPY");
        let clf = Money::new(Currency::from_code("CLF").unwrap(), 12_345);
        assert_eq!(clf.to_string(), "1.2345 CLF");
    }

    #[test]
    fn money_addition_rejects_currency_mismatch() {
        let eur = Money::new(Currency::from_code("EUR").unwrap(), 1);
        assert_eq!(usd(1).checked_add(eur), Err(PosError::CurrencyMismatch));
        assert_eq!(usd(1).checked_sub(eur), Err(PosError::CurrencyMismatch));
    }

    #[test]
    fn money_addition_and_subtraction_are_checked() {
        assert_eq!(usd(100).checked_add(usd(23)).unwrap(), usd(123));
        assert_eq!(usd(100).checked_sub(usd(123)).unwrap(), usd(-23));
        assert_eq!(
            usd(i64::MAX).checked_add(usd(1)),
            Err(PosError::ArithmeticOverflow)
        );
        assert_eq!(
            usd(i64::MIN).checked_neg(),
            Err(PosError::ArithmeticOverflow)
        );
    }

    #[test]
    fn quantity_and_rate_validation() {
        assert_eq!(
            Quantity::from_thousandths(0),
            Err(PosError::InvalidQuantity)
        );
        assert_eq!(Quantity::from_units(-1), Err(PosError::InvalidQuantity));
        assert_eq!(Quantity::from_units(2).unwrap().thousandths(), 2_000);
        assert_eq!(Rate::from_percent(101), Err(PosError::InvalidRate));
        assert_eq!(Rate::from_basis_points(825).unwrap().ppm(), 82_500);
    }

    #[test]
    fn fractional_quantity_times_price_rounds_at_the_line() {
        // 3 × 0.333 units at 10.00 = 3.33 exactly under thousandths.
        let price = usd(1_000);
        let qty = Quantity::from_thousandths(333).unwrap();
        for mode in RoundingMode::ALL {
            assert_eq!(price.mul_quantity(qty, mode).unwrap(), usd(333));
        }
    }

    #[test]
    fn half_unit_rounding_follows_the_requested_mode() {
        // 0.005 units at 1.00 = 0.5 minor units.
        let price = usd(100);
        let qty = Quantity::from_thousandths(5).unwrap();
        assert_eq!(
            price
                .mul_quantity(qty, RoundingMode::HalfAwayFromZero)
                .unwrap(),
            usd(1)
        );
        assert_eq!(
            price
                .mul_quantity(qty, RoundingMode::HalfTowardZero)
                .unwrap(),
            usd(0)
        );
        assert_eq!(
            price.mul_quantity(qty, RoundingMode::HalfEven).unwrap(),
            usd(0)
        );
    }

    #[test]
    fn money_serde_roundtrip() {
        let amount = usd(-1234);
        let json = serde_json::to_string(&amount).unwrap();
        assert_eq!(json, "{\"currency\":\"USD\",\"minor\":-1234}");
        let back: Money = serde_json::from_str(&json).unwrap();
        assert_eq!(amount, back);
    }
}
