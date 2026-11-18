// SPDX-License-Identifier: AGPL-3.0-only

//! POS-10 — deterministic localization for money, numbers, dates and labels.
//!
//! Localization affects presentation only. It never changes a [`Money`] value,
//! a tax calculation or an invoice sequence. Formatting is integer-only and
//! uses caller-supplied UTC [`Timestamp`]s plus a fixed offset; there is no
//! hidden clock and no timezone database.
//!
//! A [`Locale`] carries a BCP-47-shaped language tag, separators, grouping,
//! currency placement, date order, 12/24-hour time, an explicit UTC offset and
//! the receipt label set. Constructing one validates the configuration, so a
//! formatter cannot silently fall back to unrelated defaults.

use std::collections::BTreeMap;

use crate::audit::Timestamp;
use crate::money::{Money, Rate};

/// Day/month/year ordering used by a locale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DateOrder {
    /// 2026-11-17.
    YearMonthDay,
    /// 17/11/2026.
    DayMonthYear,
    /// 11/17/2026.
    MonthDayYear,
}

/// Digit grouping for formatted numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Grouping {
    /// No grouping separator.
    None,
    /// Groups of three: 1 234 567.
    Thousands,
    /// Indian groups: 12 34 567.
    Indian,
}

/// Whether the currency code is written before or after the amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CurrencyPlacement {
    /// `USD 1,234.56`.
    Before,
    /// `1,234.56 USD`.
    After,
}

/// 12-hour or 24-hour clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeStyle {
    /// `23:05`.
    H24,
    /// `11:05 PM`.
    H12,
}

/// A localizable receipt label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReceiptLabel {
    /// Marker printed on a copy that is not the original.
    Reprint,
    /// Invoice number.
    Invoice,
    /// Issue date.
    Date,
    /// Issuing terminal.
    Terminal,
    /// Operator or cashier identifier.
    Operator,
    /// Transaction or check reference.
    Reference,
    /// Net subtotal.
    Subtotal,
    /// Discount total.
    Discount,
    /// Tax total.
    Tax,
    /// Grand total.
    Total,
    /// Amount tendered.
    Paid,
    /// Change returned.
    Change,
    /// Tip.
    Tip,
    /// Tax registration identifier.
    TaxId,
    /// Payment method label.
    Payment,
    /// Email delivery marker.
    Email,
    /// Print delivery marker.
    Print,
    /// Ante meridiem marker.
    Am,
    /// Post meridiem marker.
    Pm,
}

impl ReceiptLabel {
    /// Every label, in stable order.
    pub const ALL: [ReceiptLabel; 19] = [
        ReceiptLabel::Reprint,
        ReceiptLabel::Invoice,
        ReceiptLabel::Date,
        ReceiptLabel::Terminal,
        ReceiptLabel::Operator,
        ReceiptLabel::Reference,
        ReceiptLabel::Subtotal,
        ReceiptLabel::Discount,
        ReceiptLabel::Tax,
        ReceiptLabel::Total,
        ReceiptLabel::Paid,
        ReceiptLabel::Change,
        ReceiptLabel::Tip,
        ReceiptLabel::TaxId,
        ReceiptLabel::Payment,
        ReceiptLabel::Email,
        ReceiptLabel::Print,
        ReceiptLabel::Am,
        ReceiptLabel::Pm,
    ];
}

/// The label set used by receipt rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptLabels {
    values: BTreeMap<ReceiptLabel, String>,
}

impl ReceiptLabels {
    /// English labels.
    pub fn english() -> Self {
        Self::from_pairs(&[
            (ReceiptLabel::Reprint, "REPRINT"),
            (ReceiptLabel::Invoice, "Invoice"),
            (ReceiptLabel::Date, "Date"),
            (ReceiptLabel::Terminal, "Terminal"),
            (ReceiptLabel::Operator, "Operator"),
            (ReceiptLabel::Reference, "Reference"),
            (ReceiptLabel::Subtotal, "Subtotal"),
            (ReceiptLabel::Discount, "Discount"),
            (ReceiptLabel::Tax, "Tax"),
            (ReceiptLabel::Total, "Total"),
            (ReceiptLabel::Paid, "Paid"),
            (ReceiptLabel::Change, "Change"),
            (ReceiptLabel::Tip, "Tip"),
            (ReceiptLabel::TaxId, "Tax ID"),
            (ReceiptLabel::Payment, "Payment"),
            (ReceiptLabel::Email, "Email"),
            (ReceiptLabel::Print, "Print"),
            (ReceiptLabel::Am, "AM"),
            (ReceiptLabel::Pm, "PM"),
        ])
    }

    /// German labels.
    pub fn german() -> Self {
        Self::from_pairs(&[
            (ReceiptLabel::Reprint, "NACHDRUCK"),
            (ReceiptLabel::Invoice, "Rechnung"),
            (ReceiptLabel::Date, "Datum"),
            (ReceiptLabel::Terminal, "Kasse"),
            (ReceiptLabel::Operator, "Bediener"),
            (ReceiptLabel::Reference, "Referenz"),
            (ReceiptLabel::Subtotal, "Zwischensumme"),
            (ReceiptLabel::Discount, "Rabatt"),
            (ReceiptLabel::Tax, "Steuer"),
            (ReceiptLabel::Total, "Gesamt"),
            (ReceiptLabel::Paid, "Bezahlt"),
            (ReceiptLabel::Change, "Rückgeld"),
            (ReceiptLabel::Tip, "Trinkgeld"),
            (ReceiptLabel::TaxId, "Steuernummer"),
            (ReceiptLabel::Payment, "Zahlung"),
            (ReceiptLabel::Email, "E-Mail"),
            (ReceiptLabel::Print, "Druck"),
            (ReceiptLabel::Am, "AM"),
            (ReceiptLabel::Pm, "PM"),
        ])
    }

    /// French labels.
    pub fn french() -> Self {
        Self::from_pairs(&[
            (ReceiptLabel::Reprint, "RÉIMPRESSION"),
            (ReceiptLabel::Invoice, "Facture"),
            (ReceiptLabel::Date, "Date"),
            (ReceiptLabel::Terminal, "Terminal"),
            (ReceiptLabel::Operator, "Opérateur"),
            (ReceiptLabel::Reference, "Référence"),
            (ReceiptLabel::Subtotal, "Sous-total"),
            (ReceiptLabel::Discount, "Remise"),
            (ReceiptLabel::Tax, "Taxe"),
            (ReceiptLabel::Total, "Total"),
            (ReceiptLabel::Paid, "Payé"),
            (ReceiptLabel::Change, "Change"),
            (ReceiptLabel::Tip, "Pourboire"),
            (ReceiptLabel::TaxId, "Numéro fiscal"),
            (ReceiptLabel::Payment, "Paiement"),
            (ReceiptLabel::Email, "Courriel"),
            (ReceiptLabel::Print, "Imprimer"),
            (ReceiptLabel::Am, "AM"),
            (ReceiptLabel::Pm, "PM"),
        ])
    }

    fn from_pairs(pairs: &[(ReceiptLabel, &str)]) -> Self {
        let mut values = BTreeMap::new();
        for (label, value) in pairs {
            values.insert(*label, (*value).to_string());
        }
        Self { values }
    }

    /// Override one label. Empty or control-bearing text is rejected.
    pub fn with(
        mut self,
        label: ReceiptLabel,
        text: impl Into<String>,
    ) -> Result<Self, LocalizationError> {
        let text = text.into();
        if text.is_empty() || text.len() > 128 || text.chars().any(char::is_control) {
            return Err(LocalizationError::InvalidLabel(label));
        }
        self.values.insert(label, text);
        Ok(self)
    }

    /// The text for `label`.
    pub fn get(&self, label: ReceiptLabel) -> &str {
        self.values
            .get(&label)
            .map(String::as_str)
            .unwrap_or_default()
    }
}

impl Default for ReceiptLabels {
    fn default() -> Self {
        Self::english()
    }
}

/// A validated presentation locale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locale {
    language: String,
    decimal_separator: char,
    grouping_separator: char,
    grouping: Grouping,
    currency_placement: CurrencyPlacement,
    currency_space: bool,
    date_order: DateOrder,
    date_separator: char,
    time_style: TimeStyle,
    negative_parentheses: bool,
    utc_offset_minutes: i16,
    labels: ReceiptLabels,
}

impl Locale {
    /// Create a locale with conventional defaults: `.` decimal separator,
    /// `,` grouping separator, thousands grouping, currency after the amount,
    /// ISO date order, 24-hour time and UTC.
    pub fn new(
        language: impl Into<String>,
        labels: ReceiptLabels,
    ) -> Result<Self, LocalizationError> {
        let language = language.into();
        validate_language(&language)?;
        Ok(Self {
            language,
            decimal_separator: '.',
            grouping_separator: ',',
            grouping: Grouping::Thousands,
            currency_placement: CurrencyPlacement::After,
            currency_space: true,
            date_order: DateOrder::YearMonthDay,
            date_separator: '-',
            time_style: TimeStyle::H24,
            negative_parentheses: false,
            utc_offset_minutes: 0,
            labels,
        })
    }

    /// Change number separators and grouping.
    pub fn with_number_format(
        mut self,
        decimal_separator: char,
        grouping_separator: char,
        grouping: Grouping,
    ) -> Result<Self, LocalizationError> {
        validate_separator(decimal_separator)?;
        validate_separator(grouping_separator)?;
        if decimal_separator == grouping_separator {
            return Err(LocalizationError::SeparatorsEqual);
        }
        self.decimal_separator = decimal_separator;
        self.grouping_separator = grouping_separator;
        self.grouping = grouping;
        Ok(self)
    }

    /// Change currency code placement.
    pub fn with_currency_format(mut self, placement: CurrencyPlacement, space: bool) -> Self {
        self.currency_placement = placement;
        self.currency_space = space;
        self
    }

    /// Change date order, date separator and clock style.
    pub fn with_date_format(
        mut self,
        order: DateOrder,
        separator: char,
        time_style: TimeStyle,
    ) -> Result<Self, LocalizationError> {
        if !separator.is_ascii_graphic() || separator.is_ascii_alphanumeric() {
            return Err(LocalizationError::InvalidDateSeparator);
        }
        self.date_order = order;
        self.date_separator = separator;
        self.time_style = time_style;
        Ok(self)
    }

    /// Wrap negative amounts in parentheses instead of prefixing `-`.
    pub fn with_negative_parentheses(mut self, enabled: bool) -> Self {
        self.negative_parentheses = enabled;
        self
    }

    /// Set the fixed offset from UTC used for displayed date and time.
    pub fn with_utc_offset_minutes(mut self, minutes: i16) -> Result<Self, LocalizationError> {
        if !(-14 * 60..=14 * 60).contains(&minutes) {
            return Err(LocalizationError::InvalidUtcOffset);
        }
        self.utc_offset_minutes = minutes;
        Ok(self)
    }

    /// The language tag.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The label set.
    pub fn labels(&self) -> &ReceiptLabels {
        &self.labels
    }

    /// The localized text for `label`.
    pub fn label(&self, label: ReceiptLabel) -> &str {
        self.labels.get(label)
    }

    /// Format a monetary amount with localized separators, grouping and
    /// currency placement. The returned string always contains the ISO
    /// currency code, so it cannot be confused with another currency.
    pub fn format_money(&self, money: Money) -> String {
        let currency = money.currency();
        let per_major = currency.minor_units_per_major() as u64;
        let minor_digits = currency.minor_units() as usize;
        let magnitude = money.minor().unsigned_abs();
        let major = magnitude / per_major;
        let fraction = magnitude % per_major;
        let mut number = self.format_grouped(major);
        if minor_digits > 0 {
            number.push(self.decimal_separator);
            number.push_str(&format!("{:0width$}", fraction, width = minor_digits));
        }
        let code = currency.code();
        let with_currency = match self.currency_placement {
            CurrencyPlacement::Before => {
                if self.currency_space {
                    format!("{code} {number}")
                } else {
                    format!("{code}{number}")
                }
            }
            CurrencyPlacement::After => {
                if self.currency_space {
                    format!("{number} {code}")
                } else {
                    format!("{number}{code}")
                }
            }
        };
        if money.is_negative() {
            if self.negative_parentheses {
                format!("({with_currency})")
            } else {
                format!("-{with_currency}")
            }
        } else {
            with_currency
        }
    }

    /// Format a whole number with grouped digits.
    pub fn format_number(&self, value: i64) -> String {
        let magnitude = value.unsigned_abs();
        let grouped = self.format_grouped(magnitude);
        if value < 0 {
            format!("-{grouped}")
        } else {
            grouped
        }
    }

    /// Format a quantity held in thousandths, trimming trailing zeros.
    pub fn format_quantity(&self, thousandths: i64) -> String {
        self.format_scaled(thousandths.unsigned_abs(), 1_000, 3, thousandths < 0)
    }

    /// Format a tax rate in percent, trimming trailing zeros.
    pub fn format_rate(&self, rate: Rate) -> String {
        // 1% is 10_000 ppm, so four decimal places cover every representable
        // rate exactly.
        let percent_scaled = i64::from(rate.ppm());
        format!(
            "{}%",
            self.format_scaled(percent_scaled.unsigned_abs(), 10_000, 4, percent_scaled < 0)
        )
    }

    /// Format the UTC timestamp as a local calendar date. The offset is fixed;
    /// this is not a timezone database and does not handle DST transitions.
    pub fn format_date(&self, timestamp: Timestamp) -> Result<String, LocalizationError> {
        let (year, month, day, _, _) = self.civil(timestamp)?;
        let sep = self.date_separator;
        match self.date_order {
            DateOrder::YearMonthDay => Ok(format!("{year:04}{sep}{month:02}{sep}{day:02}")),
            DateOrder::DayMonthYear => Ok(format!("{day:02}{sep}{month:02}{sep}{year:04}")),
            DateOrder::MonthDayYear => Ok(format!("{month:02}{sep}{day:02}{sep}{year:04}")),
        }
    }

    /// Format the UTC timestamp as a local wall-clock time.
    pub fn format_time(&self, timestamp: Timestamp) -> Result<String, LocalizationError> {
        let (_, _, _, hour, minute) = self.civil(timestamp)?;
        match self.time_style {
            TimeStyle::H24 => Ok(format!("{hour:02}:{minute:02}")),
            TimeStyle::H12 => {
                let suffix = if hour < 12 {
                    self.label(ReceiptLabel::Am)
                } else {
                    self.label(ReceiptLabel::Pm)
                };
                let hour = match hour % 12 {
                    0 => 12,
                    value => value,
                };
                Ok(format!("{hour}:{minute:02} {suffix}"))
            }
        }
    }

    /// Format the UTC timestamp as local date and time.
    pub fn format_datetime(&self, timestamp: Timestamp) -> Result<String, LocalizationError> {
        Ok(format!(
            "{} {}",
            self.format_date(timestamp)?,
            self.format_time(timestamp)?
        ))
    }

    fn civil(&self, timestamp: Timestamp) -> Result<(i64, u32, u32, u32, u32), LocalizationError> {
        let offset_ms = i64::from(self.utc_offset_minutes) * 60_000;
        let local = timestamp
            .millis()
            .checked_add(offset_ms)
            .ok_or(LocalizationError::TimestampOutOfRange)?;
        let days = local.div_euclid(86_400_000);
        let millis_of_day = local.rem_euclid(86_400_000);
        let (year, month, day) = civil_from_days(days);
        if !(0..=9999).contains(&year) {
            return Err(LocalizationError::TimestampOutOfRange);
        }
        let hour = (millis_of_day / 3_600_000) as u32;
        let minute = ((millis_of_day / 60_000) % 60) as u32;
        Ok((year, month as u32, day as u32, hour, minute))
    }

    fn format_scaled(&self, magnitude: u64, scale: u64, decimals: usize, negative: bool) -> String {
        let whole = magnitude / scale;
        let fraction = magnitude % scale;
        let mut value = self.format_grouped(whole);
        if fraction != 0 {
            let mut digits = format!("{fraction:0width$}", width = decimals);
            while digits.ends_with('0') {
                digits.pop();
            }
            value.push(self.decimal_separator);
            value.push_str(&digits);
        }
        if negative {
            format!("-{value}")
        } else {
            value
        }
    }

    fn format_grouped(&self, magnitude: u64) -> String {
        let digits = magnitude.to_string();
        let groups: Vec<&str> = match self.grouping {
            Grouping::None => return digits,
            Grouping::Thousands => group_from_right(&digits, &[3]),
            Grouping::Indian => group_from_right(&digits, &[3, 2]),
        };
        groups.join(&self.grouping_separator.to_string())
    }
}

fn group_from_right<'a>(digits: &'a str, sizes: &[usize]) -> Vec<&'a str> {
    let mut groups = Vec::new();
    let mut end = digits.len();
    let mut index = 0;
    while end > 0 {
        let size = sizes[index.min(sizes.len() - 1)];
        let start = end.saturating_sub(size);
        groups.push(&digits[start..end]);
        end = start;
        index += 1;
    }
    groups.reverse();
    groups
}

/// Convert days since 1970-01-01 to a proleptic Gregorian date.
///
/// Howard Hinnant's `civil_from_days` algorithm, using integer arithmetic.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

fn validate_language(language: &str) -> Result<(), LocalizationError> {
    if language.is_empty() {
        return Err(LocalizationError::EmptyLanguage);
    }
    if language.len() > 35
        || !language
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(LocalizationError::InvalidLanguage);
    }
    Ok(())
}

fn validate_separator(separator: char) -> Result<(), LocalizationError> {
    if separator.is_alphanumeric() || separator.is_control() || matches!(separator, '+' | '-') {
        return Err(LocalizationError::InvalidSeparator);
    }
    Ok(())
}

/// A rejected localization configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalizationError {
    /// The language tag was empty.
    EmptyLanguage,
    /// The language tag was too long or contained unsupported characters.
    InvalidLanguage,
    /// A number separator was a digit, sign, dot, comma or control character.
    InvalidSeparator,
    /// The decimal and grouping separators were equal.
    SeparatorsEqual,
    /// The date separator was not a visible non-alphanumeric character.
    InvalidDateSeparator,
    /// A receipt label was empty, too long or contained control characters.
    InvalidLabel(ReceiptLabel),
    /// The fixed UTC offset was outside −14:00 through +14:00.
    InvalidUtcOffset,
    /// The timestamp fell outside years 0000 through 9999.
    TimestampOutOfRange,
}

impl LocalizationError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            LocalizationError::EmptyLanguage => "localization.empty_language",
            LocalizationError::InvalidLanguage => "localization.invalid_language",
            LocalizationError::InvalidSeparator => "localization.invalid_separator",
            LocalizationError::SeparatorsEqual => "localization.separators_equal",
            LocalizationError::InvalidDateSeparator => "localization.invalid_date_separator",
            LocalizationError::InvalidLabel(_) => "localization.invalid_label",
            LocalizationError::InvalidUtcOffset => "localization.invalid_utc_offset",
            LocalizationError::TimestampOutOfRange => "localization.timestamp_out_of_range",
        }
    }
}

impl std::fmt::Display for LocalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalizationError::EmptyLanguage => f.write_str("language tag is empty"),
            LocalizationError::InvalidLanguage => f.write_str("invalid language tag"),
            LocalizationError::InvalidSeparator => f.write_str("invalid number separator"),
            LocalizationError::SeparatorsEqual => {
                f.write_str("decimal and grouping separators are equal")
            }
            LocalizationError::InvalidDateSeparator => f.write_str("invalid date separator"),
            LocalizationError::InvalidLabel(label) => write!(f, "invalid receipt label {label:?}"),
            LocalizationError::InvalidUtcOffset => f.write_str("UTC offset is outside ±14:00"),
            LocalizationError::TimestampOutOfRange => {
                f.write_str("timestamp is outside years 0000-9999")
            }
        }
    }
}

impl std::error::Error for LocalizationError {}
