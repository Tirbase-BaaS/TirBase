// SPDX-License-Identifier: Apache-2.0

//! Civil-time formatting for EPCIS timestamps.
//!
//! The ledger stores authenticated-time estimates as Unix seconds. EPCIS wants
//! RFC 3339 date-times with a zone offset. The adapter renders every timestamp
//! in UTC (`+00:00`) because the ledger does not record a local offset; see
//! `docs/epcis-adapter.md`, "Time and timezone".

/// Render Unix seconds as `YYYY-MM-DDTHH:MM:SS.000Z`.
pub fn rfc3339_utc(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let seconds_of_day = epoch_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z")
}

/// The timezone offset EPCIS requires alongside every `eventTime`.
pub const UTC_OFFSET: &str = "+00:00";

/// Convert a count of days since 1970-01-01 to a civil date.
///
/// Howard Hinnant's `civil_from_days`, valid for the whole `i64` range that
/// matters here (year 0 is not a concern for ledger timestamps).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(1_770_000_000), "2026-02-02T02:40:00.000Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00.000Z");
    }
}
