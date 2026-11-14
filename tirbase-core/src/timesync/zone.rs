// SPDX-License-Identifier: AGPL-3.0-only

//! Per-site time zones, DST rules, and local schedule evaluation (F-06 §3).
//!
//! TirBase stores and compares **UTC** everywhere. A site/store/venue supplies
//! its own [`SiteTimeZone`] so local schedules can be evaluated without
//! assuming a fixed offset. DST is modelled by an explicit [`DstRule`]
//! (standard offset, daylight offset, and two transition rules expressed as
//! "nth weekday of month at local time"), not by the host's `/etc/localtime`:
//! an edge gateway may be deployed far from the site it controls.
//!
//! # DST semantics
//!
//! * A local time that does not exist (spring-forward gap) resolves to the
//!   transition instant: the event runs **once**, at the first valid local
//!   instant after the gap.
//! * A local time that exists twice (autumn overlap) resolves to the **first**
//!   occurrence: the event runs **once**.
//! * [`occurrences_between`] de-duplicates by `(event id, local date)`, so a
//!   transition can neither skip a day's event nor run it twice.
//!
//! The rule shape covers the common IANA zones used by deployments (US, EU,
//! and fixed-offset sites). Zones with mid-night transitions or political
//! exceptions need their own rule configured; there is intentionally no IANA
//! database dependency in the core crate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Seconds in one day.
pub const SECS_PER_DAY: i64 = 86_400;

/// A calendar date in the proleptic Gregorian calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CivilDate {
    /// Calendar year.
    pub year: i32,
    /// Month, 1–12.
    pub month: u8,
    /// Day of month, 1–31.
    pub day: u8,
}

impl CivilDate {
    /// Construct a date, validating the month and day.
    pub fn new(year: i32, month: u8, day: u8) -> Option<Self> {
        if month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(CivilDate { year, month, day })
    }

    /// Days since 1970-01-01 (Howard Hinnant's civil-from-days algorithm).
    pub fn days_since_epoch(self) -> i64 {
        let mut y = i64::from(self.year);
        let m = i64::from(self.month);
        let d = i64::from(self.day);
        y -= i64::from(m <= 2);
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// Inverse of [`Self::days_since_epoch`].
    pub fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = mp + if mp < 10 { 3 } else { -9 };
        CivilDate {
            year: (year + i64::from(month <= 2)) as i32,
            month: month as u8,
            day: day as u8,
        }
    }

    /// The date containing `unix_secs` in UTC.
    pub fn from_unix_secs(unix_secs: i64) -> Self {
        CivilDate::from_days(unix_secs.div_euclid(SECS_PER_DAY))
    }

    /// Shift by whole days (negative allowed).
    pub fn plus_days(self, days: i64) -> Self {
        CivilDate::from_days(self.days_since_epoch() + days)
    }

    /// Weekday, `0 = Sunday … 6 = Saturday`.
    pub fn weekday(self) -> u8 {
        (self.days_since_epoch() + 4).rem_euclid(7) as u8
    }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn nth_weekday_of_month(year: i32, month: u8, weekday: u8, nth: i8) -> Option<CivilDate> {
    if !(1..=12).contains(&month) || weekday > 6 || nth == 0 || !(-1..=5).contains(&nth) {
        return None;
    }
    if nth > 0 {
        let first = CivilDate::new(year, month, 1)?;
        let offset = (i32::from(weekday) - i32::from(first.weekday())).rem_euclid(7);
        let day = 1 + offset + (i32::from(nth) - 1) * 7;
        if day > i32::from(days_in_month(year, month)) {
            None
        } else {
            CivilDate::new(year, month, day as u8)
        }
    } else {
        let last_day = days_in_month(year, month);
        let last = CivilDate::new(year, month, last_day)?;
        let offset = (i32::from(last.weekday()) - i32::from(weekday)).rem_euclid(7);
        CivilDate::new(year, month, (i32::from(last_day) - offset) as u8)
    }
}

/// One DST transition: the `nth` weekday of `month` at a local time.
///
/// `nth = 1` is the first such weekday, `nth = -1` the last. The local time is
/// interpreted in the offset in force **before** the transition, which is what
/// the rule's `start`/`end` slot supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DstTransition {
    /// Month, 1–12.
    pub month: u8,
    /// Weekday, `0 = Sunday … 6 = Saturday`.
    pub weekday: u8,
    /// Occurrence within the month (`1..=5`, or `-1` for the last).
    pub nth: i8,
    /// Local second of day (for example `2 * 3600` for 02:00).
    pub local_second_of_day: i32,
}

impl DstTransition {
    /// UTC instant of this transition in `year`, given the offset before it.
    pub fn instant_utc(&self, year: i32, offset_before_secs: i32) -> Option<i64> {
        let date = nth_weekday_of_month(year, self.month, self.weekday, self.nth)?;
        Some(
            date.days_since_epoch() * SECS_PER_DAY
                + i64::from(self.local_second_of_day)
                - i64::from(offset_before_secs),
        )
    }
}

/// A complete yearly DST rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DstRule {
    /// Offset in force outside DST, in seconds east of UTC.
    pub standard_offset_secs: i32,
    /// Offset in force during DST, in seconds east of UTC.
    pub daylight_offset_secs: i32,
    /// Start transition; expressed in standard time.
    pub start: DstTransition,
    /// End transition; expressed in daylight time.
    pub end: DstTransition,
}

impl DstRule {
    /// UTC instant DST starts in `year`.
    pub fn start_utc(&self, year: i32) -> Option<i64> {
        self.start.instant_utc(year, self.standard_offset_secs)
    }

    /// UTC instant DST ends in `year`.
    pub fn end_utc(&self, year: i32) -> Option<i64> {
        self.end.instant_utc(year, self.daylight_offset_secs)
    }

    /// Whether DST is in force at `utc_secs`.
    pub fn is_dst_at_utc(&self, utc_secs: i64) -> bool {
        let approximate_year =
            CivilDate::from_unix_secs(utc_secs + i64::from(self.standard_offset_secs)).year;
        let (Some(start), Some(end)) = (
            self.start_utc(approximate_year),
            self.end_utc(approximate_year),
        ) else {
            return false;
        };
        if start < end {
            utc_secs >= start && utc_secs < end
        } else {
            // Southern hemisphere: DST crosses the new year.
            utc_secs >= start || utc_secs < end
        }
    }
}

/// Resolution of a local wall time to UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalResolution {
    /// Exactly one UTC instant.
    Unique(i64),
    /// The local time occurs twice (autumn overlap); `first` is earlier.
    Ambiguous {
        /// Earlier occurrence (daylight offset).
        first: i64,
        /// Later occurrence (standard offset).
        second: i64,
    },
    /// The local time does not exist (spring gap); the event is moved to the
    /// transition instant.
    Skipped {
        /// First valid instant after the gap.
        next_utc: i64,
    },
}

impl LocalResolution {
    /// The instant a scheduled event should run at.
    ///
    /// Ambiguous → first occurrence; skipped → transition instant. This is the
    /// rule that makes a DST day produce exactly one run, never zero or two.
    pub fn schedule_instant(self) -> i64 {
        match self {
            LocalResolution::Unique(utc) => utc,
            LocalResolution::Ambiguous { first, .. } => first,
            LocalResolution::Skipped { next_utc } => next_utc,
        }
    }
}

/// Per-site UTC offset and optional DST rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteTimeZone {
    /// Site/store/venue identifier this zone belongs to.
    pub id: String,
    /// Standard offset, seconds east of UTC.
    pub standard_offset_secs: i32,
    /// DST rule, when the site observes DST.
    pub dst: Option<DstRule>,
}

impl SiteTimeZone {
    /// UTC, no DST.
    pub fn utc() -> Self {
        SiteTimeZone {
            id: "utc".to_string(),
            standard_offset_secs: 0,
            dst: None,
        }
    }

    /// A fixed offset with no DST (for example a store at UTC+05:30).
    pub fn fixed(id: impl Into<String>, standard_offset_secs: i32) -> Self {
        SiteTimeZone {
            id: id.into(),
            standard_offset_secs,
            dst: None,
        }
    }

    /// A site observing US Eastern DST (second Sunday March, first Sunday
    /// November, 02:00 local).
    pub fn us_eastern(id: impl Into<String>) -> Self {
        SiteTimeZone {
            id: id.into(),
            standard_offset_secs: -5 * 3_600,
            dst: Some(DstRule {
                standard_offset_secs: -5 * 3_600,
                daylight_offset_secs: -4 * 3_600,
                start: DstTransition {
                    month: 3,
                    weekday: 0,
                    nth: 2,
                    local_second_of_day: 2 * 3_600,
                },
                end: DstTransition {
                    month: 11,
                    weekday: 0,
                    nth: 1,
                    local_second_of_day: 2 * 3_600,
                },
            }),
        }
    }

    /// A site observing EU DST (last Sunday March and October, 01:00 UTC).
    pub fn eu_central(id: impl Into<String>) -> Self {
        SiteTimeZone {
            id: id.into(),
            standard_offset_secs: 3_600,
            dst: Some(DstRule {
                standard_offset_secs: 3_600,
                daylight_offset_secs: 2 * 3_600,
                start: DstTransition {
                    month: 3,
                    weekday: 0,
                    nth: -1,
                    local_second_of_day: 2 * 3_600,
                },
                end: DstTransition {
                    month: 10,
                    weekday: 0,
                    nth: -1,
                    local_second_of_day: 3 * 3_600,
                },
            }),
        }
    }

    /// Offset in force at `utc_secs`.
    pub fn offset_at_utc(&self, utc_secs: i64) -> i32 {
        match &self.dst {
            Some(rule) if rule.is_dst_at_utc(utc_secs) => rule.daylight_offset_secs,
            _ => self.standard_offset_secs,
        }
    }

    /// Whether DST is in force at `utc_secs`.
    pub fn is_dst_at_utc(&self, utc_secs: i64) -> bool {
        self.dst
            .as_ref()
            .map(|rule| rule.is_dst_at_utc(utc_secs))
            .unwrap_or(false)
    }

    /// Local second-of-day for `utc_secs`.
    pub fn local_second_of_day(&self, utc_secs: i64) -> i64 {
        (utc_secs + i64::from(self.offset_at_utc(utc_secs))).rem_euclid(SECS_PER_DAY)
    }

    /// Local date for `utc_secs`.
    pub fn local_date(&self, utc_secs: i64) -> CivilDate {
        CivilDate::from_unix_secs(utc_secs + i64::from(self.offset_at_utc(utc_secs)))
    }

    /// Resolve a local date and second-of-day to UTC.
    pub fn resolve_local(&self, date: CivilDate, local_second_of_day: i64) -> LocalResolution {
        let local_secs = date.days_since_epoch() * SECS_PER_DAY + local_second_of_day;
        let standard_utc = local_secs - i64::from(self.standard_offset_secs);

        let Some(rule) = &self.dst else {
            return LocalResolution::Unique(standard_utc);
        };

        let daylight_utc = local_secs - i64::from(rule.daylight_offset_secs);
        let standard_valid = self.offset_at_utc(standard_utc) == self.standard_offset_secs;
        let daylight_valid = self.offset_at_utc(daylight_utc) == rule.daylight_offset_secs;

        match (standard_valid, daylight_valid) {
            (true, true) if standard_utc != daylight_utc => LocalResolution::Ambiguous {
                first: standard_utc.min(daylight_utc),
                second: standard_utc.max(daylight_utc),
            },
            (false, true) => LocalResolution::Unique(daylight_utc),
            (true, false) => LocalResolution::Unique(standard_utc),
            (true, true) => LocalResolution::Unique(standard_utc),
            (false, false) => {
                // Spring gap: run at the transition instant, i.e. the first
                // valid local time after the missing interval.
                let next_utc = rule.start_utc(date.year).unwrap_or(standard_utc);
                LocalResolution::Skipped { next_utc }
            }
        }
    }
}

/// A daily recurring local-time event for one site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledEvent {
    /// Stable event identifier.
    pub id: String,
    /// Local second of day the event is scheduled at.
    pub local_second_of_day: i64,
}

impl ScheduledEvent {
    /// Construct an event at `hour:minute` local time.
    pub fn daily(id: impl Into<String>, hour: u8, minute: u8) -> Self {
        ScheduledEvent {
            id: id.into(),
            local_second_of_day: (i64::from(hour) * 3_600 + i64::from(minute) * 60)
                .rem_euclid(SECS_PER_DAY),
        }
    }
}

/// One materialised occurrence of a [`ScheduledEvent`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScheduledOccurrence {
    /// Event identifier.
    pub event_id: String,
    /// Local date the occurrence belongs to (the de-duplication key).
    pub local_date: CivilDate,
    /// UTC instant to run at.
    pub utc_secs: i64,
}

/// The occurrence of `event` on one local date.
///
/// Always returns exactly one instant for a valid date and zone — never zero,
/// which is what prevents a spring-forward day from skipping a scheduled job.
pub fn occurrence_for_local_date(
    event: &ScheduledEvent,
    zone: &SiteTimeZone,
    date: CivilDate,
) -> Option<ScheduledOccurrence> {
    let local_second_of_day = event.local_second_of_day.rem_euclid(SECS_PER_DAY);
    let resolution = zone.resolve_local(date, local_second_of_day);
    Some(ScheduledOccurrence {
        event_id: event.id.clone(),
        local_date: date,
        utc_secs: resolution.schedule_instant(),
    })
}

/// Every occurrence of `event` in `[start_utc, end_utc]`, at most one per
/// local date.
pub fn occurrences_between(
    event: &ScheduledEvent,
    zone: &SiteTimeZone,
    start_utc: i64,
    end_utc: i64,
) -> Vec<ScheduledOccurrence> {
    if end_utc < start_utc {
        return Vec::new();
    }

    let mut date = CivilDate::from_unix_secs(start_utc + i64::from(zone.standard_offset_secs))
        .plus_days(-2);
    let last = CivilDate::from_unix_secs(end_utc + i64::from(zone.standard_offset_secs))
        .plus_days(2);

    let mut seen: BTreeSet<(String, CivilDate)> = BTreeSet::new();
    let mut occurrences = Vec::new();

    while date <= last {
        if let Some(occurrence) = occurrence_for_local_date(event, zone, date) {
            if occurrence.utc_secs >= start_utc
                && occurrence.utc_secs <= end_utc
                && seen.insert((occurrence.event_id.clone(), occurrence.local_date))
            {
                occurrences.push(occurrence);
            }
        }
        date = date.plus_days(1);
    }

    occurrences
}

/// Registry of per-site zones (site/store/venue).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeZoneRegistry {
    zones: BTreeMap<String, SiteTimeZone>,
}

impl TimeZoneRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        TimeZoneRegistry::default()
    }

    /// Register (or replace) the zone for a site.
    pub fn register(&mut self, zone: SiteTimeZone) {
        self.zones.insert(zone.id.clone(), zone);
    }

    /// Zone for a site.
    pub fn get(&self, site_id: &str) -> Option<&SiteTimeZone> {
        self.zones.get(site_id)
    }

    /// Occurrences for a site's event, or an empty list for an unknown site.
    pub fn occurrences_between(
        &self,
        site_id: &str,
        event: &ScheduledEvent,
        start_utc: i64,
        end_utc: i64,
    ) -> Vec<ScheduledOccurrence> {
        match self.get(site_id) {
            Some(zone) => occurrences_between(event, zone, start_utc, end_utc),
            None => Vec::new(),
        }
    }
}

impl fmt::Display for SiteTimeZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (UTC{:+})", self.id, self.standard_offset_secs)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn utc(year: i32, month: u8, day: u8, hour: i64) -> i64 {
        CivilDate::new(year, month, day)
            .expect("date")
            .days_since_epoch()
            * SECS_PER_DAY
            + hour * 3_600
    }

    #[test]
    fn civil_dates_round_trip_through_epoch_days() {
        for (year, month, day) in [(1970, 1, 1), (2024, 2, 29), (2026, 3, 8), (2026, 11, 1)] {
            let date = CivilDate::new(year, month, day).expect("valid date");
            assert_eq!(CivilDate::from_days(date.days_since_epoch()), date);
        }
        assert_eq!(CivilDate::new(2026, 3, 8).unwrap().weekday(), 0);
        assert_eq!(CivilDate::new(2026, 11, 1).unwrap().weekday(), 0);
        assert!(CivilDate::new(2026, 2, 29).is_none());
    }

    #[test]
    fn us_eastern_offsets_and_transition_dates_are_correct_for_2026() {
        let zone = SiteTimeZone::us_eastern("store-boston");
        assert_eq!(zone.offset_at_utc(utc(2026, 1, 15, 12)), -5 * 3_600);
        assert_eq!(zone.offset_at_utc(utc(2026, 7, 15, 12)), -4 * 3_600);

        let rule = zone.dst.expect("dst rule");
        let start = rule.start_utc(2026).expect("start");
        let end = rule.end_utc(2026).expect("end");
        assert_eq!(CivilDate::from_unix_secs(start), CivilDate::new(2026, 3, 8).unwrap());
        assert_eq!(CivilDate::from_unix_secs(end), CivilDate::new(2026, 11, 1).unwrap());
        assert_eq!(start, utc(2026, 3, 8, 7)); // 02:00 EST
        assert_eq!(end, utc(2026, 11, 1, 6)); // 02:00 EDT
    }

    #[test]
    fn spring_forward_gap_runs_the_event_once_at_the_transition() {
        let zone = SiteTimeZone::us_eastern("store-boston");
        let event = ScheduledEvent::daily("open-check", 2, 30);
        let date = CivilDate::new(2026, 3, 8).unwrap();

        let resolution = zone.resolve_local(date, event.local_second_of_day);
        assert!(matches!(resolution, LocalResolution::Skipped { .. }));

        let occurrence = occurrence_for_local_date(&event, &zone, date).expect("occurrence");
        assert_eq!(
            occurrence.utc_secs,
            utc(2026, 3, 8, 7),
            "a skipped 02:30 must run once when the clock reaches 03:00 EDT"
        );
    }

    #[test]
    fn autumn_overlap_runs_the_event_once_at_the_first_occurrence() {
        let zone = SiteTimeZone::us_eastern("store-boston");
        let event = ScheduledEvent::daily("shift-start", 1, 30);
        let date = CivilDate::new(2026, 11, 1).unwrap();

        match zone.resolve_local(date, event.local_second_of_day) {
            LocalResolution::Ambiguous { first, second } => {
                assert_eq!(first, utc(2026, 11, 1, 5) + 1_800); // 01:30 EDT
                assert_eq!(second, utc(2026, 11, 1, 6) + 1_800); // 01:30 EST
            }
            other => panic!("expected an ambiguous local time, got {other:?}"),
        }

        let occurrence = occurrence_for_local_date(&event, &zone, date).expect("occurrence");
        assert_eq!(
            occurrence.utc_secs,
            utc(2026, 11, 1, 5) + 1_800,
            "an ambiguous 01:30 must run once, at the first occurrence"
        );
    }

    #[test]
    fn occurrences_never_duplicate_or_skip_across_either_transition() {
        let zone = SiteTimeZone::us_eastern("store-boston");
        let event = ScheduledEvent::daily("hourly-audit", 2, 30);

        for (start, days) in [
            (utc(2026, 3, 6, 0), 5),  // spring forward
            (utc(2026, 10, 30, 0), 5), // fall back
        ] {
            let end = start + i64::from(days) * SECS_PER_DAY;
            let occurrences = occurrences_between(&event, &zone, start, end);

            let mut per_date: BTreeMap<CivilDate, usize> = BTreeMap::new();
            for occurrence in &occurrences {
                *per_date.entry(occurrence.local_date).or_default() += 1;
            }
            assert_eq!(
                per_date.len(),
                days as usize,
                "each local date must have exactly one occurrence"
            );
            assert!(
                per_date.values().all(|count| *count == 1),
                "no local date may have a duplicate occurrence: {per_date:?}"
            );
        }
    }

    #[test]
    fn eu_central_and_fixed_offsets_resolve_locally() {
        let eu = SiteTimeZone::eu_central("store-berlin");
        let event = ScheduledEvent::daily("open", 2, 30);
        let gap_date = CivilDate::new(2026, 3, 29).unwrap();
        let occurrence = occurrence_for_local_date(&event, &eu, gap_date).expect("occurrence");
        assert_eq!(occurrence.utc_secs, utc(2026, 3, 29, 1));

        let india = SiteTimeZone::fixed("store-pune", 5 * 3_600 + 1_800);
        let nine_am = ScheduledEvent::daily("open", 9, 0);
        let date = CivilDate::new(2026, 3, 9).unwrap();
        let occurrence = occurrence_for_local_date(&nine_am, &india, date).expect("occurrence");
        assert_eq!(occurrence.utc_secs, utc(2026, 3, 9, 3) + 1_800);
    }

    #[test]
    fn zone_registry_scopes_schedules_to_the_right_site() {
        let mut registry = TimeZoneRegistry::new();
        registry.register(SiteTimeZone::us_eastern("store-boston"));
        registry.register(SiteTimeZone::fixed("store-pune", 5 * 3_600 + 1_800));

        let event = ScheduledEvent::daily("open", 9, 0);
        let start = utc(2026, 3, 8, 0);
        let end = start + SECS_PER_DAY;

        let boston = registry.occurrences_between("store-boston", &event, start, end);
        let pune = registry.occurrences_between("store-pune", &event, start, end);
        assert_eq!(boston.len(), 1);
        assert_eq!(pune.len(), 1);
        assert_ne!(boston[0].utc_secs, pune[0].utc_secs);
        assert!(registry
            .occurrences_between("unknown-site", &event, start, end)
            .is_empty());
    }
}
