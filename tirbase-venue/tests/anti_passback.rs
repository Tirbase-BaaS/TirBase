// SPDX-License-Identifier: AGPL-3.0-only

//! ST-01: anti-passback and re-entry policy enforcement.

mod common;

use tirbase_venue::{
    AntiPassbackMode, PassbackLedger, PassbackPolicy, ReEntryPolicy, ScanDirection, VenueError,
};

use common::{scan, T0};

fn ledger(anti_passback: AntiPassbackMode, re_entry: ReEntryPolicy) -> PassbackLedger {
    PassbackLedger::with_policy(PassbackPolicy::new(anti_passback, re_entry).expect("policy"))
}

fn enter(ticket: &str, ts: i64) -> tirbase_venue::ScanRecord {
    scan(ticket, "gate-n1", "zone-north", ScanDirection::In, ts)
}

fn exit(ticket: &str, ts: i64) -> tirbase_venue::ScanRecord {
    scan(ticket, "gate-n1", "zone-north", ScanDirection::Out, ts)
}

#[test]
fn strict_anti_passback_rejects_a_second_entry() {
    let mut ledger = ledger(AntiPassbackMode::Strict, ReEntryPolicy::NotAllowed);
    let first = ledger.record(&enter("ticket-1", T0)).expect("first entry");
    assert_eq!(first.entries, 1);
    assert!(!first.reentry);
    assert!(ledger.is_inside(&"ticket-1".parse().unwrap()));

    let error = ledger
        .record(&enter("ticket-1", T0 + 1000))
        .expect_err("reuse while inside must fail");
    match error {
        VenueError::AntiPassbackRejected { ticket_id, .. } => {
            assert_eq!(ticket_id.as_str(), "ticket-1");
        }
        other => panic!("expected AntiPassbackRejected, got {other:?}"),
    }
}

#[test]
fn re_entry_after_exit_is_rejected_by_default() {
    let mut ledger = PassbackLedger::new();
    ledger.record(&enter("ticket-1", T0)).unwrap();
    ledger.record(&exit("ticket-1", T0 + 1000)).unwrap();
    assert!(!ledger.is_inside(&"ticket-1".parse().unwrap()));

    let error = ledger
        .record(&enter("ticket-1", T0 + 2000))
        .expect_err("re-entry is not allowed");
    assert!(matches!(error, VenueError::ReEntryRejected { .. }));
}

#[test]
fn allowed_re_entry_is_counted() {
    let mut ledger = ledger(AntiPassbackMode::Strict, ReEntryPolicy::Allowed);
    ledger.record(&enter("ticket-1", T0)).unwrap();
    ledger.record(&exit("ticket-1", T0 + 1000)).unwrap();
    let second = ledger.record(&enter("ticket-1", T0 + 2000)).unwrap();
    assert!(second.reentry);
    assert_eq!(second.entries, 2);
    assert_eq!(second.reentries, 1);
}

#[test]
fn limited_re_entry_stops_after_the_configured_count() {
    let mut ledger = ledger(
        AntiPassbackMode::Strict,
        ReEntryPolicy::Limited { max_reentries: 1 },
    );
    ledger.record(&enter("ticket-1", T0)).unwrap();
    ledger.record(&exit("ticket-1", T0 + 1000)).unwrap();
    ledger.record(&enter("ticket-1", T0 + 2000)).unwrap();
    ledger.record(&exit("ticket-1", T0 + 3000)).unwrap();

    let error = ledger
        .record(&enter("ticket-1", T0 + 4000))
        .expect_err("re-entry limit reached");
    assert!(matches!(error, VenueError::ReEntryRejected { .. }));
}

#[test]
fn cooldown_re_entry_respects_the_delay() {
    let mut ledger = ledger(
        AntiPassbackMode::Strict,
        ReEntryPolicy::Cooldown { after_us: 5000 },
    );
    ledger.record(&enter("ticket-1", T0)).unwrap();
    ledger.record(&exit("ticket-1", T0 + 1000)).unwrap();

    let too_soon = ledger
        .record(&enter("ticket-1", T0 + 3000))
        .expect_err("cooldown has not elapsed");
    assert!(matches!(too_soon, VenueError::ReEntryRejected { .. }));

    let accepted = ledger.record(&enter("ticket-1", T0 + 6000)).unwrap();
    assert!(accepted.reentry);
}

#[test]
fn timed_anti_passback_allows_a_retry_after_the_cooldown() {
    let mut ledger = ledger(
        AntiPassbackMode::Timed { cooldown_us: 1000 },
        ReEntryPolicy::Allowed,
    );
    ledger.record(&enter("ticket-1", T0)).unwrap();

    let error = ledger
        .record(&enter("ticket-1", T0 + 500))
        .expect_err("inside cooldown");
    assert!(matches!(error, VenueError::AntiPassbackRejected { .. }));

    let retry = ledger.record(&enter("ticket-1", T0 + 1500)).unwrap();
    assert_eq!(retry.entries, 2);
}

#[test]
fn disabled_anti_passback_permits_reuse() {
    let mut ledger = ledger(AntiPassbackMode::Disabled, ReEntryPolicy::Allowed);
    ledger.record(&enter("ticket-1", T0)).unwrap();
    let second = ledger.record(&enter("ticket-1", T0 + 10)).unwrap();
    assert_eq!(second.entries, 2);
}

#[test]
fn exit_without_entry_is_rejected() {
    let mut ledger = PassbackLedger::new();
    let error = ledger
        .record(&exit("ticket-1", T0))
        .expect_err("no entry recorded");
    assert!(matches!(error, VenueError::AntiPassbackRejected { .. }));
}

#[test]
fn exit_through_a_foreign_zone_gate_is_rejected() {
    let mut ledger = ledger(AntiPassbackMode::Strict, ReEntryPolicy::Allowed);
    ledger.record(&enter("ticket-1", T0)).unwrap();
    let foreign_exit = scan(
        "ticket-1",
        "gate-v1",
        "zone-vip",
        ScanDirection::Out,
        T0 + 1000,
    );
    let error = ledger
        .record(&foreign_exit)
        .expect_err("exit gate is outside the entry zone");
    assert!(matches!(error, VenueError::AntiPassbackRejected { .. }));
    assert!(ledger.is_inside(&"ticket-1".parse().unwrap()));
}

#[test]
fn tickets_are_isolated_from_each_other() {
    let mut ledger = PassbackLedger::new();
    ledger.record(&enter("ticket-1", T0)).unwrap();
    ledger
        .record(&enter("ticket-2", T0))
        .expect("second ticket");
    let error = ledger
        .record(&enter("ticket-1", T0 + 1000))
        .expect_err("ticket 1 is still inside");
    assert!(matches!(error, VenueError::AntiPassbackRejected { .. }));
}

#[test]
fn invalid_policy_durations_are_rejected() {
    assert!(PassbackPolicy::new(
        AntiPassbackMode::Timed { cooldown_us: 0 },
        ReEntryPolicy::Allowed
    )
    .is_err());
    assert!(PassbackPolicy::new(
        AntiPassbackMode::Strict,
        ReEntryPolicy::Cooldown { after_us: 0 }
    )
    .is_err());
}
