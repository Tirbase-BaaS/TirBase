//! Task 21 lease tests (CLAIM-21.1–21.6, PV-5.8/5.8a, INV-13, S21 logic).
//! Production callers: `tirbase-gateway/src/db/single_writer_leases.rs`,
//! Stage 16 store, and admin lease-preempt/revoke paths.

use rusqlite::Connection;
use tirbase_gateway::db::single_writer_leases::{
    acquire_tx, create_table, load_tx, preempt_tx, release_all_at_boot, release_all_for_issuer_did,
    DEFAULT_LEASE_DURATION_MONO_SECS, DEFAULT_MAX_CONSECUTIVE_RENEWALS,
};

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    create_table(&c).unwrap();
    c
}

#[test]
fn claim_21_1_single_writer_exclusivity() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    acquire_tx(
        &tx,
        "t",
        "did:a",
        100,
        DEFAULT_LEASE_DURATION_MONO_SECS,
        DEFAULT_MAX_CONSECUTIVE_RENEWALS,
    )
    .unwrap();
    let err = acquire_tx(
        &tx,
        "t",
        "did:b",
        101,
        DEFAULT_LEASE_DURATION_MONO_SECS,
        DEFAULT_MAX_CONSECUTIVE_RENEWALS,
    )
    .unwrap_err();
    assert!(format!("{err:?}").contains("HeldByOther"), "{err:?}");
}

#[test]
fn claim_21_4_consecutive_renewal_cap_cooldown_s21() {
    let mut c = conn();
    let target = "t";
    let holder = "did:holder";
    let other = "did:other";
    let mut now = 0i64;
    {
        let tx = c.transaction().unwrap();
        acquire_tx(
            &tx,
            target,
            holder,
            now,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let mut hit = false;
    for _ in 0..(DEFAULT_MAX_CONSECUTIVE_RENEWALS + 3) {
        now += 5;
        let tx = c.transaction().unwrap();
        match acquire_tx(
            &tx,
            target,
            holder,
            now,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        ) {
            Ok(()) => tx.commit().unwrap(),
            Err(_) => {
                tx.commit().unwrap();
                hit = true;
                break;
            }
        }
    }
    assert!(hit, "renewal cap must trigger cooldown");
    let tx = c.transaction().unwrap();
    acquire_tx(
        &tx,
        target,
        other,
        now + 1,
        DEFAULT_LEASE_DURATION_MONO_SECS,
        DEFAULT_MAX_CONSECUTIVE_RENEWALS,
    )
    .expect("other issuer acquires during cooldown");
}

#[test]
fn claim_21_2_21_3_preemption_and_revocation_release() {
    let mut c = conn();
    {
        let tx = c.transaction().unwrap();
        acquire_tx(
            &tx,
            "t",
            "did:a",
            100,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        let prior = preempt_tx(
            &tx,
            "t",
            Some("did:b"),
            110,
            DEFAULT_LEASE_DURATION_MONO_SECS,
        )
        .unwrap();
        assert_eq!(prior.as_deref(), Some("did:a"));
        tx.commit().unwrap();
    }
    assert_eq!(release_all_for_issuer_did(&c, "did:b").unwrap(), 1);
    let tx = c.transaction().unwrap();
    assert!(load_tx(&tx, "t").unwrap().is_none());
}

#[test]
fn claim_21_5_release_all_at_boot() {
    let mut c = conn();
    {
        let tx = c.transaction().unwrap();
        acquire_tx(
            &tx,
            "t1",
            "did:a",
            100,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        acquire_tx(
            &tx,
            "t2",
            "did:b",
            100,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert!(release_all_at_boot(&c).unwrap() >= 2);
}
