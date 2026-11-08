//! Scenario S21 — Lease starvation (Task 21.14, CLAIM-21.14, PV-5.8a, INV-13).

#[test]
fn s21_consecutive_renewal_cap_cooldown_preemption_and_revocation_release() {
    use rusqlite::Connection;
    use tirbase_gateway::db::single_writer_leases::{
        acquire_tx, create_table, preempt_tx, release_all_for_issuer_did,
        DEFAULT_LEASE_DURATION_MONO_SECS, DEFAULT_MAX_CONSECUTIVE_RENEWALS,
    };
    let mut c = Connection::open_in_memory().unwrap();
    create_table(&c).unwrap();
    let target = "actuator-s21";
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
    for _ in 0..(DEFAULT_MAX_CONSECUTIVE_RENEWALS + 4) {
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
    assert!(hit, "S21 renewal cap must trigger cooldown");
    {
        let tx = c.transaction().unwrap();
        acquire_tx(
            &tx,
            target,
            other,
            now + 1,
            DEFAULT_LEASE_DURATION_MONO_SECS,
            DEFAULT_MAX_CONSECUTIVE_RENEWALS,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = c.transaction().unwrap();
        preempt_tx(
            &tx,
            target,
            Some("did:replacement"),
            now + 2,
            DEFAULT_LEASE_DURATION_MONO_SECS,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        release_all_for_issuer_did(&c, "did:replacement").unwrap(),
        1
    );
}
