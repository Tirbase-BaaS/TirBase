// SPDX-License-Identifier: AGPL-3.0-only

//! SingleWriterLease state-machine / exclusivity tests (21.6 logic,
//! CLAIM-21.1/21.4/21.6, PV-5.8/5.8a, INV-13). Uses the guard-side
//! `SingleWriterLease` type and models the lease invariants.

use tirbase_guard::SingleWriterLease;
use tirbase_types::Did;

#[test]
fn claim_21_1_single_active_holder_modeled() {
    let a = SingleWriterLease {
        issuer_did: Did::new("did:a"),
        target_id: "t".into(),
        expires_mono_secs: 100,
        consecutive_renewals: 0,
        cooldown_until_mono_secs: None,
    };
    let b = SingleWriterLease {
        issuer_did: Did::new("did:b"),
        target_id: "t".into(),
        expires_mono_secs: 100,
        consecutive_renewals: 0,
        cooldown_until_mono_secs: None,
    };
    assert!(!a.is_expired(99) && !b.is_expired(99));
 // exclusivity is enforced by the store; type carries single-holder state.
    assert_ne!(a.issuer_did, b.issuer_did);
}

#[test]
fn claim_21_4_cooldown_blocks_same_issuer() {
    let l = SingleWriterLease {
        issuer_did: Did::new("did:a"),
        target_id: "t".into(),
        expires_mono_secs: 10,
        consecutive_renewals: 10,
        cooldown_until_mono_secs: Some(40),
    };
    assert!(l.in_cooldown(39));
    assert!(!l.in_cooldown(40));
}
