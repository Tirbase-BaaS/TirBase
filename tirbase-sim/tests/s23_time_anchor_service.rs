//! Integration test: S23 wired to pass with TimeAnchorService active
//! (CLAIM-53.3, PV-28.4).

#[test]
fn s23_time_anchor_poisoning_passes_with_time_anchor_service_active() {
    tirbase_sim::scenarios::s19_s23_s31_time::run_s23(42)
        .expect("S23 must pass with TimeAnchorService active");
}
