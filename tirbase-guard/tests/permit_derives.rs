//! Compile-fail tests for `ActuationPermit` negative traits and bypass-proof
//! construction (CLAIM-11.2, CLAIM-11.3, PV-4.3, PV-4.4).
//!
//! `ActuationPermit` must NOT derive `Clone`, `Copy`, `Default`, or
//! `Deserialize` (single-use by construction), and must not be constructible
//! outside `tirbase-guard` (sealed).  The `trybuild` cases under
//! `tests/compile_fail/` assert each property fails to compile.

#[test]
fn actuation_permit_negative_derives_and_sealed_construction_fail_to_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/permit_not_clone.rs");
    t.compile_fail("tests/compile_fail/permit_not_copy.rs");
    t.compile_fail("tests/compile_fail/permit_not_default.rs");
    t.compile_fail("tests/compile_fail/permit_not_deserialize.rs");
    t.compile_fail("tests/compile_fail/permit_sealed_mesh_ingress.rs");
    t.compile_fail("tests/compile_fail/permit_sealed_cloud_ingress.rs");
    t.compile_fail("tests/compile_fail/permit_sealed_admin_ingress.rs");
    t.compile_fail("tests/compile_fail/driver_proxy_bypass.rs");
}
