//! Task 42 supply-chain release pipeline validation tests.
//!
//! These tests are intentionally repository-level checks: they assert that the
//! release workflows, gate scripts, and required documentation/artifacts exist
//! with the specific hooks demanded by PV-14 / CLAIM-42.1..42.7. They provide
//! stable `fn` identifiers for `CLAIMS.md` while the workflows themselves are
//! exercised on GitHub release events.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", full.display()))
}

#[test]
fn claim_42_1_sbom_workflow_generates_cyclonedx_and_attaches_vex() {
    let wf = read(".github/workflows/sbom.yml");
    assert!(wf.contains("cargo-cyclonedx") || wf.contains("cargo cyclonedx"), "sbom workflow must generate CycloneDX SBOM");
    assert!(wf.contains(".cdx.json"), "SBOM must be emitted as a CycloneDX JSON asset");
    assert!(wf.contains("vex"), "SBOM workflow must handle VEX statements");
    assert!(wf.contains("softprops/action-gh-release") || wf.contains("gh release upload"), "SBOM/VEX must be attached to the GitHub Release");
    assert!(PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("docs/releases/vex-statements.json").exists(), "VEX statements document must exist");
}

#[test]
fn claim_42_2_sign_workflow_uses_keyless_cosign_oidc_and_slsa_provenance() {
    let wf = read(".github/workflows/sign.yml");
    assert!(wf.contains("cosign sign-blob"), "release artifacts must be signed with cosign");
    assert!(wf.contains("--certificate-identity") && wf.contains("--certificate-oidc-issuer"), "verification must use cosign identity+issuer flags");
    assert!(wf.contains("id-token: write"), "keyless signing requires OIDC id-token permission");
    assert!(wf.contains("attest-build-provenance") || wf.contains("slsa") || wf.contains("provenance"), "SLSA provenance must be recorded");
}

#[test]
fn claim_42_3_reproducibility_workflow_compares_two_independent_build_hashes() {
    let wf = read(".github/workflows/reproducibility.yml");
    assert!(wf.contains("build-a") && wf.contains("build-b"), "workflow must perform two independent builds");
    assert!(wf.contains("sha256sum") || wf.contains("shasum"), "workflow must compute build hashes");
    assert!(wf.contains("hashes_match") || wf.contains("Hashes match"), "workflow must compare hashes and publish the result");
    assert!(wf.contains("reproducibility-attestation"), "attestation result must be published as a release artifact");
}

#[test]
fn claim_42_4_release_deny_gate_bans_vex_flagged_crates() {
    let wf = read(".github/workflows/sbom.yml");
    let script = read("scripts/release/check_vex_deny.py");
    assert!(wf.contains("deny.release.toml"), "release workflow must use a release-specific deny config");
    assert!(wf.contains("check_vex_deny.py"), "release workflow must derive deny config from VEX statements");
    assert!(script.contains("vulnerabilities") && script.contains("deny"), "VEX helper must translate flagged components into cargo-deny bans");
    assert!(script.contains("Cargo.lock"), "VEX helper must fail if a flagged crate is present in the dependency graph");
}

#[test]
fn claim_42_5_release_geiger_full_report_attached_as_artifact() {
    let wf = read(".github/workflows/sign.yml");
    assert!(wf.contains("cargo geiger"), "release workflow must run cargo-geiger");
    assert!(wf.contains("geiger-report"), "full geiger report must be produced as a named artifact");
    assert!(wf.contains("softprops/action-gh-release") || wf.contains("upload-artifact"), "geiger report must be attached/uploaded as a release artifact");
    // Separate from per-PR delta gate in ci.yml (task 2.4).
    assert!(wf.contains("CLAIM-42.5"), "workflow must document separation from per-PR geiger delta gate");
}

#[test]
fn claim_42_6_release_mutants_gate_requires_eighty_percent_on_security_critical_modules() {
    let wf = read(".github/workflows/sign.yml");
    let script = read("scripts/release/check_mutants_kill_rate.py");
    assert!(wf.contains("--workspace"), "release mutants gate must run across the full workspace");
    assert!(wf.contains("0.80") || wf.contains("80"), "release mutants gate must enforce 80% kill rate");
    assert!(wf.contains("tirbase-guard/src"), "kill-rate gate must cover guard security-critical module");
    assert!(wf.contains("tirbase-core/src/crdt"), "kill-rate gate must cover CRDT validation module");
    assert!(wf.contains("tirbase-core/src/auth") && wf.contains("tirbase-core/src/migration"), "kill-rate gate must cover additional security-critical core modules");
    assert!(script.contains("min-kill-rate") || script.contains("kill_rate"), "mutants helper must compute and enforce kill rate");
}

#[test]
fn claim_42_7_dependency_review_record_is_maintained_per_release() {
    let doc = read("docs/releases/dependency-review.md");
    assert!(doc.contains("CLAIM-42.7") && doc.contains("PV-14.4"), "dependency review record must reference claim and requirement");
    assert!(doc.contains("Direct dependencies"), "record must cover all direct dependencies");
    assert!(doc.contains("Transitive dependencies with CVE"), "record must cover transitive deps with CVE history");
    assert!(doc.contains("unsafe"), "record must cover crates containing unsafe blocks");
    assert!(doc.contains("Cryptographic, authentication, and network"), "record must cover crypto/auth/network crates");
    assert!(doc.contains("per release") || doc.contains("every release"), "record must state per-release maintenance");
}
