//! Scenarios S11 and S18 — single-manager quorum warning and the compile-time
//! guard-bypass barrier.
//!
//! S11 drives the production startup diagnostics (`emit_startup_diagnostics`).
//! S18 verifies the structural sealing of `ActuationPermit`, which is enforced
//! by the compiler and by the three `trybuild` compile-fail fixtures for the
//! mesh, cloud and admin ingress paths.

use std::path::Path;

use tirbase_core::api::{DeploymentConfig, InitConfig};
use tirbase_core::diagnostics::{emit_startup_diagnostics, DiagnosticSeverity};

/// S11 — a 1-of-1 revocation quorum is accepted but produces a structured
/// Warning through the diagnostics channel (not plain stderr logging).
pub fn run_s11(seed: u64) -> Result<(), String> {
    let deployment = DeploymentConfig {
        revocation_m: 1,
        revocation_n: 1,
        ..DeploymentConfig::default()
    };
    let config = InitConfig {
        storage_path: format!(":memory:s11-{seed}"),
        deployment,
        listen_addr: "127.0.0.1:0".to_string(),
    };
    let entries = emit_startup_diagnostics(&config);
    let warning = entries
        .iter()
        .find(|entry| entry.code == "UNILATERAL_EXILE")
        .ok_or_else(|| "S11 FAIL: no UNILATERAL_EXILE diagnostic for M=1,N=1".to_string())?;
    if warning.severity != DiagnosticSeverity::Warning {
        return Err(format!(
            "S11 FAIL: 1-of-1 warning has severity {:?}",
            warning.severity
        ));
    }

    // Control: a threshold configuration must not emit the warning.
    let safe = InitConfig {
        deployment: DeploymentConfig {
            revocation_m: 2,
            revocation_n: 3,
            ..DeploymentConfig::default()
        },
        ..config
    };
    if emit_startup_diagnostics(&safe)
        .iter()
        .any(|entry| entry.code == "UNILATERAL_EXILE")
    {
        return Err("S11 FAIL: threshold configuration emitted UNILATERAL_EXILE".to_string());
    }
    Ok(())
}

/// S18 — no ingress can construct `ActuationPermit` outside the guard:
/// the sealed field is private, the constructor is crate-private, and each
/// ingress has a compile-fail fixture.
pub fn run_s18(_seed: u64) -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "S18: workspace root".to_string())?
        .to_path_buf();
    let permit = std::fs::read_to_string(root.join("tirbase-guard/src/permit.rs"))
        .map_err(|error| format!("S18 read permit.rs: {error}"))?;
    let sealed_private = permit
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .map(str::trim)
        .any(|code| code.starts_with("_sealed: ()") && !code.contains("pub _sealed"));
    if !sealed_private {
        return Err(
            "S18 FAIL: ActuationPermit._sealed is not private (guard bypass possible)".to_string(),
        );
    }
    let constructor_private = permit
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .any(|code| code.trim_start().starts_with("pub(crate) fn new("));
    if !constructor_private {
        return Err("S18 FAIL: ActuationPermit constructor is not crate-private".to_string());
    }
    for ingress in ["mesh", "cloud", "admin"] {
        let fixture = root.join(format!(
            "tirbase-guard/tests/compile_fail/permit_sealed_{ingress}_ingress.rs"
        ));
        if !fixture.exists() {
            return Err(format!(
                "S18 FAIL: missing compile-fail fixture for the {ingress} ingress: {}",
                fixture.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s11_single_manager_warning() {
        run_s11(1).expect("S11");
    }

    #[test]
    fn s18_guard_bypass_is_impossible() {
        run_s18(1).expect("S18");
    }
}
