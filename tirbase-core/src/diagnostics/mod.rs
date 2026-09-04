//! v1 Diagnostic Entries — structured startup diagnostics and warnings (Req 21).
//!
//! All diagnostic entries are emitted via a structured log channel at init time.
//! They document v1 limitations so system integrators can design operational
//! procedures that account for them.

#![allow(dead_code, unused_variables)]

use crate::api::InitConfig;

/// The severity of a diagnostic entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    /// Informational notice — no action required.
    Info,
    /// Warning — operator should be aware of a trade-off or limitation.
    Warning,
}

/// A single structured diagnostic entry.
#[derive(Debug, Clone)]
pub struct DiagnosticEntry {
    pub severity: DiagnosticSeverity,
    /// Short code identifying the diagnostic (e.g., "UNVERIFIED_RETENTION").
    pub code: &'static str,
    pub message: String,
}

/// Emit all startup diagnostic entries for the given configuration (Req 21).
///
/// This function is called once during `CoreHandle::init()`.
/// All entries are collected and can be forwarded to the application's log sink.
pub fn emit_startup_diagnostics(config: &InitConfig) -> Vec<DiagnosticEntry> {
    let mut entries = Vec::new();

    // Req 21.1 — isolated-device UNVERIFIED retention
    entries.push(DiagnosticEntry {
        severity: DiagnosticSeverity::Info,
        code: "UNVERIFIED_RETENTION",
        message: "A device isolated from all nodes carrying a Revocation_Delta retains \
                  Trust_Level UNVERIFIED and continues to merge Deltas until its \
                  Biscuit_Token Epoch expires.".to_string(),
    });

    // Req 21.4 — LoRa/satellite duty-cycle limitation
    entries.push(DiagnosticEntry {
        severity: DiagnosticSeverity::Info,
        code: "LORA_DUTY_CYCLE",
        message: "LoRa and satellite transports are subject to regulatory duty-cycle limits. \
                  TirBase does not assume continuous channel availability on those transports."
            .to_string(),
    });

    // Req 21.5 — multi-hop tree topology / no hub-and-spoke
    entries.push(DiagnosticEntry {
        severity: DiagnosticSeverity::Info,
        code: "TREE_TOPOLOGY",
        message: "Multi-hop packet routing uses tree topology. Hub-and-spoke routing via a \
                  static local relay is not implemented in v1.".to_string(),
    });

    // Req 21.3 — spatial diversity tag spoofing (only when Anchor_Attested_Location is disabled)
    if !config.deployment.anchor_attested_location {
        entries.push(DiagnosticEntry {
            severity: DiagnosticSeverity::Info,
            code: "TAG_SPOOF_RISK",
            message: "Spatial_Diversity quorum protects against honest device failure and data \
                      loss but does not protect against a fully compromised device that falsifies \
                      its own squad or tunnel_sector tag.".to_string(),
        });
    }

    // Req 21.2 — 1-of-1 revocation unilateral exile warning
    if config.deployment.revocation_m == 1 && config.deployment.revocation_n == 1 {
        entries.push(DiagnosticEntry {
            severity: DiagnosticSeverity::Warning,
            code: "UNILATERAL_EXILE",
            message: "A single Manager_DID can unilaterally exile any device without requiring \
                      a second approval (M=1, N=1 revocation configuration).".to_string(),
        });
    }

    // Req 21.6 — extended Biscuit TTL accepted-risk warning
    let biscuit_ttl = config.deployment.biscuit_ttl_secs;
    if biscuit_ttl > 24 * 3600 {
        entries.push(DiagnosticEntry {
            severity: DiagnosticSeverity::Warning,
            code: "EXTENDED_TTL",
            message: format!(
                "Biscuit_Token TTL is set to {} seconds (>{} hours). A partitioned or \
                 compromised device retains valid token access for the full TTL duration if it \
                 never receives a Revocation_Delta. This window ({:.1}h) is an accepted \
                 operational trade-off.",
                biscuit_ttl,
                24,
                biscuit_ttl as f64 / 3600.0,
            ),
        });
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{DeploymentConfig, InitConfig};

    /// Returns `true` if any entry in `entries` has the given `code`.
    fn has_code(entries: &[DiagnosticEntry], code: &str) -> bool {
        entries.iter().any(|e| e.code == code)
    }

    fn base_config() -> InitConfig {
        InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig::default(),
        }
    }

    // ── Req 21.1 ─────────────────────────────────────────────────────────────

    #[test]
    fn unverified_retention_always_present() {
        let config = base_config();
        let entries = emit_startup_diagnostics(&config);
        assert!(
            has_code(&entries, "UNVERIFIED_RETENTION"),
            "UNVERIFIED_RETENTION should be emitted on every init"
        );
    }

    #[test]
    fn unverified_retention_is_info() {
        let config = base_config();
        let entries = emit_startup_diagnostics(&config);
        let entry = entries.iter().find(|e| e.code == "UNVERIFIED_RETENTION").unwrap();
        assert_eq!(entry.severity, DiagnosticSeverity::Info);
    }

    // ── Req 21.2 ─────────────────────────────────────────────────────────────

    #[test]
    fn unilateral_exile_present_when_m1_n1() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            has_code(&entries, "UNILATERAL_EXILE"),
            "UNILATERAL_EXILE should be emitted when M=1 and N=1"
        );
    }

    #[test]
    fn unilateral_exile_absent_when_m2_n3() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 3,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            !has_code(&entries, "UNILATERAL_EXILE"),
            "UNILATERAL_EXILE should NOT be emitted when M=2, N=3"
        );
    }

    #[test]
    fn unilateral_exile_absent_when_m1_n2() {
        // M=1 but N≠1 — not a unilateral configuration
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 2,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            !has_code(&entries, "UNILATERAL_EXILE"),
            "UNILATERAL_EXILE should NOT be emitted when N≠1"
        );
    }

    #[test]
    fn unilateral_exile_is_warning() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        let entry = entries.iter().find(|e| e.code == "UNILATERAL_EXILE").unwrap();
        assert_eq!(entry.severity, DiagnosticSeverity::Warning);
    }

    // ── Req 21.3 ─────────────────────────────────────────────────────────────

    #[test]
    fn tag_spoof_risk_present_when_anchor_attested_disabled() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                anchor_attested_location: false,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            has_code(&entries, "TAG_SPOOF_RISK"),
            "TAG_SPOOF_RISK should be emitted when anchor_attested_location is false"
        );
    }

    #[test]
    fn tag_spoof_risk_absent_when_anchor_attested_enabled() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                anchor_attested_location: true,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            !has_code(&entries, "TAG_SPOOF_RISK"),
            "TAG_SPOOF_RISK should NOT be emitted when anchor_attested_location is true"
        );
    }

    #[test]
    fn tag_spoof_risk_is_info() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                anchor_attested_location: false,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        let entry = entries.iter().find(|e| e.code == "TAG_SPOOF_RISK").unwrap();
        assert_eq!(entry.severity, DiagnosticSeverity::Info);
    }

    // ── Req 21.4 ─────────────────────────────────────────────────────────────

    #[test]
    fn lora_duty_cycle_always_present() {
        let config = base_config();
        let entries = emit_startup_diagnostics(&config);
        assert!(
            has_code(&entries, "LORA_DUTY_CYCLE"),
            "LORA_DUTY_CYCLE should be emitted on every init"
        );
    }

    #[test]
    fn lora_duty_cycle_is_info() {
        let config = base_config();
        let entries = emit_startup_diagnostics(&config);
        let entry = entries.iter().find(|e| e.code == "LORA_DUTY_CYCLE").unwrap();
        assert_eq!(entry.severity, DiagnosticSeverity::Info);
    }

    // ── Req 21.5 ─────────────────────────────────────────────────────────────

    #[test]
    fn tree_topology_always_present() {
        let config = base_config();
        let entries = emit_startup_diagnostics(&config);
        assert!(
            has_code(&entries, "TREE_TOPOLOGY"),
            "TREE_TOPOLOGY should be emitted on every init"
        );
    }

    #[test]
    fn tree_topology_is_info() {
        let config = base_config();
        let entries = emit_startup_diagnostics(&config);
        let entry = entries.iter().find(|e| e.code == "TREE_TOPOLOGY").unwrap();
        assert_eq!(entry.severity, DiagnosticSeverity::Info);
    }

    // ── Req 21.6 ─────────────────────────────────────────────────────────────

    #[test]
    fn extended_ttl_present_when_ttl_exceeds_24h() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                biscuit_ttl_secs: 24 * 3600 + 1, // one second over 24h
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            has_code(&entries, "EXTENDED_TTL"),
            "EXTENDED_TTL should be emitted when TTL > 86400s"
        );
    }

    #[test]
    fn extended_ttl_absent_when_ttl_exactly_24h() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                biscuit_ttl_secs: 24 * 3600, // exactly 24h — not extended
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            !has_code(&entries, "EXTENDED_TTL"),
            "EXTENDED_TTL should NOT be emitted when TTL == 86400s"
        );
    }

    #[test]
    fn extended_ttl_absent_when_ttl_below_24h() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                biscuit_ttl_secs: 3600, // 1h
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        assert!(
            !has_code(&entries, "EXTENDED_TTL"),
            "EXTENDED_TTL should NOT be emitted when TTL < 86400s"
        );
    }

    #[test]
    fn extended_ttl_is_warning() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                biscuit_ttl_secs: 48 * 3600,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        let entry = entries.iter().find(|e| e.code == "EXTENDED_TTL").unwrap();
        assert_eq!(entry.severity, DiagnosticSeverity::Warning);
    }

    // ── Composite: all-triggering config emits all 6 codes ───────────────────

    #[test]
    fn all_six_diagnostics_emitted_when_all_conditions_met() {
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 48 * 3600,
                anchor_attested_location: false,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        for code in &[
            "UNVERIFIED_RETENTION",
            "LORA_DUTY_CYCLE",
            "TREE_TOPOLOGY",
            "TAG_SPOOF_RISK",
            "UNILATERAL_EXILE",
            "EXTENDED_TTL",
        ] {
            assert!(
                has_code(&entries, code),
                "Expected diagnostic code '{}' to be present",
                code
            );
        }
    }

    // ── Baseline: default config emits exactly the 3 unconditional codes ─────

    #[test]
    fn default_config_emits_only_unconditional_diagnostics() {
        // DeploymentConfig::default() has anchor_attested_location=false,
        // revocation_m=0, revocation_n=0, biscuit_ttl_secs=0 —
        // so TAG_SPOOF_RISK fires but UNILATERAL_EXILE and EXTENDED_TTL do not.
        let config = InitConfig {
            storage_path: ":memory:".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                anchor_attested_location: true, // suppress TAG_SPOOF_RISK
                revocation_m: 2,
                revocation_n: 3,
                biscuit_ttl_secs: 3600,
                ..Default::default()
            },
        };
        let entries = emit_startup_diagnostics(&config);
        // Must be present
        assert!(has_code(&entries, "UNVERIFIED_RETENTION"));
        assert!(has_code(&entries, "LORA_DUTY_CYCLE"));
        assert!(has_code(&entries, "TREE_TOPOLOGY"));
        // Must be absent
        assert!(!has_code(&entries, "TAG_SPOOF_RISK"));
        assert!(!has_code(&entries, "UNILATERAL_EXILE"));
        assert!(!has_code(&entries, "EXTENDED_TTL"));
    }
}
