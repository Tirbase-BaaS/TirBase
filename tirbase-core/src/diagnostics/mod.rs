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
