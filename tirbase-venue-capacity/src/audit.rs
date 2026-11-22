// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, attributable audit trail for operator actions.
//!
//! Audit entries record who did what, to which scope, and why. The log is
//! capped; the oldest entries are dropped and counted, so a reader can tell
//! that history was lost.

use serde::{Deserialize, Serialize};

use crate::limit::LimitScope;

/// Largest retained audit history.
pub const MAX_AUDIT_ENTRIES: usize = 512;

/// An auditable capacity action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    OverrideGranted,
    OverrideUsed,
    OverrideRevoked,
    OverrideExpired,
    ReconciliationAdopted,
}

impl AuditAction {
    pub fn code(&self) -> &'static str {
        match self {
            AuditAction::OverrideGranted => "override_granted",
            AuditAction::OverrideUsed => "override_used",
            AuditAction::OverrideRevoked => "override_revoked",
            AuditAction::OverrideExpired => "override_expired",
            AuditAction::ReconciliationAdopted => "reconciliation_adopted",
        }
    }
}

/// One audit fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub at_utc_us: i64,
    pub action: AuditAction,
    /// The person or system that performed the action.
    pub actor: String,
    pub scope: LimitScope,
    /// Override id or observation id the action refers to.
    pub reference: String,
    pub detail: String,
}
