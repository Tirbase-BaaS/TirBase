// SPDX-License-Identifier: AGPL-3.0-only

//! Operator overrides.
//!
//! An override is requested by one person and approved by another, is scoped to
//! exactly one envelope, grants a bounded headroom above that hard limit for a
//! bounded number of passages, and expires at a stated instant. Every grant,
//! use, revocation and expiry lands in the audit log with its actors.

use serde::{Deserialize, Serialize};

use crate::limit::LimitScope;

/// A request to exceed a hard limit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideGrant {
    pub override_id: String,
    pub scope: LimitScope,
    /// The operational lead asking for the headroom.
    pub requested_by: String,
    /// The supervisor approving it; must differ from `requested_by`.
    pub approved_by: String,
    pub reason: String,
    pub granted_at_utc_us: i64,
    pub expires_at_utc_us: i64,
    /// Extra people admitted above the hard limit.
    pub max_headroom: u32,
    /// Maximum number of passages admitted under this override.
    pub max_uses: u32,
}

/// Lifecycle state of an override at a given instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideState {
    Active,
    /// All permitted passages have been used.
    Exhausted,
    Expired,
    Revoked,
}

impl OverrideState {
    pub fn code(&self) -> &'static str {
        match self {
            OverrideState::Active => "active",
            OverrideState::Exhausted => "exhausted",
            OverrideState::Expired => "expired",
            OverrideState::Revoked => "revoked",
        }
    }
}

/// An approved override.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityOverride {
    pub override_id: String,
    pub scope: LimitScope,
    pub requested_by: String,
    pub approved_by: String,
    pub reason: String,
    pub granted_at_utc_us: i64,
    pub expires_at_utc_us: i64,
    pub max_headroom: u32,
    pub max_uses: u32,
    pub uses: u32,
    pub last_used_at_utc_us: Option<i64>,
    pub revoked_at_utc_us: Option<i64>,
    #[serde(default)]
    pub(crate) expired_audited: bool,
}

impl CapacityOverride {
    /// Evaluate the override at `now_utc_us`.
    ///
    /// Revocation and exhaustion win over the deadline; an override whose
    /// deadline has passed is never active again.
    pub fn state(&self, now_utc_us: i64) -> OverrideState {
        if self.revoked_at_utc_us.is_some() {
            return OverrideState::Revoked;
        }
        if now_utc_us >= self.expires_at_utc_us {
            return OverrideState::Expired;
        }
        if self.uses >= self.max_uses {
            return OverrideState::Exhausted;
        }
        OverrideState::Active
    }

    pub fn remaining_uses(&self) -> u32 {
        self.max_uses.saturating_sub(self.uses)
    }

    /// Whether the override covers an occupancy of `attempted` against `hard`.
    pub fn covers(&self, hard: u32, attempted: u32, now_utc_us: i64) -> bool {
        self.state(now_utc_us) == OverrideState::Active
            && u64::from(attempted) <= u64::from(hard) + u64::from(self.max_headroom)
    }
}
