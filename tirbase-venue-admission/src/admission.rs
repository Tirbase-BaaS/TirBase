// SPDX-License-Identifier: AGPL-3.0-only

//! The gate admission guard: one call per ticket presentation.
//!
//! `GateAdmission::admit` verifies the ticket signature and issuer key state,
//! the ticket's validity window, the revocation list's freshness, the ticket's
//! revocation status, and finally single use across gates and epochs. A stale
//! or missing revocation list never admits a ticket; the alarm policy
//! additionally records an operator alarm.
//!
//! Ticket entitlement (event, venue, gate and zone scope, holder binding) is
//! ST-05's validator job; this layer is the gate-side guard over an
//! authenticated ticket.

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, TicketId};
use tirbase_venue_ticket::{Denial, IssuerKeyRing, SignedTicket};

use crate::error::RevocationError;
use crate::replay::{GateReplayGuard, ReplayKey, ReplayVerdict};
use crate::revocation::{
    ApplyOutcome, DeltaPolicy, RevocationAccumulator, RevocationLedger, SignedRevocationDelta,
    SubmitOutcome,
};

/// What to do when the revocation list is missing or expired. Both modes
/// refuse the ticket; `Alarm` records an operator alarm as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StalePolicy {
    FailClosed,
    Alarm,
}

/// Why a stale list was detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleReason {
    Missing,
    Expired,
}

/// Recorded under [`StalePolicy::Alarm`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationAlarm {
    pub reason: StaleReason,
    pub version: u64,
    pub expires_at_utc_us: i64,
    pub detected_at_utc_us: i64,
}

/// Why the gate refused a ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDeny {
    /// Signature, issuer key or validity-window failure from ST-05.
    Ticket(Denial),
    /// No revocation list has ever been accumulated.
    RevocationListMissing,
    /// The accumulated list's expiry has passed.
    RevocationListExpired {
        version: u64,
        expires_at_utc_us: i64,
    },
    /// The ticket id is in the accumulated revocation list.
    Revoked { ticket_id: TicketId },
    /// The same key (same gate, same epoch) was already admitted.
    Duplicate { replay_key: ReplayKey },
    /// The ticket was admitted at another gate.
    CrossGate {
        replay_key: ReplayKey,
        claimed_by: GateId,
    },
    /// The ticket was admitted at this gate in an earlier epoch.
    AlreadyUsed {
        replay_key: ReplayKey,
        claimed_epoch: u64,
    },
}

impl GateDeny {
    /// Stable machine code; ticket denials report their ST-05 code.
    pub fn code(&self) -> &'static str {
        match self {
            GateDeny::Ticket(denial) => denial.code(),
            GateDeny::RevocationListMissing => "revocation_list_missing",
            GateDeny::RevocationListExpired { .. } => "revocation_list_expired",
            GateDeny::Revoked { .. } => "revoked_ticket",
            GateDeny::Duplicate { .. } => "duplicate",
            GateDeny::CrossGate { .. } => "cross_gate",
            GateDeny::AlreadyUsed { .. } => "already_used",
        }
    }
}

impl std::fmt::Display for GateDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateDeny::Ticket(denial) => write!(f, "{denial}"),
            GateDeny::RevocationListMissing => write!(f, "no revocation list accumulated"),
            GateDeny::RevocationListExpired {
                version,
                expires_at_utc_us,
            } => write!(
                f,
                "revocation list v{version} expired at {expires_at_utc_us}"
            ),
            GateDeny::Revoked { ticket_id } => write!(f, "ticket {ticket_id} is revoked"),
            GateDeny::Duplicate { replay_key } => write!(f, "duplicate presentation {replay_key}"),
            GateDeny::CrossGate {
                replay_key,
                claimed_by,
            } => write!(
                f,
                "ticket already admitted at gate {claimed_by} (key {replay_key})"
            ),
            GateDeny::AlreadyUsed {
                replay_key,
                claimed_epoch,
            } => write!(
                f,
                "ticket already admitted at this gate in epoch {claimed_epoch} (key {replay_key})"
            ),
        }
    }
}

impl std::error::Error for GateDeny {}

/// The gate's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Admitted {
        replay_key: ReplayKey,
        claim_expires_at_utc_us: i64,
    },
    Denied(GateDeny),
}

impl GateDecision {
    pub fn is_admitted(&self) -> bool {
        matches!(self, GateDecision::Admitted { .. })
    }

    pub fn denial(&self) -> Option<&GateDeny> {
        match self {
            GateDecision::Denied(denial) => Some(denial),
            GateDecision::Admitted { .. } => None,
        }
    }

    pub fn replay_key(&self) -> Option<&ReplayKey> {
        match self {
            GateDecision::Admitted { replay_key, .. } => Some(replay_key),
            GateDecision::Denied(_) => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            GateDecision::Admitted { .. } => "admitted",
            GateDecision::Denied(denial) => denial.code(),
        }
    }
}

/// One gate's admission guard.
#[derive(Clone, Debug, PartialEq)]
pub struct GateAdmission {
    guard: GateReplayGuard,
    revocations: RevocationAccumulator,
    policy: StalePolicy,
    alarm: Option<RevocationAlarm>,
}

impl GateAdmission {
    /// Build a guard with no revocation state accumulated yet.
    pub fn new(guard: GateReplayGuard, policy: StalePolicy) -> Self {
        Self {
            guard,
            revocations: RevocationAccumulator::new(),
            policy,
            alarm: None,
        }
    }

    pub fn guard(&self) -> &GateReplayGuard {
        &self.guard
    }

    pub fn revocations(&self) -> &RevocationAccumulator {
        &self.revocations
    }

    pub fn ledger(&self) -> &RevocationLedger {
        self.revocations.ledger()
    }

    pub fn policy(&self) -> StalePolicy {
        self.policy
    }

    pub fn alarm(&self) -> Option<&RevocationAlarm> {
        self.alarm.as_ref()
    }

    pub fn take_alarm(&mut self) -> Option<RevocationAlarm> {
        self.alarm.take()
    }

    /// Verify and apply one revocation delta, honouring offline ordering.
    pub fn apply_delta(
        &mut self,
        signed: &SignedRevocationDelta,
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<SubmitOutcome, RevocationError> {
        self.revocations.submit(signed, ring, policy, at_utc_us)
    }

    /// Apply a bundle of deltas in any order, returning how many applied.
    pub fn apply_bundle(
        &mut self,
        deltas: &[SignedRevocationDelta],
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<usize, RevocationError> {
        self.revocations.apply_bundle(deltas, ring, policy, at_utc_us)
    }

    /// Apply a delta directly to the ledger, refusing a chain gap.
    pub fn apply_to_ledger(
        &mut self,
        signed: &SignedRevocationDelta,
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<ApplyOutcome, RevocationError> {
        self.revocations
            .ledger_mut()
            .apply(signed, ring, policy, at_utc_us)
    }

    /// Admit or refuse one ticket presentation at one gate.
    pub fn admit(
        &mut self,
        ticket: &SignedTicket,
        gate_id: &GateId,
        at_utc_us: i64,
        ring: &IssuerKeyRing,
    ) -> GateDecision {
        let payload = &ticket.payload;
        if payload.check_shape().is_err() {
            return GateDecision::Denied(GateDeny::Ticket(Denial::Malformed("payload shape")));
        }
        if let Err(denial) = ticket.verify_signature(ring, at_utc_us) {
            return GateDecision::Denied(GateDeny::Ticket(denial));
        }
        if at_utc_us < payload.valid_from_utc_us {
            return GateDecision::Denied(GateDeny::Ticket(Denial::NotYetValid {
                valid_from_utc_us: payload.valid_from_utc_us,
            }));
        }
        if at_utc_us >= payload.valid_until_utc_us {
            return GateDecision::Denied(GateDeny::Ticket(Denial::Expired {
                valid_until_utc_us: payload.valid_until_utc_us,
            }));
        }
        if let Err(deny) = self.check_revocation_freshness(at_utc_us) {
            return GateDecision::Denied(deny);
        }
        if self.ledger().is_revoked(&payload.ticket_id) {
            return GateDecision::Denied(GateDeny::Revoked {
                ticket_id: payload.ticket_id.clone(),
            });
        }

        match self.guard.admit(payload, gate_id, at_utc_us) {
            ReplayVerdict::Fresh {
                key,
                claim_expires_at_utc_us,
            } => GateDecision::Admitted {
                replay_key: key,
                claim_expires_at_utc_us,
            },
            ReplayVerdict::Duplicate { key } => {
                GateDecision::Denied(GateDeny::Duplicate { replay_key: key })
            }
            ReplayVerdict::CrossGate { key, claimed_by, .. } => {
                GateDecision::Denied(GateDeny::CrossGate {
                    replay_key: key,
                    claimed_by,
                })
            }
            ReplayVerdict::AlreadyUsed {
                key, claimed_epoch, ..
            } => GateDecision::Denied(GateDeny::AlreadyUsed {
                replay_key: key,
                claimed_epoch,
            }),
            ReplayVerdict::NotYetValid {
                valid_from_utc_us, ..
            } => GateDecision::Denied(GateDeny::Ticket(Denial::NotYetValid {
                valid_from_utc_us,
            })),
            ReplayVerdict::WindowClosed {
                valid_until_utc_us, ..
            } => GateDecision::Denied(GateDeny::Ticket(Denial::Expired {
                valid_until_utc_us,
            })),
        }
    }

    fn check_revocation_freshness(&mut self, at_utc_us: i64) -> Result<(), GateDeny> {
        if self.ledger().version() == 0 {
            self.record_alarm(StaleReason::Missing, 0, 0, at_utc_us);
            return Err(GateDeny::RevocationListMissing);
        }
        let version = self.ledger().version();
        let expires_at_utc_us = self.ledger().expires_at_utc_us();
        if expires_at_utc_us <= at_utc_us {
            self.record_alarm(StaleReason::Expired, version, expires_at_utc_us, at_utc_us);
            return Err(GateDeny::RevocationListExpired {
                version,
                expires_at_utc_us,
            });
        }
        Ok(())
    }

    fn record_alarm(
        &mut self,
        reason: StaleReason,
        version: u64,
        expires_at_utc_us: i64,
        at_utc_us: i64,
    ) {
        if self.policy == StalePolicy::Alarm {
            self.alarm = Some(RevocationAlarm {
                reason,
                version,
                expires_at_utc_us,
                detected_at_utc_us: at_utc_us,
            });
        }
    }
}
