// SPDX-License-Identifier: AGPL-3.0-only

//! Offline decision API.
//!
//! [`OfflineValidator::validate`] is the whole kernel: it checks the issuer
//! signature and key state, the venue scope, the validity window, the holder
//! binding, the freshness and contents of the revocation list, and finally the
//! anti-replay store — returning either an [`Admission`] or a typed [`Denial`].
//!
//! Revocation freshness is never silently ignored: a missing, expired,
//! rolled-back or unverifiable list refuses the ticket, and with
//! [`StaleRevocationPolicy::Alarm`] it also raises an operator alarm.

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, TicketId, VenueId, ZoneId};

use crate::decision::{scope_denial, Denial};
use crate::keys::IssuerKeyRing;
use crate::payload::{EventId, HolderBinding, VenueScope};
use crate::replay::ReplayStore;
use crate::signed::{SignedRevocationList, SignedTicket, TicketRevocationList};

/// What to do when the revocation list is missing or expired.
///
/// Both modes refuse the ticket; `Alarm` additionally records an operator
/// alarm so a console can page on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleRevocationPolicy {
    FailClosed,
    Alarm,
}

/// Whether a holder binding is required, optional or ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderPolicy {
    /// Never compare holder bindings.
    Ignore,
    /// Compare when the ticket carries one.
    Optional,
    /// Require the ticket to carry one.
    Required,
}

/// Validator configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorPolicy {
    pub holder: HolderPolicy,
    pub require_revocation_list: bool,
    pub stale_list: StaleRevocationPolicy,
}

impl ValidatorPolicy {
    /// Revocation required, holder optional, stale list fails closed.
    pub fn standard() -> Self {
        Self {
            holder: HolderPolicy::Optional,
            require_revocation_list: true,
            stale_list: StaleRevocationPolicy::FailClosed,
        }
    }
}

/// Recorded when a stale list is detected under [`StaleRevocationPolicy::Alarm`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleListAlarm {
    pub version: u64,
    pub expired_at_utc_us: i64,
    pub detected_at_utc_us: i64,
}

/// What the gate is asking the kernel to admit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationRequest {
    pub scope: VenueScope,
    pub at_utc_us: i64,
    /// The holder binding the reader observed, if any.
    pub holder: Option<HolderBinding>,
}

impl ValidationRequest {
    pub fn new(scope: VenueScope, at_utc_us: i64) -> Self {
        Self {
            scope,
            at_utc_us,
            holder: None,
        }
    }

    pub fn with_holder(mut self, holder: HolderBinding) -> Self {
        self.holder = Some(holder);
        self
    }
}

/// An accepted ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admission {
    pub ticket_id: TicketId,
    pub event_id: EventId,
    pub venue_id: VenueId,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    pub nonce: u64,
    /// True when the ticket carried a holder binding that was checked.
    pub holder_bound: bool,
}

/// Result of applying a revocation list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationStatus {
    pub version: u64,
    pub issued_at_utc_us: i64,
    pub expires_at_utc_us: i64,
    pub revoked: usize,
    pub applied_at_utc_us: i64,
}

/// The offline ticket validation kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfflineValidator {
    ring: IssuerKeyRing,
    revocation: Option<TicketRevocationList>,
    applied_version: u64,
    replay: ReplayStore,
    policy: ValidatorPolicy,
    alarm: Option<StaleListAlarm>,
}

impl OfflineValidator {
    /// Build a validator with no revocation list loaded.
    pub fn new(ring: IssuerKeyRing, replay: ReplayStore, policy: ValidatorPolicy) -> Self {
        Self {
            ring,
            revocation: None,
            applied_version: 0,
            replay,
            policy,
            alarm: None,
        }
    }

    pub fn ring(&self) -> &IssuerKeyRing {
        &self.ring
    }

    pub fn policy(&self) -> ValidatorPolicy {
        self.policy
    }

    pub fn revocation_list(&self) -> Option<&TicketRevocationList> {
        self.revocation.as_ref()
    }

    pub fn revocation_version(&self) -> u64 {
        self.applied_version
    }

    pub fn replay_store(&self) -> &ReplayStore {
        &self.replay
    }

    /// Outstanding operator alarm from a stale list, if any.
    pub fn alarm(&self) -> Option<&StaleListAlarm> {
        self.alarm.as_ref()
    }

    /// Take the alarm, clearing it.
    pub fn take_alarm(&mut self) -> Option<StaleListAlarm> {
        self.alarm.take()
    }

    /// Persist the anti-replay store across a reader restart.
    pub fn replay_json(&self) -> Result<String, crate::error::TicketError> {
        self.replay.to_json()
    }

    /// Restore a persisted anti-replay store.
    pub fn restore_replay(&mut self, json: &str) -> Result<(), crate::error::TicketError> {
        self.replay = ReplayStore::from_json(json)?;
        Ok(())
    }

    /// Apply a freshly distributed revocation list.
    ///
    /// Rejects a list whose signature or key is invalid, one older than the
    /// applied version, and one that is already expired at `at_utc_us`.
    pub fn refresh_revocation(
        &mut self,
        signed: &SignedRevocationList,
        at_utc_us: i64,
    ) -> Result<RevocationStatus, Denial> {
        signed.verify(&self.ring, at_utc_us)?;
        let list = &signed.list;
        if list.version < self.applied_version {
            return Err(Denial::RevocationListRollback {
                applied: self.applied_version,
                offered: list.version,
            });
        }
        if list.expires_at_utc_us <= at_utc_us {
            self.record_alarm(list, at_utc_us);
            return Err(Denial::RevocationListExpired {
                version: list.version,
                expired_at_utc_us: list.expires_at_utc_us,
            });
        }
        self.applied_version = list.version;
        let status = RevocationStatus {
            version: list.version,
            issued_at_utc_us: list.issued_at_utc_us,
            expires_at_utc_us: list.expires_at_utc_us,
            revoked: list.len(),
            applied_at_utc_us: at_utc_us,
        };
        self.revocation = Some(list.clone());
        Ok(status)
    }

    fn record_alarm(&mut self, list: &TicketRevocationList, at_utc_us: i64) {
        if self.policy.stale_list == StaleRevocationPolicy::Alarm {
            self.alarm = Some(StaleListAlarm {
                version: list.version,
                expired_at_utc_us: list.expires_at_utc_us,
                detected_at_utc_us: at_utc_us,
            });
        }
    }

    /// Validate one signed ticket for one admission request.
    pub fn validate(
        &mut self,
        ticket: &SignedTicket,
        request: &ValidationRequest,
    ) -> Result<Admission, Denial> {
        let payload = &ticket.payload;
        payload
            .check_shape()
            .map_err(|_| Denial::Malformed("payload shape"))?;

        ticket.verify_signature(&self.ring, request.at_utc_us)?;

        if let Some(denial) = scope_denial(&request.scope, &payload.scope) {
            return Err(denial);
        }
        if request.at_utc_us < payload.valid_from_utc_us {
            return Err(Denial::NotYetValid {
                valid_from_utc_us: payload.valid_from_utc_us,
            });
        }
        if !payload.is_valid_at(request.at_utc_us) {
            return Err(Denial::Expired {
                valid_until_utc_us: payload.valid_until_utc_us,
            });
        }
        self.check_holder(payload.holder.as_ref(), request.holder.as_ref())?;
        self.check_revocation_freshness(request.at_utc_us)?;

        let list = self
            .revocation
            .as_ref()
            .expect("freshness check requires a list when policy demands one");
        if list.is_revoked(&payload.ticket_id) {
            return Err(Denial::RevokedTicket {
                ticket_id: payload.ticket_id.clone(),
            });
        }

        if !self.replay.record(payload.replay_key(), request.at_utc_us) {
            return Err(Denial::Replayed {
                ticket_id: payload.ticket_id.clone(),
                nonce: payload.nonce,
            });
        }

        Ok(Admission {
            ticket_id: payload.ticket_id.clone(),
            event_id: payload.scope.event_id.clone(),
            venue_id: payload.scope.venue_id.clone(),
            gate_id: payload.scope.gate_id.clone(),
            zone_id: payload.scope.zone_id.clone(),
            nonce: payload.nonce,
            holder_bound: payload.holder.is_some(),
        })
    }

    fn check_holder(
        &self,
        required: Option<&HolderBinding>,
        presented: Option<&HolderBinding>,
    ) -> Result<(), Denial> {
        match self.policy.holder {
            HolderPolicy::Ignore => Ok(()),
            HolderPolicy::Optional => match required {
                None => Ok(()),
                Some(required) => match presented {
                    Some(presented) if presented == required => Ok(()),
                    _ => Err(Denial::HolderMismatch),
                },
            },
            HolderPolicy::Required => match required {
                None => Err(Denial::HolderBindingRequired),
                Some(required) => match presented {
                    Some(presented) if presented == required => Ok(()),
                    _ => Err(Denial::HolderMismatch),
                },
            },
        }
    }

    fn check_revocation_freshness(&mut self, at_utc_us: i64) -> Result<(), Denial> {
        let Some(list) = self.revocation.as_ref() else {
            return if self.policy.require_revocation_list {
                Err(Denial::RevocationListMissing)
            } else {
                Ok(())
            };
        };
        if list.expires_at_utc_us <= at_utc_us {
            let version = list.version;
            let expired_at_utc_us = list.expires_at_utc_us;
            let list = list.clone();
            self.record_alarm(&list, at_utc_us);
            return Err(Denial::RevocationListExpired {
                version,
                expired_at_utc_us,
            });
        }
        Ok(())
    }
}
