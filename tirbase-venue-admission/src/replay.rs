// SPDX-License-Identifier: AGPL-3.0-only

//! Gate-scoped replay keys and the bounded replay store.
//!
//! A replay key is `ticket id + nonce + gate id + epoch`. The gate and epoch
//! make every key distinct per lane and time bucket, while a separate
//! ticket-level claim records the *first* gate that admitted the ticket, so a
//! ticket presented at a second gate is refused even after the epoch rolls
//! over. Claims and keys live until the ticket's own validity window ends, so
//! reuse after the window is refused by the window check and storage is
//! reclaimed once windows close.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_venue::{GateId, TicketId};
use tirbase_venue_ticket::TicketPayload;

use crate::error::ReplayError;

/// Default epoch length: 15 minutes.
pub const DEFAULT_EPOCH_LEN_US: i64 = 900_000_000;
/// Shortest accepted epoch.
pub const MIN_EPOCH_LEN_US: i64 = 1_000_000;
/// Longest accepted epoch: 24 hours.
pub const MAX_EPOCH_LEN_US: i64 = 86_400_000_000;
/// Default replay-store capacity.
pub const DEFAULT_REPLAY_CAPACITY: usize = 100_000;
/// Largest accepted replay-store capacity.
pub const MAX_REPLAY_CAPACITY: usize = 1_000_000;

/// How presentation times are bucketed into epochs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochPolicy {
    pub epoch_len_us: i64,
}

impl EpochPolicy {
    /// Build an epoch policy in `1 s ..= 24 h`.
    pub fn new(epoch_len_us: i64) -> Result<Self, ReplayError> {
        if !(MIN_EPOCH_LEN_US..=MAX_EPOCH_LEN_US).contains(&epoch_len_us) {
            return Err(ReplayError::InvalidConfig("epoch length out of range"));
        }
        Ok(Self { epoch_len_us })
    }

    /// The epoch containing an instant, floor-divided and clamped at zero.
    pub fn epoch_of(&self, at_utc_us: i64) -> u64 {
        if at_utc_us <= 0 {
            0
        } else {
            (at_utc_us / self.epoch_len_us) as u64
        }
    }
}

impl Default for EpochPolicy {
    fn default() -> Self {
        Self {
            epoch_len_us: DEFAULT_EPOCH_LEN_US,
        }
    }
}

/// One replay key: ticket id, nonce, gate and epoch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReplayKey {
    pub ticket_id: TicketId,
    pub nonce: u64,
    pub gate_id: GateId,
    pub epoch: u64,
}

impl ReplayKey {
    pub fn new(ticket_id: TicketId, nonce: u64, gate_id: GateId, epoch: u64) -> Self {
        Self {
            ticket_id,
            nonce,
            gate_id,
            epoch,
        }
    }

    /// The exact key string stored per gate and epoch.
    pub fn key(&self) -> String {
        format!(
            "{}#{}@{}@{}",
            self.ticket_id.as_str(),
            self.nonce,
            self.gate_id.as_str(),
            self.epoch
        )
    }

    /// The ticket-level claim key, shared by every gate and epoch.
    pub fn ticket_key(&self) -> String {
        format!("{}#{}", self.ticket_id.as_str(), self.nonce)
    }
}

impl fmt::Display for ReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.key())
    }
}

/// The first admitted use of a ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Claim {
    gate_id: GateId,
    epoch: u64,
    admitted_at_utc_us: i64,
    expires_at_utc_us: i64,
}

/// Outcome of presenting a ticket to the replay store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// First use: the key and the ticket-level claim are now recorded.
    Fresh {
        key: ReplayKey,
        claim_expires_at_utc_us: i64,
    },
    /// The same key (same gate, same epoch) was already admitted.
    Duplicate { key: ReplayKey },
    /// The ticket was already admitted at another gate.
    CrossGate {
        key: ReplayKey,
        claimed_by: GateId,
        claimed_at_utc_us: i64,
    },
    /// The ticket was already admitted at this gate in an earlier epoch.
    AlreadyUsed {
        key: ReplayKey,
        claimed_epoch: u64,
        claimed_at_utc_us: i64,
    },
    /// Presented before the ticket's validity window.
    NotYetValid {
        key: ReplayKey,
        valid_from_utc_us: i64,
    },
    /// Presented after the ticket's validity window.
    WindowClosed {
        key: ReplayKey,
        valid_until_utc_us: i64,
    },
}

impl ReplayVerdict {
    pub fn is_admitted(&self) -> bool {
        matches!(self, ReplayVerdict::Fresh { .. })
    }

    pub fn code(&self) -> &'static str {
        match self {
            ReplayVerdict::Fresh { .. } => "fresh",
            ReplayVerdict::Duplicate { .. } => "duplicate",
            ReplayVerdict::CrossGate { .. } => "cross_gate",
            ReplayVerdict::AlreadyUsed { .. } => "already_used",
            ReplayVerdict::NotYetValid { .. } => "not_yet_valid",
            ReplayVerdict::WindowClosed { .. } => "window_closed",
        }
    }
}

/// Bounded, persistable replay store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReplayGuard {
    epoch: EpochPolicy,
    capacity: usize,
    /// Exact `ticket#nonce@gate@epoch` keys with their expiry.
    exact: BTreeMap<String, i64>,
    /// Ticket-level claims, so cross-gate reuse is caught across epochs.
    claims: BTreeMap<String, Claim>,
    evicted: u64,
}

impl GateReplayGuard {
    /// Build a guard. `capacity` bounds each of the two maps.
    pub fn new(epoch: EpochPolicy, capacity: usize) -> Result<Self, ReplayError> {
        if capacity == 0 || capacity > MAX_REPLAY_CAPACITY {
            return Err(ReplayError::InvalidConfig("replay capacity out of range"));
        }
        Ok(Self {
            epoch,
            capacity,
            exact: BTreeMap::new(),
            claims: BTreeMap::new(),
            evicted: 0,
        })
    }

    pub fn epoch_policy(&self) -> EpochPolicy {
        self.epoch
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    pub fn claims_len(&self) -> usize {
        self.claims.len()
    }

    /// Entries dropped by capacity or cleanup.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Record an admission if this is the ticket's first use.
    pub fn admit(
        &mut self,
        payload: &TicketPayload,
        gate_id: &GateId,
        at_utc_us: i64,
    ) -> ReplayVerdict {
        let epoch = self.epoch.epoch_of(at_utc_us);
        let key = ReplayKey::new(
            payload.ticket_id.clone(),
            payload.nonce,
            gate_id.clone(),
            epoch,
        );
        if at_utc_us < payload.valid_from_utc_us {
            return ReplayVerdict::NotYetValid {
                key,
                valid_from_utc_us: payload.valid_from_utc_us,
            };
        }
        if at_utc_us >= payload.valid_until_utc_us {
            return ReplayVerdict::WindowClosed {
                key,
                valid_until_utc_us: payload.valid_until_utc_us,
            };
        }
        self.prune(at_utc_us);

        let ticket_key = key.ticket_key();
        if let Some(claim) = self.claims.get(&ticket_key) {
            if &claim.gate_id != gate_id {
                return ReplayVerdict::CrossGate {
                    key,
                    claimed_by: claim.gate_id.clone(),
                    claimed_at_utc_us: claim.admitted_at_utc_us,
                };
            }
            if claim.epoch == epoch {
                return ReplayVerdict::Duplicate { key };
            }
            return ReplayVerdict::AlreadyUsed {
                key,
                claimed_epoch: claim.epoch,
                claimed_at_utc_us: claim.admitted_at_utc_us,
            };
        }

        let expires_at_utc_us = payload.valid_until_utc_us;
        self.remember_exact(key.key(), expires_at_utc_us);
        self.remember_claim(
            ticket_key,
            Claim {
                gate_id: gate_id.clone(),
                epoch,
                admitted_at_utc_us: at_utc_us,
                expires_at_utc_us,
            },
        );
        ReplayVerdict::Fresh {
            key,
            claim_expires_at_utc_us: expires_at_utc_us,
        }
    }

    /// Drop entries whose ticket window has closed.
    pub fn prune(&mut self, now_utc_us: i64) {
        let before = self.exact.len() + self.claims.len();
        self.exact.retain(|_, expires| *expires > now_utc_us);
        self.claims
            .retain(|_, claim| claim.expires_at_utc_us > now_utc_us);
        let after = self.exact.len() + self.claims.len();
        self.evicted = self
            .evicted
            .saturating_add((before.saturating_sub(after)) as u64);
    }

    fn remember_exact(&mut self, key: String, expires_at_utc_us: i64) {
        while self.exact.len() >= self.capacity {
            let Some(oldest) = self
                .exact
                .iter()
                .min_by_key(|(_, expires)| **expires)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.exact.remove(&oldest);
            self.evicted = self.evicted.saturating_add(1);
        }
        self.exact.insert(key, expires_at_utc_us);
    }

    fn remember_claim(&mut self, key: String, claim: Claim) {
        while self.claims.len() >= self.capacity {
            let Some(oldest) = self
                .claims
                .iter()
                .min_by_key(|(_, claim)| (claim.expires_at_utc_us, claim.admitted_at_utc_us))
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.claims.remove(&oldest);
            self.evicted = self.evicted.saturating_add(1);
        }
        self.claims.insert(key, claim);
    }

    pub fn to_json(&self) -> Result<String, ReplayError> {
        serde_json::to_string(self).map_err(|_| ReplayError::CorruptStore("serialize failed"))
    }

    pub fn from_json(json: &str) -> Result<Self, ReplayError> {
        let guard: Self =
            serde_json::from_str(json).map_err(|_| ReplayError::CorruptStore("parse failed"))?;
        if guard.capacity == 0 || guard.capacity > MAX_REPLAY_CAPACITY {
            return Err(ReplayError::CorruptStore("capacity out of range"));
        }
        EpochPolicy::new(guard.epoch.epoch_len_us)
            .map_err(|_| ReplayError::CorruptStore("epoch length out of range"))?;
        Ok(guard)
    }
}
