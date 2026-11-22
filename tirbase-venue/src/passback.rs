// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-passback and re-entry policy.
//!
//! A [`PassbackLedger`] records entry/exit scans per ticket and rejects reuse
//! according to the configured policy:
//!
//! * **anti-passback** prevents using the same ticket twice without leaving
//!   (strict, or timed with a cooldown);
//! * **re-entry policy** governs a ticket that returns after a recorded exit
//!   (forbidden, allowed, limited count, or cooldown).

use std::collections::BTreeMap;

use crate::error::VenueError;
use crate::ids::{GateId, TicketId, ZoneId};

/// Direction of a scan at a gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDirection {
    /// Entering the zone through the gate.
    In,
    /// Leaving the zone through the gate.
    Out,
}

/// How the ledger rejects repeated entry without an intervening exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiPassbackMode {
    /// No anti-passback enforcement.
    Disabled,
    /// A ticket may never enter while it is already inside.
    Strict,
    /// A ticket may retry entry once `cooldown_us` has elapsed since its entry.
    Timed { cooldown_us: i64 },
}

/// How the ledger treats a ticket returning after an exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReEntryPolicy {
    /// Re-entry is refused.
    NotAllowed,
    /// Re-entry is always permitted.
    Allowed,
    /// At most `max_reentries` returns are permitted.
    Limited { max_reentries: u32 },
    /// Re-entry is permitted once `after_us` has elapsed since the exit.
    Cooldown { after_us: i64 },
}

/// Combined anti-passback and re-entry configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PassbackPolicy {
    pub anti_passback: AntiPassbackMode,
    pub re_entry: ReEntryPolicy,
}

impl Default for PassbackPolicy {
    fn default() -> Self {
        Self {
            anti_passback: AntiPassbackMode::Strict,
            re_entry: ReEntryPolicy::NotAllowed,
        }
    }
}

impl PassbackPolicy {
    /// Create a policy, validating that timed durations are positive.
    pub fn new(
        anti_passback: AntiPassbackMode,
        re_entry: ReEntryPolicy,
    ) -> Result<Self, VenueError> {
        if let AntiPassbackMode::Timed { cooldown_us } = anti_passback {
            if cooldown_us <= 0 {
                return Err(VenueError::InvalidTimeWindow);
            }
        }
        if let ReEntryPolicy::Cooldown { after_us } = re_entry {
            if after_us <= 0 {
                return Err(VenueError::InvalidTimeWindow);
            }
        }
        Ok(Self {
            anti_passback,
            re_entry,
        })
    }
}

/// One credential scan presented to the ledger.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanRecord {
    pub ticket_id: TicketId,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    pub direction: ScanDirection,
    pub ts_utc_us: i64,
}

/// Result of an accepted scan.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanOutcome {
    pub ticket_id: TicketId,
    pub direction: ScanDirection,
    pub zone_id: ZoneId,
    /// True when this entry follows a prior exit.
    pub reentry: bool,
    /// Number of accepted entries for the ticket.
    pub entries: u32,
    /// Number of accepted re-entries for the ticket.
    pub reentries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TicketState {
    inside: Option<ZoneId>,
    entered_utc_us: i64,
    last_exit_utc_us: Option<i64>,
    entries: u32,
    reentries: u32,
}

/// Per-ticket anti-passback state, keyed by ticket id.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PassbackLedger {
    policy: PassbackPolicy,
    tickets: BTreeMap<TicketId, TicketState>,
}

impl Default for PassbackLedger {
    fn default() -> Self {
        Self::with_policy(PassbackPolicy::default())
    }
}

impl PassbackLedger {
    /// Ledger with the default policy (strict anti-passback, no re-entry).
    pub fn new() -> Self {
        Self::default()
    }

    /// Ledger with an explicit policy.
    pub fn with_policy(policy: PassbackPolicy) -> Self {
        Self {
            policy,
            tickets: BTreeMap::new(),
        }
    }

    /// The configured policy.
    pub fn policy(&self) -> PassbackPolicy {
        self.policy
    }

    /// True while the ticket is recorded inside a zone.
    pub fn is_inside(&self, ticket_id: &TicketId) -> bool {
        self.tickets
            .get(ticket_id)
            .map(|state| state.inside.is_some())
            .unwrap_or(false)
    }

    /// Record a scan, accepting or rejecting it according to policy.
    pub fn record(&mut self, scan: &ScanRecord) -> Result<ScanOutcome, VenueError> {
        match scan.direction {
            ScanDirection::In => self.record_entry(scan),
            ScanDirection::Out => self.record_exit(scan),
        }
    }

    fn record_entry(&mut self, scan: &ScanRecord) -> Result<ScanOutcome, VenueError> {
        let prior = self.tickets.get(&scan.ticket_id).cloned();

        if let Some(state) = &prior {
            if state.inside.is_some() {
                let inside_since = scan.ts_utc_us - state.entered_utc_us;
                match self.policy.anti_passback {
                    AntiPassbackMode::Strict => {
                        return Err(VenueError::AntiPassbackRejected {
                            ticket_id: scan.ticket_id.clone(),
                            reason: "ticket is already inside",
                        });
                    }
                    AntiPassbackMode::Timed { cooldown_us } => {
                        if inside_since < cooldown_us {
                            return Err(VenueError::AntiPassbackRejected {
                                ticket_id: scan.ticket_id.clone(),
                                reason: "ticket is already inside and the cooldown has not elapsed",
                            });
                        }
                    }
                    AntiPassbackMode::Disabled => {}
                }
            }
        }

        let is_reentry = prior
            .as_ref()
            .map(|state| state.entries > 0)
            .unwrap_or(false);
        if is_reentry {
            if let Some(state) = &prior {
                self.check_reentry(scan, state)?;
            }
        }

        let mut state = prior.unwrap_or(TicketState {
            inside: None,
            entered_utc_us: scan.ts_utc_us,
            last_exit_utc_us: None,
            entries: 0,
            reentries: 0,
        });
        state.entries = state
            .entries
            .checked_add(1)
            .ok_or(VenueError::ArithmeticOverflow)?;
        if is_reentry {
            state.reentries = state
                .reentries
                .checked_add(1)
                .ok_or(VenueError::ArithmeticOverflow)?;
        }
        state.inside = Some(scan.zone_id.clone());
        state.entered_utc_us = scan.ts_utc_us;
        state.last_exit_utc_us = None;

        let outcome = ScanOutcome {
            ticket_id: scan.ticket_id.clone(),
            direction: ScanDirection::In,
            zone_id: scan.zone_id.clone(),
            reentry: is_reentry,
            entries: state.entries,
            reentries: state.reentries,
        };
        self.tickets.insert(scan.ticket_id.clone(), state);
        Ok(outcome)
    }

    fn check_reentry(&self, scan: &ScanRecord, state: &TicketState) -> Result<(), VenueError> {
        let reject = |reason: &'static str| {
            Err(VenueError::ReEntryRejected {
                ticket_id: scan.ticket_id.clone(),
                reason,
            })
        };
        match self.policy.re_entry {
            ReEntryPolicy::NotAllowed => reject("re-entry is not allowed by policy"),
            ReEntryPolicy::Allowed => Ok(()),
            ReEntryPolicy::Limited { max_reentries } => {
                if state.reentries >= max_reentries {
                    reject("re-entry limit reached")
                } else {
                    Ok(())
                }
            }
            ReEntryPolicy::Cooldown { after_us } => match state.last_exit_utc_us {
                Some(exit_utc_us) if scan.ts_utc_us - exit_utc_us >= after_us => Ok(()),
                Some(_) => reject("re-entry cooldown has not elapsed"),
                None => reject("no exit recorded for a cooldown re-entry"),
            },
        }
    }

    fn record_exit(&mut self, scan: &ScanRecord) -> Result<ScanOutcome, VenueError> {
        let Some(state) = self.tickets.get_mut(&scan.ticket_id) else {
            return Err(VenueError::AntiPassbackRejected {
                ticket_id: scan.ticket_id.clone(),
                reason: "exit without a recorded entry",
            });
        };
        match &state.inside {
            None => {
                return Err(VenueError::AntiPassbackRejected {
                    ticket_id: scan.ticket_id.clone(),
                    reason: "exit without a recorded entry",
                });
            }
            Some(zone_id) if zone_id != &scan.zone_id => {
                return Err(VenueError::AntiPassbackRejected {
                    ticket_id: scan.ticket_id.clone(),
                    reason: "exit gate does not belong to the entry zone",
                });
            }
            Some(_) => {}
        }

        state.inside = None;
        state.last_exit_utc_us = Some(scan.ts_utc_us);
        Ok(ScanOutcome {
            ticket_id: scan.ticket_id.clone(),
            direction: ScanDirection::Out,
            zone_id: scan.zone_id.clone(),
            reentry: false,
            entries: state.entries,
            reentries: state.reentries,
        })
    }
}
