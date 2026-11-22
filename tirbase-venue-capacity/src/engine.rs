// SPDX-License-Identifier: AGPL-3.0-only

//! The capacity engine.
//!
//! One engine owns one venue envelope's occupancy. Every presence event is
//! idempotent on its event id, so a retried delivery (or a repeated ticket
//! presentation) never inflates occupancy. Ingress is checked against the
//! gate, zone and venue envelopes in that order; egress is always allowed
//! unless nobody is counted inside.

use std::collections::{BTreeMap, VecDeque};

use tirbase_venue::{GateId, VenueId, ZoneId};
use tirbase_venue_ticket::Admission;

use crate::audit::{AuditAction, AuditEntry, MAX_AUDIT_ENTRIES};
use crate::error::CapacityError;
use crate::event::{
    Alarm, Decision, Denial, Direction, EventSource, Occupancy, PresenceEvent,
};
use crate::limit::{CapacityConfig, HardPolicy, LimitScope};
use crate::overrides::{CapacityOverride, OverrideGrant, OverrideState};
use crate::reconcile::{
    Adoption, Observation, ObservationKind, ReconciliationReport, ReconciliationStatus,
    SourceKind,
};

/// Default number of remembered event ids.
pub const DEFAULT_DEDUPE_CAPACITY: usize = 100_000;
/// Largest accepted dedupe capacity.
pub const MAX_DEDUPE_CAPACITY: usize = 1_000_000;
/// Default duplicate-detection retention (one day).
pub const DEFAULT_DEDUPE_RETENTION_US: i64 = 86_400_000_000;
/// Longest accepted duplicate-detection retention (30 days).
pub const MAX_DEDUPE_RETENTION_US: i64 = 30 * 86_400_000_000;

/// Enforces one venue's capacity envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapacityEngine {
    config: CapacityConfig,
    occupancy: Occupancy,
    seen: BTreeMap<String, i64>,
    dedupe_capacity: usize,
    dedupe_retention_us: i64,
    seen_dropped: u64,
    overrides: BTreeMap<String, CapacityOverride>,
    audit: VecDeque<AuditEntry>,
    audit_seq: u64,
    audit_dropped: u64,
}

impl CapacityEngine {
    /// Build an engine, validating the envelope.
    pub fn new(config: CapacityConfig) -> Result<Self, CapacityError> {
        config.validate()?;
        let occupancy = Occupancy::with_scope(&config);
        Ok(Self {
            config,
            occupancy,
            seen: BTreeMap::new(),
            dedupe_capacity: DEFAULT_DEDUPE_CAPACITY,
            dedupe_retention_us: DEFAULT_DEDUPE_RETENTION_US,
            seen_dropped: 0,
            overrides: BTreeMap::new(),
            audit: VecDeque::new(),
            audit_seq: 0,
            audit_dropped: 0,
        })
    }

    /// Override the idempotency bounds.
    pub fn with_dedupe(
        mut self,
        capacity: usize,
        retention_us: i64,
    ) -> Result<Self, CapacityError> {
        if capacity == 0 || capacity > MAX_DEDUPE_CAPACITY {
            return Err(CapacityError::InvalidConfig(
                "dedupe capacity out of range",
            ));
        }
        if retention_us <= 0 || retention_us > MAX_DEDUPE_RETENTION_US {
            return Err(CapacityError::InvalidConfig(
                "dedupe retention out of range",
            ));
        }
        self.dedupe_capacity = capacity;
        self.dedupe_retention_us = retention_us;
        Ok(self)
    }

    pub fn config(&self) -> &CapacityConfig {
        &self.config
    }

    pub fn venue_id(&self) -> &VenueId {
        self.config.venue_id()
    }

    pub fn occupancy(&self) -> &Occupancy {
        &self.occupancy
    }

    pub fn venue_occupancy(&self) -> u32 {
        self.occupancy.venue()
    }

    pub fn zone_occupancy(&self, zone_id: &ZoneId) -> u32 {
        self.occupancy.zone(zone_id)
    }

    pub fn gate_occupancy(&self, gate_id: &GateId) -> u32 {
        self.occupancy.gate(gate_id)
    }

    /// Event ids evicted or pruned since start; duplicates older than the
    /// retention window can therefore count again.
    pub fn seen_dropped(&self) -> u64 {
        self.seen_dropped
    }

    /// Audit entries in sequence order.
    pub fn audit(&self) -> impl Iterator<Item = &AuditEntry> {
        self.audit.iter()
    }

    /// Audit entries dropped because the log was full.
    pub fn audit_dropped(&self) -> u64 {
        self.audit_dropped
    }

    /// Every known override, in override-id order.
    pub fn overrides(&self) -> impl Iterator<Item = &CapacityOverride> {
        self.overrides.values()
    }

    pub fn override_by_id(&self, override_id: &str) -> Option<&CapacityOverride> {
        self.overrides.get(override_id)
    }

    /// Count one presence event.
    ///
    /// Returns the typed decision; configuration mistakes are errors. Only
    /// counted events are remembered, so a refused passage can be retried
    /// (after an override or a corrective egress) without being reported as a
    /// duplicate.
    pub fn record(&mut self, event: &PresenceEvent) -> Result<Decision, CapacityError> {
        self.check_event(event)?;
        self.prune_seen(event.at_utc_us);
        if self.seen.contains_key(&event.event_id) {
            return Ok(Decision::Duplicate {
                occupancy: self.occupancy.clone(),
                event_id: event.event_id.clone(),
            });
        }
        Ok(match event.direction {
            Direction::Ingress => self.ingress(event),
            Direction::Egress => self.egress(event),
        })
    }

    /// Count an ST-05 admission as an ingress.
    pub fn record_admission(
        &mut self,
        admission: &Admission,
        direction: Direction,
        at_utc_us: i64,
        source: EventSource,
    ) -> Result<Decision, CapacityError> {
        let event = PresenceEvent::from_admission(admission, direction, at_utc_us, source);
        self.record(&event)
    }

    /// Request and record an override grant. The approver must differ from the
    /// requester, and a second active override for the same scope is refused.
    pub fn grant_override(
        &mut self,
        grant: OverrideGrant,
    ) -> Result<CapacityOverride, CapacityError> {
        if grant.override_id.trim().is_empty() {
            return Err(CapacityError::InvalidOverride("override id is empty"));
        }
        if grant.requested_by.trim().is_empty() {
            return Err(CapacityError::InvalidOverride("requester is empty"));
        }
        if grant.approved_by.trim().is_empty() {
            return Err(CapacityError::InvalidOverride("approver is empty"));
        }
        if grant.requested_by.trim() == grant.approved_by.trim() {
            return Err(CapacityError::InvalidOverride(
                "requester cannot approve their own override",
            ));
        }
        if grant.reason.trim().is_empty() {
            return Err(CapacityError::InvalidOverride("reason is empty"));
        }
        if grant.max_headroom == 0 {
            return Err(CapacityError::InvalidOverride("headroom must be positive"));
        }
        if grant.max_uses == 0 {
            return Err(CapacityError::InvalidOverride("max uses must be positive"));
        }
        if grant.expires_at_utc_us <= grant.granted_at_utc_us {
            return Err(CapacityError::InvalidOverride(
                "expiry must be after the grant time",
            ));
        }
        if !self.scope_exists(&grant.scope) {
            return Err(CapacityError::InvalidOverride(
                "override scope is not in this envelope",
            ));
        }
        if self
            .active_override(&grant.scope, grant.granted_at_utc_us)
            .is_some()
        {
            return Err(CapacityError::OverrideAlreadyActive(grant.scope));
        }
        let record = CapacityOverride {
            override_id: grant.override_id.clone(),
            scope: grant.scope.clone(),
            requested_by: grant.requested_by,
            approved_by: grant.approved_by,
            reason: grant.reason.clone(),
            granted_at_utc_us: grant.granted_at_utc_us,
            expires_at_utc_us: grant.expires_at_utc_us,
            max_headroom: grant.max_headroom,
            max_uses: grant.max_uses,
            uses: 0,
            last_used_at_utc_us: None,
            revoked_at_utc_us: None,
            expired_audited: false,
        };
        let actor = record.approved_by.clone();
        let detail = format!(
            "requested by {}: {}",
            record.requested_by, grant.reason
        );
        let override_id = record.override_id.clone();
        let scope = record.scope.clone();
        self.overrides.insert(override_id.clone(), record.clone());
        self.push_audit(
            grant.granted_at_utc_us,
            AuditAction::OverrideGranted,
            actor,
            scope,
            override_id,
            detail,
        );
        Ok(record)
    }

    /// Revoke an override before its expiry.
    pub fn revoke_override(
        &mut self,
        override_id: &str,
        actor: &str,
        reason: &str,
        at_utc_us: i64,
    ) -> Result<CapacityOverride, CapacityError> {
        if actor.trim().is_empty() {
            return Err(CapacityError::EmptyAttribution("revoking actor"));
        }
        if reason.trim().is_empty() {
            return Err(CapacityError::EmptyAttribution("revocation reason"));
        }
        let Some(existing) = self.overrides.get(override_id) else {
            return Err(CapacityError::UnknownOverride(override_id.to_owned()));
        };
        if existing.revoked_at_utc_us.is_some() {
            return Err(CapacityError::InvalidOverride("override is already revoked"));
        }
        let scope = existing.scope.clone();
        let revoked = {
            let record = self
                .overrides
                .get_mut(override_id)
                .expect("override exists");
            record.revoked_at_utc_us = Some(at_utc_us);
            record.clone()
        };
        self.push_audit(
            at_utc_us,
            AuditAction::OverrideRevoked,
            actor.to_owned(),
            scope,
            override_id.to_owned(),
            reason.to_owned(),
        );
        Ok(revoked)
    }

    /// Prune expired idempotency entries and audit newly expired overrides.
    ///
    /// Returns the ids of overrides that expired at this sweep.
    pub fn sweep(&mut self, now_utc_us: i64) -> Vec<String> {
        self.prune_seen(now_utc_us);
        let mut expired = Vec::new();
        let ids: Vec<String> = self.overrides.keys().cloned().collect();
        for override_id in ids {
            let Some(record) = self.overrides.get_mut(&override_id) else {
                continue;
            };
            if record.expired_audited
                || record.revoked_at_utc_us.is_some()
                || now_utc_us < record.expires_at_utc_us
            {
                continue;
            }
            record.expired_audited = true;
            let scope = record.scope.clone();
            let actor = record.approved_by.clone();
            expired.push(override_id.clone());
            self.push_audit(
                now_utc_us,
                AuditAction::OverrideExpired,
                actor,
                scope,
                override_id,
                format!("expired at {now_utc_us}"),
            );
        }
        expired
    }

    /// Compare an observation with counted occupancy. Changes nothing.
    pub fn reconcile(
        &self,
        observation: &Observation,
    ) -> Result<ReconciliationReport, CapacityError> {
        if observation.observation_id.trim().is_empty() {
            return Err(CapacityError::InvalidObservation("observation id is empty"));
        }
        if observation.source.trim().is_empty() {
            return Err(CapacityError::InvalidObservation("source is empty"));
        }
        if self.config.zone_limit(&observation.zone_id).is_none() {
            return Err(CapacityError::UnknownZone(observation.zone_id.clone()));
        }
        let tracked = self.occupancy.zone(&observation.zone_id);
        let (source_kind, observed) = match observation.kind {
            ObservationKind::Turnstile {
                ingress_total,
                egress_total,
            } => (
                SourceKind::Turnstile,
                i64::from(ingress_total) - i64::from(egress_total),
            ),
            ObservationKind::Occupancy { occupancy } => {
                (SourceKind::OccupancySensor, i64::from(occupancy))
            }
        };
        let delta = observed - i64::from(tracked);
        let status = match delta.cmp(&0) {
            std::cmp::Ordering::Equal => ReconciliationStatus::Agree,
            std::cmp::Ordering::Greater => ReconciliationStatus::ObservedHigher,
            std::cmp::Ordering::Less => ReconciliationStatus::ObservedLower,
        };
        Ok(ReconciliationReport {
            observation_id: observation.observation_id.clone(),
            zone_id: observation.zone_id.clone(),
            source: observation.source.clone(),
            source_kind,
            at_utc_us: observation.at_utc_us,
            tracked,
            observed,
            delta,
            status,
        })
    }

    /// Adopt an observation as the zone's occupancy.
    ///
    /// This is an operator action: it needs an attributable actor and a reason,
    /// it writes an audit entry, and it re-evaluates the zone and venue limits
    /// against the adopted figure so an over-capacity adoption alarms.
    pub fn adopt_observation(
        &mut self,
        observation: &Observation,
        actor: &str,
        reason: &str,
    ) -> Result<Adoption, CapacityError> {
        if actor.trim().is_empty() {
            return Err(CapacityError::EmptyAttribution("adopting actor"));
        }
        if reason.trim().is_empty() {
            return Err(CapacityError::EmptyAttribution("adoption reason"));
        }
        let report = self.reconcile(observation)?;
        let previous = self.occupancy.zone(&observation.zone_id);
        let adopted = report.observed.clamp(0, i64::from(u32::MAX)) as u32;
        self.occupancy
            .set_zone(&observation.zone_id, adopted);

        let mut alarms = Vec::new();
        self.limit_alarms(
            LimitScope::Zone(observation.zone_id.clone()),
            adopted,
            &mut alarms,
        );
        self.limit_alarms(LimitScope::Venue, self.occupancy.venue(), &mut alarms);
        if report.status != ReconciliationStatus::Agree {
            alarms.push(Alarm::SensorDisagreement {
                zone_id: observation.zone_id.clone(),
                tracked: report.tracked,
                observed: report.observed,
            });
        }

        let audit_seq = self.push_audit(
            observation.at_utc_us,
            AuditAction::ReconciliationAdopted,
            actor.to_owned(),
            LimitScope::Zone(observation.zone_id.clone()),
            observation.observation_id.clone(),
            format!(
                "{} -> {} via {} ({}); {reason}",
                previous,
                adopted,
                report.source_kind.code(),
                report.source
            ),
        );
        Ok(Adoption {
            report,
            previous,
            adopted,
            alarms,
            audit_seq,
        })
    }

    // --- internals -----------------------------------------------------

    fn check_event(&self, event: &PresenceEvent) -> Result<(), CapacityError> {
        if event.event_id.trim().is_empty() {
            return Err(CapacityError::EmptyEventId);
        }
        if &event.venue_id != self.config.venue_id() {
            return Err(CapacityError::VenueMismatch {
                expected: self.config.venue_id().clone(),
                presented: event.venue_id.clone(),
            });
        }
        if self.config.zone_limit(&event.zone_id).is_none() {
            return Err(CapacityError::UnknownZone(event.zone_id.clone()));
        }
        match self.config.zone_of_gate(&event.gate_id) {
            None => Err(CapacityError::UnknownGate(event.gate_id.clone())),
            Some(zone_id) if zone_id == &event.zone_id => Ok(()),
            Some(_) => Err(CapacityError::GateNotInZone {
                gate_id: event.gate_id.clone(),
                zone_id: event.zone_id.clone(),
            }),
        }
    }

    fn ingress(&mut self, event: &PresenceEvent) -> Decision {
        let (alarms, covering_overrides, denial) = self.check_limits(event);
        if let Some(denial) = denial {
            return Decision::Denied {
                denial,
                occupancy: self.occupancy.clone(),
                alarms,
            };
        }

        self.occupancy
            .increment(&event.zone_id, &event.gate_id);
        self.remember(&event.event_id, event.at_utc_us);

        for override_id in covering_overrides {
            let scope = {
                let Some(record) = self.overrides.get_mut(&override_id) else {
                    continue;
                };
                record.uses = record.uses.saturating_add(1);
                record.last_used_at_utc_us = Some(event.at_utc_us);
                record.scope.clone()
            };
            self.push_audit(
                event.at_utc_us,
                AuditAction::OverrideUsed,
                format!("gate:{}", event.gate_id),
                scope,
                override_id,
                format!("event {} admitted at gate {}", event.event_id, event.gate_id),
            );
        }

        Decision::Allowed {
            occupancy: self.occupancy.clone(),
            alarms,
        }
    }

    fn egress(&mut self, event: &PresenceEvent) -> Decision {
        let zone_occupancy = self.occupancy.zone(&event.zone_id);
        if zone_occupancy == 0 {
            return Decision::Denied {
                denial: Denial::EgressUnderflow {
                    scope: LimitScope::Zone(event.zone_id.clone()),
                    occupancy: 0,
                },
                occupancy: self.occupancy.clone(),
                alarms: Vec::new(),
            };
        }
        if self.occupancy.venue() == 0 {
            return Decision::Denied {
                denial: Denial::EgressUnderflow {
                    scope: LimitScope::Venue,
                    occupancy: 0,
                },
                occupancy: self.occupancy.clone(),
                alarms: Vec::new(),
            };
        }

        let mut alarms = Vec::new();
        if self.occupancy.gate(&event.gate_id) == 0 {
            alarms.push(Alarm::GateUnbalanced {
                gate_id: event.gate_id.clone(),
            });
        }
        self.occupancy
            .decrement(&event.zone_id, &event.gate_id);
        self.remember(&event.event_id, event.at_utc_us);
        Decision::Allowed {
            occupancy: self.occupancy.clone(),
            alarms,
        }
    }

    fn check_limits(&self, event: &PresenceEvent) -> (Vec<Alarm>, Vec<String>, Option<Denial>) {
        let mut checks = Vec::new();
        if let Some(limit) = self.config.gate_limit(&event.gate_id) {
            checks.push((
                LimitScope::Gate(event.gate_id.clone()),
                limit,
                self.occupancy.gate(&event.gate_id),
            ));
        }
        if let Some(limit) = self.config.zone_limit(&event.zone_id) {
            checks.push((
                LimitScope::Zone(event.zone_id.clone()),
                limit,
                self.occupancy.zone(&event.zone_id),
            ));
        }
        checks.push((
            LimitScope::Venue,
            self.config.venue_limit(),
            self.occupancy.venue(),
        ));

        let mut alarms = Vec::new();
        let mut used = Vec::new();
        let mut override_alarms = Vec::new();
        for (scope, limit, current) in checks {
            let attempted = current.saturating_add(1);
            if attempted > limit.hard {
                match limit.hard_policy {
                    HardPolicy::Reject => match self.active_override(&scope, event.at_utc_us) {
                        Some(record) if record.covers(limit.hard, attempted, event.at_utc_us) => {
                            used.push(record.override_id.clone());
                            override_alarms.push(Alarm::OverrideUsed {
                                override_id: record.override_id.clone(),
                                scope: scope.clone(),
                                occupancy: attempted,
                            });
                        }
                        _ => {
                            return (
                                alarms,
                                used,
                                Some(Denial::HardLimit {
                                    scope,
                                    limit: limit.hard,
                                    occupancy: current,
                                    attempted,
                                }),
                            );
                        }
                    },
                    HardPolicy::Alarm => alarms.push(Alarm::HardLimit {
                        scope: scope.clone(),
                        limit: limit.hard,
                        occupancy: attempted,
                    }),
                }
            }
            if attempted > limit.soft {
                alarms.push(Alarm::SoftLimit {
                    scope,
                    limit: limit.soft,
                    occupancy: attempted,
                });
            }
        }
        // An override is only announced once the whole ingress is admitted;
        // a later envelope can still refuse it.
        alarms.extend(override_alarms);
        (alarms, used, None)
    }

    fn limit_alarms(&self, scope: LimitScope, occupancy: u32, alarms: &mut Vec<Alarm>) {
        let limit = match &scope {
            LimitScope::Venue => Some(self.config.venue_limit()),
            LimitScope::Zone(zone_id) => self.config.zone_limit(zone_id),
            LimitScope::Gate(gate_id) => self.config.gate_limit(gate_id),
        };
        let Some(limit) = limit else {
            return;
        };
        if occupancy > limit.hard {
            alarms.push(Alarm::HardLimit {
                scope: scope.clone(),
                limit: limit.hard,
                occupancy,
            });
        }
        if occupancy > limit.soft {
            alarms.push(Alarm::SoftLimit {
                scope,
                limit: limit.soft,
                occupancy,
            });
        }
    }

    fn scope_exists(&self, scope: &LimitScope) -> bool {
        match scope {
            LimitScope::Venue => true,
            LimitScope::Zone(zone_id) => self.config.zone_limit(zone_id).is_some(),
            LimitScope::Gate(gate_id) => self.config.zone_of_gate(gate_id).is_some(),
        }
    }

    fn active_override(&self, scope: &LimitScope, now_utc_us: i64) -> Option<&CapacityOverride> {
        self.overrides
            .values()
            .find(|record| &record.scope == scope && record.state(now_utc_us) == OverrideState::Active)
    }

    fn prune_seen(&mut self, now_utc_us: i64) {
        let retention = self.dedupe_retention_us;
        self.seen
            .retain(|_, at| now_utc_us.saturating_sub(*at) < retention);
    }

    fn remember(&mut self, event_id: &str, at_utc_us: i64) {
        while self.seen.len() >= self.dedupe_capacity {
            let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.seen.remove(&oldest);
            self.seen_dropped = self.seen_dropped.saturating_add(1);
        }
        self.seen.insert(event_id.to_owned(), at_utc_us);
    }

    fn push_audit(
        &mut self,
        at_utc_us: i64,
        action: AuditAction,
        actor: String,
        scope: LimitScope,
        reference: String,
        detail: String,
    ) -> u64 {
        self.audit_seq = self.audit_seq.saturating_add(1);
        let entry = AuditEntry {
            seq: self.audit_seq,
            at_utc_us,
            action,
            actor,
            scope,
            reference,
            detail,
        };
        if self.audit.len() >= MAX_AUDIT_ENTRIES {
            self.audit.pop_front();
            self.audit_dropped = self.audit_dropped.saturating_add(1);
        }
        self.audit.push_back(entry);
        self.audit_seq
    }
}
