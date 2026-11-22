// SPDX-License-Identifier: AGPL-3.0-only

//! Reader health, tamper latch, offline cache and access resolution.
//!
//! The controller ties the reader protocols to the ST-01 venue model: a
//! presented card is mapped to a credential, checked against revocation, then
//! resolved through the venue access policies and the anti-passback ledger.
//! While the reader is offline only a cached, unexpired grant for the same gate
//! is honoured, and revocation is always evaluated first — including after a
//! restart from the persisted cache.

use tirbase_venue::{
    AccessPolicyId, AccessPolicyRegistry, GateId, PassbackLedger, PassbackPolicy, ReaderId,
    ScanDirection, ScanRecord, SpaceModel, Ticket, TicketId, TopologyVersion, ZoneId,
};

use crate::credential::{
    CardholderId, Credential, CredentialId, CredentialRegistry, PresentedCredential,
};
use crate::error::AccessError;
use crate::revocation::{AppliedRevocation, CachedGrant, OfflineCache, RevocationDelta};

/// Whether the reader link is up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Online,
    Offline,
}

/// Whether the reader has an uncleared tamper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperState {
    Clear,
    Latched,
}

/// Reader health events.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HealthEvent {
    ReaderOnline,
    ReaderOffline { failures: u32 },
    TamperDetected,
    TamperCleared,
    SecureChannelEstablished,
    SecureChannelFailed,
    CredentialGranted { credential_id: CredentialId },
    CredentialDenied { fingerprint: String },
}

/// A health event with the time it was raised.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HealthEventRecord {
    pub at_utc_us: i64,
    pub event: HealthEvent,
}

impl HealthEventRecord {
    pub fn new(at_utc_us: i64, event: HealthEvent) -> Self {
        Self { at_utc_us, event }
    }
}

/// Health and tamper state for one reader.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReaderHealth {
    pub reader_id: ReaderId,
    pub link: LinkState,
    pub tamper: TamperState,
    pub failures: u32,
    pub last_seen_utc_us: Option<i64>,
    pub secure_channel: bool,
}

impl ReaderHealth {
    /// A configured reader starts online with a clear tamper.
    pub fn new(reader_id: ReaderId) -> Self {
        Self {
            reader_id,
            link: LinkState::Online,
            tamper: TamperState::Clear,
            failures: 0,
            last_seen_utc_us: None,
            secure_channel: false,
        }
    }

    /// Refuse credentials while tampered.
    pub fn ensure_operational(&self) -> Result<(), AccessError> {
        if self.tamper == TamperState::Latched {
            return Err(AccessError::ReaderTampered(self.reader_id.clone()));
        }
        Ok(())
    }

    pub fn is_online(&self) -> bool {
        self.link == LinkState::Online
    }

    /// Record a reply from the reader.
    pub fn observe(&mut self, ts_utc_us: i64) {
        self.last_seen_utc_us = Some(ts_utc_us);
    }

    pub fn mark_online(&mut self) -> Vec<HealthEvent> {
        if self.link == LinkState::Online {
            return Vec::new();
        }
        self.link = LinkState::Online;
        self.failures = 0;
        vec![HealthEvent::ReaderOnline]
    }

    pub fn mark_offline(&mut self) -> Vec<HealthEvent> {
        self.failures = self.failures.saturating_add(1);
        self.link = LinkState::Offline;
        self.secure_channel = false;
        vec![HealthEvent::ReaderOffline {
            failures: self.failures,
        }]
    }

    /// Latch a tamper. Repeats are idempotent and raise no second event.
    pub fn observe_tamper(&mut self) -> Vec<HealthEvent> {
        if self.tamper == TamperState::Latched {
            return Vec::new();
        }
        self.tamper = TamperState::Latched;
        vec![HealthEvent::TamperDetected]
    }

    /// Clear a tamper. Requires an explicit, authorised reset.
    pub fn clear_tamper(&mut self, authorised: bool) -> Result<Vec<HealthEvent>, AccessError> {
        if self.tamper == TamperState::Clear {
            return Ok(Vec::new());
        }
        if !authorised {
            return Err(AccessError::ReaderTampered(self.reader_id.clone()));
        }
        self.tamper = TamperState::Clear;
        Ok(vec![HealthEvent::TamperCleared])
    }

    pub fn secure_established(&mut self) -> Vec<HealthEvent> {
        self.secure_channel = true;
        vec![HealthEvent::SecureChannelEstablished]
    }

    pub fn secure_failed(&mut self) -> Vec<HealthEvent> {
        self.secure_channel = false;
        vec![HealthEvent::SecureChannelFailed]
    }
}

/// The decision returned for an accepted card.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessGrant {
    pub credential_id: CredentialId,
    pub holder_id: CardholderId,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    pub policy_id: AccessPolicyId,
    pub ticket_id: TicketId,
    /// True when the decision came from the offline cache.
    pub offline: bool,
}

/// Access controller for one reader, bound to a venue topology version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessController {
    reader: ReaderHealth,
    topology: TopologyVersion,
    policies: AccessPolicyRegistry,
    space: SpaceModel,
    credentials: CredentialRegistry,
    cache: OfflineCache,
    passback: PassbackLedger,
    offline_grant_ttl_us: i64,
    events: Vec<HealthEventRecord>,
}

impl AccessController {
    /// Build a controller. Offline grants are cached for four hours.
    pub fn new(
        reader_id: ReaderId,
        topology: TopologyVersion,
        policies: AccessPolicyRegistry,
        space: SpaceModel,
        credentials: CredentialRegistry,
    ) -> Self {
        Self {
            cache: OfflineCache::new(reader_id.clone()),
            reader: ReaderHealth::new(reader_id),
            topology,
            policies,
            space,
            credentials,
            passback: PassbackLedger::new(),
            offline_grant_ttl_us: 4 * 60 * 60 * 1_000_000,
            events: Vec::new(),
        }
    }

    pub fn with_passback(mut self, policy: PassbackPolicy) -> Self {
        self.passback = PassbackLedger::with_policy(policy);
        self
    }

    pub fn reader(&self) -> &ReaderHealth {
        &self.reader
    }

    pub fn reader_mut(&mut self) -> &mut ReaderHealth {
        &mut self.reader
    }

    pub fn credentials(&self) -> &CredentialRegistry {
        &self.credentials
    }

    pub fn credentials_mut(&mut self) -> &mut CredentialRegistry {
        &mut self.credentials
    }

    pub fn cache(&self) -> &OfflineCache {
        &self.cache
    }

    pub fn events(&self) -> &[HealthEventRecord] {
        &self.events
    }

    pub fn drain_events(&mut self) -> Vec<HealthEventRecord> {
        std::mem::take(&mut self.events)
    }

    pub fn revocation_version(&self) -> u64 {
        self.cache.revocation.version()
    }

    /// Push one health event list into the controller's log.
    pub fn record_health(&mut self, at_utc_us: i64, events: Vec<HealthEvent>) {
        for event in events {
            self.events
                .push(HealthEventRecord::new(at_utc_us, event));
        }
    }

    /// Mark the reader offline. Credentials then need a cached grant.
    pub fn go_offline(&mut self, at_utc_us: i64) -> Vec<HealthEvent> {
        let events = self.reader.mark_offline();
        self.record_health(at_utc_us, events.clone());
        events
    }

    pub fn go_online(&mut self, at_utc_us: i64) -> Vec<HealthEvent> {
        let events = self.reader.mark_online();
        self.record_health(at_utc_us, events.clone());
        events
    }

    /// Local revocation, effective immediately and persisted with the cache.
    pub fn revoke(&mut self, id: CredentialId) -> bool {
        self.cache.revocation.revoke(id)
    }

    /// Apply an operator revocation delta, refusing a regression.
    pub fn apply_revocation(
        &mut self,
        delta: &RevocationDelta,
    ) -> Result<AppliedRevocation, AccessError> {
        self.cache.revocation.apply(delta)
    }

    /// Persist revocation state, cached grants and secure-channel status.
    pub fn cache_json(&self) -> Result<String, AccessError> {
        self.cache.to_json()
    }

    /// Restore previously persisted state (revocation survives a restart).
    pub fn restore_cache(&mut self, json: &str) -> Result<(), AccessError> {
        let cache = OfflineCache::from_json(json)?;
        if cache.reader_id != self.reader.reader_id {
            return Err(AccessError::CacheCorrupt("cache belongs to another reader"));
        }
        self.cache = cache;
        Ok(())
    }

    /// Resolve a presented card at a gate.
    pub fn authorize(
        &mut self,
        presented: &PresentedCredential,
        gate_id: &GateId,
        at_utc_us: i64,
    ) -> Result<AccessGrant, AccessError> {
        self.reader.ensure_operational()?;
        self.reader.observe(at_utc_us);
        let fingerprint = presented.fingerprint();

        let credential = match self.credentials.validate(presented, at_utc_us) {
            Ok(credential) => credential.clone(),
            Err(error) => return self.deny(at_utc_us, None, fingerprint, error),
        };

        if self.cache.revocation.is_revoked(&credential.id) {
            return self.deny(
                at_utc_us,
                Some(credential.id.clone()),
                fingerprint,
                AccessError::CredentialRevoked(credential.id.clone()),
            );
        }

        if !self.reader.is_online() {
            let Some(grant) = self.cache.grant(&fingerprint, gate_id, at_utc_us).cloned() else {
                return self.deny(
                    at_utc_us,
                    Some(credential.id.clone()),
                    fingerprint,
                    AccessError::NoCachedGrant,
                );
            };
            let grant = AccessGrant {
                credential_id: grant.credential_id,
                holder_id: grant.holder_id,
                gate_id: grant.gate_id,
                zone_id: grant.zone_id,
                policy_id: grant.policy_id,
                ticket_id: grant.ticket_id,
                offline: true,
            };
            self.events.push(HealthEventRecord::new(
                at_utc_us,
                HealthEvent::CredentialGranted {
                    credential_id: grant.credential_id.clone(),
                },
            ));
            return Ok(grant);
        }

        match self.resolve_online(&credential, gate_id, at_utc_us) {
            Ok(grant) => {
                self.cache.remember_grant(
                    &fingerprint,
                    CachedGrant {
                        credential_id: grant.credential_id.clone(),
                        holder_id: grant.holder_id.clone(),
                        gate_id: grant.gate_id.clone(),
                        zone_id: grant.zone_id.clone(),
                        policy_id: grant.policy_id.clone(),
                        ticket_id: grant.ticket_id.clone(),
                        expires_at_utc_us: at_utc_us.saturating_add(self.offline_grant_ttl_us),
                    },
                );
                self.events.push(HealthEventRecord::new(
                    at_utc_us,
                    HealthEvent::CredentialGranted {
                        credential_id: grant.credential_id.clone(),
                    },
                ));
                Ok(grant)
            }
            Err(error) => self.deny(
                at_utc_us,
                Some(credential.id.clone()),
                fingerprint,
                error,
            ),
        }
    }

    fn deny(
        &mut self,
        at_utc_us: i64,
        credential_id: Option<CredentialId>,
        fingerprint: String,
        error: AccessError,
    ) -> Result<AccessGrant, AccessError> {
        let _ = credential_id;
        self.events.push(HealthEventRecord::new(
            at_utc_us,
            HealthEvent::CredentialDenied { fingerprint },
        ));
        Err(error)
    }

    fn resolve_online(
        &mut self,
        credential: &Credential,
        gate_id: &GateId,
        at_utc_us: i64,
    ) -> Result<AccessGrant, AccessError> {
        let ticket_id = TicketId::new(format!("tkt-{}", credential.id.as_str()))?;
        let ticket = Ticket::new(ticket_id.clone(), credential.ticket_type_id.clone());
        let decision = self.policies.resolve_in_space(
            &self.topology,
            &self.space,
            &ticket,
            gate_id,
            at_utc_us,
        )?;
        self.passback.record(&ScanRecord {
            ticket_id: ticket_id.clone(),
            gate_id: decision.gate_id.clone(),
            zone_id: decision.zone_id.clone(),
            direction: ScanDirection::In,
            ts_utc_us: at_utc_us,
        })?;
        Ok(AccessGrant {
            credential_id: credential.id.clone(),
            holder_id: credential.holder_id.clone(),
            gate_id: decision.gate_id,
            zone_id: decision.zone_id,
            policy_id: decision.policy_id,
            ticket_id,
            offline: false,
        })
    }
}
