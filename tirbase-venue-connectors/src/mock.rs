// SPDX-License-Identifier: Apache-2.0

//! Mock venue vendor APIs.
//!
//! [`MockVenueApi`] is a deterministic, in-memory vendor fixture for all five
//! domains. It implements the generic connector plus every family trait, records
//! what it received, deduplicates on the event id like a well-behaved vendor,
//! and can inject transient failures. Point a connector's transport at it (or
//! use it directly) to test the framework and to run the conformance suite
//! without vendor credentials.
//!
//! For HTTP-level contract tests, a connector's own suite can point at
//! `tirbase_integrations::MockVendorServer`; this mock exercises the venue
//! semantics the framework is responsible for.

use std::collections::BTreeMap;
use std::sync::Mutex;

use tirbase_integrations::{ConnectorHealth, ConnectorKind, DeliveryResult};

use crate::domain::{
    AccessConnector, BmsConnector, CctvConnector, PaConnector, TicketingConnector,
    VenueCapabilities, VenueConnector, VenueDomain,
};
use crate::event::VenueEvent;

/// Mock vendor behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockVenueConfig {
    /// Reject the first `fail_first` deliveries as retryable.
    pub fail_first: usize,
    /// Recognise a repeated event id as a duplicate. A broken fixture can turn
    /// this off to prove the conformance suite catches double delivery.
    pub dedupe: bool,
}

impl Default for MockVenueConfig {
    fn default() -> Self {
        Self {
            fail_first: 0,
            dedupe: true,
        }
    }
}

impl MockVenueConfig {
    /// Inject `count` transient failures.
    pub fn with_fail_first(mut self, count: usize) -> Self {
        self.fail_first = count;
        self
    }

    /// Turn vendor deduplication on or off.
    pub fn with_dedupe(mut self, dedupe: bool) -> Self {
        self.dedupe = dedupe;
        self
    }
}

struct MockState {
    records: BTreeMap<String, usize>,
    events: Vec<VenueEvent>,
    calls: usize,
    failures: usize,
}

/// In-memory venue vendor fixture.
pub struct MockVenueApi {
    name: String,
    venue: String,
    domains: Vec<VenueDomain>,
    config: MockVenueConfig,
    state: Mutex<MockState>,
}

impl MockVenueApi {
    /// Build a fixture with a name and the domains it implements.
    pub fn new(
        name: impl Into<String>,
        venue: impl Into<String>,
        domains: Vec<VenueDomain>,
    ) -> Self {
        Self::with_config(name, venue, domains, MockVenueConfig::default())
    }

    /// Build a fixture with explicit behaviour.
    pub fn with_config(
        name: impl Into<String>,
        venue: impl Into<String>,
        domains: Vec<VenueDomain>,
        config: MockVenueConfig,
    ) -> Self {
        let failures = config.fail_first;
        Self {
            name: name.into(),
            venue: venue.into(),
            domains,
            config,
            state: Mutex::new(MockState {
                records: BTreeMap::new(),
                events: Vec::new(),
                calls: 0,
                failures,
            }),
        }
    }

    /// Replace the transient failure budget.
    pub fn set_failures(&self, count: usize) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failures = count;
    }

    /// Stop injecting failures.
    pub fn clear_failures(&self) {
        self.set_failures(0);
    }

    /// Delivered events, oldest first (a broken fixture records duplicates).
    pub fn delivered_events(&self) -> Vec<VenueEvent> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .events
            .clone()
    }

    /// Distinct accepted event ids.
    pub fn record_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .records
            .len()
    }

    /// Delivery attempts observed.
    pub fn calls(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .calls
    }

    fn record(&self, event: &VenueEvent) -> DeliveryResult {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.calls += 1;
        if state.failures > 0 {
            state.failures -= 1;
            return DeliveryResult::retryable("mock vendor transient failure", Some(1));
        }
        let key = event.event_id();
        let count = {
            let entry = state.records.entry(key).or_insert(0);
            *entry += 1;
            *entry
        };
        if count > 1 {
            if self.config.dedupe {
                return DeliveryResult::duplicate("mock vendor recognised the event id");
            }
            state.events.push(event.clone());
            return DeliveryResult::delivered("mock vendor accepted a second record");
        }
        state.events.push(event.clone());
        DeliveryResult::delivered("mock vendor accepted the event")
    }
}

impl VenueConnector for MockVenueApi {
    fn name(&self) -> &str {
        &self.name
    }

    fn venue(&self) -> &str {
        &self.venue
    }

    fn domains(&self) -> &[VenueDomain] {
        &self.domains
    }

    fn capabilities(&self) -> VenueCapabilities {
        VenueCapabilities {
            idempotent: self.config.dedupe,
            signed_webhooks: true,
            max_payload_bytes: 1024 * 1024,
            transport: ConnectorKind::Http,
        }
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy(format!("mock venue vendor {}", self.name))
    }

    fn deliver(&self, event: &VenueEvent) -> DeliveryResult {
        if !self
            .domains
            .iter()
            .any(|domain| domain.accepts(event.kind()))
        {
            return DeliveryResult::permanent(format!(
                "mock {} does not handle {} events",
                self.name,
                event.kind().as_str()
            ));
        }
        self.record(event)
    }
}

impl TicketingConnector for MockVenueApi {}
impl AccessConnector for MockVenueApi {}
impl BmsConnector for MockVenueApi {}
impl CctvConnector for MockVenueApi {}
impl PaConnector for MockVenueApi {}
