// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-site fleet and tenant isolation integration tests (CC-19).
//!
//! Proves the three close-out criteria — a tenant cannot see another tenant's
//! sites or exports, a fleet rollout pauses on health failure, and a cross-site
//! query requires an explicit capability — plus config drift, per-site
//! health/compliance and fleet-scale pagination.

use std::collections::{BTreeMap, BTreeSet};

use tirbase_gateway::fleet::{
    tenant_path, ComplianceStatus, CrossSiteQuery, FirmwareChannel, FleetAccess, FleetError,
    FleetNodeDraft, FleetNodeKind, FleetQuery, FleetRegistry, HealthStatus, RolloutKind,
    RolloutRequest, RolloutState, CONTEXT_FLEET_EXPORT, MAX_PAGE_SIZE,
};
use tirbase_types::identity::{CapabilityScope, OperatorPermission};

const EXPIRY: i64 = 10_000;

fn access(org: &str, permissions: &[OperatorPermission]) -> FleetAccess {
    FleetAccess::new(
        format!("did:key:z6Mk{org}Operator"),
        CapabilityScope::new(tenant_path(org, None), permissions.to_vec(), None, EXPIRY),
    )
}

fn full_access(org: &str) -> FleetAccess {
    access(
        org,
        &[
            OperatorPermission::Read,
            OperatorPermission::Write,
            OperatorPermission::AuditRead,
            OperatorPermission::Administer,
        ],
    )
}

fn site(registry: &FleetRegistry, access: &FleetAccess, org: &str, site_id: &str, at_est: i64) {
    registry
        .register_node(
            access,
            FleetNodeDraft::new(
                site_id,
                tenant_path(org, Some(site_id)),
                FleetNodeKind::Site,
                site_id,
                format!("Site {site_id}"),
            ),
            at_est,
        )
        .expect("site node");
    registry
        .set_node_status(
            access,
            site_id,
            HealthStatus::Healthy,
            ComplianceStatus::Compliant,
            at_est,
        )
        .expect("site status");
}

fn gateway(
    registry: &FleetRegistry,
    access: &FleetAccess,
    org: &str,
    site_id: &str,
    node_id: &str,
    at_est: i64,
) {
    registry
        .register_node(
            access,
            FleetNodeDraft::new(
                node_id,
                tenant_path(org, Some(site_id)),
                FleetNodeKind::Gateway,
                site_id,
                format!("Gateway {node_id}"),
            ),
            at_est,
        )
        .expect("gateway node");
}

fn key_fingerprint(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

#[test]
fn a_tenant_cannot_see_another_tenants_sites_exports_keys_or_configs() {
    let registry = FleetRegistry::open_in_memory().expect("fleet");
    let acme = full_access("acme");
    let globex = full_access("globex");

    site(&registry, &acme, "acme", "s1", 1_000);
    gateway(&registry, &acme, "acme", "s1", "gw-a1", 1_000);
    site(&registry, &acme, "acme", "s2", 1_000);
    registry
        .register_node(
            &acme,
            FleetNodeDraft::new(
                "room-r2",
                tenant_path("acme", Some("s2")),
                FleetNodeKind::Room,
                "s2",
                "Cold room",
            )
            .with_parent("s2"),
            1_000,
        )
        .expect("room");
    site(&registry, &globex, "globex", "g1", 1_000);
    gateway(&registry, &globex, "globex", "g1", "gw-g1", 1_000);

    // Fleet view: only the caller's sites, and the counts agree.
    let view = registry.fleet_view(&acme, 1_100).expect("view");
    let site_ids: Vec<&str> = view
        .sites
        .iter()
        .map(|site| site.site_id.as_str())
        .collect();
    assert_eq!(site_ids, vec!["s1", "s2"]);
    assert_eq!(view.summary.sites, 2);
    assert_eq!(view.summary.gateways, 1);
    assert_eq!(view.summary.rooms, 1);
    assert_eq!(view.summary.total, 4);
    assert!(!site_ids.contains(&"g1"));

    // Listing can never reach the other tenant's rows.
    let page = registry
        .list_nodes(&acme, &FleetQuery::default(), 1_100)
        .expect("list");
    assert_eq!(page.total_matched, 4);
    assert!(page.items.iter().all(|node| node.node_id != "gw-g1"));

    // A direct read is denied, not silently empty.
    match registry.get_node(&acme, "gw-g1", 1_100) {
        Err(FleetError::CrossTenantDenied { principal, .. }) => {
            assert!(principal.contains("acme"), "{principal}");
        }
        other => panic!("expected cross-tenant denial, got {other:?}"),
    }

    // A write into another tenant is denied.
    assert!(matches!(
        registry.register_node(
            &acme,
            FleetNodeDraft::new(
                "gw-injected",
                tenant_path("globex", Some("g1")),
                FleetNodeKind::Gateway,
                "g1",
                "Injected",
            ),
            1_100,
        ),
        Err(FleetError::CrossTenantDenied { .. })
    ));

    // Exports: each tenant exports its own fleet only.
    let acme_export = registry.export_tenant(&acme, 1_200).expect("acme export");
    let globex_export = registry
        .export_tenant(&globex, 1_200)
        .expect("globex export");
    assert!(acme_export.node_ids.iter().all(|id| id != "gw-g1"));
    assert!(acme_export.site_ids.iter().all(|id| id != "g1"));
    assert_eq!(acme_export.node_count, 4);
    assert_eq!(globex_export.node_count, 2);
    assert_ne!(acme_export.digest, globex_export.digest);

    let acme_exports = registry.list_exports(&acme, 1_200).expect("exports");
    assert_eq!(acme_exports.len(), 1);
    assert_eq!(acme_exports[0].export_id, acme_export.export_id);
    assert!(matches!(
        registry.read_export(&acme, &globex_export.export_id, 1_200),
        Err(FleetError::CrossTenantDenied { .. })
    ));

    // Keys are isolated and key material is never accepted, only a fingerprint.
    registry
        .register_tenant_key(
            &acme,
            "key-acme",
            &tenant_path("acme", Some("s1")),
            "export-signing",
            &key_fingerprint("acme"),
            1_300,
        )
        .expect("acme key");
    registry
        .register_tenant_key(
            &globex,
            "key-globex",
            &tenant_path("globex", Some("g1")),
            "export-signing",
            &key_fingerprint("globex"),
            1_300,
        )
        .expect("globex key");
    let keys = registry.tenant_keys(&acme, 1_300).expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, "key-acme");
    assert!(matches!(
        registry.register_tenant_key(
            &acme,
            "key-short",
            &tenant_path("acme", None),
            "export-signing",
            "deadbeef",
            1_300,
        ),
        Err(FleetError::Invalid { ref field, .. }) if field == "fingerprint"
    ));

    // Configs are isolated too.
    let mut values = BTreeMap::new();
    values.insert("sample_interval_s".to_string(), "60".to_string());
    registry
        .set_config(
            &globex,
            "cfg-globex",
            &tenant_path("globex", Some("g1")),
            Some("g1".to_string()),
            values.clone(),
            1_400,
        )
        .expect("globex config");
    assert!(registry
        .tenant_configs(&acme, 1_400)
        .expect("configs")
        .is_empty());
    assert!(matches!(
        registry.config_drift(&acme, "cfg-globex", 1_400),
        Err(FleetError::CrossTenantDenied { .. })
    ));

    // A site-scoped capability sees only that site, even inside its own tenant.
    let site_scoped = FleetAccess::new(
        "did:key:z6MkAcmeSiteOperator",
        CapabilityScope::new(
            tenant_path("acme", Some("s1")),
            vec![OperatorPermission::Read],
            None,
            EXPIRY,
        ),
    );
    let site_nodes = registry
        .list_nodes(&site_scoped, &FleetQuery::default(), 1_450)
        .expect("site scope");
    assert_eq!(site_nodes.total_matched, 2, "site s1 and its gateway");
    assert!(site_nodes.items.iter().all(|node| node.site_id == "s1"));
    assert!(matches!(
        registry.get_node(&site_scoped, "room-r2", 1_450),
        Err(FleetError::CrossTenantDenied { .. })
    ));

    // A capability past its expiry does nothing at all.
    let expired = FleetAccess::new(
        "did:key:z6MkExpired",
        CapabilityScope::new(
            tenant_path("acme", None),
            vec![OperatorPermission::Read],
            None,
            50,
        ),
    );
    assert!(matches!(
        registry.fleet_view(&expired, 100),
        Err(FleetError::CapabilityExpired { .. })
    ));

    // A read-only capability cannot write.
    let reader = access("acme", &[OperatorPermission::Read]);
    assert!(matches!(
        registry.register_node(
            &reader,
            FleetNodeDraft::new(
                "gw-reader",
                tenant_path("acme", Some("s1")),
                FleetNodeKind::Gateway,
                "s1",
                "Reader",
            ),
            1_500,
        ),
        Err(FleetError::PermissionDenied { .. })
    ));
}

// ---------------------------------------------------------------------------
// Cross-site query
// ---------------------------------------------------------------------------

#[test]
fn cross_site_query_requires_an_explicit_capability() {
    let registry = FleetRegistry::open_in_memory().expect("fleet");
    let acme = full_access("acme");
    site(&registry, &acme, "acme", "s1", 1_000);
    gateway(&registry, &acme, "acme", "s1", "gw-1", 1_000);
    site(&registry, &acme, "acme", "s2", 1_000);
    gateway(&registry, &acme, "acme", "s2", "gw-2", 1_000);

    // Same capability, same tenant, but no explicit grant: refused.
    assert_eq!(
        registry
            .cross_site_query(&acme, &CrossSiteQuery::default(), 1_100)
            .expect_err("no grant"),
        FleetError::CrossSiteCapabilityRequired
    );

    // A grant for s1 only does not authorize s2.
    registry
        .register_cross_site_grant(
            &acme,
            "grant-s1",
            vec!["s1".to_string()],
            5_000,
            "regional review",
            1_100,
        )
        .expect("grant s1");
    let partial = CrossSiteQuery {
        grant_id: Some("grant-s1".to_string()),
        sites: vec!["s1".to_string(), "s2".to_string()],
        ..CrossSiteQuery::default()
    };
    assert_eq!(
        registry
            .cross_site_query(&acme, &partial, 1_200)
            .expect_err("s2 not granted"),
        FleetError::CrossSiteScopeDenied {
            site_id: "s2".to_string()
        }
    );

    // With empty `sites` the grant's own sites bound the query.
    let granted = registry
        .cross_site_query(
            &acme,
            &CrossSiteQuery {
                grant_id: Some("grant-s1".to_string()),
                ..CrossSiteQuery::default()
            },
            1_200,
        )
        .expect("granted query");
    assert_eq!(granted.total_matched, 2);
    assert!(granted.items.iter().all(|node| node.site_id == "s1"));

    // A grant covering both sites authorizes the cross-site read.
    registry
        .register_cross_site_grant(
            &acme,
            "grant-both",
            vec!["s1".to_string(), "s2".to_string()],
            5_000,
            "quarterly audit",
            1_200,
        )
        .expect("grant both");
    let both = registry
        .cross_site_query(
            &acme,
            &CrossSiteQuery {
                grant_id: Some("grant-both".to_string()),
                kinds: vec![FleetNodeKind::Gateway],
                ..CrossSiteQuery::default()
            },
            1_300,
        )
        .expect("both sites");
    let sites: BTreeSet<&str> = both
        .items
        .iter()
        .map(|node| node.site_id.as_str())
        .collect();
    assert_eq!(sites, BTreeSet::from(["s1", "s2"]));
    assert_eq!(both.total_matched, 2);

    // Grants expire.
    registry
        .register_cross_site_grant(
            &acme,
            "grant-short",
            vec!["s1".to_string()],
            1_500,
            "short review",
            1_400,
        )
        .expect("short grant");
    assert!(matches!(
        registry.cross_site_query(
            &acme,
            &CrossSiteQuery {
                grant_id: Some("grant-short".to_string()),
                ..CrossSiteQuery::default()
            },
            1_600,
        ),
        Err(FleetError::CrossSiteGrantExpired { .. })
    ));

    // Another tenant's grant cannot be borrowed, even by a wider capability.
    let globex = full_access("globex");
    site(&registry, &globex, "globex", "g1", 1_400);
    registry
        .register_cross_site_grant(
            &globex,
            "grant-globex",
            vec!["g1".to_string()],
            5_000,
            "globex review",
            1_400,
        )
        .expect("globex grant");
    assert!(matches!(
        registry.cross_site_query(
            &acme,
            &CrossSiteQuery {
                grant_id: Some("grant-globex".to_string()),
                ..CrossSiteQuery::default()
            },
            1_500,
        ),
        Err(FleetError::CrossTenantDenied { .. })
    ));

    // Only an administrator may issue a grant.
    let reader = access(
        "acme",
        &[OperatorPermission::Read, OperatorPermission::Write],
    );
    assert!(matches!(
        registry.register_cross_site_grant(
            &reader,
            "grant-self",
            vec!["s1".to_string()],
            5_000,
            "self service",
            1_500,
        ),
        Err(FleetError::PermissionDenied {
            permission: "administer"
        })
    ));
}

// ---------------------------------------------------------------------------
// Bulk rollout
// ---------------------------------------------------------------------------

#[test]
fn a_fleet_rollout_pauses_on_health_failure() {
    let registry = FleetRegistry::open_in_memory().expect("fleet");
    let acme = full_access("acme");
    site(&registry, &acme, "acme", "s1", 1_000);
    for index in 1..=5 {
        let node_id = format!("gw-{index}");
        gateway(&registry, &acme, "acme", "s1", &node_id, 1_000);
        registry
            .set_node_status(
                &acme,
                &node_id,
                if index == 3 {
                    HealthStatus::Unhealthy
                } else {
                    HealthStatus::Healthy
                },
                ComplianceStatus::Compliant,
                1_000,
            )
            .expect("health");
    }

    let plan = registry
        .plan_rollout(
            &acme,
            RolloutRequest::new("roll-1", RolloutKind::Profile, "profile-cold-2")
                .with_batch_size(10),
            1_100,
        )
        .expect("plan");
    assert_eq!(plan.state, RolloutState::Pending);
    assert_eq!(plan.targets.len(), 5, "site node is not a rollout target");

    // The rollout stops at the unhealthy gateway instead of skipping it.
    let paused = registry.run_rollout(&acme, "roll-1", 1_200).expect("run");
    assert_eq!(paused.state, RolloutState::Paused);
    assert_eq!(paused.applied(), vec!["gw-1", "gw-2"]);
    assert_eq!(paused.pending(), vec!["gw-3", "gw-4", "gw-5"]);
    let pause = paused.pause.expect("pause evidence");
    assert_eq!(pause.node_id, "gw-3");
    assert_eq!(pause.health, HealthStatus::Unhealthy);
    assert!(pause.detail.contains("gw-3"), "{}", pause.detail);
    for node_id in ["gw-1", "gw-2"] {
        assert_eq!(
            registry
                .get_node(&acme, node_id, 1_200)
                .expect("node")
                .profile_id,
            "profile-cold-2"
        );
    }
    assert_eq!(
        registry
            .get_node(&acme, "gw-3", 1_200)
            .expect("node")
            .profile_id,
        "",
        "a paused target must not be half-applied"
    );

    // Running a paused rollout is refused; resume is the explicit action.
    assert!(matches!(
        registry.run_rollout(&acme, "roll-1", 1_250),
        Err(FleetError::RolloutPaused { .. })
    ));

    // Resuming while the gateway is still unhealthy pauses again immediately.
    let still = registry
        .resume_rollout(&acme, "roll-1", 1_300)
        .expect("resume");
    assert_eq!(still.state, RolloutState::Paused);
    assert_eq!(still.applied().len(), 2);

    // Fixing the fleet lets the rollout finish.
    registry
        .set_node_status(
            &acme,
            "gw-3",
            HealthStatus::Healthy,
            ComplianceStatus::Compliant,
            1_400,
        )
        .expect("fix");
    let done = registry
        .resume_rollout(&acme, "roll-1", 1_400)
        .expect("resume");
    assert_eq!(done.state, RolloutState::Completed);
    assert_eq!(done.applied().len(), 5);
    assert!(done.pause.is_none());
    assert!(registry
        .list_rollouts(&acme, 1_400)
        .expect("rollouts")
        .iter()
        .all(|plan| plan.operation_id != "roll-other"));

    // Firmware rollouts pick up the channel and version.
    let _firmware = registry
        .plan_rollout(
            &acme,
            RolloutRequest::new("roll-fw", RolloutKind::Firmware, "2.4.0")
                .with_channel(FirmwareChannel::Canary)
                .with_targets(vec!["gw-1".to_string(), "gw-2".to_string()])
                .with_batch_size(1),
            1_500,
        )
        .expect("plan firmware");
    assert_eq!(
        registry
            .run_rollout(&acme, "roll-fw", 1_500)
            .expect("batch")
            .state,
        RolloutState::Running
    );
    let completed = registry
        .run_rollout(&acme, "roll-fw", 1_510)
        .expect("batch");
    assert_eq!(completed.state, RolloutState::Completed);
    let node = registry.get_node(&acme, "gw-2", 1_510).expect("node");
    assert_eq!(node.firmware_version, "2.4.0");
    assert_eq!(node.channel, FirmwareChannel::Canary);

    // The hold channel refuses a rollout before anything is planned.
    assert_eq!(
        registry
            .plan_rollout(
                &acme,
                RolloutRequest::new("roll-held", RolloutKind::Firmware, "2.5.0")
                    .with_channel(FirmwareChannel::Hold),
                1_600,
            )
            .expect_err("held"),
        FleetError::ChannelHeld
    );

    // Abort stops the rollout; applied targets stay applied.
    let aborted_plan = registry
        .plan_rollout(
            &acme,
            RolloutRequest::new("roll-abort", RolloutKind::Profile, "profile-v3")
                .with_batch_size(1),
            1_700,
        )
        .expect("plan");
    assert_eq!(aborted_plan.targets.len(), 5);
    let partial = registry
        .run_rollout(&acme, "roll-abort", 1_700)
        .expect("batch");
    assert_eq!(partial.applied().len(), 1);
    let aborted = registry
        .abort_rollout(&acme, "roll-abort", 1_710)
        .expect("abort");
    assert_eq!(aborted.state, RolloutState::Aborted);
    assert_eq!(aborted.applied().len(), 1);
    assert_eq!(aborted.pending().len(), 4);
    assert!(matches!(
        registry.run_rollout(&acme, "roll-abort", 1_720),
        Err(FleetError::RolloutFinished { .. })
    ));

    // A rollout is tenant-scoped and invisible to another tenant.
    let globex = full_access("globex");
    assert!(matches!(
        registry.rollout_status(&globex, "roll-1", 1_800),
        Err(FleetError::CrossTenantDenied { .. })
    ));
}

// ---------------------------------------------------------------------------
// Config drift
// ---------------------------------------------------------------------------

#[test]
fn config_drift_is_reported_per_node() {
    let registry = FleetRegistry::open_in_memory().expect("fleet");
    let acme = full_access("acme");
    site(&registry, &acme, "acme", "s1", 1_000);
    gateway(&registry, &acme, "acme", "s1", "gw-1", 1_000);
    gateway(&registry, &acme, "acme", "s1", "gw-2", 1_000);

    let mut matching = BTreeMap::new();
    matching.insert("sample_interval_s".to_string(), "60".to_string());
    matching.insert("mkt_limit_c".to_string(), "80".to_string());
    registry
        .set_node_config(&acme, "gw-1", matching.clone(), 1_100)
        .expect("config 1");

    let mut drifted = BTreeMap::new();
    drifted.insert("sample_interval_s".to_string(), "30".to_string());
    drifted.insert("debug".to_string(), "true".to_string());
    registry
        .set_node_config(&acme, "gw-2", drifted, 1_100)
        .expect("config 2");

    let mut desired = BTreeMap::new();
    desired.insert("sample_interval_s".to_string(), "60".to_string());
    desired.insert("mkt_limit_c".to_string(), "80".to_string());
    registry
        .set_config(
            &acme,
            "cfg-s1",
            &tenant_path("acme", Some("s1")),
            Some("s1".to_string()),
            desired,
            1_200,
        )
        .expect("config");

    let rows = registry
        .config_drift(&acme, "cfg-s1", 1_300)
        .expect("drift");
    assert_eq!(rows.len(), 2);
    let first = rows.iter().find(|row| row.node_id == "gw-1").expect("gw-1");
    assert!(!first.drifted);
    assert!(first.missing.is_empty() && first.differing.is_empty());

    let second = rows.iter().find(|row| row.node_id == "gw-2").expect("gw-2");
    assert!(second.drifted);
    assert_eq!(second.site_id, "s1");
    assert_eq!(second.missing, vec!["mkt_limit_c".to_string()]);
    assert_eq!(second.differing, vec!["sample_interval_s".to_string()]);
    assert_eq!(second.unexpected, vec!["debug".to_string()]);
}

// ---------------------------------------------------------------------------
// Health and compliance roll-up
// ---------------------------------------------------------------------------

#[test]
fn per_site_health_and_compliance_roll_up() {
    let registry = FleetRegistry::open_in_memory().expect("fleet");
    let acme = full_access("acme");
    site(&registry, &acme, "acme", "s1", 1_000);
    site(&registry, &acme, "acme", "s2", 1_000);
    gateway(&registry, &acme, "acme", "s1", "gw-1", 1_000);
    gateway(&registry, &acme, "acme", "s1", "gw-2", 1_000);
    gateway(&registry, &acme, "acme", "s2", "gw-3", 1_000);

    registry
        .set_node_status(
            &acme,
            "gw-1",
            HealthStatus::Healthy,
            ComplianceStatus::Compliant,
            1_100,
        )
        .expect("gw-1");
    registry
        .set_node_status(
            &acme,
            "gw-2",
            HealthStatus::Degraded,
            ComplianceStatus::Unknown,
            1_100,
        )
        .expect("gw-2");
    registry
        .set_node_status(
            &acme,
            "gw-3",
            HealthStatus::Unhealthy,
            ComplianceStatus::NonCompliant,
            1_100,
        )
        .expect("gw-3");

    let s1 = registry.site_status(&acme, "s1", 1_200).expect("s1");
    assert_eq!(s1.health, HealthStatus::Degraded);
    assert_eq!(s1.compliance, ComplianceStatus::Unknown);
    assert_eq!(s1.nodes, 3);
    assert_eq!(s1.healthy, 2, "site node plus gw-1");
    assert_eq!(s1.degraded, 1);
    assert_eq!(s1.non_compliant, 0);

    let s2 = registry.site_status(&acme, "s2", 1_200).expect("s2");
    assert_eq!(s2.health, HealthStatus::Unhealthy);
    assert_eq!(s2.compliance, ComplianceStatus::NonCompliant);
    assert_eq!(s2.unhealthy, 1);
    assert_eq!(s2.non_compliant, 1);

    let view = registry.fleet_view(&acme, 1_200).expect("view");
    assert_eq!(view.summary.sites, 2);
    assert_eq!(view.summary.gateways, 3);
    assert_eq!(view.summary.healthy, 3, "two site nodes plus gw-1");
    assert_eq!(view.summary.degraded, 1);
    assert_eq!(view.summary.unhealthy, 1);
    assert_eq!(view.summary.non_compliant, 1);
    assert_eq!(view.summary.total, 5);
    assert_eq!(
        view.sites
            .iter()
            .map(|site| site.site_id.as_str())
            .collect::<Vec<_>>(),
        vec!["s1", "s2"]
    );

    // An unknown site is a not-found, not an empty status.
    assert!(matches!(
        registry.site_status(&acme, "s9", 1_200),
        Err(FleetError::NotFound { .. })
    ));
}

// ---------------------------------------------------------------------------
// Fleet-scale pagination
// ---------------------------------------------------------------------------

#[test]
fn fleet_scale_pagination_is_stable_and_complete() {
    let registry = FleetRegistry::open_in_memory().expect("fleet");
    let acme = full_access("acme");
    site(&registry, &acme, "acme", "s1", 1_000);
    const GATEWAYS: usize = 1_200;
    for index in 0..GATEWAYS {
        gateway(
            &registry,
            &acme,
            "acme",
            "s1",
            &format!("gw-{index:04}"),
            1_000,
        );
    }

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = registry
            .list_nodes(
                &acme,
                &FleetQuery {
                    kinds: vec![FleetNodeKind::Gateway],
                    site_id: Some("s1".to_string()),
                    cursor: cursor.clone(),
                    limit: Some(MAX_PAGE_SIZE),
                    ..FleetQuery::default()
                },
                1_100,
            )
            .expect("page");
        pages += 1;
        assert_eq!(page.total_matched, GATEWAYS);
        assert!(page.items.len() <= MAX_PAGE_SIZE);
        for node in &page.items {
            assert_eq!(node.kind, FleetNodeKind::Gateway);
            assert_eq!(node.site_id, "s1");
        }
        seen.extend(page.items.iter().map(|node| node.node_id.clone()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(pages < 100, "pagination failed to terminate");
    }

    assert_eq!(pages, GATEWAYS / MAX_PAGE_SIZE);
    assert_eq!(seen.len(), GATEWAYS);
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), GATEWAYS, "no page repeated or dropped a node");
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(sorted, seen, "pages arrive in stable id order");

    // An oversized page is clamped rather than accepted.
    let clamped = registry
        .list_nodes(
            &acme,
            &FleetQuery {
                kinds: vec![FleetNodeKind::Gateway],
                limit: Some(10_000),
                ..FleetQuery::default()
            },
            1_100,
        )
        .expect("clamped");
    assert_eq!(clamped.items.len(), MAX_PAGE_SIZE);
    assert!(clamped.next_cursor.is_some());

    // The final cursor yields an empty page with the true total.
    let tail = registry
        .list_nodes(
            &acme,
            &FleetQuery {
                kinds: vec![FleetNodeKind::Gateway],
                cursor: seen.last().cloned(),
                ..FleetQuery::default()
            },
            1_100,
        )
        .expect("tail");
    assert!(tail.items.is_empty());
    assert!(tail.next_cursor.is_none());
    assert_eq!(tail.total_matched, GATEWAYS);

    // A bounded rollout over the whole fleet is still batched.
    let plan = registry
        .plan_rollout(
            &acme,
            RolloutRequest::new("roll-fleet", RolloutKind::Profile, "profile-v1")
                .with_batch_size(1_000),
            2_000,
        )
        .expect("plan");
    assert_eq!(plan.targets.len(), GATEWAYS);
    assert_eq!(plan.batch_size, 100, "batch size is clamped to the bound");
    let _ = CONTEXT_FLEET_EXPORT;
}
