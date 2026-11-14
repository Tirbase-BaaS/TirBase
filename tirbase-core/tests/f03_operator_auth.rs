// SPDX-License-Identifier: AGPL-3.0-only

//! F-03: Identity, RBAC, tenancy, and operator model tests.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tirbase_core::events::{install_security_event_sink, SecurityEvent, SecurityEventCategory};
use tirbase_core::operator_auth::capability::{
    delegate_capability_token, issue_capability_token, CapabilityVerification,
};
use tirbase_core::operator_auth::service::{
    role_allows, AcceptingMfaHook, AuthorizationRequest, LockoutPolicy, MfaHook, MfaHookResult,
    OidcClaims, OidcVerifier, OperatorAuthService, SessionPolicy,
};
use tirbase_core::operator_auth::store::{
    derive_salt, OidcIdentity, OperatorIdentityStore, OperatorPrincipalRecord,
};
use tirbase_core::traits::SecurityEventSink;
use tirbase_types::identity::{
    AuthMethod, CapabilityScope, DelegationConstraints, OperatorCapability, OperatorPermission,
    OperatorRole, PrincipalId, PrincipalKind, TenantLevel, TenantPath, TenantSegment, Vertical,
};

static SINK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Default)]
struct RecordingSink {
    events: Mutex<Vec<SecurityEvent>>,
}

impl SecurityEventSink for RecordingSink {
    fn emit(&self, event: SecurityEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn with_sink<T>(f: impl FnOnce(Arc<RecordingSink>) -> T) -> T {
    let _guard = SINK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sink = Arc::new(RecordingSink::default());
    let previous = install_security_event_sink(sink.clone());
    let out = f(sink);
    if let Some(prev) = previous {
        let _ = install_security_event_sink(prev);
    }
    out
}

fn org_site(org: &str, site: &str) -> TenantPath {
    TenantPath::new(vec![
        TenantSegment::new(TenantLevel::Organisation, org),
        TenantSegment::new(TenantLevel::Site, site),
    ])
}

fn authority_keys() -> (Vec<u8>, Vec<u8>) {
    let kp = biscuit_auth::KeyPair::new();
    (
        kp.private().to_bytes().to_vec(),
        kp.public().to_bytes().to_vec(),
    )
}

fn base_principal(id: &str, tenant: TenantPath) -> PrincipalId {
    PrincipalId::new(id, PrincipalKind::User, tenant)
}

fn cap(
    subject: PrincipalId,
    role: OperatorRole,
    tenant: TenantPath,
    perms: Vec<OperatorPermission>,
    vertical: Option<Vertical>,
    expires_at: i64,
    delegatable: bool,
    max_depth: u8,
    cap_id: &str,
) -> OperatorCapability {
    OperatorCapability {
        subject,
        role,
        scope: CapabilityScope::new(tenant, perms, vertical, expires_at),
        delegation: DelegationConstraints {
            delegatable,
            max_depth,
        },
        issuer: "authority".to_string(),
        capability_id: cap_id.to_string(),
        issued_at: 1_000,
    }
}

struct TempDirGuard(std::path::PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_store(name: &str) -> (TempDirGuard, std::path::PathBuf) {
    let mut dir = std::env::temp_dir();
    let uniq = format!(
        "tirbase-f03-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    dir.push(uniq);
    std::fs::create_dir_all(&dir).expect("tempdir");
    let path = dir.join(format!("{name}.json"));
    (TempDirGuard(dir), path)
}

#[test]
fn f03_cross_tenant_reads_writes_denied() {
    with_sink(|_sink| {
        let (privk, pubk) = authority_keys();
        let (_dir, path) = temp_store("tenant");
        let store = OperatorIdentityStore::load_or_create(&path).expect("store");
        let svc = OperatorAuthService::new(
            store,
            privk,
            pubk,
            SessionPolicy { ttl_secs: 3600 },
            LockoutPolicy::default(),
            Arc::new(AcceptingMfaHook),
            None,
        );

        let tenant_a = org_site("acme", "site-a");
        let tenant_b = org_site("acme", "site-b");
        let subject = base_principal("user-a", tenant_a.clone());
        let capability = cap(
            subject,
            OperatorRole::Operator,
            tenant_a.clone(),
            vec![OperatorPermission::Read, OperatorPermission::Write],
            Some(Vertical::Retail),
            10_000,
            false,
            0,
            "cap-a",
        );
        let token = svc.issue_capability(&capability).expect("issue");
        let verified = svc.verify_capability(&token, 2_000).expect("verify");
        assert_eq!(verified.capability.subject.id, "user-a");

        let allow_read = svc.authorize(&AuthorizationRequest {
            principal_id: "user-a".to_string(),
            role: OperatorRole::Operator,
            vertical: Vertical::Retail,
            target_tenant: tenant_a.clone(),
            permission: OperatorPermission::Read,
            scope: capability.scope.clone(),
        });
        assert!(allow_read.allowed, "same-tenant read should be allowed");
        let allow_write = svc.authorize(&AuthorizationRequest {
            principal_id: "user-a".to_string(),
            role: OperatorRole::Operator,
            vertical: Vertical::Retail,
            target_tenant: tenant_a.clone(),
            permission: OperatorPermission::Write,
            scope: capability.scope.clone(),
        });
        assert!(allow_write.allowed, "same-tenant write should be allowed");

        let deny_read = svc.authorize(&AuthorizationRequest {
            principal_id: "user-a".to_string(),
            role: OperatorRole::Operator,
            vertical: Vertical::Retail,
            target_tenant: tenant_b.clone(),
            permission: OperatorPermission::Read,
            scope: capability.scope.clone(),
        });
        assert!(!deny_read.allowed, "cross-tenant read must be denied");
        let deny_write = svc.authorize(&AuthorizationRequest {
            principal_id: "user-a".to_string(),
            role: OperatorRole::Operator,
            vertical: Vertical::Retail,
            target_tenant: tenant_b,
            permission: OperatorPermission::Write,
            scope: capability.scope,
        });
        assert!(!deny_write.allowed, "cross-tenant write must be denied");
    });
}

#[test]
fn f03_role_matrix_tests_pass_for_every_vertical() {
    let verticals = Vertical::ALL;
    let roles = OperatorRole::ALL;
    let perms = OperatorPermission::ALL;

    for vertical in verticals {
        for role in roles {
            for permission in perms {
                let allowed = role_allows(role, vertical, permission);
                let expected = match role {
                    OperatorRole::Operator => matches!(
                        permission,
                        OperatorPermission::Read
                            | OperatorPermission::Write
                            | OperatorPermission::Command
                    ),
                    OperatorRole::Supervisor => matches!(
                        permission,
                        OperatorPermission::Read
                            | OperatorPermission::Write
                            | OperatorPermission::Command
                            | OperatorPermission::Approve
                    ),
                    OperatorRole::Qa => matches!(
                        permission,
                        OperatorPermission::Read
                            | OperatorPermission::Approve
                            | OperatorPermission::AuditRead
                    ),
                    OperatorRole::Auditor => {
                        matches!(permission, OperatorPermission::Read | OperatorPermission::AuditRead)
                    }
                    OperatorRole::Admin => matches!(
                        permission,
                        OperatorPermission::Read
                            | OperatorPermission::Write
                            | OperatorPermission::Command
                            | OperatorPermission::Approve
                            | OperatorPermission::AuditRead
                            | OperatorPermission::Administer
                            | OperatorPermission::Delegate
                    ),
                    OperatorRole::Integrator => matches!(
                        permission,
                        OperatorPermission::Read
                            | OperatorPermission::Write
                            | OperatorPermission::Command
                    ),
                    OperatorRole::BreakGlass => matches!(
                        permission,
                        OperatorPermission::Read
                            | OperatorPermission::Write
                            | OperatorPermission::Command
                            | OperatorPermission::BreakGlass
                    ),
                };
                assert_eq!(
                    allowed, expected,
                    "matrix mismatch for vertical={:?} role={:?} permission={:?}",
                    vertical, role, permission
                );
            }
        }
    }
}

#[test]
fn f03_delegation_cannot_widen_authority() {
    with_sink(|_sink| {
        let (privk, pubk) = authority_keys();
        let tenant = org_site("acme", "site-a");
        let child_tenant = TenantPath::new(vec![
            TenantSegment::new(TenantLevel::Organisation, "acme"),
            TenantSegment::new(TenantLevel::Site, "site-a"),
            TenantSegment::new(TenantLevel::Zone, "z1"),
        ]);
        let wider_tenant =
            TenantPath::new(vec![TenantSegment::new(TenantLevel::Organisation, "acme")]);
        let other_org =
            TenantPath::new(vec![TenantSegment::new(TenantLevel::Organisation, "other")]);

        let parent = cap(
            base_principal("admin-a", tenant.clone()),
            OperatorRole::Admin,
            tenant.clone(),
            vec![
                OperatorPermission::Read,
                OperatorPermission::Write,
                OperatorPermission::Command,
                OperatorPermission::Delegate,
            ],
            Some(Vertical::Retail),
            10_000,
            true,
            2,
            "cap-parent",
        );
        let parent_token = issue_capability_token(&parent, &privk).expect("issue");
        let empty_revoked_caps = BTreeSet::new();
        let empty_revoked_principals = BTreeSet::new();
        let verification =
            CapabilityVerification::new(&empty_revoked_caps, &empty_revoked_principals, 2_000);

        let narrowed = cap(
            base_principal("op-b", child_tenant.clone()),
            OperatorRole::Operator,
            child_tenant,
            vec![OperatorPermission::Read],
            Some(Vertical::Retail),
            5_000,
            false,
            0,
            "cap-child",
        );
        assert!(delegate_capability_token(
            &parent_token,
            &narrowed,
            &privk,
            &pubk,
            &verification
        )
        .is_ok());

        let widened_tenant = cap(
            base_principal("op-b", wider_tenant.clone()),
            OperatorRole::Operator,
            wider_tenant,
            vec![OperatorPermission::Read],
            Some(Vertical::Retail),
            5_000,
            false,
            0,
            "cap-wide-tenant",
        );
        assert!(delegate_capability_token(
            &parent_token,
            &widened_tenant,
            &privk,
            &pubk,
            &verification
        )
        .is_err());

        let crossed = cap(
            base_principal("op-b", other_org.clone()),
            OperatorRole::Operator,
            other_org,
            vec![OperatorPermission::Read],
            Some(Vertical::Retail),
            5_000,
            false,
            0,
            "cap-cross-org",
        );
        assert!(delegate_capability_token(&parent_token, &crossed, &privk, &pubk, &verification)
            .is_err());

        let more_perms = cap(
            base_principal("op-b", tenant.clone()),
            OperatorRole::Operator,
            tenant.clone(),
            vec![OperatorPermission::Read, OperatorPermission::Administer],
            Some(Vertical::Retail),
            5_000,
            false,
            0,
            "cap-more-perms",
        );
        assert!(delegate_capability_token(
            &parent_token,
            &more_perms,
            &privk,
            &pubk,
            &verification
        )
        .is_err());

        let later_expiry = cap(
            base_principal("op-b", tenant.clone()),
            OperatorRole::Operator,
            tenant.clone(),
            vec![OperatorPermission::Read],
            Some(Vertical::Retail),
            20_000,
            false,
            0,
            "cap-later",
        );
        assert!(delegate_capability_token(
            &parent_token,
            &later_expiry,
            &privk,
            &pubk,
            &verification
        )
        .is_err());

        let same_depth = cap(
            base_principal("op-b", tenant),
            OperatorRole::Operator,
            org_site("acme", "site-a"),
            vec![OperatorPermission::Read],
            Some(Vertical::Retail),
            5_000,
            true,
            2,
            "cap-same-depth",
        );
        assert!(delegate_capability_token(
            &parent_token,
            &same_depth,
            &privk,
            &pubk,
            &verification
        )
        .is_err());
    });
}

#[test]
fn f03_revoked_principal_loses_access_on_next_request() {
    with_sink(|sink| {
        let (privk, pubk) = authority_keys();
        let (_dir, path) = temp_store("revoke");
        let mut store = OperatorIdentityStore::load_or_create(&path).expect("store");

        let tenant = org_site("acme", "site-a");
        let principal = base_principal("user-rev", tenant.clone());
        store
            .upsert_principal(OperatorPrincipalRecord {
                principal: principal.clone(),
                role: OperatorRole::Operator,
                enabled: true,
                mfa: tirbase_core::operator_auth::store::MfaSetting::NotRequired,
                allowed_auth: vec![AuthMethod::Local],
            })
            .expect("upsert principal");
        let salt = derive_salt(b"user-rev-salt");
        store
            .set_local_password("user-rev", "password123", salt)
            .expect("set password");

        let svc = OperatorAuthService::new(
            store,
            privk,
            pubk,
            SessionPolicy { ttl_secs: 3600 },
            LockoutPolicy::default(),
            Arc::new(AcceptingMfaHook),
            None,
        );

        let session = svc
            .authenticate_local("user-rev", "password123", None, 1_000, "sess-1")
            .expect("auth");
        assert_eq!(session.principal.id, "user-rev");
        let validated = svc
            .validate_session("sess-1", 1_100)
            .expect("session valid before revoke");
        assert_eq!(validated.session_id, "sess-1");

        svc.revoke_principal("user-rev").expect("revoke principal");

        let denied = svc.validate_session("sess-1", 1_101);
        assert!(
            denied.is_err(),
            "revoked principal must lose access on next request"
        );

        let capability = cap(
            base_principal("user-rev", org_site("acme", "site-a")),
            OperatorRole::Operator,
            org_site("acme", "site-a"),
            vec![OperatorPermission::Read],
            Some(Vertical::Retail),
            10_000,
            false,
            0,
            "cap-rev",
        );
        assert!(svc.issue_capability(&capability).is_err());

        let events = sink.events.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.category == SecurityEventCategory::OperatorAuth),
            "expected operator auth audit events"
        );
    });
}

#[derive(Debug)]
struct StaticOidcVerifier {
    issuer: String,
    subject: String,
    audience: Option<String>,
}

impl OidcVerifier for StaticOidcVerifier {
    fn verify(
        &self,
        _token: &str,
        _now_secs: i64,
    ) -> Result<OidcClaims, tirbase_core::errors::TirBaseError> {
        Ok(OidcClaims {
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            audience: self.audience.clone(),
        })
    }
}

#[derive(Debug)]
struct MfaAlwaysRequired;
impl MfaHook for MfaAlwaysRequired {
    fn verify(&self, _principal_id: &str, _proof: Option<&str>, _now_secs: i64) -> MfaHookResult {
        MfaHookResult::Required
    }
}

#[test]
fn f03_local_and_oidc_auth_sessions_lockout_and_mfa_hooks() {
    with_sink(|_sink| {
        let (privk, pubk) = authority_keys();
        let (_dir, path) = temp_store("auth");
        let mut store = OperatorIdentityStore::load_or_create(&path).expect("store");
        let tenant = org_site("acme", "site-a");
        let principal = base_principal("user-oidc", tenant.clone());
        store
            .upsert_principal(OperatorPrincipalRecord {
                principal: principal.clone(),
                role: OperatorRole::Operator,
                enabled: true,
                mfa: tirbase_core::operator_auth::store::MfaSetting::NotRequired,
                allowed_auth: vec![AuthMethod::Local, AuthMethod::Oidc],
            })
            .expect("principal");
        store
            .set_local_password("user-oidc", "pw", derive_salt(b"s1"))
            .expect("pw");
        store
            .upsert_oidc_identity(OidcIdentity {
                principal_id: "user-oidc".to_string(),
                issuer: "https://issuer.example".to_string(),
                subject: "sub-1".to_string(),
                audience: Some("tirbase".to_string()),
            })
            .expect("oidc");

        let verifier = Arc::new(StaticOidcVerifier {
            issuer: "https://issuer.example".to_string(),
            subject: "sub-1".to_string(),
            audience: Some("tirbase".to_string()),
        });
        let svc = OperatorAuthService::new(
            store,
            privk,
            pubk,
            SessionPolicy { ttl_secs: 60 },
            LockoutPolicy {
                threshold: 2,
                lockout_secs: 300,
            },
            Arc::new(AcceptingMfaHook),
            Some(verifier),
        );

        let s = svc
            .authenticate_oidc("user-oidc", "tok", None, 100, "oidc-sess")
            .expect("oidc");
        assert_eq!(s.auth_method, "oidc");
        assert!(svc.validate_session("oidc-sess", 150).is_ok());
        assert!(
            svc.validate_session("oidc-sess", 161).is_err(),
            "session must expire"
        );

        assert!(svc
            .authenticate_local("user-oidc", "bad", None, 200, "l1")
            .is_err());
        assert!(svc
            .authenticate_local("user-oidc", "bad", None, 201, "l2")
            .is_err());
        assert!(
            svc.authenticate_local("user-oidc", "pw", None, 202, "l3")
                .is_err(),
            "account must be locked after threshold"
        );

        let (_dir2, path2) = temp_store("mfa");
        let mut store2 = OperatorIdentityStore::load_or_create(&path2).expect("store2");
        store2
            .upsert_principal(OperatorPrincipalRecord {
                principal,
                role: OperatorRole::Operator,
                enabled: true,
                mfa: tirbase_core::operator_auth::store::MfaSetting::Required,
                allowed_auth: vec![AuthMethod::Local],
            })
            .expect("principal2");
        store2
            .set_local_password("user-oidc", "pw", derive_salt(b"s2"))
            .expect("pw2");
        let (privk2, pubk2) = authority_keys();
        let svc2 = OperatorAuthService::new(
            store2,
            privk2,
            pubk2,
            SessionPolicy { ttl_secs: 60 },
            LockoutPolicy::default(),
            Arc::new(MfaAlwaysRequired),
            None,
        );
        let mfa = svc2.authenticate_local("user-oidc", "pw", None, 10, "m1");
        assert!(matches!(
            mfa,
            Err(tirbase_core::operator_auth::service::OperatorAuthError::MfaRequired)
        ));
    });
}
