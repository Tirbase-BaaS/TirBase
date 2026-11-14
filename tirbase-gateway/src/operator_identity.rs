// SPDX-License-Identifier: AGPL-3.0-only

//! F-03 operator identity production caller for the gateway.
//!
//! Provides capability-based operator authorization checks wired into admin
//! dispatch when an operator identity store and authority keys are configured.

use std::sync::Arc;

use tirbase_core::operator_auth::service::{
    AcceptingMfaHook, AuthorizationRequest, LockoutPolicy, OperatorAuthService, SessionPolicy,
};
use tirbase_core::operator_auth::store::OperatorIdentityStore;
use tirbase_types::identity::{OperatorPermission, OperatorRole, TenantLevel, TenantPath, TenantSegment, Vertical};

/// Build an [`OperatorAuthService`] from configured paths/keys.
///
/// This is a production helper used by gateway admin wiring to load operator
/// identity state for authorization decisions.
pub fn load_operator_auth_service(
    store_path: &std::path::Path,
    authority_private_key_hex: &str,
    authority_public_key_hex: &str,
) -> Result<Arc<OperatorAuthService>, String> {
    let store = OperatorIdentityStore::load_or_create(store_path)
        .map_err(|e| format!("load operator identity store: {e}"))?;
    let private_key = hex::decode(authority_private_key_hex.trim())
        .map_err(|e| format!("decode operator authority private key: {e}"))?;
    let public_key = hex::decode(authority_public_key_hex.trim())
        .map_err(|e| format!("decode operator authority public key: {e}"))?;
    Ok(Arc::new(OperatorAuthService::new(
        store,
        private_key,
        public_key,
        SessionPolicy::default(),
        LockoutPolicy::default(),
        Arc::new(AcceptingMfaHook),
        None,
    )))
}

/// Authorize an operator capability token for a tenant-scoped permission.
///
/// Production caller used by admin dispatch (`operator-authorize`) to enforce
/// tenant boundaries, role/vertical matrix, and revocation on the next request.
pub fn authorize_operator_capability(
    service: &OperatorAuthService,
    capability_token_hex: &str,
    role: OperatorRole,
    vertical: Vertical,
    tenant: &TenantPath,
    permission: OperatorPermission,
    now_est: i64,
) -> serde_json::Value {
    let token = match hex::decode(capability_token_hex.trim()) {
        Ok(t) => t,
        Err(e) => {
            return serde_json::json!({
                "status": 400,
                "error": format!("capability_token_hex: {e}")
            })
        }
    };
    let verified = match service.verify_capability(&token, now_est) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "status": 403,
                "error": e.to_string(),
                "decision": "deny"
            })
        }
    };
    let decision = service.authorize(&AuthorizationRequest {
        principal_id: verified.capability.subject.id.clone(),
        role,
        vertical,
        target_tenant: tenant.clone(),
        permission,
        scope: verified.capability.scope,
    });
    serde_json::json!({
        "status": if decision.allowed { 200 } else { 403 },
        "decision": if decision.allowed { "allow" } else { "deny" },
        "reason": decision.reason,
        "principal_id": verified.capability.subject.id,
        "capability_id": verified.capability.capability_id,
    })
}

/// Parse a simple tenant path from segments `[{level,id}, ...]`.
pub fn parse_tenant_path(value: &serde_json::Value) -> Result<TenantPath, String> {
    let arr = value
        .as_array()
        .ok_or_else(|| "tenant must be an array of {level,id} segments".to_string())?;
    let mut segments = Vec::with_capacity(arr.len());
    for seg in arr {
        let level_str = seg
            .get("level")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "tenant segment missing level".to_string())?;
        let id = seg
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "tenant segment missing id".to_string())?;
        let level = match level_str {
            "Organisation" | "organisation" | "org" => TenantLevel::Organisation,
            "Site" | "site" => TenantLevel::Site,
            "Store" | "store" => TenantLevel::Store,
            "Venue" | "venue" => TenantLevel::Venue,
            "Zone" | "zone" => TenantLevel::Zone,
            "Gate" | "gate" => TenantLevel::Gate,
            "ColdRoom" | "cold_room" | "cold-room" => TenantLevel::ColdRoom,
            other => return Err(format!("unknown tenant level {other}")),
        };
        segments.push(TenantSegment::new(level, id));
    }
    Ok(TenantPath::new(segments))
}

/// Parse operator role string.
pub fn parse_operator_role(value: &str) -> Result<OperatorRole, String> {
    value
        .parse::<OperatorRole>()
        .map_err(|_| format!("unknown operator role {value}"))
}

/// Parse vertical string.
pub fn parse_vertical(value: &str) -> Result<Vertical, String> {
    value
        .parse::<Vertical>()
        .map_err(|_| format!("unknown vertical {value}"))
}

/// Parse permission string.
pub fn parse_permission(value: &str) -> Result<OperatorPermission, String> {
    value
        .parse::<OperatorPermission>()
        .map_err(|_| format!("unknown operator permission {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::operator_auth::service::{AcceptingMfaHook, LockoutPolicy, SessionPolicy};
    use tirbase_core::operator_auth::store::OperatorIdentityStore;
    use tirbase_types::identity::{
        CapabilityScope, DelegationConstraints, OperatorCapability, OperatorPermission, OperatorRole,
        PrincipalId, PrincipalKind, TenantLevel, TenantPath, TenantSegment, Vertical,
    };

    fn tenant() -> TenantPath {
        TenantPath::new(vec![
            TenantSegment::new(TenantLevel::Organisation, "acme"),
            TenantSegment::new(TenantLevel::Site, "s1"),
        ])
    }

    #[test]
    fn f03_gateway_operator_authorize_production_caller_denies_cross_tenant() {
        let dir = std::env::temp_dir().join(format!(
            "tirbase-f03-gw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store_path = dir.join("store.json");
        let store = OperatorIdentityStore::load_or_create(&store_path).unwrap();
        let kp = biscuit_auth::KeyPair::new();
        let svc = Arc::new(OperatorAuthService::new(
            store,
            kp.private().to_bytes().to_vec(),
            kp.public().to_bytes().to_vec(),
            SessionPolicy::default(),
            LockoutPolicy::default(),
            Arc::new(AcceptingMfaHook),
            None,
        ));
        let cap = OperatorCapability {
            subject: PrincipalId::new("u1", PrincipalKind::User, tenant()),
            role: OperatorRole::Operator,
            scope: CapabilityScope::new(
                tenant(),
                vec![OperatorPermission::Read],
                Some(Vertical::Retail),
                10_000,
            ),
            delegation: DelegationConstraints { delegatable: false, max_depth: 0 },
            issuer: "a".into(),
            capability_id: "c1".into(),
            issued_at: 1,
        };
        let tok = hex::encode(svc.issue_capability(&cap).unwrap());
        let other = TenantPath::new(vec![
            TenantSegment::new(TenantLevel::Organisation, "acme"),
            TenantSegment::new(TenantLevel::Site, "s2"),
        ]);
        let denied = authorize_operator_capability(&svc, &tok, OperatorRole::Operator, Vertical::Retail, &other, OperatorPermission::Read, 100);
        assert_eq!(denied["decision"], "deny");
        let allowed = authorize_operator_capability(&svc, &tok, OperatorRole::Operator, Vertical::Retail, &tenant(), OperatorPermission::Read, 100);
        assert_eq!(allowed["decision"], "allow");
        let _ = std::fs::remove_dir_all(dir);
    }
}
