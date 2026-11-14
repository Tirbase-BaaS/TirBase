// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin provisioning` — F-04 device provisioning and lifecycle.
//!
//! Operates directly on the gateway `primary.db` provisioning registry, so an
//! operator can issue claims, mint signed payloads, enrol online or offline,
//! rotate/revoke/replace/decommission credentials, transfer ownership, report
//! versions, and query the registry without a running gateway process.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use tirbase_core::provisioning::{
    DeviceQuery, ProvisioningPayload, ReportedVersions, VersionSet,
};
use tirbase_gateway::provisioning::{
    parse_device_state, parse_public_key_hex, parse_signing_key_hex, parse_tenant_path_string,
    ProvisioningService,
};
use tirbase_types::identity::TenantPath;

/// Parsed `tirbase-admin provisioning` invocation.
#[derive(Debug, Clone, Default)]
pub struct ProvisioningArgs {
    pub action: String,
    pub db_path: Option<PathBuf>,
    pub signer_seed_hex: Option<String>,
    pub authority_public_key_hex: Option<String>,
    pub tenant: Option<String>,
    pub site: Option<String>,
    pub device_type: Option<String>,
    pub device_id: Option<String>,
    pub device_public_key_hex: Option<String>,
    pub claim_code: Option<String>,
    pub credential_id: Option<String>,
    pub payload_file: Option<PathBuf>,
    pub firmware_version: Option<String>,
    pub config_version: Option<String>,
    pub ttl_secs: Option<i64>,
    pub issued_by: Option<String>,
    pub actor: Option<String>,
    pub state: Option<String>,
}

impl ProvisioningArgs {
    fn actor(&self) -> String {
        self.actor.clone().unwrap_or_else(|| "operator".to_string())
    }
}

fn tenant_from_arg(value: &str) -> Result<TenantPath> {
    parse_tenant_path_string(value).map_err(|error| anyhow::anyhow!("{error}"))
}

fn open_service(args: &ProvisioningArgs) -> Result<ProvisioningService> {
    let db_path = args
        .db_path
        .as_ref()
        .context("missing required --db-path")?;
    let signer = match &args.signer_seed_hex {
        Some(seed_hex) => Some(
            parse_signing_key_hex(seed_hex)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("--signer-seed-hex")?,
        ),
        None => None,
    };
    let public = match (&args.authority_public_key_hex, &signer) {
        (Some(hex_key), _) => parse_public_key_hex(hex_key).map_err(|error| anyhow::anyhow!("{error}"))?,
        (None, Some(signer)) => signer.verifying_key().to_bytes(),
        (None, None) => bail!("--authority-public-key-hex or --signer-seed-hex is required"),
    };
    ProvisioningService::open(db_path, public, signer).map_err(|error| anyhow::anyhow!("{error}"))
}

fn read_payload(args: &ProvisioningArgs) -> Result<ProvisioningPayload> {
    let path = args
        .payload_file
        .as_ref()
        .context("missing required --payload-file")?;
    let body =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&body).context("parse provisioning payload JSON")
}

fn build_payload(args: &ProvisioningArgs, service: &ProvisioningService, now: i64) -> Result<ProvisioningPayload> {
    let tenant = args
        .tenant
        .as_deref()
        .context("missing required --tenant")?;
    let device_id = args
        .device_id
        .as_deref()
        .context("missing required --device-id")?;
    let public_hex = args
        .device_public_key_hex
        .as_deref()
        .context("missing required --device-public-key-hex")?;
    let device_type = args
        .device_type
        .as_deref()
        .context("missing required --device-type")?;
    let device_public_key = parse_public_key_hex(public_hex).map_err(|error| anyhow::anyhow!("{error}"))?;
    let ttl = args.ttl_secs.unwrap_or(3600);
    let versions = VersionSet {
        firmware_version: args.firmware_version.clone(),
        config_version: args.config_version.clone(),
    };
    service
        .build_payload(
            format!("payload-{device_id}-{now}"),
            device_id.to_string(),
            device_public_key,
            tenant_from_arg(tenant)?,
            args.site.clone(),
            device_type.to_string(),
            args.claim_code.clone(),
            versions,
            now,
            Some(now.saturating_add(ttl.max(1))),
            args.issued_by.clone().unwrap_or_else(|| args.actor()),
        )
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// Execute one provisioning action and return the JSON result.
pub fn run(args: &ProvisioningArgs) -> Result<Value> {
    let service = open_service(args)?;
    let now = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
    let result = match args.action.as_str() {
        "claim" => {
            let tenant = args
                .tenant
                .as_deref()
                .context("missing required --tenant")?;
            let nonce = format!(
                "{}:{}:{}:{:?}",
                args.actor(),
                now,
                tenant,
                tirbase_core::traits::monotonic_now()
            )
            .into_bytes();
            service
                .issue_claim_code(
                    tenant_from_arg(tenant)?,
                    args.site.clone(),
                    args.device_type.clone(),
                    args.issued_by.clone().unwrap_or_else(|| args.actor()),
                    args.ttl_secs.unwrap_or(3600),
                    &nonce,
                    now,
                )
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "payload" => {
            let payload = build_payload(args, &service, now)?;
            json!({"payload": payload})
        }
        "enroll" => {
            let payload = if args.payload_file.is_some() {
                read_payload(args)?
            } else {
                build_payload(args, &service, now)?
            };
            service
                .enrol(&payload, args.actor(), now)
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "offline" => {
            let payload = if args.payload_file.is_some() {
                read_payload(args)?
            } else {
                build_payload(args, &service, now)?
            };
            service
                .apply_offline(&payload, args.actor(), now)
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "rotate" | "replace" | "decommission" | "reissue" => {
            let device_id = args
                .device_id
                .as_deref()
                .context("missing required --device-id")?;
            match args.action.as_str() {
                "rotate" => service.rotate(device_id, args.actor(), now),
                "replace" => service.replace(device_id, args.actor(), now),
                "decommission" => service.decommission(device_id, args.actor(), now),
                _ => service.authorise_reissue(device_id, args.actor(), now),
            }
            .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "revoke" => {
            let device_id = args
                .device_id
                .as_deref()
                .context("missing required --device-id")?;
            service
                .revoke(
                    device_id,
                    args.credential_id.as_deref(),
                    args.actor(),
                    now,
                )
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "transfer" => {
            let device_id = args
                .device_id
                .as_deref()
                .context("missing required --device-id")?;
            let tenant = args
                .tenant
                .as_deref()
                .context("missing required --tenant")?;
            service
                .transfer(
                    device_id,
                    tenant_from_arg(tenant)?,
                    args.site.clone(),
                    args.actor(),
                    now,
                )
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "report" => {
            let device_id = args
                .device_id
                .as_deref()
                .context("missing required --device-id")?;
            service
                .report_versions(
                    device_id,
                    ReportedVersions {
                        firmware_version: args.firmware_version.clone(),
                        config_version: args.config_version.clone(),
                        reported_at_est: Some(now),
                    },
                    args.actor(),
                    now,
                )
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "drift" => {
            let device_id = args
                .device_id
                .as_deref()
                .context("missing required --device-id")?;
            service
                .drift(device_id)
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "query" => {
            let tenant = match args.tenant.as_deref() {
                Some(value) => Some(tenant_from_arg(value)?),
                None => None,
            };
            let state = match args.state.as_deref() {
                Some(value) => Some(
                    parse_device_state(value)
                        .ok_or_else(|| anyhow::anyhow!("unknown device state {value:?}"))?,
                ),
                None => None,
            };
            service
                .query(&DeviceQuery {
                    tenant,
                    site: args.site.clone(),
                    device_type: args.device_type.clone(),
                    state,
                })
                .map_err(|error| anyhow::anyhow!("{error}"))?
        }
        "audit" => service
            .audit(args.device_id.as_deref())
            .map_err(|error| anyhow::anyhow!("{error}"))?,
        other => bail!(
            "unknown provisioning action {other:?}; expected claim|payload|enroll|offline|rotate|revoke|replace|decommission|reissue|transfer|report|drift|query|audit"
        ),
    };
    Ok(result)
}

/// Print a result as pretty JSON.
pub fn print_result(result: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}
