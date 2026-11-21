// SPDX-License-Identifier: AGPL-3.0-only

//! F-08 webhook endpoint management and delivery drain.
//!
//! Endpoints are persisted in the gateway's primary database. `drain` performs
//! one delivery pass using the production HTTPS transport and honours the
//! persisted exponential backoff; schedule it from the operator's timer.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::json;
use tirbase_gateway::webhooks::{ReqwestTransport, WebhookDispatcher};

#[derive(Debug, Clone)]
pub struct WebhookArgs {
    pub db_path: PathBuf,
    /// `add|list|enable|disable|drain`
    pub action: String,
    pub endpoint_id: Option<String>,
    pub url: Option<String>,
    pub secret_file: Option<PathBuf>,
    pub now_est: i64,
}

pub fn run(args: &WebhookArgs) -> Result<String> {
    let dispatcher = WebhookDispatcher::open(&args.db_path)
        .map_err(|e| anyhow::anyhow!("open webhook store: {e}"))?;
    match args.action.as_str() {
        "add" => {
            let endpoint_id = args
                .endpoint_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--endpoint-id is required for add"))?;
            let url = args
                .url
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--url is required for add"))?;
            let secret_path = args
                .secret_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--secret-file is required for add"))?;
            let secret = std::fs::read_to_string(secret_path)
                .with_context(|| format!("read webhook secret {}", secret_path.display()))?;
            let secret = secret.trim_end_matches('\n');
            let endpoint = dispatcher
                .add_endpoint(endpoint_id, url, secret, args.now_est)
                .map_err(|e| anyhow::anyhow!("add endpoint: {e}"))?;
            Ok(json!({
                "status": 200,
                "endpoint": {
                    "endpoint_id": endpoint.endpoint_id,
                    "url": endpoint.url,
                    "enabled": endpoint.enabled,
                    "created_est": endpoint.created_est,
                }
            })
            .to_string())
        }
        "list" => {
            let endpoints = dispatcher
                .endpoints()
                .map_err(|e| anyhow::anyhow!("list endpoints: {e}"))?;
            Ok(json!({ "status": 200, "endpoints": endpoints }).to_string())
        }
        "enable" | "disable" => {
            let endpoint_id = args
                .endpoint_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--endpoint-id is required for {}", args.action))?;
            dispatcher
                .set_enabled(endpoint_id, args.action == "enable")
                .map_err(|e| anyhow::anyhow!("{} endpoint: {e}", args.action))?;
            Ok(json!({ "status": 200, "endpoint_id": endpoint_id, "enabled": args.action == "enable" }).to_string())
        }
        "drain" => {
            let (delivered, failed) = dispatcher
                .deliver_pending(&ReqwestTransport, args.now_est)
                .map_err(|e| anyhow::anyhow!("drain webhooks: {e}"))?;
            Ok(json!({ "status": 200, "delivered": delivered, "failed": failed }).to_string())
        }
        other => anyhow::bail!("unknown webhook action {other}"),
    }
}
