// SPDX-License-Identifier: AGPL-3.0-only

//! F-08 admin CLI for the cold-chain, POS and venue resource API.
//!
//! The CLI drives the same `VerticalApi` dispatch surface as the HTTP admin
//! listener, against the local `primary.db`. It exists for offline/on-device
//! operation; remote callers use the generated TypeScript/Python clients.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tirbase_gateway::vertical_api::VerticalApi;

#[derive(Debug, Clone)]
pub struct VerticalArgs {
    pub db_path: PathBuf,
    /// `list|get|create|patch|delete`
    pub action: String,
    /// `cold-chain|pos|venues`
    pub vertical: String,
    /// `sites|readings|orders|lines|venues|gates`
    pub kind: String,
    pub id: Option<String>,
    pub parent_id: Option<String>,
    pub tenant: Option<String>,
    pub data_json: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<usize>,
}

pub struct VerticalResult {
    pub status: u16,
    pub body: String,
}

pub fn run(args: &VerticalArgs) -> Result<VerticalResult> {
    let api = VerticalApi::open(&args.db_path)
        .map_err(|e| anyhow::anyhow!("open vertical store: {e}"))?;
    let collection = if let Some(parent) = &args.parent_id {
        format!(
            "/admin/{}/{}/{}/{}",
            args.vertical,
            args.parent_kind(),
            parent,
            args.kind
        )
    } else {
        format!("/admin/{}/{}", args.vertical, args.kind)
    };
    let mut query = Vec::new();
    if let Some(tenant) = &args.tenant {
        query.push(format!("tenant={tenant}"));
    }
    if let Some(limit) = args.limit {
        query.push(format!("limit={limit}"));
    }
    if let Some(cursor) = args.cursor {
        query.push(format!("cursor={cursor}"));
    }
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query.join("&"))
    };
    let (method, path, body) = match args.action.as_str() {
        "list" => ("GET", format!("{collection}{query}"), None),
        "create" => {
            let mut value: serde_json::Value = match &args.data_json {
                Some(raw) => serde_json::from_str(raw).context("--data-json is not valid JSON")?,
                None => serde_json::json!({}),
            };
            if let (Some(tenant), Some(obj)) = (&args.tenant, value.as_object_mut()) {
                obj.insert("tenant".into(), serde_json::json!(tenant));
            }
            ("POST", collection, Some(value.to_string()))
        }
        "get" | "patch" | "delete" => {
            if args.parent_id.is_some() {
                anyhow::bail!("item actions address a root resource; omit --parent-id");
            }
            let id = args
                .id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--id is required for {}", args.action))?;
            let path = format!("{collection}/{id}{query}");
            let body = if args.action == "patch" {
                Some(args.data_json.as_deref().unwrap_or("{}").to_string())
            } else {
                None
            };
            (
                match args.action.as_str() {
                    "get" => "GET",
                    "patch" => "PATCH",
                    _ => "DELETE",
                },
                path,
                body,
            )
        }
        other => anyhow::bail!("unknown vertical action {other}"),
    };
    let (status, body) = api.dispatch(
        method,
        &path,
        body.as_deref(),
        tirbase_core::traits::wall_hint_secs().unwrap_or(0),
    );
    if status >= 400 {
        anyhow::bail!("vertical API returned {status}: {body}");
    }
    Ok(VerticalResult { status, body })
}

impl VerticalArgs {
    /// Parent collection for a child resource (`readings` live under `sites`).
    fn parent_kind(&self) -> &str {
        match self.kind.as_str() {
            "readings" => "sites",
            "lines" => "orders",
            "gates" => "venues",
            other => other,
        }
    }
}
