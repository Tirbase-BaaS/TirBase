// SPDX-License-Identifier: AGPL-3.0-only

//! Prometheus metrics endpoint (CLAIM-35.5, PV-11.1).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use anyhow::Result;
use axum::{routing::get, Router};

/// Process-wide gateway metrics registry.
#[derive(Debug, Default)]
pub struct GatewayMetrics {
    pub guard_decisions_total: AtomicU64,
    pub effects_ledger_writes_total: AtomicU64,
    pub replay_rejections_total: AtomicU64,
    security_events_total: RwLock<BTreeMap<String, u64>>,
    quarantine_entries_total: RwLock<BTreeMap<String, u64>>,
}

impl GatewayMetrics {
    pub fn inc_guard_decision(&self) {
        self.guard_decisions_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_effects_ledger_write(&self) {
        self.effects_ledger_writes_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_replay_rejection(&self) {
        self.replay_rejections_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_security_event(&self, severity: &str) {
        let mut map = self
            .security_events_total
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *map.entry(severity.to_string()).or_insert(0) += 1;
    }
    pub fn inc_quarantine_entry(&self, store: &str) {
        let mut map = self
            .quarantine_entries_total
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *map.entry(store.to_string()).or_insert(0) += 1;
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP guard_decisions_total Total guard decisions.\n");
        out.push_str("# TYPE guard_decisions_total counter\n");
        out.push_str(&format!(
            "guard_decisions_total {}\n",
            self.guard_decisions_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP effects_ledger_writes_total Total effects ledger writes.\n");
        out.push_str("# TYPE effects_ledger_writes_total counter\n");
        out.push_str(&format!(
            "effects_ledger_writes_total {}\n",
            self.effects_ledger_writes_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP security_events_total Total security events by severity.\n");
        out.push_str("# TYPE security_events_total counter\n");
        {
            let map = self
                .security_events_total
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if map.is_empty() {
                out.push_str("security_events_total{severity=\"none\"} 0\n");
            } else {
                for (sev, val) in map.iter() {
                    out.push_str(&format!(
                        "security_events_total{{severity=\"{}\"}} {}\n",
                        sev, val
                    ));
                }
            }
        }
        out.push_str("# HELP replay_rejections_total Total replay rejections.\n");
        out.push_str("# TYPE replay_rejections_total counter\n");
        out.push_str(&format!(
            "replay_rejections_total {}\n",
            self.replay_rejections_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP quarantine_entries_total Total quarantine entries by store.\n");
        out.push_str("# TYPE quarantine_entries_total counter\n");
        {
            let map = self
                .quarantine_entries_total
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if map.is_empty() {
                out.push_str("quarantine_entries_total{store=\"none\"} 0\n");
            } else {
                for (store, val) in map.iter() {
                    out.push_str(&format!(
                        "quarantine_entries_total{{store=\"{}\"}} {}\n",
                        store, val
                    ));
                }
            }
        }
        out
    }
}

static GLOBAL_METRICS: OnceLock<Arc<GatewayMetrics>> = OnceLock::new();

/// Get or initialize the process-wide metrics registry.
pub fn global_metrics() -> Arc<GatewayMetrics> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(GatewayMetrics::default()))
        .clone()
}

/// Install a specific metrics registry as global (test helper).
pub fn install_global_metrics(metrics: Arc<GatewayMetrics>) -> Arc<GatewayMetrics> {
    let _ = GLOBAL_METRICS.set(metrics.clone());
    global_metrics()
}

async fn metrics_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<GatewayMetrics>>,
) -> impl axum::response::IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics.render_prometheus(),
    )
}

/// Start Prometheus metrics HTTP server on the given address.
pub async fn run_metrics_server(
    addr: std::net::SocketAddr,
    metrics: Arc<GatewayMetrics>,
) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);
    tracing::info!("metrics endpoint listening on http://{addr}/metrics");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
