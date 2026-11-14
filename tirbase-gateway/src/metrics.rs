// SPDX-License-Identifier: AGPL-3.0-only

//! Prometheus metrics endpoint (CLAIM-35.5, PV-11.1, F-10).
//!
//! The original CLAIM-35.5 counters remain stable. F-10 adds the SLO
//! instruments consumed by `ops/prometheus/rules/tirbase-slo.yml`:
//!
//! * `tirbase_guard_decision_seconds` — Stage 0–15 decision latency.
//! * `tirbase_ledger_append_seconds` — durable effects-ledger append latency.
//! * `tirbase_alarm_delivery_seconds` — webhook/alarm delivery latency.
//! * `tirbase_gate_decision_seconds` — venue gate operation latency.
//! * `tirbase_payment_intent_completion_seconds` — POS payment completion.
//! * `tirbase_vertical_request_seconds{vertical}` — per-vertical API latency.
//!
//! No label ever carries a tenant, object id, DID, PAN, or location. Labels are
//! bounded enums (vertical, kind, method, outcome) so cardinality cannot grow
//! with customer data.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::Result;
use axum::{routing::get, Router};

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const PAYMENT_BUCKETS: &[f64] = &[
    1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
];

/// A small lock-free Prometheus histogram. `sum_micros` keeps the exposition
/// exact enough for latency SLOs without floating-point atomics.
#[derive(Debug)]
pub struct Histogram {
    bounds: &'static [f64],
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    pub fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: (0..bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, duration: Duration) {
        self.observe_secs(duration.as_secs_f64());
    }

    pub fn observe_secs(&self, secs: f64) {
        if !secs.is_finite() || secs < 0.0 {
            return;
        }
        for (index, bound) in self.bounds.iter().enumerate() {
            if secs <= *bound {
                self.buckets[index].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add((secs * 1_000_000.0) as u64, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str, labels: &[(&str, &str)]) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} histogram\n"));
        for (index, bound) in self.bounds.iter().enumerate() {
            let rendered_bound = format_bound(*bound);
            let mut all = labels.to_vec();
            all.push(("le", rendered_bound.as_str()));
            out.push_str(&format!(
                "{name}_bucket{} {}\n",
                render_labels(&all),
                self.buckets[index].load(Ordering::Relaxed)
            ));
        }
        let mut all = labels.to_vec();
        all.push(("le", "+Inf"));
        out.push_str(&format!(
            "{name}_bucket{} {}\n",
            render_labels(&all),
            self.count.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "{name}_sum{} {}\n",
            render_labels(labels),
            self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
        ));
        out.push_str(&format!(
            "{name}_count{} {}\n",
            render_labels(labels),
            self.count.load(Ordering::Relaxed)
        ));
    }
}

fn format_bound(bound: f64) -> String {
    if bound.fract() == 0.0 {
        format!("{bound:.0}")
    } else {
        let mut s = format!("{bound}");
        while s.ends_with('0') {
            s.pop();
        }
        s
    }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn render_labels(labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let body = labels
        .iter()
        .map(|(name, value)| format!("{name}=\"{}\"", escape_label(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

fn labels_key(labels: &[(&str, &str)]) -> String {
    labels
        .iter()
        .map(|(name, value)| format!("{name}\u{1e}{value}"))
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

/// Counter with a bounded label set. Keys are encoded internally; callers
/// supply only server-side enum values, never request data.
#[derive(Debug, Default)]
struct LabeledCounter {
    values: RwLock<BTreeMap<String, u64>>,
}

impl LabeledCounter {
    fn inc(&self, labels: &[(&str, &str)]) {
        let key = labels_key(labels);
        let mut values = self.values.write().unwrap_or_else(|e| e.into_inner());
        *values.entry(key).or_insert(0) += 1;
    }

    fn render(&self, out: &mut String, name: &str, help: &str, fallback: &[(&str, &str)]) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} counter\n"));
        let values = self.values.read().unwrap_or_else(|e| e.into_inner());
        if values.is_empty() {
            out.push_str(&format!("{name}{} 0\n", render_labels(fallback)));
            return;
        }
        for (key, value) in values.iter() {
            let labels: Vec<(&str, &str)> = key
                .split('\u{1f}')
                .filter_map(|pair| pair.split_once('\u{1e}'))
                .collect();
            out.push_str(&format!("{name}{} {value}\n", render_labels(&labels)));
        }
    }
}

/// Process-wide gateway metrics registry.
#[derive(Debug)]
pub struct GatewayMetrics {
    pub guard_decisions_total: AtomicU64,
    pub effects_ledger_writes_total: AtomicU64,
    pub replay_rejections_total: AtomicU64,
    security_events_total: RwLock<BTreeMap<String, u64>>,
    quarantine_entries_total: RwLock<BTreeMap<String, u64>>,

    guard_decision_seconds: Histogram,
    ledger_append_seconds: Histogram,
    alarm_delivery_seconds: Histogram,
    gate_decision_seconds: Histogram,
    payment_intent_completion_seconds: Histogram,
    vertical_request_seconds: RwLock<BTreeMap<String, Histogram>>,

    alarm_deliveries_total: LabeledCounter,
    payment_intents_total: LabeledCounter,
    driver_operations_total: LabeledCounter,
    adapter_operations_total: LabeledCounter,
    gateway_requests_total: LabeledCounter,
    vertical_appends_total: LabeledCounter,
    gate_decisions_total: LabeledCounter,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self {
            guard_decisions_total: AtomicU64::new(0),
            effects_ledger_writes_total: AtomicU64::new(0),
            replay_rejections_total: AtomicU64::new(0),
            security_events_total: RwLock::new(BTreeMap::new()),
            quarantine_entries_total: RwLock::new(BTreeMap::new()),
            guard_decision_seconds: Histogram::new(LATENCY_BUCKETS),
            ledger_append_seconds: Histogram::new(LATENCY_BUCKETS),
            alarm_delivery_seconds: Histogram::new(LATENCY_BUCKETS),
            gate_decision_seconds: Histogram::new(LATENCY_BUCKETS),
            payment_intent_completion_seconds: Histogram::new(PAYMENT_BUCKETS),
            vertical_request_seconds: RwLock::new(BTreeMap::new()),
            alarm_deliveries_total: LabeledCounter::default(),
            payment_intents_total: LabeledCounter::default(),
            driver_operations_total: LabeledCounter::default(),
            adapter_operations_total: LabeledCounter::default(),
            gateway_requests_total: LabeledCounter::default(),
            vertical_appends_total: LabeledCounter::default(),
            gate_decisions_total: LabeledCounter::default(),
        }
    }
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

    pub fn observe_guard_decision(&self, duration: Duration) {
        self.guard_decision_seconds.observe(duration);
    }

    pub fn observe_ledger_append(&self, duration: Duration) {
        self.ledger_append_seconds.observe(duration);
    }

    pub fn observe_alarm_delivery(&self, duration: Duration) {
        self.alarm_delivery_seconds.observe(duration);
    }

    pub fn observe_gate_decision(&self, duration: Duration) {
        self.gate_decision_seconds.observe(duration);
    }

    pub fn observe_payment_intent_completion(&self, duration: Duration) {
        self.payment_intent_completion_seconds.observe(duration);
    }

    pub fn observe_vertical_request(&self, vertical: &str, duration: Duration) {
        let mut map = self
            .vertical_request_seconds
            .write()
            .unwrap_or_else(|e| e.into_inner());
        map.entry(vertical.to_string())
            .or_insert_with(|| Histogram::new(LATENCY_BUCKETS))
            .observe(duration);
    }

    pub fn inc_alarm_delivery(&self, vertical: &str, outcome: &str) {
        self.alarm_deliveries_total
            .inc(&[("vertical", vertical), ("outcome", outcome)]);
    }

    pub fn inc_payment_intent(&self, vertical: &str, outcome: &str) {
        self.payment_intents_total
            .inc(&[("vertical", vertical), ("outcome", outcome)]);
    }

    pub fn inc_driver_operation(&self, driver: &str, operation: &str, outcome: &str) {
        self.driver_operations_total.inc(&[
            ("driver", driver),
            ("operation", operation),
            ("outcome", outcome),
        ]);
    }

    pub fn inc_adapter_operation(&self, adapter: &str, operation: &str, outcome: &str) {
        self.adapter_operations_total.inc(&[
            ("adapter", adapter),
            ("operation", operation),
            ("outcome", outcome),
        ]);
    }

    pub fn inc_gateway_request(&self, surface: &str, method: &str, status: &str) {
        self.gateway_requests_total.inc(&[
            ("surface", surface),
            ("method", method),
            ("status", status),
        ]);
    }

    pub fn inc_vertical_append(&self, vertical: &str) {
        self.vertical_appends_total.inc(&[("vertical", vertical)]);
    }

    pub fn inc_gate_decision(&self, vertical: &str, outcome: &str) {
        self.gate_decisions_total
            .inc(&[("vertical", vertical), ("outcome", outcome)]);
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
                        escape_label(sev),
                        val
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
                        escape_label(store),
                        val
                    ));
                }
            }
        }

        self.guard_decision_seconds.render(
            &mut out,
            "tirbase_guard_decision_seconds",
            "Guard Stage 0-15 decision latency in seconds.",
            &[],
        );
        self.ledger_append_seconds.render(
            &mut out,
            "tirbase_ledger_append_seconds",
            "Durable effects-ledger append latency in seconds.",
            &[],
        );
        self.alarm_delivery_seconds.render(
            &mut out,
            "tirbase_alarm_delivery_seconds",
            "Alarm/webhook delivery latency in seconds.",
            &[],
        );
        self.gate_decision_seconds.render(
            &mut out,
            "tirbase_gate_decision_seconds",
            "Venue gate operation latency in seconds.",
            &[],
        );
        self.payment_intent_completion_seconds.render(
            &mut out,
            "tirbase_payment_intent_completion_seconds",
            "POS payment intent completion latency in seconds.",
            &[],
        );
        {
            let map = self
                .vertical_request_seconds
                .read()
                .unwrap_or_else(|e| e.into_inner());
            for (vertical, histogram) in map.iter() {
                histogram.render(
                    &mut out,
                    "tirbase_vertical_request_seconds",
                    "Vertical API request latency in seconds.",
                    &[("vertical", vertical)],
                );
            }
        }

        self.alarm_deliveries_total.render(
            &mut out,
            "tirbase_alarm_deliveries_total",
            "Alarm deliveries by vertical and outcome.",
            &[("vertical", "none"), ("outcome", "none")],
        );
        self.payment_intents_total.render(
            &mut out,
            "tirbase_payment_intents_total",
            "POS payment intents by vertical and outcome.",
            &[("vertical", "pos"), ("outcome", "none")],
        );
        self.driver_operations_total.render(
            &mut out,
            "tirbase_driver_operations_total",
            "Driver operations by driver, operation and outcome.",
            &[
                ("driver", "none"),
                ("operation", "none"),
                ("outcome", "none"),
            ],
        );
        self.adapter_operations_total.render(
            &mut out,
            "tirbase_adapter_operations_total",
            "Adapter operations by adapter, operation and outcome.",
            &[
                ("adapter", "none"),
                ("operation", "none"),
                ("outcome", "none"),
            ],
        );
        self.gateway_requests_total.render(
            &mut out,
            "tirbase_gateway_requests_total",
            "Gateway requests by surface, method and status class.",
            &[("surface", "none"), ("method", "none"), ("status", "none")],
        );
        self.vertical_appends_total.render(
            &mut out,
            "tirbase_vertical_appends_total",
            "Vertical ledger appends by vertical.",
            &[("vertical", "none")],
        );
        self.gate_decisions_total.render(
            &mut out,
            "tirbase_gate_decisions_total",
            "Venue gate decisions by vertical and outcome.",
            &[("vertical", "venues"), ("outcome", "none")],
        );

        out.push_str("# HELP tirbase_build_info Build identity for the running gateway.\n");
        out.push_str("# TYPE tirbase_build_info gauge\n");
        out.push_str(&format!(
            "tirbase_build_info{{version=\"{}\",licence=\"AGPL-3.0-only\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slo_histograms_and_labelled_counters_render() {
        let metrics = GatewayMetrics::default();
        metrics.observe_guard_decision(Duration::from_millis(20));
        metrics.observe_ledger_append(Duration::from_millis(80));
        metrics.observe_alarm_delivery(Duration::from_secs(3));
        metrics.observe_gate_decision(Duration::from_millis(40));
        metrics.observe_payment_intent_completion(Duration::from_secs(90));
        metrics.observe_vertical_request("pos", Duration::from_millis(12));
        metrics.inc_alarm_delivery("cold-chain", "delivered");
        metrics.inc_payment_intent("pos", "completed");
        metrics.inc_driver_operation("modbus", "read", "ok");
        metrics.inc_adapter_operation("mqtt", "publish", "ok");
        metrics.inc_gateway_request("admin", "GET", "2xx");
        metrics.inc_vertical_append("cold-chain");
        metrics.inc_gate_decision("venues", "allowed");

        let body = metrics.render_prometheus();
        for name in [
            "tirbase_guard_decision_seconds_bucket",
            "tirbase_ledger_append_seconds_sum",
            "tirbase_alarm_delivery_seconds_count",
            "tirbase_gate_decision_seconds_bucket",
            "tirbase_payment_intent_completion_seconds_bucket",
            "tirbase_vertical_request_seconds_bucket{vertical=\"pos\",le=",
            "tirbase_alarm_deliveries_total{vertical=\"cold-chain\",outcome=\"delivered\"}",
            "tirbase_payment_intents_total{vertical=\"pos\",outcome=\"completed\"}",
            "tirbase_driver_operations_total{driver=\"modbus\",operation=\"read\",outcome=\"ok\"}",
            "tirbase_adapter_operations_total{adapter=\"mqtt\",operation=\"publish\",outcome=\"ok\"}",
            "tirbase_gateway_requests_total{surface=\"admin\",method=\"GET\",status=\"2xx\"}",
            "tirbase_vertical_appends_total{vertical=\"cold-chain\"}",
            "tirbase_gate_decisions_total{vertical=\"venues\",outcome=\"allowed\"}",
            "tirbase_build_info{version=",
        ] {
            assert!(body.contains(name), "missing {name} in:\n{body}");
        }
    }

    #[test]
    fn label_values_are_escaped() {
        let metrics = GatewayMetrics::default();
        metrics.inc_alarm_delivery("a\"b", "delivered");
        let body = metrics.render_prometheus();
        assert!(body.contains("vertical=\"a\\\"b\""), "{body}");
    }
}
