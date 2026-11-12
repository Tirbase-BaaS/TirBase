//! Health endpoint and watchdog keepalive (CLAIM-4.9.3,
//! CLAIM-13.7, PV-4.15).
//!
//! * `GET /health` → 200 OK within 500 ms on 127.0.0.1 (liveness).
//! * A dedicated forward-progress health-loop task runs independently of
//! command evaluation and sends `sd_notify WATCHDOG=1` on each iteration.
//! Stalling the loop causes the systemd watchdog to time out.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{routing::get, Router};
use tokio::sync::Notify;

/// Shared counters proving the health loop is making forward progress.
#[derive(Debug, Default)]
pub struct HealthLoopState {
    ticks: AtomicU64,
}

impl HealthLoopState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Acquire)
    }
    fn tick(&self) -> u64 {
        self.ticks.fetch_add(1, Ordering::AcqRel) + 1
    }
}

/// Sink for watchdog keepalives (testable; production uses sd_notify).
pub trait WatchdogNotifier: Send + Sync + std::fmt::Debug {
    fn notify_watchdog(&self);
}

#[derive(Debug, Default)]
pub struct NoopWatchdogNotifier;
impl WatchdogNotifier for NoopWatchdogNotifier {
    fn notify_watchdog(&self) {}
}

/// Production sd_notify notifier (Linux). On non-Linux or when not running
/// under systemd with watchdog enabled, the call is a harmless no-op/best-effort.
#[derive(Debug, Default)]
pub struct SdNotifyWatchdogNotifier;
impl WatchdogNotifier for SdNotifyWatchdogNotifier {
    fn notify_watchdog(&self) {
        #[cfg(target_os = "linux")]
        {
 // Best-effort: if not under systemd watchdog this is ignored.
 // Use the minimal NOTIFY_SOCKET protocol to avoid a libsystemd dep.
            if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
                use std::os::unix::net::UnixDatagram;
                if let Ok(sock) = UnixDatagram::unbound() {
                    let _ = sock.send_to(b"WATCHDOG=1", socket_path);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ();
        }
    }
}

/// Run the forward-progress health loop (CLAIM-13.7).
///
/// `interval` controls cadence. The loop is *not* tied to `evaluate()`/command
/// admission; it proves the process is alive and making progress. It stops
/// when `shutdown` is notified.
pub async fn run_health_loop(
    state: Arc<HealthLoopState>,
    notifier: Arc<dyn WatchdogNotifier>,
    interval: Duration,
    shutdown: Arc<Notify>,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                state.tick();
                notifier.notify_watchdog();
            }
            _ = shutdown.notified() => break,
        }
    }
}

/// Start the health HTTP server on the given address.
pub async fn run_health_server(addr: std::net::SocketAddr) -> Result<()> {
    let app = Router::new().route("/health", get(health_handler));
    tracing::info!("health endpoint listening on http://{addr}/health");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_handler() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({"status": "ok"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[derive(Debug, Default)]
    struct CountingNotifier(AtomicU64);
    impl WatchdogNotifier for CountingNotifier {
        fn notify_watchdog(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl CountingNotifier {
        fn count(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn health_returns_200_within_500ms() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let app = axum::Router::new().route("/health", axum::routing::get(health_handler));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let start = tirbase_core::traits::monotonic_now();
        let resp = reqwest::get(format!("http://{addr}/health"))
            .await
            .expect("GET");
        assert_eq!(resp.status(), 200);
        assert!(tirbase_core::traits::monotonic_now().saturating_sub(start) < 500_000);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn watchdog_keepalive_sent_every_iteration_claim_13_7() {
        let state = HealthLoopState::new();
        let notifier = Arc::new(CountingNotifier::default());
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(run_health_loop(
            state.clone(),
            notifier.clone() as Arc<dyn WatchdogNotifier>,
            Duration::from_millis(20),
            shutdown.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(120)).await;
        shutdown.notify_one();
        let _ = task.await;
        assert!(
            state.ticks() >= 3,
            "health loop must make forward progress (ticks={})",
            state.ticks()
        );
        assert!(
            notifier.count() >= 3,
            "WATCHDOG=1 must be sent each iteration (count={})",
            notifier.count()
        );
    }

    #[tokio::test]
    async fn stalled_health_loop_stops_sending_watchdog_claim_13_7() {
 // Wiring-mutation/proof proxy: if the loop does not run, no keepalives
 // are sent. (A real watchdog timeout is a systemd behavior; this test
 // proves the notifier is driven only by the loop.)
        let state = HealthLoopState::new();
        let notifier = Arc::new(CountingNotifier::default());
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(run_health_loop(
            state.clone(),
            notifier.clone() as Arc<dyn WatchdogNotifier>,
            Duration::from_millis(20),
            shutdown.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(70)).await;
        let before = notifier.count();
 // "Stall" by stopping the loop (simulates a stalled forward-progress task).
        shutdown.notify_one();
        let _ = task.await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            notifier.count(),
            before,
            "stalled/stopped loop must not send watchdog keepalives"
        );
        assert!(state.ticks() >= 2);
    }
}

/// Test-only counting notifier (exported for integration tests).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct CountingNotifier(pub AtomicU64);
#[cfg(any(test, feature = "test-util"))]
impl WatchdogNotifier for CountingNotifier {
    fn notify_watchdog(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[cfg(any(test, feature = "test-util"))]
impl CountingNotifier {
    pub fn count(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
