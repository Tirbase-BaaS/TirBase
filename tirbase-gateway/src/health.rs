//! Health endpoint: `GET /health` → 200 OK
//!
//! Binds to 127.0.0.1 on the configured port.
//! Returns 200 OK with JSON body `{"status":"ok"}` within 500 ms (PV-30.3).
//! No guard state is read at this stage — pure liveness check only.
//!
//! CLAIMS: CLAIM-4.9.3

use anyhow::Result;
use axum::{routing::get, Router};
use std::net::SocketAddr;

/// Start the health HTTP server on the given address.
///
/// The function binds a TCP listener at `addr`, registers `GET /health`,
/// and drives the `axum::serve` loop.  The returned `Future` resolves only
/// if the server shuts down (or on error).
pub async fn run_health_server(addr: SocketAddr) -> Result<()> {
    let app = Router::new().route("/health", get(health_handler));

    tracing::info!("health endpoint listening on http://{addr}/health");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Handler: always returns 200 OK with `{"status":"ok"}`.
async fn health_handler() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({"status": "ok"}))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Validates: PV-30.3 — health endpoint returns 200 OK within 500 ms,
    /// bound to 127.0.0.1.
    ///
    /// CLAIMS: CLAIM-4.9.3
    #[tokio::test]
    async fn health_returns_200_within_500ms() {
        // Bind to a random port so parallel test runs never conflict.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind to ephemeral port");
        let addr = listener.local_addr().expect("local_addr");

        let app = axum::Router::new().route("/health", axum::routing::get(health_handler));

        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("health server exited unexpectedly");
        });

        // Give the server a moment to accept connections.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let start = Instant::now();
        let resp = reqwest::get(format!("http://{addr}/health"))
            .await
            .expect("GET /health");
        let elapsed = start.elapsed();

        assert_eq!(resp.status(), 200, "expected 200 OK from /health");
        assert!(
            elapsed < Duration::from_millis(500),
            "health endpoint took {elapsed:?}, expected < 500 ms"
        );

        // Verify the body is {"status":"ok"}.
        let body: serde_json::Value = resp.json().await.expect("JSON body");
        assert_eq!(body["status"], "ok", "unexpected body: {body}");
    }
}
