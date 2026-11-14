// SPDX-License-Identifier: AGPL-3.0-only

//! F-08 acceptance: vertical resource journey, tenant isolation, idempotency,
//! webhook signatures/retries/replay protection.

use std::collections::BTreeMap;
use std::sync::Arc;

use tirbase_gateway::vertical_api::VerticalApi;
use tirbase_gateway::webhooks::{
    self, signed_headers, verify_webhook, WebhookDispatcher, WebhookHeaders, WebhookTransport,
};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tirbase-f08-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn json_body(status_body: &str) -> serde_json::Value {
    serde_json::from_str(status_body).expect("JSON response")
}

fn create(api: &VerticalApi, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let (status, text) = api.dispatch("POST", path, Some(&body.to_string()), 1_000);
    (status, json_body(&text))
}

#[test]
fn f08_full_vertical_journey_is_tenant_scoped_and_paginated() {
    let dir = temp_dir("journey");
    let api = VerticalApi::open(dir.join("primary.db")).unwrap();

    let (status, site) = create(
        &api,
        "/admin/cold-chain/sites",
        serde_json::json!({"tenant":"acme","name":"Cold Room 1","idempotency_key":"site-1"}),
    );
    assert_eq!(status, 201);
    let site_id = site["object"]["id"].as_str().unwrap().to_string();
    // Replaying the idempotency key returns the original object.
    let (status, replay) = create(
        &api,
        "/admin/cold-chain/sites",
        serde_json::json!({"tenant":"acme","name":"Cold Room 1b","idempotency_key":"site-1"}),
    );
    assert_eq!(status, 200);
    assert_eq!(replay["idempotent_replay"], true);
    assert_eq!(replay["object"]["id"], site_id);

    let (status, reading) = create(
        &api,
        &format!("/admin/cold-chain/sites/{site_id}/readings"),
        serde_json::json!({"tenant":"acme","celsius_milli":-18_500}),
    );
    assert_eq!(status, 201);
    assert_eq!(reading["object"]["parent_id"], site_id);

    let (status, order) = create(
        &api,
        "/admin/pos/orders",
        serde_json::json!({"tenant":"acme","currency":"EUR","total_minor":1250}),
    );
    assert_eq!(status, 201);
    let order_id = order["object"]["id"].as_str().unwrap().to_string();
    let (status, line) = create(
        &api,
        &format!("/admin/pos/orders/{order_id}/lines"),
        serde_json::json!({
            "tenant":"acme","sku":"SKU-1","quantity":2,"unit_price_minor":625
        }),
    );
    assert_eq!(status, 201);
    assert_eq!(line["object"]["data"]["sku"], "SKU-1");

    let (status, venue) = create(
        &api,
        "/admin/venues",
        serde_json::json!({"tenant":"acme","name":"North Stand"}),
    );
    assert_eq!(status, 201);
    let venue_id = venue["object"]["id"].as_str().unwrap().to_string();
    let (status, gate) = create(
        &api,
        &format!("/admin/venues/{venue_id}/gates"),
        serde_json::json!({"tenant":"acme","name":"Gate A"}),
    );
    assert_eq!(status, 201);
    assert_eq!(gate["object"]["data"]["name"], "Gate A");

    // Pagination.
    create(
        &api,
        &format!("/admin/cold-chain/sites/{site_id}/readings"),
        serde_json::json!({"tenant":"acme","celsius_milli":-19_000}),
    );
    let (status, text) = api.dispatch(
        "GET",
        &format!("/admin/cold-chain/sites/{site_id}/readings?tenant=acme&limit=1"),
        None,
        1_000,
    );
    assert_eq!(status, 200);
    let page = json_body(&text);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["total"], 2);
    assert!(page["next_cursor"].is_string());

    // Cross-tenant reads/writes are invisible.
    let (status, text) = api.dispatch(
        "GET",
        "/admin/cold-chain/sites?tenant=other",
        None,
        1_000,
    );
    assert_eq!(status, 200);
    assert_eq!(json_body(&text)["total"], 0);
    let (status, _) = api.dispatch(
        "GET",
        &format!("/admin/cold-chain/sites/{site_id}?tenant=other"),
        None,
        1_000,
    );
    assert_eq!(status, 404);

    // Validation and conflicts are explicit.
    let (status, body) = create(
        &api,
        "/admin/pos/orders",
        serde_json::json!({"tenant":"acme","currency":"EURO","total_minor":1}),
    );
    assert_eq!(status, 400);
    assert_eq!(body["code"], "VERTICAL_BAD_REQUEST");
    let (status, _) = create(
        &api,
        "/admin/cold-chain/sites",
        serde_json::json!({"tenant":"acme","id":"fixed","name":"A"}),
    );
    assert_eq!(status, 201);
    let (status, body) = create(
        &api,
        "/admin/cold-chain/sites",
        serde_json::json!({"tenant":"acme","id":"fixed","name":"B"}),
    );
    assert_eq!(status, 409);
    assert_eq!(body["code"], "VERTICAL_ID_CONFLICT");

    let _ = std::fs::remove_dir_all(&dir);
}

type RecordedCall = (String, BTreeMap<String, String>, String);

#[derive(Debug, Default)]
struct RecordingTransport {
    fail: bool,
    calls: std::sync::Mutex<Vec<RecordedCall>>,
}

impl WebhookTransport for RecordingTransport {
    fn post(
        &self,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: &str,
    ) -> Result<u16, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.to_string(), headers.clone(), body.to_string()));
        if self.fail {
            Err("sink unavailable".to_string())
        } else {
            Ok(204)
        }
    }
}

#[test]
fn f08_webhooks_are_signed_retried_and_replay_protected() {
    let dir = temp_dir("webhook");
    let dispatcher =
        Arc::new(WebhookDispatcher::open(dir.join("primary.db")).unwrap());
    dispatcher
        .add_endpoint("ep-1", "https://sink.example/hook", "0123456789abcdef", 100)
        .unwrap();
    let api = VerticalApi::open(dir.join("primary.db"))
        .unwrap()
        .with_webhooks(dispatcher.clone());

    let (status, _) = create(
        &api,
        "/admin/venues",
        serde_json::json!({"tenant":"acme","name":"Arena"}),
    );
    assert_eq!(status, 201);
    let pending = dispatcher.pending(1_000).unwrap();
    assert_eq!(pending.len(), 1);
    let delivery = &pending[0];
    assert_eq!(delivery.event_type, "venues.venue.created");

    // Signature covers timestamp + body; a valid signature verifies once.
    let headers = signed_headers(
        "0123456789abcdef",
        &delivery.delivery_id,
        1_000,
        &delivery.payload_json,
    )
    .unwrap();
    verify_webhook(
        &dispatcher,
        "0123456789abcdef",
        &headers,
        &delivery.payload_json,
        1_000,
        true,
    )
    .unwrap();
    let replay = verify_webhook(
        &dispatcher,
        "0123456789abcdef",
        &headers,
        &delivery.payload_json,
        1_001,
        true,
    );
    assert!(replay.is_err(), "replayed delivery id must be rejected");

    // Stale timestamps and tampered bodies fail before replay handling.
    let stale = WebhookHeaders {
        timestamp: 1,
        ..headers.clone()
    };
    assert!(verify_webhook(
        &dispatcher,
        "0123456789abcdef",
        &stale,
        &delivery.payload_json,
        1_000,
        false
    )
    .is_err());
    assert!(verify_webhook(
        &dispatcher,
        "0123456789abcdef",
        &headers,
        "{\"tampered\":true}",
        1_000,
        false
    )
    .is_err());

    // A failed attempt schedules a bounded retry rather than losing the event.
    let failing = RecordingTransport {
        fail: true,
        ..Default::default()
    };
    let (delivered, failed) = dispatcher.deliver_pending(&failing, 1_000).unwrap();
    assert_eq!((delivered, failed), (0, 1));
    let after = dispatcher.pending(2_000).unwrap();
    assert_eq!(after.len(), 1);
    assert!(after[0].next_attempt_est > 1_000);

    let working = RecordingTransport::default();
    let (delivered, failed) = dispatcher
        .deliver_pending(&working, after[0].next_attempt_est)
        .unwrap();
    assert_eq!((delivered, failed), (1, 0));
    let calls = working.calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://sink.example/hook");
    assert!(calls[0].1.contains_key("X-TirBase-Signature"));
    assert!(dispatcher.pending(10_000).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f08_webhook_signing_is_deterministic_and_key_bound() {
    let a = webhooks::sign_webhook("secret-secret-secret", 42, "{\"a\":1}").unwrap();
    let b = webhooks::sign_webhook("secret-secret-secret", 42, "{\"a\":1}").unwrap();
    let c = webhooks::sign_webhook("other-secret-secret", 42, "{\"a\":1}").unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(a.starts_with("sha256="));
}
