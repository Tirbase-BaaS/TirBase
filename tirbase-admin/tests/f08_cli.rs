// SPDX-License-Identifier: AGPL-3.0-only

//! F-08: the admin CLI drives the same vertical resources and webhooks as the
//! HTTP API.

use tirbase_admin::cmd;

#[test]
fn cli_vertical_journey_and_webhook_management() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("primary.db");
    let create = |vertical: &str, kind: &str, data: &str| {
        cmd::vertical::run(&cmd::vertical::VerticalArgs {
            db_path: db.clone(),
            action: "create".into(),
            vertical: vertical.into(),
            kind: kind.into(),
            id: None,
            parent_id: None,
            tenant: Some("acme".into()),
            data_json: Some(data.into()),
            limit: None,
            cursor: None,
        })
        .unwrap()
    };

    let site = create("cold-chain", "sites", r#"{"name":"Cold Room 1"}"#);
    assert_eq!(site.status, 201);
    let site_json: serde_json::Value = serde_json::from_str(&site.body).unwrap();
    let site_id = site_json["object"]["id"].as_str().unwrap().to_string();

    let reading = cmd::vertical::run(&cmd::vertical::VerticalArgs {
        db_path: db.clone(),
        action: "create".into(),
        vertical: "cold-chain".into(),
        kind: "readings".into(),
        id: None,
        parent_id: None,
        tenant: Some("acme".into()),
        data_json: Some(r#"{"celsius_milli":-18500}"#.into()),
        limit: None,
        cursor: None,
    });
    // A reading without --parent-id addresses a root collection the server
    // does not expose; the CLI must surface that as an error, not success.
    assert!(reading.is_err());

    let child = cmd::vertical::run(&cmd::vertical::VerticalArgs {
        db_path: db.clone(),
        action: "create".into(),
        vertical: "cold-chain".into(),
        kind: "readings".into(),
        id: None,
        parent_id: Some(site_id.clone()),
        tenant: Some("acme".into()),
        data_json: Some(r#"{"celsius_milli":-18500}"#.into()),
        limit: None,
        cursor: None,
    })
    .unwrap();
    assert_eq!(child.status, 201);

    let list = cmd::vertical::run(&cmd::vertical::VerticalArgs {
        db_path: db.clone(),
        action: "list".into(),
        vertical: "cold-chain".into(),
        kind: "readings".into(),
        id: None,
        parent_id: Some(site_id),
        tenant: Some("acme".into()),
        data_json: None,
        limit: Some(10),
        cursor: None,
    })
    .unwrap();
    let list_json: serde_json::Value = serde_json::from_str(&list.body).unwrap();
    assert_eq!(list_json["total"], 1);

    let secret_path = dir.path().join("webhook.secret");
    std::fs::write(&secret_path, "0123456789abcdef\n").unwrap();
    let added = cmd::webhook::run(&cmd::webhook::WebhookArgs {
        db_path: db.clone(),
        action: "add".into(),
        endpoint_id: Some("ep-1".into()),
        url: Some("https://sink.example/hook".into()),
        secret_file: Some(secret_path),
        now_est: 1_000,
    })
    .unwrap();
    assert!(added.contains("\"endpoint_id\":\"ep-1\""));
    assert!(
        !added.contains("0123456789abcdef"),
        "secret must not be printed"
    );

    let listed = cmd::webhook::run(&cmd::webhook::WebhookArgs {
        db_path: db,
        action: "list".into(),
        endpoint_id: None,
        url: None,
        secret_file: None,
        now_est: 1_000,
    })
    .unwrap();
    assert!(listed.contains("https://sink.example/hook"));
    assert!(!listed.contains("\"secret\""));
}
