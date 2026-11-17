// SPDX-License-Identifier: AGPL-3.0-only

//! CC-21: `/admin/reporting/*` over HTTP.
//!
//! A loopback HTTP/1.1 listener forwards each request to the real
//! [`tirbase_gateway::admin::dispatch_http_request`] path, so the test exercises
//! routing, credential checks, tenant scoping and the JSON contracts the audit
//! screen consumes — not a private helper.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use tirbase_gateway::admin::{dispatch_http_request, AdminCaller, AdminState};
use tirbase_gateway::reporting::{
    CeremonyRequest, ReauthMethod, ReauthProof, ReportKind, ReportRequest, ReportService,
    ReportSigner, SignerEnrollment,
};

const SEED: &str = r#"
CREATE TABLE IF NOT EXISTS excursion_records (
    record_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, site_id TEXT NOT NULL,
    device_id TEXT NOT NULL, lot_id TEXT, state TEXT NOT NULL, state_rank INTEGER NOT NULL,
    opened_est INTEGER NOT NULL, updated_est INTEGER NOT NULL, revision INTEGER NOT NULL,
    detection_json TEXT NOT NULL, disposition_json TEXT, resolution_json TEXT, closed_est INTEGER
);
CREATE TABLE IF NOT EXISTS excursion_events (
    record_id TEXT NOT NULL, seq INTEGER NOT NULL, event TEXT NOT NULL,
    at_est INTEGER NOT NULL, detail_json TEXT NOT NULL, PRIMARY KEY (record_id, seq)
);
"#;

fn hex_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn seed(db: &Path) {
    let conn = Connection::open(db).expect("seed db");
    conn.execute_batch(SEED).expect("seed schema");
    conn.execute(
        "INSERT INTO excursion_records (record_id, tenant, site_id, device_id, lot_id, state, \
         state_rank, opened_est, updated_est, revision, detection_json) \
         VALUES ('e-1', 'acme', 's1', 'd1', 'L1', 'quarantined', 1, 1000, 2000, 1, ?1)",
        [r#"{"reasons":["temperature_high"],"max_c":125}"#],
    )
    .expect("excursion");
    conn.execute(
        "INSERT INTO excursion_events (record_id, seq, event, at_est, detail_json) \
         VALUES ('e-1', 1, 'detected', 1000, '{\"reasons\":[\"temperature_high\"]}')",
        [],
    )
    .expect("event");
}

/// Loopback HTTP/1.1 server that answers `expected` requests through the real
/// admin dispatcher as a kernel-attested local caller.
fn serve(
    state: Arc<AdminState>,
    listener: TcpListener,
    expected: usize,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..expected {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break None,
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                }
                if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(position + 4);
                }
            };
            let Some(header_end) = header_end else {
                continue;
            };
            let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default().to_string();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let path = parts.next().unwrap_or("/").to_string();
            let content_length = lines
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buffer.len() < header_end + content_length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                }
            }
            let body = String::from_utf8_lossy(&buffer[header_end..]).to_string();
            let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or(10_000);
            let (status, response) = dispatch_http_request(
                &method,
                &path,
                if body.is_empty() { None } else { Some(&body) },
                Some(&state),
                now_est,
                &AdminCaller::Local,
            );
            let _ = write!(
                stream,
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
        }
    })
}

fn http_get(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let (head, body) = raw.split_once("\r\n\r\n").expect("http response");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("status line");
    (status, serde_json::from_str(body).expect("json body"))
}

fn http_post(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let (head, body) = raw.split_once("\r\n\r\n").expect("http response");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("status line");
    (status, serde_json::from_str(body).expect("json body"))
}

#[test]
fn reporting_endpoints_serve_the_audit_screen_over_http() {
    let directory = tempfile::tempdir().expect("tempdir");
    let db = directory.path().join("primary.db");
    let service = ReportService::open(&db, ReportSigner::from_seed(&[7u8; 32])).expect("service");
    seed(&db);

    let acme_report = service
        .generate(&ReportRequest::new(
            ReportKind::ExcursionHistory,
            "acme",
            "did:qa",
            10_000,
        ))
        .expect("acme report");
    let acme_aging = service
        .generate(&ReportRequest::new(
            ReportKind::QuarantineAging,
            "acme",
            "did:qa",
            10_000,
        ))
        .expect("aging report");
    let northwind = service
        .generate(&ReportRequest::new(
            ReportKind::ExcursionHistory,
            "northwind",
            "did:qa",
            10_000,
        ))
        .expect("northwind report");

    service
        .enroll_signer(
            &SignerEnrollment {
                signer_id: "did:qa".to_string(),
                credential_sha256: hex_digest("correct horse"),
                role: "quality".to_string(),
                enrolled_est: 1000,
            },
            "did:admin",
        )
        .expect("enroll");
    service
        .open_ceremony(&CeremonyRequest::new(
            "c-1",
            &acme_report.report_id,
            "did:qa",
            "Approving batch release",
            ReauthProof {
                method: ReauthMethod::Password,
                at_est: 9_900,
                credential_sha256: hex_digest("correct horse"),
            },
            10_000,
        ))
        .expect("ceremony");
    let signature = service.sign_ceremony("c-1", 10_050).expect("signature");

    let state = Arc::new(AdminState {
        reporting: Some(Arc::new(Mutex::new(service))),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = serve(state, listener, 13);

    // Listing is tenant-scoped and kind filtering is honoured.
    let (status, list) = http_get(addr, "/admin/reporting/reports?tenant=acme&limit=10");
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["items"].as_array().expect("items").len(), 2);
    let filtered = http_get(
        addr,
        "/admin/reporting/reports?tenant=acme&kind=excursion_history",
    );
    assert_eq!(filtered.0, 200, "{}", filtered.1);
    assert_eq!(filtered.1["items"].as_array().expect("items").len(), 1);

    let (_, other) = http_get(addr, "/admin/reporting/reports?tenant=northwind");
    assert_eq!(other["items"].as_array().expect("items").len(), 1);
    assert_eq!(other["items"][0]["report_id"], northwind.report_id.as_str());

    // Detail returns the report for its own tenant only.
    let detail_path = format!(
        "/admin/reporting/reports/{}?tenant=acme",
        acme_report.report_id
    );
    let (status, detail) = http_get(addr, &detail_path);
    assert_eq!(status, 200, "{detail}");
    assert_eq!(
        detail["report"]["report_id"],
        acme_report.report_id.as_str()
    );
    assert_eq!(detail["report"]["tenant"], "acme");
    let (status, denied) = http_get(
        addr,
        &format!(
            "/admin/reporting/reports/{}?tenant=northwind",
            acme_report.report_id
        ),
    );
    assert_eq!(status, 404, "{denied}");
    assert_eq!(denied["error"], "unknown report");

    // Signatures are listed for the owning tenant.
    let (status, signatures) = http_get(
        addr,
        &format!(
            "/admin/reporting/reports/{}/signatures?tenant=acme",
            acme_report.report_id
        ),
    );
    assert_eq!(status, 200, "{signatures}");
    let listed = signatures["signatures"].as_array().expect("signatures");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["signature_id"], signature.signature_id.as_str());
    assert_eq!(listed[0]["signer_id"], "did:qa");
    assert_eq!(listed[0]["reason"], "Approving batch release");

    // Audit entries are filtered to the tenant's reports, exports and signatures.
    let (status, audit) = http_get(addr, "/admin/reporting/audit?tenant=acme&limit=100");
    assert_eq!(status, 200, "{audit}");
    let entries = audit["entries"].as_array().expect("entries");
    assert!(!entries.is_empty());
    let acme_subjects = [
        acme_report.report_id.clone(),
        acme_aging.report_id.clone(),
        signature.ceremony_id.clone(),
        signature.signature_id.clone(),
    ];
    for entry in entries {
        let subject = entry["subject"].as_str().expect("subject");
        assert!(
            acme_subjects.iter().any(|id| id == subject),
            "tenant audit leaked {subject}"
        );
        assert_ne!(subject, northwind.report_id);
    }

    let (status, other_audit) = http_get(addr, "/admin/reporting/audit?tenant=northwind");
    assert_eq!(status, 200, "{other_audit}");
    let other_entries = other_audit["entries"].as_array().expect("entries");
    assert_eq!(other_entries.len(), 1);
    assert_eq!(other_entries[0]["subject"], northwind.report_id.as_str());

    // Chain verification.
    let (status, verification) = http_get(addr, "/admin/reporting/audit/verify?tenant=acme");
    assert_eq!(status, 200, "{verification}");
    assert_eq!(verification["verification"]["valid"], true);
    assert!(
        verification["verification"]["entries"]
            .as_u64()
            .unwrap_or_default()
            >= 4
    );

    // A missing tenant parameter is refused, not defaulted.
    let (status, missing) = http_get(addr, "/admin/reporting/audit");
    assert_eq!(status, 400, "{missing}");
    assert_eq!(missing["error"], "tenant query parameter is required");
    let (status, missing) = http_get(addr, "/admin/reporting/reports");
    assert_eq!(status, 400, "{missing}");

    // An unknown report and a write are refused.
    let (status, unknown) = http_get(addr, "/admin/reporting/reports/rpt-0000?tenant=acme");
    assert_eq!(status, 404, "{unknown}");
    let (status, write) = http_post(addr, "/admin/reporting/reports?tenant=acme");
    assert_eq!(status, 405, "{write}");

    server.join().expect("server thread");
}

#[test]
fn reporting_endpoints_fail_closed_without_a_service_or_credential() {
    // No reporting service mounted: 503, never a fabricated empty page.
    let (status, response) = dispatch_http_request(
        "GET",
        "/admin/reporting/reports?tenant=acme",
        None,
        Some(&AdminState::default()),
        10_000,
        &AdminCaller::Local,
    );
    assert_eq!(status, 503, "{response}");
    assert!(response.contains("ADMIN_STATE_UNCONFIGURED"), "{response}");

    let directory = tempfile::tempdir().expect("tempdir");
    let db = directory.path().join("primary.db");
    let service = ReportService::open(&db, ReportSigner::from_seed(&[7u8; 32])).expect("service");
    let state = AdminState {
        reporting: Some(Arc::new(Mutex::new(service))),
        ..Default::default()
    };

    // A remote caller without a scoped credential is refused before any read.
    for caller in [
        AdminCaller::Remote {
            biscuit_token_hex: None,
        },
        AdminCaller::Remote {
            biscuit_token_hex: Some("00ff".to_string()),
        },
    ] {
        let (status, response) = dispatch_http_request(
            "GET",
            "/admin/reporting/reports?tenant=acme",
            None,
            Some(&state),
            10_000,
            &caller,
        );
        assert_eq!(status, 401, "{response}");
    }
}
