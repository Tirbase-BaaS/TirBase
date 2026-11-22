// SPDX-License-Identifier: AGPL-3.0-only

//! Minimal std-only HTTP surface for the Apache-2.0 command-center console.
//!
//! JSON only, loopback by default, CORS enabled so the static UI can be served
//! separately. Every mutation carries actor and role and returns the command
//! center's attributable error rather than a generic 500.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::engine::{CommandCenter, CommandError, LockCommand};
use crate::model::{IncidentActionKind, Role};

const MAX_BODY: usize = 1_048_576;

/// Run the HTTP server until the listener fails.
pub fn serve(listener: TcpListener, center: Arc<Mutex<CommandCenter>>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let center = Arc::clone(&center);
                thread::spawn(move || {
                    if let Err(error) = handle(stream, center) {
                        eprintln!("command-center connection error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("command-center accept error: {error}"),
        }
    }
}

/// Bind and serve the command center.
pub fn run(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "venue-command-center listening on http://127.0.0.1:{}",
        listener.local_addr()?.port()
    );
    let center = CommandCenter::new(now_utc_us())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    serve(listener, Arc::new(Mutex::new(center)));
    Ok(())
}

fn handle(mut stream: TcpStream, center: Arc<Mutex<CommandCenter>>) -> std::io::Result<()> {
    let Some(request) = read_request(&mut stream)? else {
        return Ok(());
    };
    let (status, body) = route(&request, &center);
    let body =
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Unprocessable Entity",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type,x-actor,x-role\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut raw = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(None);
        }
        raw.extend_from_slice(&buffer[..read]);
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if raw.len() > 64 * 1024 {
            return Ok(None);
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let Some(first) = lines.next() else {
        return Ok(None);
    };
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let path = target.split('?').next().unwrap_or_default().to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);
    let mut body = raw[header_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..read]);
    }
    body.truncate(length);
    Ok(Some(Request {
        method,
        path,
        headers,
        body,
    }))
}

fn route(request: &Request, center: &Arc<Mutex<CommandCenter>>) -> (u16, Value) {
    if request.method == "OPTIONS" {
        return (200, json!({"ok": true}));
    }
    if request.method == "GET" && request.path == "/api/health" {
        return (
            200,
            json!({"status":"ok","service":"tirbase-venue-command-center"}),
        );
    }
    if request.method == "GET" && request.path == "/api/state" {
        let actor = header(request, "x-actor").unwrap_or("anonymous");
        let role = header(request, "x-role")
            .and_then(Role::parse)
            .unwrap_or(Role::Auditor);
        let center = center.lock().expect("command center lock");
        return (
            200,
            serde_json::to_value(center.snapshot(actor, role, now_utc_us()))
                .expect("snapshot serializes"),
        );
    }
    if request.method == "POST" {
        if let Some(incident_id) = request
            .path
            .strip_prefix("/api/incidents/")
            .and_then(|rest| rest.strip_suffix("/actions"))
        {
            return incident_action(request, center, incident_id);
        }
        match request.path.as_str() {
            "/api/lockdown" => return lockdown(request, center),
            "/api/drill/start" => return drill(request, center, true),
            "/api/drill/end" => return drill(request, center, false),
            _ => {}
        }
    }
    (
        404,
        json!({"code":"not_found","message":"unknown endpoint"}),
    )
}

#[derive(Deserialize)]
struct ActorBody {
    actor: String,
    role: Role,
}

#[derive(Deserialize)]
struct IncidentBody {
    action: String,
    note: Option<String>,
    actor: String,
    role: Role,
}

#[derive(Deserialize)]
struct LockdownBody {
    command: String,
    scope: String,
    reason: String,
    approvers: Vec<String>,
    actor: String,
    role: Role,
}

fn incident_action(
    request: &Request,
    center: &Arc<Mutex<CommandCenter>>,
    incident_id: &str,
) -> (u16, Value) {
    let body: IncidentBody = match parse_body(request) {
        Ok(body) => body,
        Err(error) => return error_response(error),
    };
    let Some(kind) = IncidentActionKind::parse(&body.action) else {
        return (
            422,
            json!({"code":"invalid_action","message":"unknown incident action"}),
        );
    };
    let mut center = center.lock().expect("command center lock");
    match center.incident_action(
        &body.actor,
        body.role,
        incident_id,
        kind,
        body.note.as_deref(),
        now_utc_us(),
    ) {
        Ok(incident) => (
            200,
            serde_json::to_value(incident).expect("incident serializes"),
        ),
        Err(error) => error_response(error),
    }
}

fn lockdown(request: &Request, center: &Arc<Mutex<CommandCenter>>) -> (u16, Value) {
    let body: LockdownBody = match parse_body(request) {
        Ok(body) => body,
        Err(error) => return error_response(error),
    };
    let Some(command) = LockCommand::parse(&body.command) else {
        return (
            422,
            json!({"code":"invalid_action","message":"command must be lockdown or release"}),
        );
    };
    let mut center = center.lock().expect("command center lock");
    match center.lockdown(
        &body.actor,
        body.role,
        command,
        &body.scope,
        &body.reason,
        &body.approvers,
        now_utc_us(),
    ) {
        Ok(outcome) => (
            200,
            serde_json::to_value(outcome).expect("outcome serializes"),
        ),
        Err(error) => error_response(error),
    }
}

fn drill(request: &Request, center: &Arc<Mutex<CommandCenter>>, start: bool) -> (u16, Value) {
    let body: ActorBody = match parse_body(request) {
        Ok(body) => body,
        Err(error) => return error_response(error),
    };
    let mut center = center.lock().expect("command center lock");
    let now = now_utc_us();
    let result = if start {
        center
            .start_drill(&body.actor, body.role, now)
            .map(|snapshot| serde_json::to_value(snapshot).expect("snapshot serializes"))
    } else {
        center
            .end_drill(&body.actor, body.role, now)
            .map(|report| serde_json::to_value(report).expect("after-action report serializes"))
    };
    match result {
        Ok(value) => (200, value),
        Err(error) => error_response(error),
    }
}

fn parse_body<T: for<'de> Deserialize<'de>>(request: &Request) -> Result<T, CommandError> {
    serde_json::from_slice(&request.body).map_err(|_| CommandError {
        code: "invalid_body",
        message: "request body is not valid JSON for this endpoint".to_string(),
    })
}

fn error_response(error: CommandError) -> (u16, Value) {
    (
        error.http_status(),
        json!({"code": error.code, "message": error.message}),
    )
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.headers.get(name).map(String::as_str)
}

fn now_utc_us() -> i64 {
    tirbase_core::traits::wall_hint().unwrap_or(0)
}
