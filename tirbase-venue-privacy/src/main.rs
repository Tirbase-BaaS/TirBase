// SPDX-License-Identifier: AGPL-3.0-only

//! `venue-privacy` — run CCTV retention, legal-hold and subject-rights actions
//! against a JSON state file. This is the operational caller for the ST-13
//! store; the HTTP/command-center integration can use the same library API.

use std::env;
use std::fs;
use std::process;

use tirbase_venue_privacy::{
    CctvActor, CctvError, CctvEvent, CctvEventKind, CctvHoldScope, CctvLegalHold, CctvRole,
    CctvStore,
};

const USAGE: &str = "\
usage: venue-privacy --state <file> --actor <id> --role <role> --venue <id> [--now <unix-secs>] <command>

commands:
  ingest <event-id> <camera-id> <zone-id> <security|access_anomaly|safety|operational>
         [--subject <pseudonym>] [--note <text>]
  read <event-id>
  list
  purge
  export <pseudonymous-subject-ref>
  delete <pseudonymous-subject-ref> <request-id>
  hold <hold-id> <subject|event|venue> <value> <reason...>
  release <hold-id>
";

fn main() {
    if let Err(error) = run() {
        eprintln!("venue-privacy: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{USAGE}");
        return Ok(());
    }
    let state_path = required_flag(&args, "--state")?;
    let actor_id = required_flag(&args, "--actor")?;
    let venue_id = required_flag(&args, "--venue")?;
    let role = CctvRole::parse(&required_flag(&args, "--role")?).ok_or_else(|| {
        "unknown --role (security, safety, auditor, privacy_officer, manager)".to_string()
    })?;
    let now = optional_flag(&args, "--now")
        .map(|value| value.parse::<i64>())
        .transpose()
        .map_err(|_| "--now must be an integer unix second".to_string())?
        .unwrap_or_else(current_unix_secs);
    if now <= 0 {
        return Err("--now must be positive".to_string());
    }
    let actor = CctvActor::new(&actor_id, role, &venue_id).map_err(display)?;
    let mut store = load_store(&state_path)?;

    let command_args = command_args(&args);
    let Some(command) = command_args.first().map(String::as_str) else {
        return Err(format!("no command\n{USAGE}"));
    };
    match command {
        "ingest" => {
            let event_id = command_args
                .get(1)
                .ok_or_else(|| "ingest needs <event-id>".to_string())?;
            let camera_id = command_args
                .get(2)
                .ok_or_else(|| "ingest needs <camera-id>".to_string())?;
            let zone_id = command_args
                .get(3)
                .ok_or_else(|| "ingest needs <zone-id>".to_string())?;
            let kind = command_args
                .get(4)
                .and_then(|value| CctvEventKind::parse(value))
                .ok_or_else(|| "ingest needs a valid event kind".to_string())?;
            let mut event = CctvEvent::new(event_id, &venue_id, camera_id, zone_id, kind, now)
                .map_err(display)?;
            if let Some(subject) = optional_flag(&args, "--subject") {
                event = event.with_subject(subject).map_err(display)?;
            }
            if let Some(note) = optional_flag(&args, "--note") {
                event = event.with_note(note).map_err(display)?;
            }
            store.insert(&actor, event).map_err(display)?;
            print_json(&store.read(&actor, event_id, now).map_err(display)?)?;
        }
        "read" => {
            let event_id = command_args
                .get(1)
                .ok_or_else(|| "read needs <event-id>".to_string())?;
            let event = store.read(&actor, event_id, now).map_err(display)?;
            print_json(&event)?;
        }
        "list" => {
            let events = store.list(&actor, now);
            print_json(&events)?;
        }
        "purge" => {
            let report = store.purge_expired(&actor, now).map_err(display)?;
            print_json(&report)?;
        }
        "export" => {
            let subject = command_args
                .get(1)
                .ok_or_else(|| "export needs a subject reference".to_string())?;
            let report = store
                .subject_export(&actor, subject, now)
                .map_err(display)?;
            print_json(&report)?;
        }
        "delete" => {
            let subject = command_args
                .get(1)
                .ok_or_else(|| "delete needs a subject reference".to_string())?;
            let request_id = command_args
                .get(2)
                .ok_or_else(|| "delete needs a request id".to_string())?;
            let report = store
                .delete_subject(&actor, subject, request_id, now)
                .map_err(display)?;
            print_json(&report)?;
        }
        "hold" => {
            let hold_id = command_args
                .get(1)
                .ok_or_else(|| "hold needs a hold id".to_string())?;
            let scope = command_args
                .get(2)
                .ok_or_else(|| "hold needs subject, event or venue".to_string())?;
            let value = command_args
                .get(3)
                .ok_or_else(|| "hold needs a scope value".to_string())?;
            let reason = command_args
                .get(4..)
                .ok_or_else(|| "hold needs a reason".to_string())?
                .join(" ");
            if reason.trim().is_empty() {
                return Err("hold needs a reason".to_string());
            }
            let scope = match scope.as_str() {
                "subject" => CctvHoldScope::Subject(value.clone()),
                "event" => CctvHoldScope::Event(value.clone()),
                "venue" => CctvHoldScope::Venue(value.clone()),
                _ => return Err("hold scope must be subject, event or venue".to_string()),
            };
            let hold =
                CctvLegalHold::new(hold_id, &venue_id, scope, reason, now).map_err(display)?;
            store.add_legal_hold(&actor, hold, now).map_err(display)?;
            print_json(&serde_json::json!({"hold_id": hold_id, "status": "active"}))?;
        }
        "release" => {
            let hold_id = command_args
                .get(1)
                .ok_or_else(|| "release needs a hold id".to_string())?;
            store
                .release_legal_hold(&actor, hold_id, now)
                .map_err(display)?;
            print_json(&serde_json::json!({"hold_id": hold_id, "status": "released"}))?;
        }
        other => return Err(format!("unknown command {other:?}\n{USAGE}")),
    }

    save_store(&state_path, &store)?;
    Ok(())
}

fn load_store(path: &str) -> Result<CctvStore, String> {
    match fs::read_to_string(path) {
        Ok(text) => CctvStore::from_json(&text).map_err(display),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CctvStore::new()),
        Err(error) => Err(format!("read {path}: {error}")),
    }
}

fn save_store(path: &str, store: &CctvStore) -> Result<(), String> {
    let text = store.to_json().map_err(display)?;
    let temporary = format!("{path}.tmp");
    fs::write(&temporary, text).map_err(|error| format!("write {temporary}: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("replace {path}: {error}"))
}

fn command_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--state" | "--actor" | "--role" | "--venue" | "--now" | "--subject" | "--note"
        ) {
            index += 2;
            continue;
        }
        if arg.starts_with("--") {
            index += 1;
            continue;
        }
        out.push(arg.clone());
        index += 1;
    }
    out
}

fn required_flag(args: &[String], name: &str) -> Result<String, String> {
    optional_flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn optional_flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn current_unix_secs() -> i64 {
    tirbase_core::traits::wall_hint().unwrap_or(0)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("serialize output: {error}"))?;
    println!("{text}");
    Ok(())
}

fn display(error: CctvError) -> String {
    error.to_string()
}
