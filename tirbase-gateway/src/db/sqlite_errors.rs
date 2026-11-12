//! SQLite error → `NodeMode` / `SecurityEvent` mapping (//! CLAIM-18.3, CLAIM-18.4, PV-9).

use rusqlite::{ffi, Connection, Error as RusqliteError};
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};

/// Which gateway database produced an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
    Primary,
    Derived,
}

impl DbKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DbKind::Primary => "primary",
            DbKind::Derived => "derived",
        }
    }
}

/// Hardening pragmas applied to both databases after creation/open (CLAIM-18.3).
pub const HARDENING_PRAGMAS: [(&str, &str); 3] = [
    ("trusted_schema", "OFF"),
    ("foreign_keys", "ON"),
    ("cache_size", "-4096"),
];

pub fn apply_hardening_pragmas(conn: &Connection, kind: DbKind) -> Result<(), SqliteErrorAction> {
    for (name, value) in HARDENING_PRAGMAS {
        conn.pragma_update(None, name, value).map_err(|e| {
            SqliteErrorAction::from_rusqlite(kind, &e, &format!("PRAGMA {name}={value}"))
        })?;
    }
    Ok(())
}

/// Classified SQLite failure and the required gateway response (CLAIM-18.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteErrorAction {
 /// `SQLITE_FULL` (ENOSPC): emit High `StorageFull`, continue with reduced logging.
    StorageFull { kind: DbKind, detail: String },
 /// `SQLITE_IOERR`: treat as corruption/IO failure; enter `Restricted`.
    EnterRestrictedIo { kind: DbKind, detail: String },
 /// `SQLITE_CORRUPT`: enter `Restricted`; PrimaryLedger unrecoverable → operator intervention.
    EnterRestrictedCorrupt { kind: DbKind, detail: String },
 /// Non-mapped DB error (no mode transition by 18.4).
    Other { kind: DbKind, detail: String },
 /// Filesystem/open error outside rusqlite code mapping.
    IoError {
        kind: DbKind,
        context: String,
        detail: String,
    },
}

impl SqliteErrorAction {
    pub fn from_rusqlite(kind: DbKind, err: &RusqliteError, context: &str) -> Self {
        let detail = format!("{kind} {context}: {err}", kind = kind.as_str());
        match classify(err) {
            Some(ffi::SQLITE_FULL) => SqliteErrorAction::StorageFull { kind, detail },
            Some(ffi::SQLITE_IOERR) => SqliteErrorAction::EnterRestrictedIo { kind, detail },
            Some(ffi::SQLITE_CORRUPT) => SqliteErrorAction::EnterRestrictedCorrupt { kind, detail },
            _ => SqliteErrorAction::Other { kind, detail },
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            SqliteErrorAction::StorageFull { detail, .. }
            | SqliteErrorAction::EnterRestrictedIo { detail, .. }
            | SqliteErrorAction::EnterRestrictedCorrupt { detail, .. }
            | SqliteErrorAction::Other { detail, .. }
            | SqliteErrorAction::IoError { detail, .. } => detail,
        }
    }

 /// Apply the mapping: emit the required SecurityEvent and, for IOERR/CORRUPT,
 /// transition the node to `Restricted` (CLAIM-18.4).
    pub fn apply(&self, node_mode: Option<&NodeModeState>) {
        match self {
            SqliteErrorAction::StorageFull { kind, detail } => {
                emit(
                    SecurityEvent::new(
                        SecurityEventCategory::Startup,
                        Severity::High,
                        ReasonCode::StorageFull,
                    )
                    .with_target(kind.as_str())
                    .with_detail(detail.clone()),
                );
 // SQLITE_FULL: continue with reduced logging; no mode transition.
            }
            SqliteErrorAction::EnterRestrictedIo { kind, detail } => {
                emit(
                    SecurityEvent::new(
                        SecurityEventCategory::Startup,
                        Severity::Critical,
                        ReasonCode::StorageError,
                    )
                    .with_target(kind.as_str())
                    .with_detail(detail.clone()),
                );
                emit(
                    SecurityEvent::new(
                        SecurityEventCategory::ModeTransition,
                        Severity::Critical,
                        ReasonCode::EnteredRestricted,
                    )
                    .with_target(kind.as_str())
                    .with_detail(format!(
                        "SQLITE_IOERR on {} DB: entering Restricted",
                        kind.as_str()
                    )),
                );
                if let Some(mode) = node_mode {
                    mode.set(NodeMode::Restricted);
                }
            }
            SqliteErrorAction::EnterRestrictedCorrupt { kind, detail } => {
                let mut full_detail = detail.clone();
                if *kind == DbKind::Primary {
                    full_detail.push_str(
                        "; PrimaryLedger corruption unrecoverable — operator intervention required",
                    );
                } else {
                    full_detail.push_str("; DerivedLedger corruption — rebuild may be attempted; operator intervention required if rebuild fails");
                }
                emit(
                    SecurityEvent::new(
                        SecurityEventCategory::Startup,
                        Severity::Critical,
                        ReasonCode::StorageCorrupt,
                    )
                    .with_target(kind.as_str())
                    .with_detail(full_detail.clone()),
                );
                emit(
                    SecurityEvent::new(
                        SecurityEventCategory::ModeTransition,
                        Severity::Critical,
                        ReasonCode::EnteredRestricted,
                    )
                    .with_target(kind.as_str())
                    .with_detail(full_detail),
                );
                if let Some(mode) = node_mode {
                    mode.set(NodeMode::Restricted);
                }
            }
            SqliteErrorAction::Other { .. } | SqliteErrorAction::IoError { .. } => {}
        }
    }
}

impl std::fmt::Display for SqliteErrorAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

impl std::error::Error for SqliteErrorAction {}

fn classify(err: &RusqliteError) -> Option<i32> {
    match err {
        RusqliteError::SqliteFailure(code, _) => Some(primary_code(*code)),
        _ => None,
    }
}

fn primary_code(code: rusqlite::ffi::Error) -> i32 {
    code.extended_code & 0xff
}

/// Test hook: construct an action from a primary SQLite result code.
/// Used by integration tests to exercise the mapping without corrupting a real DB.
pub fn action_for_primary_code(
    kind: DbKind,
    primary_code: i32,
    context: &str,
) -> SqliteErrorAction {
    let detail = format!(
        "{kind} {context}: injected sqlite primary code {primary_code}",
        kind = kind.as_str()
    );
    match primary_code {
        ffi::SQLITE_FULL => SqliteErrorAction::StorageFull { kind, detail },
        ffi::SQLITE_IOERR => SqliteErrorAction::EnterRestrictedIo { kind, detail },
        ffi::SQLITE_CORRUPT => SqliteErrorAction::EnterRestrictedCorrupt { kind, detail },
        _ => SqliteErrorAction::Other { kind, detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct Sink(std::sync::Mutex<Vec<SecurityEvent>>);
    impl tirbase_core::traits::SecurityEventSink for Sink {
        fn emit(&self, event: SecurityEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn hardening_pragmas_are_applied() {
        let conn = Connection::open_in_memory().unwrap();
        apply_hardening_pragmas(&conn, DbKind::Primary).unwrap();
        let ts: i32 = conn
            .query_row("PRAGMA trusted_schema", [], |r| r.get(0))
            .unwrap();
        let fk: i32 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        let cs: i32 = conn
            .query_row("PRAGMA cache_size", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ts, 0);
        assert_eq!(fk, 1);
        assert_eq!(cs, -4096);
    }

    #[test]
    fn full_emits_high_event_without_mode_change() {
        let _g = crate::EVENT_SINK_TEST_LOCK.lock().unwrap();
        let sink = Arc::new(Sink::default());
        let prev = tirbase_core::events::install_security_event_sink(sink.clone());
        let mode = NodeModeState::new(NodeMode::Normal);
        action_for_primary_code(DbKind::Primary, ffi::SQLITE_FULL, "write").apply(Some(&mode));
        tirbase_core::events::install_security_event_sink(
            prev.unwrap_or_else(|| Arc::new(Sink::default())),
        );
        assert_eq!(mode.get(), NodeMode::Normal);
        let events = sink.0.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.reason_code == ReasonCode::StorageFull && e.severity == Severity::High));
    }

    #[test]
    fn ioerr_and_corrupt_enter_restricted() {
        let _g = crate::EVENT_SINK_TEST_LOCK.lock().unwrap();
        let sink = Arc::new(Sink::default());
        let prev = tirbase_core::events::install_security_event_sink(sink.clone());
        let mode = NodeModeState::new(NodeMode::Normal);
        action_for_primary_code(DbKind::Primary, ffi::SQLITE_IOERR, "read").apply(Some(&mode));
        assert_eq!(mode.get(), NodeMode::Restricted);
        action_for_primary_code(DbKind::Derived, ffi::SQLITE_CORRUPT, "quick_check")
            .apply(Some(&mode));
        assert_eq!(mode.get(), NodeMode::Restricted);
        tirbase_core::events::install_security_event_sink(
            prev.unwrap_or_else(|| Arc::new(Sink::default())),
        );
        let events = sink.0.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.reason_code == ReasonCode::StorageError));
        assert!(events
            .iter()
            .any(|e| e.reason_code == ReasonCode::StorageCorrupt));
    }
}
