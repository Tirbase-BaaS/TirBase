//! Admin Unix-socket listener with SO_PEERCRED authentication.
//!
//! Listens on `/run/tirbase/admin.sock` (configurable via `GatewayConfig`).
//! Authenticates callers via `SO_PEERCRED` — only processes running as root
//! (UID 0) or the same UID as the gateway process are accepted.  All 12
//! endpoints return `501 Not Implemented` until wired in subsequent tasks.
//!
//! # Endpoint inventory (task 36.3a – 36.3l)
//!
//! | Method | Path                         | Future task |
//! |--------|------------------------------|-------------|
//! | POST   | /admin/enroll                | 36.3a       |
//! | POST   | /admin/mint                  | 36.3b       |
//! | POST   | /admin/rotate                | 36.3c       |
//! | POST   | /admin/policy                | 36.3d       |
//! | GET    | /admin/events                | 36.3e       |
//! | POST   | /admin/simulate              | 36.3f       |
//! | POST   | /admin/challenge             | 36.3g       |
//! | GET    | /admin/mode                  | 36.3h       |
//! | POST   | /admin/lockdown-exit         | 36.3i       |
//! | POST   | /admin/chain-recovery        | 36.3j       |
//! | GET    | /admin/status/{issuer_did}   | 36.3k       |
//! | POST   | /admin/sequence-reset        | 36.3l       |
//!
//! # Security note
//! `SO_PEERCRED` is a Linux kernel facility (see `man 7 unix`).  The entire
//! listener and peer-credential check are `#[cfg(target_os = "linux")]` so the
//! crate still compiles on macOS / Windows developer machines.  On those
//! platforms `run_admin_listener` returns an `Err` indicating the feature is
//! unsupported.
//!
//! CLAIM-4.9.2 — PV-30.2
// ─────────────────────────────────────────────────────────────────────────────
// Linux-only implementation
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    /// Start the admin listener on the given socket path.
    ///
    /// Removes a stale socket file, creates parent directories, binds the
    /// listener, then loops accepting connections.  Each connection is spawned
    /// onto a new tokio task for concurrent handling.
    pub async fn run_admin_listener(sock_path: &Path) -> anyhow::Result<()> {
        // Remove stale socket file if present (harmless if absent).
        let _ = std::fs::remove_file(sock_path);

        // Create parent directory tree if it does not exist.
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(sock_path)?;
        tracing::info!(path = %sock_path.display(), "admin listener bound");

        loop {
            let (stream, _addr) = listener.accept().await?;
            tokio::spawn(async move {
                if let Err(e) = handle_admin_connection(stream).await {
                    tracing::warn!(error = %e, "admin connection error");
                }
            });
        }
    }

    /// Handle a single admin connection.
    ///
    /// 1. Authenticate via `SO_PEERCRED` — accept only root (UID 0) or the
    ///    gateway's own UID.
    /// 2. Read one newline-delimited JSON command line.
    /// 3. Dispatch to a stub handler that returns `501 Not Implemented`.
    /// 4. Write the response line and flush.
    async fn handle_admin_connection(stream: UnixStream) -> anyhow::Result<()> {
        // ── SO_PEERCRED authentication ────────────────────────────────────────
        let peer_cred = stream.peer_cred()?;
        // SAFETY: `getuid` is async-signal-safe and has no preconditions.
        let gateway_uid = unsafe { libc::getuid() };

        let peer_uid = peer_cred.uid();
        if peer_uid != 0 && peer_uid != gateway_uid {
            tracing::warn!(
                peer_uid,
                gateway_uid,
                "admin: rejecting unauthenticated connection"
            );
            // Drop the stream; the OS closes the socket.
            return Ok(());
        }

        tracing::debug!(peer_uid, "admin: authenticated connection accepted");

        // ── Read one newline-delimited JSON command ───────────────────────────
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let command = line.trim();

        // ── Dispatch and write response ───────────────────────────────────────
        let response = dispatch_admin_command(command);
        let stream_mut = reader.get_mut();
        stream_mut.write_all(response.as_bytes()).await?;
        stream_mut.flush().await?;
        Ok(())
    }

    /// Dispatch a command string to one of the 12 stub endpoint handlers.
    ///
    /// The command is expected to be a JSON object with a `"cmd"` key, e.g.
    /// `{"cmd":"enroll","payload":{...}}`.  Unknown commands return HTTP-style
    /// 400; all known endpoints return 501 until wired in later tasks.
    fn dispatch_admin_command(command: &str) -> String {
        let cmd = parse_cmd_field(command);
        let body = match cmd.as_deref() {
            // 36.3a — device enrollment
            Some("enroll") => stub_501("enroll"),
            // 36.3b — scoped Biscuit token minting
            Some("mint") => stub_501("mint"),
            // 36.3c — key rotation
            Some("rotate") => stub_501("rotate"),
            // 36.3d — push policy bundle (tightening or loosening)
            Some("policy") => stub_501("policy"),
            // 36.3e — security event inspection (SSE / paginated)
            Some("events") => stub_501("events"),
            // 36.3f — command simulation dry-run (no side effects)
            Some("simulate") => stub_501("simulate"),
            // 36.3g — issue challenge nonce for UNVERIFIED + critical params
            Some("challenge") => stub_501("challenge"),
            // 36.3h — return current NodeMode
            Some("mode") => stub_501("mode"),
            // 36.3i — LOCKDOWN exit (M-of-N co-signatures)
            Some("lockdown-exit") => stub_501("lockdown-exit"),
            // 36.3j — hash-chain recovery (exit Restricted mode)
            Some("chain-recovery") => stub_501("chain-recovery"),
            // 36.3k — Guard status per issuer DID
            Some("status") => stub_501("status"),
            // 36.3l — sequence-window reset (PolicyAuthority signed)
            Some("sequence-reset") => stub_501("sequence-reset"),
            // Unknown command
            _ => r#"{"status":400,"error":"unknown command"}"#.to_string(),
        };
        format!("{body}\n")
    }

    /// Return a JSON 501 Not Implemented response for `endpoint`.
    fn stub_501(endpoint: &str) -> String {
        format!(
            r#"{{"status":501,"error":"not implemented","endpoint":"{endpoint}"}}"#
        )
    }

    /// Minimal extraction of the `"cmd"` field value from a JSON object.
    ///
    /// Uses no external parser intentionally — this is a placeholder until the
    /// request schema is formalised in task 36.1.  Returns `None` if the field
    /// is absent or the input is not parseable.
    fn parse_cmd_field(json: &str) -> Option<String> {
        // Scan for `"cmd"` key then grab the next quoted string value.
        let mut parts = json.split('"');
        while let Some(segment) = parts.next() {
            if segment.trim_end_matches(|c: char| c.is_whitespace() || c == ':') == "cmd" {
                // Skip any whitespace / colon tokens.
                return parts.find(|s| !s.trim().is_empty()).map(|s| s.to_string());
            }
        }
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── parse_cmd_field ───────────────────────────────────────────────────

        #[test]
        fn parse_cmd_field_simple() {
            let json = r#"{"cmd":"enroll","payload":{}}"#;
            assert_eq!(parse_cmd_field(json).as_deref(), Some("enroll"));
        }

        #[test]
        fn parse_cmd_field_unknown_returns_none() {
            // A JSON object with no "cmd" key.
            assert_eq!(parse_cmd_field(r#"{"foo":"bar"}"#), None);
        }

        #[test]
        fn parse_cmd_field_empty_string() {
            assert_eq!(parse_cmd_field(""), None);
        }

        // ── dispatch_admin_command ────────────────────────────────────────────

        /// Every known command must return a 501 response body.
        #[test]
        fn all_12_endpoints_return_501() {
            let endpoints = [
                "enroll",
                "mint",
                "rotate",
                "policy",
                "events",
                "simulate",
                "challenge",
                "mode",
                "lockdown-exit",
                "chain-recovery",
                "status",
                "sequence-reset",
            ];
            for ep in &endpoints {
                let cmd_json = format!(r#"{{"cmd":"{ep}"}}"#);
                let response = dispatch_admin_command(&cmd_json);
                assert!(
                    response.contains("\"status\":501"),
                    "endpoint '{ep}' did not return 501; got: {response}"
                );
                assert!(
                    response.contains(&format!(r#""endpoint":"{ep}""#)),
                    "endpoint field missing for '{ep}'; got: {response}"
                );
            }
        }

        #[test]
        fn unknown_command_returns_400() {
            let response = dispatch_admin_command(r#"{"cmd":"does-not-exist"}"#);
            assert!(
                response.contains("\"status\":400"),
                "unexpected response: {response}"
            );
        }

        #[test]
        fn response_is_newline_terminated() {
            let response = dispatch_admin_command(r#"{"cmd":"enroll"}"#);
            assert!(
                response.ends_with('\n'),
                "response must end with newline; got: {response:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public surface — re-export the Linux implementation; provide a no-op shim on
// other platforms so `cargo check` passes everywhere.
// ─────────────────────────────────────────────────────────────────────────────

/// Start the admin Unix-socket listener.
///
/// On Linux this binds `/run/tirbase/admin.sock`, authenticates via
/// `SO_PEERCRED`, and dispatches the 12 stub admin endpoints.
///
/// On other platforms (developer macOS, CI) this returns an error immediately
/// to avoid a hard compile-time failure on non-Linux hosts.
pub async fn run_admin_listener(sock_path: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run_admin_listener(sock_path).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sock_path;
        anyhow::bail!(
            "admin Unix-socket listener is Linux-only (SO_PEERCRED); \
             not supported on this platform"
        )
    }
}
