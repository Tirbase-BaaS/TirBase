// SPDX-License-Identifier: Apache-2.0

//! SMTP connector.
//!
//! The session is written out as plain SMTP commands so it can be driven over
//! any stream — a deployment supplies a [`SmtpDialer`] that returns a
//! [`SmtpConnection`] (TLS is the dialer's job), and tests supply a scripted one.
//! What this module owns is the protocol: greeting, `EHLO`, `AUTH PLAIN` when a
//! username is configured, envelope, `DATA` with dot-stuffing and CRLF line
//! endings, and reply-code classification (4xx retriable, 5xx permanent).

use crate::message::AlertMessage;
use crate::secrets::{SecretRef, SecretStore, SecretValue};
use crate::transport::{DeliveryFailure, DeliveryReceipt, DeliveryTarget, NotifyTransport};

/// One server reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    /// Three-digit status code.
    pub code: u16,
    /// Text after the code.
    pub text: String,
}

impl SmtpReply {
    /// Parse a reply line such as `250 2.0.0 Ok` or `354 End data with <CR><LF>`.
    pub fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.len() < 3 || !line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err(format!("malformed SMTP reply {line:?}"));
        }
        let code = line[..3]
            .parse::<u16>()
            .map_err(|error| format!("malformed SMTP reply code: {error}"))?;
        let text = line
            .get(4..)
            .unwrap_or("")
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Ok(Self { code, text })
    }

    /// `true` for 2xx.
    pub fn is_positive(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Convert a non-success reply into a failure with the right retry advice.
    pub fn failure(&self, stage: &str) -> DeliveryFailure {
        let detail = format!("smtp {stage}: {} {}", self.code, self.text);
        if (400..500).contains(&self.code) {
            DeliveryFailure::retriable(detail)
        } else {
            DeliveryFailure::permanent(detail)
        }
    }
}

/// The socket the session runs on.
pub trait SmtpConnection: Send {
    /// Write one command line (no CRLF; the implementation adds it).
    fn write_line(&mut self, line: &str) -> Result<(), String>;
    /// Read the next complete reply (all lines of a multi-line reply).
    fn read_reply(&mut self) -> Result<SmtpReply, String>;
}

/// Opens a connection to a relay. TLS, if any, belongs here.
pub trait SmtpDialer: Send + Sync + std::fmt::Debug {
    /// Connect to `host:port`.
    fn connect(&self, host: &str, port: u16) -> Result<Box<dyn SmtpConnection>, String>;
}

/// Credentials the session will send. The password is resolved by reference.
#[derive(Debug)]
pub struct SmtpCredentials {
    /// Authentication identity.
    pub username: String,
    /// Password, already resolved.
    pub password: SecretValue,
}

/// `subject` header value, with CR/LF stripped so a title cannot inject headers.
pub fn header_safe(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

/// Render the RFC 5322 message (without the terminating dot).
pub fn render_email(message: &AlertMessage, from: &str, to: &str) -> String {
    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", header_safe(from)));
    email.push_str(&format!("To: {}\r\n", header_safe(to)));
    email.push_str(&format!("Subject: {}\r\n", header_safe(&message.subject())));
    email.push_str("MIME-Version: 1.0\r\n");
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("Content-Transfer-Encoding: 8bit\r\n");
    email.push_str("Auto-Submitted: auto-generated\r\n");
    email.push('\r');
    email.push('\n');
    for line in message.plain_text().lines() {
        email.push_str(line);
        email.push_str("\r\n");
    }
    email
}

/// Normalise `text` to CRLF line endings and dot-stuff the lines that need it.
pub fn encode_data(text: &str) -> String {
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    // A trailing newline terminates the last line; it does not start a new one.
    if text.ends_with('\n') {
        lines.pop();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for line in lines {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// `AUTH PLAIN` command for `username` and `password`.
pub fn auth_plain_command(username: &str, password: &str) -> String {
    let mut plain = Vec::new();
    plain.push(0u8);
    plain.extend_from_slice(username.as_bytes());
    plain.push(0u8);
    plain.extend_from_slice(password.as_bytes());
    format!("AUTH PLAIN {}", base64_encode(&plain))
}

/// Standard base64, padded.
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Run one delivery over an established connection.
///
/// Leaves the connection open after `QUIT` so a caller can reuse it; the caller
/// owns closing the socket.
pub fn send_over_connection(
    connection: &mut dyn SmtpConnection,
    from: &str,
    to: &str,
    message: &AlertMessage,
    credentials: Option<&SmtpCredentials>,
    helo: &str,
) -> Result<(), DeliveryFailure> {
    let expect = |connection: &mut dyn SmtpConnection, stage: &str, codes: &[u16]| {
        let reply = connection
            .read_reply()
            .map_err(|error| DeliveryFailure::retriable(format!("smtp {stage}: {error}")))?;
        if codes.contains(&reply.code) {
            Ok(())
        } else {
            Err(reply.failure(stage))
        }
    };
    let write = |connection: &mut dyn SmtpConnection, line: &str| {
        connection
            .write_line(line)
            .map_err(|error| DeliveryFailure::retriable(format!("smtp write: {error}")))
    };

    expect(connection, "greeting", &[220])?;
    write(connection, &format!("EHLO {helo}"))?;
    expect(connection, "ehlo", &[250])?;
    if let Some(credentials) = credentials {
        write(
            connection,
            &auth_plain_command(&credentials.username, credentials.password.expose()),
        )?;
        // 235 accepted; 503 "already authenticated" is not a failure for us.
        expect(connection, "auth", &[235, 503])?;
    }
    write(connection, &format!("MAIL FROM:<{from}>"))?;
    expect(connection, "mail from", &[250])?;
    write(connection, &format!("RCPT TO:<{to}>"))?;
    // 250 recipient accepted; 251 forwarded.
    expect(connection, "rcpt to", &[250, 251])?;
    write(connection, "DATA")?;
    expect(connection, "data", &[354])?;
    // Data is dot-stuffed, then terminated by a lone `.` line, which must not
    // itself be stuffed.
    let body = format!("{}.", encode_data(&render_email(message, from, to)));
    let body = format!("{body}\r\n");
    for line in body.split_inclusive("\r\n") {
        write(connection, line.trim_end_matches("\r\n"))?;
    }
    expect(connection, "message", &[250])?;
    write(connection, "QUIT")?;
    // A server that drops the connection after QUIT is not a delivery failure.
    let _ = connection.read_reply();
    Ok(())
}

/// SMTP channel: resolves the password by reference and drives a session.
#[derive(Debug)]
pub struct SmtpConnector {
    channel: String,
    host: String,
    port: u16,
    from: String,
    helo: String,
    username: Option<String>,
    secrets: Box<dyn SecretStore>,
    dialer: Box<dyn SmtpDialer>,
}

impl SmtpConnector {
    /// A connector for `channel` using the relay at `host:port`.
    pub fn new(
        channel: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        from: impl Into<String>,
        dialer: Box<dyn SmtpDialer>,
        secrets: Box<dyn SecretStore>,
    ) -> Self {
        let host = host.into();
        Self {
            channel: channel.into(),
            helo: host.clone(),
            host,
            port,
            from: from.into(),
            username: None,
            secrets,
            dialer,
        }
    }

    /// Authenticate as `username`; the password comes from the target's secret
    /// reference.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    fn credentials(
        &self,
        target: &DeliveryTarget,
    ) -> Result<Option<SmtpCredentials>, DeliveryFailure> {
        let Some(username) = self.username.as_ref() else {
            // Configured without a username: no secret is resolved or sent.
            if target.secret_ref.is_some() {
                return Err(DeliveryFailure::permanent(
                    "smtp channel has a secret reference but no username",
                ));
            }
            return Ok(None);
        };
        let reference: &SecretRef = target.secret_ref.as_ref().ok_or_else(|| {
            DeliveryFailure::permanent("smtp channel has a username but no secret reference")
        })?;
        let password = self
            .secrets
            .get(reference)
            .map_err(|error| DeliveryFailure::permanent(format!("secret {reference}: {error}")))?;
        Ok(Some(SmtpCredentials {
            username: username.clone(),
            password,
        }))
    }
}

impl NotifyTransport for SmtpConnector {
    fn channel(&self) -> &str {
        &self.channel
    }

    fn deliver(
        &self,
        message: &AlertMessage,
        target: &DeliveryTarget,
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let credentials = self.credentials(target)?;
        let mut connection = self
            .dialer
            .connect(&self.host, self.port)
            .map_err(|error| DeliveryFailure::retriable(format!("smtp connect: {error}")))?;
        send_over_connection(
            connection.as_mut(),
            &self.from,
            &target.address,
            message,
            credentials.as_ref(),
            &self.helo,
        )?;
        Ok(DeliveryReceipt { provider_id: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Severity;
    use crate::secrets::MemorySecretStore;

    /// Scripted server: replies with the given codes, records the commands.
    #[derive(Debug, Default)]
    struct ScriptedConnection {
        codes: std::collections::VecDeque<u16>,
        lines: Vec<String>,
    }

    impl SmtpConnection for ScriptedConnection {
        fn write_line(&mut self, line: &str) -> Result<(), String> {
            self.lines.push(line.to_string());
            Ok(())
        }

        fn read_reply(&mut self) -> Result<SmtpReply, String> {
            let code = self.codes.pop_front().unwrap_or(250);
            SmtpReply::parse(&format!("{code} ok"))
        }
    }

    #[derive(Debug)]
    struct FixedDialer {
        codes: std::sync::Mutex<Vec<u16>>,
    }

    impl SmtpDialer for FixedDialer {
        fn connect(&self, _host: &str, _port: u16) -> Result<Box<dyn SmtpConnection>, String> {
            Ok(Box::new(ScriptedConnection {
                codes: self.codes.lock().unwrap().drain(..).collect(),
                lines: Vec::new(),
            }))
        }
    }

    #[test]
    fn replies_parse_and_classify() {
        let reply = SmtpReply::parse("250 2.0.0 Ok\r\n").expect("reply");
        assert_eq!(reply.code, 250);
        assert_eq!(reply.text, "2.0.0 Ok");
        assert!(reply.is_positive());
        assert!(SmtpReply::parse("250-PIPELINING").expect("reply").code == 250);
        assert!(SmtpReply::parse("oops").is_err());
        assert!(
            SmtpReply::parse("450 later")
                .expect("reply")
                .failure("rcpt")
                .retriable
        );
        assert!(
            !SmtpReply::parse("550 no")
                .expect("reply")
                .failure("rcpt")
                .retriable
        );
    }

    #[test]
    fn data_encoding_stuffs_dots_and_terminates() {
        let encoded = encode_data("Subject: x\n\n.line one\n..line two");
        assert_eq!(encoded, "Subject: x\r\n\r\n..line one\r\n...line two\r\n");
        let message = AlertMessage::new("a", "d", Severity::Critical, "t");
        let encoded = format!(
            "{}.\r\n",
            encode_data(&render_email(&message, "a@example.com", "b@example.com"))
        );
        assert!(encoded.ends_with("\r\n.\r\n"), "{encoded:?}");
        assert!(encoded.contains("Subject: [CRITICAL] unknown default: t\r\n"));
    }

    #[test]
    fn header_injection_is_removed() {
        let mut message = AlertMessage::new("a", "d", Severity::Critical, "title");
        message.title = "evil\r\nBcc: attacker@example.com".to_string();
        let email = render_email(&message, "a@example.com", "b@example.com");
        let headers = email.split("\r\n\r\n").next().expect("headers");
        assert!(!headers.contains("\r\nBcc:"), "{headers}");
        assert_eq!(header_safe("a\r\nb"), "a  b");
    }

    #[test]
    fn auth_plain_and_base64_match_the_reference_encoding() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(
            auth_plain_command("user", "pass"),
            format!("AUTH PLAIN {}", base64_encode(b"\0user\0pass"))
        );
    }

    #[test]
    fn a_session_runs_greeting_ehlo_auth_envelope_data_and_quit() {
        let mut connection = ScriptedConnection {
            codes: [220, 250, 235, 250, 250, 354, 250, 221].into(),
            lines: Vec::new(),
        };
        let credentials = SmtpCredentials {
            username: "notify@tirbase.local".to_string(),
            password: SecretValue::new("pw"),
        };
        let message = AlertMessage::new("alert-1", "dedup-1", Severity::Critical, "too warm");
        send_over_connection(
            &mut connection,
            "alerts@tirbase.local",
            "oncall@tirbase.local",
            &message,
            Some(&credentials),
            "relay.local",
        )
        .expect("session");
        assert_eq!(connection.lines[0], "EHLO relay.local");
        assert!(connection.lines[1].starts_with("AUTH PLAIN "));
        assert_eq!(connection.lines[2], "MAIL FROM:<alerts@tirbase.local>");
        assert_eq!(connection.lines[3], "RCPT TO:<oncall@tirbase.local>");
        assert_eq!(connection.lines[4], "DATA");
        assert_eq!(connection.lines.last().map(String::as_str), Some("QUIT"));
        assert!(connection
            .lines
            .iter()
            .any(|line| line.starts_with("Subject: [CRITICAL]")));
    }

    #[test]
    fn a_rejected_recipient_is_a_permanent_failure() {
        let mut connection = ScriptedConnection {
            codes: [220, 250, 250, 550].into(),
            lines: Vec::new(),
        };
        let message = AlertMessage::new("a", "d", Severity::Warning, "t");
        let failure = send_over_connection(
            &mut connection,
            "alerts@tirbase.local",
            "nobody@example.com",
            &message,
            None,
            "relay.local",
        )
        .expect_err("550");
        assert!(!failure.retriable);
        assert!(failure.detail.contains("rcpt to"), "{failure}");
    }

    #[test]
    fn the_connector_resolves_the_password_by_reference_only() {
        let dialer = FixedDialer {
            codes: std::sync::Mutex::new(vec![220, 250, 235, 250, 250, 354, 250, 221]),
        };
        let secrets = MemorySecretStore::new().with("smtp/alerting", "pw");
        let connector = SmtpConnector::new(
            "smtp",
            "relay.example.com",
            587,
            "alerts@tirbase.local",
            Box::new(dialer),
            Box::new(secrets),
        )
        .with_username("notify@tirbase.local");
        let message = AlertMessage::new("a", "d", Severity::Critical, "t");
        let target = DeliveryTarget {
            channel: "smtp".into(),
            address: "oncall@tirbase.local".into(),
            secret_ref: Some(SecretRef::new("smtp/alerting").expect("ref")),
        };
        connector.deliver(&message, &target).expect("delivered");

        // A channel with a username but no secret reference cannot authenticate.
        let online = DeliveryTarget {
            secret_ref: None,
            ..target.clone()
        };
        let failure = connector.deliver(&message, &online).expect_err("no secret");
        assert!(!failure.retriable);
        assert!(failure.detail.contains("secret reference"), "{failure}");
    }
}
