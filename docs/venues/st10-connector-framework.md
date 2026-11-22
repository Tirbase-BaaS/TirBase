# ST-10 — Generic venue integration framework

**Status:** complete. **Licence:** Apache-2.0. **Crate:** `tirbase-venue-connectors`.
**Depends on:** ST-08 semantics, CC-20 (`tirbase-integrations`).

ST-10 gives venue vendors a supported way to connect ticketing, access control,
building management, CCTV and public address systems without linking the AGPL
venue runtime. It is the venue-domain layer over the CC-20 integration framework:
the generic connector trait, mapping DSL, retry engine, dead-letter queue and
HMAC helpers stay in `tirbase-integrations`; this crate adds the venue event
schemas, the five domain interfaces, venue privacy rules, signed webhook
verification and a conformance suite.

## Licence boundary

```text
closed venue connector (proprietary, any licence)
        │
        ├── tirbase-venue-connectors        Apache-2.0  ← this crate
        │        └── tirbase-integrations   Apache-2.0  ← CC-20
        │                 └── serde, serde_json, sha2, hex, toml, reqwest, zeroize…
        │
        └── (no edge to) tirbase-venue*, tirbase-gateway, tirbase-core, …
                              AGPL-3.0-only venue/runtime crates
```

`tirbase-venue-connectors/tests/agpl_free.rs` walks `Cargo.lock` from this crate,
refuses any AGPL first-party dependency and asserts that no `tirbase-venue*`
runtime crate is reachable at all. A closed connector can therefore be built,
tested and shipped against this crate and `tirbase-integrations` alone.

The framework does not import ST-02..ST-09 types. It reproduces the boundary
contract — scan, decision, alarm, announcement and the policy outcomes — as
Apache-2.0 schemas, which is what keeps the connector edge independent of the
runtime's copyleft.

## What is in the box

| Module | Content |
|---|---|
| `event` | `TicketScan`, `AccessDecision`, `VenueAlarm`, `Announcement`, `VenueEvent`, strict schemas and validation. |
| `domain` | `VenueConnector` plus `TicketingConnector`, `AccessConnector`, `BmsConnector`, `CctvConnector`, `PaConnector`; metadata-only `CameraContext`; `BmsPointWrite`. |
| `mapping` | `ConnectorProfile` TOML: vendor, domain, venue, endpoint, secret references, privacy, retry and the embedded CC-20 mapping document. |
| `idempotency` | Deterministic event ids and per-connector keys; `VenueDispatcher` drives the CC-20 outbox, retry and dead-letter engine. |
| `privacy` | `PrivacyPolicy`, holder pseudonymisation, text scrubbing, biometric/media refusal, retention bounds. |
| `webhook` | `VenueWebhookVerifier`, `InboundVenueEvents`, signed callback parsing and replay suppression. |
| `mock` | `MockVenueApi`, an in-memory vendor fixture for all five domains with dedupe and failure injection. |
| `conformance` | `certify`, the certification gate for a closed connector. |

## Event schemas

All four schemas are `deny_unknown_fields`; an undeclared vendor extension is a
deserialization error, not a silent pass-through.

| Event | Required identity | Key fields |
|---|---|---|
| `ticket_scan` | `scan_id` | venue, gate, ticket, opaque holder reference, optional holder name/email (never delivered), entry/exit, timestamp. |
| `access_decision` | `decision_id` | answered scan, venue, gate, `granted` or `denied` with a stable reason code, timestamp. |
| `alarm` | `alarm_id` | venue, zone, family (`crowd_density`, `gate_fault`, `sensor_fault`, `intrusion`, `operator_panic`, `network_loss`), severity, source, optional detail. |
| `announcement` | `announcement_id` | venue, zones, severity, text, language, start/end. |

Fire detection and suppression are deliberately absent from `AlarmKind`: this
framework never controls or replaces a fire system.

Validation bounds every identifier (1–128 bytes, no whitespace/control
characters), announcement text (500 bytes), alarm detail (1,000 bytes), the
language tag and the announcement window.

## Connector interfaces

A connector implements `VenueConnector` once:

```rust
fn name(&self) -> &str;
fn venue(&self) -> &str;
fn domains(&self) -> &[VenueDomain];
fn capabilities(&self) -> VenueCapabilities; // default
fn health(&self) -> ConnectorHealth;
fn deliver(&self, event: &VenueEvent) -> DeliveryResult;
```

and opts into the family traits it supports. Their typed methods default to
`deliver`, so there is one dispatch path:

- `TicketingConnector::on_ticket_scan`
- `AccessConnector::on_access_decision`
- `BmsConnector::on_alarm`, `write_point` (defaults to a permanent refusal)
- `CctvConnector::on_alarm`, `camera_context` (metadata only, defaults to a
  permanent refusal)
- `PaConnector::on_announcement`

`deliver` always receives a **redacted** event. `DeliveryResult` classifications
are the CC-20 set: `Delivered`, `Duplicate`, `Retryable`, `Permanent`; a
connector must return `Duplicate` when the vendor already has the idempotency
key.

## Mapping configuration

A profile is strict TOML:

```toml
schema_version = 1
connector = "vendor-ticketing"
domain = "ticketing"
venue = "venue-1"
endpoint = "https://vendor.example/venue/events"
webhook_secret_ref = "env:VENUE_WEBHOOK_SECRET"

[privacy]
holder = "pseudonymise"          # or "omit"
pseudonym_salt_ref = "env:VENUE_PRIVACY_SALT"
max_retention_secs = 86400

[retry]
max_attempts = 4
base_delay_secs = 2
factor = 2
max_delay_secs = 60

[mapping]
schema_version = 1

[[mapping.field]]
target = "scan.id"
source = "event.event_id"
required = true

[[mapping.field]]
target = "scan.ticket"
source = "payload.ticket_id"
required = true
```

Validation rejects an unsupported schema version, a malformed name, a non-HTTPS
endpoint (plain HTTP is allowed only for a loopback fixture with
`allow_insecure_loopback = true`), a secret *value* where a secret *reference* is
required, a non-positive retention or retry field, and any mapping document the
CC-20 compiler refuses. Secrets themselves are resolved by the host from the
environment or a file; they never appear in the profile.

`CompiledProfile::apply_to_event` redacts the event, builds the CC-20 mapping
context `{event, payload}` and produces the vendor JSON.

## Idempotency, retries and dead letters

Both ids are deterministic functions of the venue, event family and the
producer's native id:

- `event_id(event)` → `vne-…`, stable across restarts;
- per-connector `IntegrationEvent::idempotency_key` and the explicit
  `scan_idempotency_key` / `announcement_idempotency_key` helpers.

`VenueDispatcher` wraps one CC-20 `DeliveryEngine`. `submit` validates and
redacts the event, then queues it. Submitting the same scan or announcement again
returns `AlreadyQueued` or `AlreadyDelivered` and creates no second record.
`flush` asks the connector for one attempt per due record; retry backoff,
`Retry-After` handling, dead-lettering after the budget and replay all come from
the engine. A dead-letter replay reuses the original event id and key, so the
vendor answers `Duplicate` rather than creating a second scan or announcement. A
replay after the event has settled is refused.

There is no clock and no randomness in the framework: every instant is supplied
by the caller.

## Webhook verification

Inbound vendor callbacks must carry:

- a timestamp header (`x-venue-timestamp` by default);
- an HMAC-SHA256 signature header (`x-venue-signature`) with one or more
  `v1=<hex>` values over
  `"TirBase/v1/VenueWebhook\0<timestamp>.<body>"`.

`VenueWebhookVerifier` checks the timestamp window (±300 s by default, using
constant-time comparison), accepts any configured secret during rotation, and
**refuses an unsigned body before parsing it** with `MissingSignature`. Tampering,
a stale timestamp and malformed signatures each get a distinct error.

`InboundVenueEvents` verifies, parses and validates the event, then suppresses a
replayed callback: the same event id and body returns `replay: true` and the
caller does not process it again; the same id with a different signed body is
`PayloadConflict`.

## Redaction and privacy rules

| Data | Rule |
|---|---|
| Holder reference | Pseudonymised with a deployment salt (`vh-…`, deterministic per deployment) or replaced by `redacted` when the policy is `omit`. The raw scanner reference never leaves the venue. |
| Holder name / email | Removed, never truncated or transformed. |
| Announcement text | Email addresses and phone-like numbers scrubbed to `[redacted-email]` / `[redacted-number]`. |
| Alarm detail | Scrubbed; camera media markers refused. |
| Camera context | Metadata only: venue, camera, zone, trigger, timestamp. No frame, clip, thumbnail or embedding can be represented. |
| Biometrics | Any biometric marker in a prepared event is refused. |
| Retention | The policy exposes a retention deadline and `may_retain`. |

The raw event stays with the venue; only `PrivacyPolicy::prepare` output is
queued, stored in the outbox and handed to a connector.

## Mocks and conformance

`MockVenueApi` implements the generic connector and every family trait for a
chosen set of domains. It records events, deduplicates on the event id (unless
deliberately configured with `dedupe = false`), and injects transient failures.

`conformance::certify(connector, privacy, webhook, checked_est)` runs:

- **identity** — bounded name, bound venue, at least one domain;
- **health** — a non-empty readiness statement;
- **idempotent-capability** — the connector declares vendor deduplication;
- **delivery-<domain>** — a redacted sample event per declared domain is
  delivered;
- **replay-<domain>** — the same event is presented again and must come back
  `Duplicate`, so a replayed scan or announcement cannot create a second record;
- **unsigned-webhook** — an unsigned callback is rejected;
- **signed-webhook** — a correctly signed callback is accepted;
- **tampered-webhook** — a changed body fails;
- **privacy-holder** — the prepared scan carries no holder name, email or raw
  holder reference.

A report is `certified` only when every check passes; `failures()` names the
failing checks. This is the gate a closed connector must pass before release.

## Building a closed connector

1. **Create the crate** and depend on `tirbase-venue-connectors` (Apache-2.0).
   Do not add any `tirbase-*` runtime dependency.
2. **Implement `VenueConnector`** for your vendor transport, returning the
   vendor's `name`, bound `venue`, supported `domains` and classifications. Add
   the matching family trait impls (`impl TicketingConnector for Vendor {}`).
3. **Ship a profile** with `ConnectorProfile::from_toml`, resolving
   `env:`/`file:` secret references in your host and building the privacy policy
   with `CompiledProfile::privacy(salt)`.
4. **Wire `VenueDispatcher`** per profile, passing `CompiledProfile::retry_policy`.
   Submit every scan, decision, alarm and announcement through it; never call the
   vendor directly.
5. **Expose `VenueWebhookVerifier`** on your inbound endpoint and route accepted
   events through `InboundVenueEvents` so replays are suppressed.
6. **Add a vendor fixture** (an in-memory mock for unit tests, the CC-20
   `MockVendorServer` or a sandbox for HTTP contract tests) and prove retry,
   dead-letter replay and duplicate handling.
7. **Run `conformance::certify`** against the fixture. Attach the report JSON to
   the release. Do not ship a connector that is not certified.
8. **Document** credentials, rotation, mapping fields, failure recovery and the
   privacy policy actually configured for the venue.

## Non-goals

- **No fire-system control.** The framework does not connect to, command,
  inhibit or substitute for fire detection or suppression. Emergency egress
  remains the fire system's responsibility.
- **No biometrics or camera media.** There is no API surface for face
  templates, embeddings, fingerprints or video: CCTV is metadata-only.
- **No safety certification.** The conformance suite proves connector contract
  behaviour, not fitness for a safety function, SIL/ASIL rating or regulatory
  acceptance.
- **No AGPL linkage.** A closed connector cannot and must not reach the AGPL
  venue runtime through this framework; the dependency test enforces it.

## Tests

`tirbase-venue-connectors/tests/`:

- `st10_connectors.rs` — schema strictness and round-trip; profile validation,
  secret references and mapping; scan/announcement replay suppression; retry
  backoff and dead-letter replay; signed, unsigned, stale, tampered and rotated
  webhook signatures; inbound replay and payload conflict; holder pseudonymity,
  field removal, text scrubbing, media and biometric refusal; conformance
  certification and the double-delivery failure.
- `agpl_free.rs` — manifest licence and dependency checks, full `Cargo.lock`
  reachability, and the `LICENSING.md` row.
