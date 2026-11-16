# Alerts and notification framework (CC-17)

`tirbase-gateway::alerts` is the runtime's alerting engine: it deduplicates,
routes, delivers at least once, retries, escalates, records acknowledgements and
keeps a delivery audit. The transports it delivers through live in the
Apache-2.0 `tirbase-notify` crate, so a vendor can ship a closed connector
(Slack, Teams, PagerDuty, SMS) against a permissive interface.

## Licence boundary

| Piece | Licence | Where |
|---|---|---|
| The `AlertNotifier` trait, routing, deduplication, retries, escalation, acknowledgement, dead letters, audit | AGPL-3.0-only | `tirbase-gateway/src/alerts/` |
| The connector interface (`NotifyTransport`), the alert message model, secrets by reference, retry arithmetic, on-call rotations, and the generic email/webhook/console connectors | Apache-2.0 | `tirbase-notify/` |

`tirbase-notify` depends on no AGPL crate (`tirbase-notify/tests/agpl_free.rs`
walks `Cargo.lock` and cross-checks the denylist against `LICENSING.md`). A
closed vendor plugin implements `tirbase_notify::NotifyTransport` and is passed
to `AlertRouter::new`; it never links the AGPL engine. Vendor SaaS connectors are
**not** in this repository — the open repo ships the interface and the generic
connectors only.

## Guarantees

* **At least once.** A delivery row is written before any transport is called
  and marked `delivered` only after the transport accepts it. A crash between
  "sent" and "recorded" re-sends on the next `run_due`, with the same alert id,
  deduplication key and delivery id, so a receiver keyed on them collapses the
  repeat.
* **No duplicate pages.** Alerts are unique on `(tenant, dedup_key)`: raising the
  same event again returns `RaiseOutcome::Duplicate` and queues nothing.
  Deliveries are unique on `(alert, channel, address, level)`.
* **Retries and dead letters.** A retriable failure increments the attempt count,
  stores the error and schedules the next attempt with bounded exponential
  backoff (`RetryPolicy`, jitter derived from the alert id so a restart computes
  the same deadline). A permanent failure, or an exhausted budget, moves the
  delivery to `alert_dead_letters` with its last error; `dead_letters()` returns
  them.
* **Escalation.** A rule with `escalate_after_secs` and `max_level > 1` pages the
  next on-call level once `occurred_est + escalate_after_secs × level` passes
  without an acknowledgement. Escalating writes an `escalated` audit row; an
  acknowledgement stops it. A broken rotation is recorded as
  `escalation_unrouted` rather than swallowed.
* **Acknowledgement.** `acknowledge(alert_id, by, at_est)` is idempotent: the
  first call acknowledges, later calls report `AlreadyAcknowledged` with the
  original name and time.
* **Secrets by reference.** A channel carries a `SecretRef` (a name). The
  transport resolves it at delivery time; the database stores the reference in
  `alert_deliveries.secret_ref` and no secret value reaches a row, an audit entry
  or a `Debug` rendering.

## Routing

A route rule selects by severity and site, and names on-call roles and channels:

1. A site-specific rule wins over a global one; among equally specific rules the
   lowest `rule_id` wins, so configuration order cannot change who is paged.
2. Each role resolves through the on-call rotation **at the alert's observation
   time**, so replaying or back-filling an alert pages whoever was on call then.
3. Person-directed channels (email) are addressed to the on-call member; group
   channels (webhook, console) use their own endpoint and describe the role in
   the payload.
4. Duplicate `(channel, address)` pairs are collapsed.
5. A role with no rotation at that level is an error, not a silent drop; an alert
   with no matching rule is stored, audited as `unrouted`, and visible in
   `open_alerts` — it is never quietly discarded.

## Configuration

`AlertsConfig` parses the `[alerts]` section of the gateway configuration. Every
struct denies unknown fields, so an inline `secret`/`password`/`token` key fails
to parse instead of becoming a stored value.

```toml
[alerts]
secrets_dir = "/etc/tirbase/secrets"

[alerts.retry]
max_attempts = 6
base_secs = 15
max_secs = 900

[[alerts.channels]]
name = "email"
kind = "email"                          # email | webhook | console
endpoint = "alerts@tirbase.local"       # sender mailbox
secret_ref = "smtp/alerting"            # a name, never a value

[[alerts.channels]]
name = "console"
kind = "console"
endpoint = "-"

[[alerts.routes]]
rule_id = "excursion"
min_severity = "warning"
site_id = "site-1"                      # optional; omit for every site
roles = ["cold-chain"]
channels = ["email", "console"]
ack_required = true
escalate_after_secs = 900
max_level = 2

[[alerts.on_call]]
role = "cold-chain"
level = 1
start_est = 1770000000
period_secs = 604800
members = ["ana@example.com", "bo@example.com"]

[[alerts.on_call]]
role = "cold-chain"
level = 2
start_est = 1770000000
period_secs = 604800
members = ["lead@example.com"]
```

Secrets are files under `secrets_dir`, one per reference name (for example
`/etc/tirbase/secrets/smtp/alerting`). `FileSecretStore` rejects absolute names,
`..` components and symlinks that escape the root. A webhook endpoint must be
`https://`.

## Connectors

| Kind | Behaviour |
|---|---|
| `email` | SMTP session: greeting, `EHLO`, `AUTH PLAIN` when a username is configured (password from the secret reference), envelope, `DATA` with CRLF endings and dot-stuffing, `QUIT`. 4xx is retriable, 5xx permanent. Header values are sanitised so a title cannot inject headers. TLS belongs to the dialer the deployment supplies. |
| `webhook` | `POST` with a deterministic JSON body, `Idempotency-Key` = deduplication key, `X-TirBase-Delivery`, `X-TirBase-Timestamp`, `X-TirBase-Escalation` and `X-TirBase-Signature: sha256=<hex HMAC-SHA256(secret, "timestamp.body")>`. 2xx delivered; 408/425/429/5xx retriable; other 4xx permanent. |
| `console` | One tab-separated line per delivery: time, severity, site, role, level, ack state, alert id, title. The local fallback when no relay is configured. |

## Bridging CC-11

`Alert::from_excursion(&ExcursionNotification, Severity)` turns a workflow
notification into an alert and **keeps the notification id as both the alert id
and the deduplication key**, so the excursion workflow and the alerting framework
cannot disagree about whether two notifications are the same event.

## Operating it

```rust
let router = AlertRouter::new(store, routing, transports, retry_policy)?;
router.raise(&alert)?;            // dedup, route, queue, first attempt
router.run_due(now_est)?;         // retries + escalations, on a timer
router.acknowledge("alert-1", "ana", now_est)?;
router.dead_letters()?;           // what stopped trying, and why
router.audit("alert-1")?;         // raised, queued, delivered, retry, dead_letter, escalated, acknowledged, unrouted
```

The engine never reads a clock: `raise` uses the alert's `occurred_est` and
`run_due` takes the current time from its caller, so decisions are reproducible
from stored state and testable without sleeping.

## Tests

```sh
cargo test -p tirbase-notify        # connectors, secrets, backoff, on-call maths
cargo test -p tirbase-gateway --test alerts
```

`tirbase-gateway/tests/alerts.rs` covers the three acceptance conditions
directly: raising the same event twice pages once (including a different alert id
with the same deduplication key), a failed delivery is retried with backoff,
stays visible in `deliveries()` and the audit, and becomes a dead letter when the
budget is exhausted or the failure is permanent; and an unacknowledged critical
alert pages level 2 at its deadline while an acknowledged one does not. It also
covers at-least-once resumption across a restart on the same database, secrets
resolved by reference end to end through a webhook, routing precedence by site
and severity, the console connector, and the CC-11 bridge.
