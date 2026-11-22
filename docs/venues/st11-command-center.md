# ST-11 — Command center and incident UI

**Status:** complete. **Licence:** AGPL-3.0-only backend, Apache-2.0 UI.
**Backend:** `tirbase-venue-command-center`. **UI:** `console/venue-command-center/`.
**Depends on:** ST-08 (`tirbase-venue-lockdown`), F-09 console conventions.

ST-11 is the venue's operator-facing control plane. It joins the approved
lockdown/override engine from ST-08 to an attributable incident workflow, a live
zone/gate map, drill isolation and after-action reporting, and exposes one
role-aware JSON state document. The console is a separate Apache-2.0 static
application that talks to the AGPL backend over HTTP; it links no runtime code.

## Licence boundary

```text
console/venue-command-center/          Apache-2.0 static UI
        │  HTTP + JSON only
        ▼
tirbase-venue-command-center           AGPL-3.0-only  ← this task
        ├── tirbase-venue-lockdown     AGPL-3.0-only  ST-08 approvals/engine
        ├── tirbase-venue-capacity     AGPL-3.0-only
        ├── tirbase-venue-ticket       AGPL-3.0-only  Ed25519 command signers
        └── tirbase-venue              AGPL-3.0-only
```

The UI carries an Apache-2.0 SPDX header on every source file and contains no
AGPL import, reference or linked runtime. The backend crate declares
`AGPL-3.0-only` and the repository matrix records both rows. The console licence
check now walks `venue-command-center/` as well, forbidding AGPL markers and
non-console dependencies.

## What is in the box

| Area | Implementation |
|---|---|
| Venue map | Two zones and three gates, live occupancy, soft/hard limits, occupancy bars, per-zone and per-gate alarm state, gate posture, ingress/egress. |
| Incident workflow | `open → acknowledged → dispatched → escalated → resolved → reported`, with role checks, required escalation/resolution notes and one action record per step. |
| Lockdown and override | Venue or zone lockdown and release, signed through ST-08 by two configured approvers, with requester/approver attribution, reason, expiry and an audit row. |
| Drill mode | A separate tactical state with its own incidents, audit, command ids and `LockdownEngine`. Drill actions cannot reach live state. |
| After-action report | Incident reports with participants/timeline; drill reports with an explicit `live_gate_state_unchanged` proof. |
| Role-aware views | Operator, supervisor, safety officer and auditor capabilities are computed by the backend and used by the UI. |
| Audit | Append-only sequence with time, actor, role, action, subject, detail and drill flag. |

The backend uses the fixed venue fixture `venue-1` (TirBase Arena):
`zone-north` with `gate-n1`/`gate-n2`, and `zone-south` with `gate-s1`.

## Role matrix

| Capability | Operator | Supervisor | Safety officer | Auditor |
|---|---:|---:|---:|---:|
| View state / audit | ✓ | ✓ | ✓ | ✓ |
| Acknowledge, dispatch, escalate | ✓ | ✓ | ✓ | — |
| Resolve, generate report | — | ✓ | ✓ | — |
| Request/approve lockdown or release | — | ✓ | ✓ | — |
| Start/end drill | — | ✓ | ✓ | — |

The UI reflects this: an auditor sees the map, incidents, audit and reports with
all mutation controls disabled and a read-only notice; operators see only the
incident actions their role permits; the lockdown/drill controls are available
only to supervisors and safety officers.

## Incident attribution

Every mutation requires an actor and role. The backend rejects a blank actor,
checks the role's capability, applies a status transition and writes both:

1. an `IncidentAction` (`action_id`, kind, actor, role, time, note, from/to
   status) on the incident; and
2. an `AuditEntry` (`seq`, time, actor, role, action, subject, detail, drill).

Escalate and resolve require a non-empty note, so a status cannot change without
a recorded reason. A report produces an `AfterActionReport` whose participants
are derived from the action history.

## Lockdown approvals

The command center configures ST-08 with an approval policy of **2 of 2** for
lockdown and release. A request:

1. checks the requester's role and reason;
2. rejects a short approval list, duplicates, unknown names and self-approval;
3. builds an exact `CommandRequest` for `venue` or `zone:<id>`, valid for one
   hour;
4. signs it with the named custodians' Ed25519 keys and verifies it through
   `LockdownEngine::execute`;
5. records `lockdown.engaged` / `lockdown.released` with requester, approvers,
   scope and reason.

Release must use the same scope as the active lockdown. The gate posture is the
ST-08 fail-safe posture: ingress refused while locked, **egress always open**.

The three demo custodians (`custodian-1`, `custodian-2`, `custodian-3`) use
deterministic seeds so the local acceptance tests are reproducible. They are
fixtures, not a production key-management design; a deployment must supply
identity-backed approvers and authenticated operators.

## Drill isolation

Starting a drill:

- captures the live gate-posture fingerprint;
- forks occupancy and incident state into a new `TacticalState`;
- creates a **new** ST-08 `LockdownEngine`, so live lockdowns are not copied and
  cannot be released from the drill;
- stores drill command ids and audit separately.

Every incident action and lockdown command resolves to the drill state while the
mode is `drill`. Ending the drill writes a drill report to the live state, compares
the live fingerprint with the captured baseline, records `unchanged` or `CHANGED`,
and returns to live. There is no code path from a drill mutation to `live`.

## HTTP API

The backend binds loopback `127.0.0.1:4190` (override with `--port`) and serves
JSON with permissive CORS for the separately served console.

| Method | Path | Body / headers |
|---|---|---|
| `GET` | `/api/health` | — |
| `GET` | `/api/state` | `x-actor`, `x-role` headers |
| `POST` | `/api/incidents/{id}/actions` | `{action, note?, actor, role}` |
| `POST` | `/api/lockdown` | `{command: "lockdown"\|"release", scope, reason, approvers, actor, role}` |
| `POST` | `/api/drill/start` | `{actor, role}` |
| `POST` | `/api/drill/end` | `{actor, role}` → after-action report |

Errors carry a stable `code` and a message; forbidden role actions are HTTP 403,
validation failures 422, and state conflicts (drill already running, no drill,
invalid transition, not locked) 409. No secrets or private keys are returned.

This std-only HTTP surface is a local control-plane fixture, not an internet
gateway: it has no TLS, session authentication or rate limiting. Run it behind
the venue's authenticated edge before exposing it.

## Running

```bash
# Backend (AGPL)
cargo run -p tirbase-venue-command-center --bin venue-command-center -- --port 4190

# Static UI (Apache-2.0), separate terminal
python3 -m http.server 4191 --bind 127.0.0.1 --directory console/venue-command-center

# Playwright journeys (starts both servers itself)
npm --prefix console run test:command-center
```

The UI defaults to `http://127.0.0.1:4190`; override with
`window.TIRBASE_COMMAND_CENTER_API`.

## Verification

- `cargo test -p tirbase-venue-command-center` — 6 engine/acceptance tests:
  approved lockdown initiate + release; one-approval and self-approval refusal
  without gate mutation; ordered incident workflow with every action attributable;
  role enforcement; drill lockdown isolation and unchanged live fingerprint;
  live zone lockdown surviving a drill.
- `cargo clippy -p tirbase-venue-command-center --all-targets --no-deps -- -D warnings`
  — clean.
- `npm --prefix console run test:command-center` — 4 Playwright journeys:
  operator incident acknowledge/dispatch attribution; supervisor lockdown with two
  approvals and release; drill lockdown, end and report proving live gates
  unchanged; auditor read-only view.
- `node console/scripts/check-licence.mjs` — console-wide Apache-2.0 boundary.

## Non-goals and open items

- No production identity provider or operator session authentication; role and
  actor are supplied by the caller in this fixture.
- No capacity-override or break-glass UI in this increment. ST-08 supports both;
  the lockdown/release path is the approval-gated override exposed here.
- No fire-system control or safety certification.
- The Playwright suite exercises Chromium locally; it is not a cross-browser
  certification.
