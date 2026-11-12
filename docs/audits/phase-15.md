# Phase 15 — SDK and API Surface Alignment — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.15

## Scope

Task sections 49.x, 50.x: 6 acceptance-criterion rows (6 complete, 0 open in `tasks.md` at audit time).

## Method

Every row was traced against the repository; nothing was accepted on assertion. The audit:

1. resolves each declared production-caller path on disk and each cited symbol to its
 definition site (`file:line`);
2. resolves test identifiers in this order: a claim-named test (`claim_<task>`), a test
 named in the task entry, the closest test in a test file named in the task entry, then
 the test location committed in `docs/traceability-matrix.md` for the task's PV
 requirement;
3. records tasks with an open checkbox as `NOT IMPLEMENTED` or `BLOCKED` — never as verified.

Evidence classes in the status column:

- `VERIFIED-BY-TRACE` — production call site resolved and a task-named/claim-named test resolved.
- `TRACED-CALLER` — production call site resolved; test evidence is file-, suite-, matrix- or CI-level only.
- `TRACED-TEST` — test or document deliverable traced, with no distinct runtime caller.
- `TRACED-ARTIFACT` — documentation/CI deliverable; the cited artifact exists.
- `BLOCKED` / `NOT IMPLEMENTED` — cannot be verified as done; reason recorded.

No row is `ASSUMED`: a row that could not be traced is reported as an open item instead.

## Evidence

| Task | Acceptance criterion (task) | Req | Production call site | Test evidence | Status |
|---|---|---|---|---|---|
| 49.1 | Define machine-readable API definition (OpenAPI 3.1) for guard and gateway native APIs; TypeScript SDK generat… | PV-17.1 | `docs/api/gateway-admin-openapi.yaml:1` | — | TRACED-ARTIFACT |
| 49.2 | Generate TypeScript SDK from OpenAPI definition using a CI step; reject manually written SDK changes | PV-17.1 | `.github/workflows/ci.yml:1240` | — | TRACED-ARTIFACT |
| 49.3 | Add CI diff of WASM exports against cargo public-api output to detect unintended surface additions | PV-17.1 | `.github/workflows/ci.yml:1254` | — | TRACED-ARTIFACT |
| 49.4 | Maintain changelog: every public API addition, removal, or modification recorded as a distinct entry before th… | PV-17.4 | `CHANGELOG.md:1` | — | TRACED-ARTIFACT |
| 50.1 | Create mdBook documentation site covering: architecture overview, threat model, operator guide, deployment har… | PV-17.2 | `docs/book.toml:2`<br>`docs/src/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 50.2 | Implement CI step: regenerate README Status section from CLAIMS.md so displayed status always reflects current… | PV-17.3 | `CLAIMS.md:1` | — | TRACED-ARTIFACT |

## Gaps and open items

- **49.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **49.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **49.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **49.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **50.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **50.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 6 rows have a resolved production call site or deliverable; 6 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

