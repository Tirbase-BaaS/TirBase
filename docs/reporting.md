# Reports, audit and e-signatures (CC-21)

AGPL backend: `tirbase_gateway::reporting`. Apache-2.0 UI:
`console/src/screens/AuditScreen.tsx` talking through `console/src/audit.ts`.

The reporting service reads the tables the excursion, lot, asset-registry and
lineage-ledger modules already own (`primary.db`), and owns only its own tables:

| Table | Purpose |
| --- | --- |
| `report_generations` | one immutable row per generated report (content JSON, digest, sources, ALCOA+) |
| `report_exports` | rendered CSV/JSON/PDF bodies, digests, signed manifests, prunable bodies |
| `report_audit` | hash-chained append-only log: generation, export, signing, re-auth failures, retention |
| `report_signers` | enrolled signer id, SHA-256 of the re-auth credential, role |
| `esign_ceremonies` | opened ceremonies bound to a report digest, reason, nonce; single-use |
| `esign_signatures` | completed Ed25519 signatures |

## Reports

`ReportKind`: `excursion_history`, `quarantine_aging`, `disposition`,
`calibration_due`, `lot_traceability`, `export_verification`.

`ReportRequest` selects the tenant, an optional time range and an optional lot or
asset subject. Every report row carries `sources: SourceRef[]`, where each source
names the row kind, its id and a SHA-256 (or, for ledger entries, the ledger's own
`entry_hash`). The report also holds the deduplicated union of sources, so
`report.cites(SourceKind::LedgerEntry, "exc-ledger-1")` proves the trace, and
`report.ledger_refs()` lists the chain entries a report depends on.

The report id is `rpt-<16 hex>` of the content digest
(`TirBase/v1/ReportContent` over kind, tenant, generation instant, generator,
range, columns, rows, totals and sources). Regenerating the same content is
idempotent: same id, no second audit entry. The digest is what exports,
manifests and e-signatures bind to.

## ALCOA+

`Report::alcoa` assesses the nine criteria with evidence strings:

- **attributable** — generator named and every row cites at least one source.
- **legible** — every declared column renders in every row.
- **contemporaneous** — no source timestamp post-dates the generation instant.
- **original** — the content digest recomputes from the stored report.
- **accurate** — every source digest is 64 hex characters.
- **complete** — totals exist and every row is populated.
- **consistent** — row keys are unique.
- **enduring** — the generation row and its audit entry exist.
- **available** — the report is stored and exportable.

`AlcoaAssessment::satisfied()` is true only when all nine hold.

## E-signature ceremony

1. `enroll_signer` stores the SHA-256 of the signer's credential (never the
   credential).
2. `open_ceremony` requires `ReauthProof { method, at_est, credential_sha256 }`
   no older than `REAUTH_WINDOW_SECS` (900 s) and a reason of 8–512 characters.
   A wrong credential digest returns `ReauthFailed`; a stale one returns
   `ReauthNotFresh`; both are audited as `esign_reauth_failed`.
3. The ceremony binds the report id, content digest, signer and a deterministic
   nonce.
4. `sign_ceremony` signs the canonical payload
   (`TirBase/v1/EsignPayload` over report id, digest, signer, ceremony, nonce,
   reason, signing instant) with Ed25519, exactly once. A second call returns
   `CeremonyAlreadyUsed`; if the stored report no longer hashes to the bound
   digest it returns `RecordChanged`.
5. `verify_signature` recomputes the report digest from the stored rows *and*
   re-verifies the signature, so editing the stored report invalidates it, and a
   signature produced for one report cannot be verified against another.

## Exports

`export(report_id, format, actor, now)` renders deterministic CSV, JSON or PDF
bytes, then builds an `ExportManifest` (format version, export id, report id,
kind, tenant, content digest, row count, body digest and length, exporter,
public key, algorithm) and signs the manifest JSON with Ed25519. The manifest
digest is domain-separated (`TirBase/v1/ReportManifest`), the body digest with
`TirBase/v1/ReportBody`. `verify_export` recomputes both and re-verifies the
signature. The `export_verification` report re-derives every stored export's
verdict (`valid`, `body_pruned`, `signature_invalid`, `body_digest_mismatch`,
`manifest_digest_mismatch`).

PDF is produced in-crate with the built-in Helvetica face (no external library,
no embedded font), paginated at 66 lines.

## Audit, retention and restore

`report_audit` is append-only and hash-chained
(`TirBase/v1/ReportAudit` over seq, previous hash, instant, actor, action,
subject and canonical detail). `verify_audit_chain` recomputes every link and
reports sequence gaps, previous-hash mismatches and entry-hash mismatches.

`prune_export_bodies(before_est, actor, now)` drops only export *bodies* older
than the cut-off, keeps their digests, manifests and signatures, and appends an
`exports_pruned` entry naming what was pruned. Generations, signatures and the
chain itself are never pruned. `snapshot_to(path)` writes a transactionally
consistent `VACUUM INTO` copy; opening it restores the audit chain, generations,
signatures and any bodies pruned after the snapshot.

## UI endpoint contract

The console screen reads these paths through the generated SDK's generic HTTP
methods. They are mounted in `tirbase_gateway::admin::dispatch_http_request`,
which serves both the local Unix socket and the mTLS remote listener:

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/admin/reporting/reports?tenant=&kind=&limit=` | `{ status, tenant, items: ReportSummary[] }` |
| `GET` | `/admin/reporting/reports/{id}?tenant=` | `{ status, tenant, report: Report }` |
| `GET` | `/admin/reporting/reports/{id}/signatures?tenant=` | `{ status, tenant, signatures: EsignResult[] }` |
| `GET` | `/admin/reporting/audit?tenant=&limit=` | `{ status, tenant, entries: AuditEntry[] }` |
| `GET` | `/admin/reporting/audit/verify?tenant=` | `{ status, tenant, verification: AuditVerification }` |

All five are `GET`-only (a write answers `405`). Credentials follow the same
model as every other admin route: a kernel-attested local caller is trusted, and
a remote caller must present a valid scoped Biscuit token — missing or
unverifiable credentials answer `401 ADMIN_CREDENTIAL_REQUIRED`, and a verified
role other than `Auditor` or `PolicyAuthority` answers `403
ADMIN_CREDENTIAL_INSUFFICIENT`, because audit material is privileged.

The `tenant` parameter is required (`400` when absent, never defaulted). Every
listing is filtered by it, and a report belonging to another tenant answers
`404` exactly like an unknown id, so report ids cannot be probed across
tenants. Audit rows are resolved through the tenant's report ids and their
export, signature and ceremony subjects; gateway-level rows (signer enrollment,
retention pruning, chain verification) are not part of a tenant view. Unknown
kinds answer `400`, and an unconfigured process answers `503
ADMIN_STATE_UNCONFIGURED`.

The service is mounted by the gateway binary when `report_signing_seed_path`
names a file holding a 64-hex-character Ed25519 seed; that key signs exports and
e-signatures. Without it the surface stays offline with `503` rather than
signing with an ephemeral key.

## Tests

`tirbase-gateway/tests/reports.rs` seeds excursion, lot and calibration rows with
SQL and appends real ledger entries through `LineageLedger`, then asserts:

- a report cites the source excursion events and ledger entries, with digests
  equal to the ledger's `entry_hash`;
- e-signature ceremonies refuse wrong and stale re-authentication, cannot be
  signed twice, cannot be replayed onto another report, and fail after the stored
  report is tampered with;
- exports render, verify and are re-derived by the verification report;
- retention prunes bodies while the audit chain, generations and signatures
  remain verifiable, and a snapshot restores them.

`tirbase-gateway/tests/reporting_http.rs` seeds a database, generates reports for
two tenants and signs one, then drives a loopback HTTP/1.1 listener that forwards
to the real `dispatch_http_request` path. It asserts the five contracts the audit
screen consumes, tenant isolation on listing, detail and audit (a foreign report
is a `404`), filtered audit subjects, chain verification, the `400` for a missing
tenant, the `405` for a write, `503` without a service and `401` without a remote
credential.
