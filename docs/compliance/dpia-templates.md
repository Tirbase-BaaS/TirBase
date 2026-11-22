# DPIA Templates and Data-Flow Maps (F-15)

> **Disclaimer (cannot-claim-compliance):** Templates only. They do **not** constitute a completed DPIA or legal advice. A qualified Data Protection Officer/legal counsel must complete and sign off before pilots involving personal data in regulated jurisdictions (e.g. EU/UK). Record the completed DPIA review per pilot (see §5).

## 1. How to use this document

- For each vertical deployment, copy the relevant section into a project DPIA record and complete all fields.
- **Data-flow maps** below are descriptive; attach architecture diagrams and network diagrams in the project record.
- Cross-reference: `docs/compliance/data-protection-procedures.md`, `docs/THREAT_MODEL.md`, `SECURITY.md`.

## 2. Shared platform (all verticals)

### 2.1 Typical data categories (non-exhaustive)
| Category | Examples | Notes |
|----------|----------|-------|
| Identity/credentials | DID identifiers, Biscuit tokens (references), admin mTLS cert subjects | Avoid storing raw secrets in logs; redact per `tirbase-gateway/src/telemetry.rs` patterns |
| Operational telemetry | Timestamps, device IDs, site/venue/order IDs, command outcomes | May become personal if linked to individuals (e.g. operator accounts in external IAM) |
| Security events | Hash-chained events (`security_log`); may include actor DID, reason codes, redacted details | Pseudonymization/salting options exist (`security_log_export.rs`, CLAIM-27.x) |
| Audit exports | JSON/CSV exports for operators/auditors | Treat as sensitive; access-controlled distribution |

### 2.2 Data-flow map (shared)
```
[Field devices / drivers] --frames--> [Gateway (guarded ingress)]
        |                                    |
        v                                    v
  [Local persistence: SQLite WAL] <---> [Applied effects / security log (PrimaryLedger)]
        |                                    |
        +--> [Optional cloud anchor/sync (mTLS)] --> [Operator cloud/Vendor]
        +--> [Admin API / console (mTLS + Bearer)] --> [Operator/Auditor UI]
        +--> [Exports] --> [Auditor / regulator handoff (controlled)]
```

### 2.3 DPIA checklist (shared)
- [ ] Lawful basis and purpose documented per data category
- [ ] Retention and deletion schedule agreed (see data-protection-procedures)
- [ ] Residency/transfer requirements assessed
- [ ] Access control matrix (roles: CommandIssuer, PolicyAuthority, Auditor, etc.) reviewed
- [ ] Logging/monitoring reviewed for minimization (no unnecessary PII in payloads)
- [ ] Incident response and breach notification contacts listed

## 3. Vertical: Cold chain

**Typical personal data touches:** operator names/emails in ticketing systems (external), technician IDs in work orders (external). On-device data is primarily temperature/site IDs unless explicitly extended.

**Data-flow notes:** sensors → gateway → local DB → optional exports to compliance systems. Ensure site/operator identifiers are pseudonymized where possible.

**DPIA prompts:**
- Are operator identities stored on the edge node? If yes, list fields, purpose, retention.
- Who receives excursion reports/exports? (processors/subprocessors list)
- Cross-border transfer of export files?

## 4. Vertical: POS (point of sale)

**Higher PII risk if extended:** customer receipts may include names/contacts if stored; loyalty IDs may be personal data. Default F-08 POS resources are order/line/sale records scoped by tenant — confirm whether any personal fields are introduced.

**Data-flow notes:** POS client → gateway/admin API or vertical API → SQLite; exports for accounting/audit.

**DPIA prompts:**
- Inventory every field that could identify a natural person (even indirectly).
- Payment card data: **must not** be stored in TirBase unless explicitly designed and PCI-scoped (out of default scope) — document exception or prohibition.
- Receipt retention vs tax law retention; legal hold interaction.

## 5. Vertical: Stadium / venue

**ST-13 supersedes this section for venue deployments.** Use the four completed
per-domain baselines and the field register:

- [`venue-dpia/README.md`](venue-dpia/README.md) — ticket, credential, CCTV and
  access DPIAs
- [`venue-data-flow-retention.md`](venue-data-flow-retention.md) — data-flow map
  and retention schedule
- [`venue-cctv-retention.md`](venue-cctv-retention.md) — metadata-only CCTV and
  enforced retention
- [`venue-subject-access-deletion.md`](venue-subject-access-deletion.md) — SAR
  and deletion with legal hold

**Typical personal data touches:** attendee/session identifiers in access logs if integrated with ticketing; gate operator accounts external. Gate events may be linked to ticket IDs (personal data) depending on integration.

**Data-flow notes:** gate controllers/scanners → gateway → event logs; potential sync to venue management systems. CCTV is metadata-only in TirBase; video, if used, remains in the venue VMS under a separate DPIA.

**DPIA prompts:**
- Biometric or facial recognition: if any, **do not** process in TirBase without a separate high-risk DPIA and legal basis review (explicitly call out).
- Video is out of scope for this runtime; document the VMS/video controller boundary.

## 6. Pilot privacy review record (required before pilot)

| Field | Value |
|-------|-------|
| Pilot name / customer | |
| Verticals in scope | |
| DPIA owner | |
| Completed date | |
| Residual risks accepted by | |
| Links to data-flow diagrams | |
| Links to completed templates (sections 3–5) | |

**Done-when (F-15):** “Privacy review is recorded before a pilot.” — attach this record (completed) to the pilot folder and reference it in project tracking. The ST-13 software-pilot record is at [`venue-pilot-privacy-signoff.md`](venue-pilot-privacy-signoff.md); a customer pilot needs a completed customer record.
