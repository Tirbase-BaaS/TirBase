# IEC 62443 SL2/SL3 dossier — TirBase cold-chain gateway

**Status:** DRAFT evidence dossier. Not a certification, not an assessment report, and not
a claim of conformity. An accredited assessor must review and sign `review/assessor-review-record.md`
before any customer or regulator sees this as evidence.

**Target security levels:** SL 2 for the field/gateway zone, SL 3 for the gateway and
management conduit where remote administration is enabled. Where a deployment cannot meet
an SL 3 requirement, the deployment profile must record the lower target and the
compensating controls (see `requirements.csv`).

**Component baseline:** the release under validation, with the CC-22 validation campaign
(`docs/evidence/hil/cc22-sensor-controller-validation/`) and the current `CLAIMS.md`
registry as evidence.

## 1. Zones and conduits

The reference model is in `zones.csv` and `conduits.csv`. It follows the Purdue-style split but
does not claim compliance with any particular vendor reference architecture.

| Zone | Assets | Target SL | Rationale |
| --- | --- | --- | --- |
| Z1 Field devices | Sensors, controllers, actuators on 1-Wire, 4–20 mA, BLE, BACnet, Modbus | SL 2 | Physically reachable on site; compromise can falsify readings or actuate |
| Z2 Edge gateway | TirBase gateway, guard, driver processes, local store | SL 2 (SL 3 when remote admin enabled) | Trust boundary; holds keys, policy and records |
| Z3 Operations | Operator console, local admin workstation | SL 2 | Human decisions, audit review |
| Z4 Enterprise/cloud | Reporting, fleet console, backups | SL 2 | Aggregated data; outbound-only from Z2 |

Conduits and their controls are listed in the CSV: protocol, direction, authentication,
integrity, and the requirement ids that apply.

## 2. Threat model

Assets: readings and their provenance, calibration state, release decisions, signing keys,
policy/envelope definitions, audit chain, availability of monitoring.

| Threat | Vector | Impact | Existing control | Residual / gap |
| --- | --- | --- | --- | --- |
| Falsified reading | Spoofed sensor, replayed frame, tampered bus | Wrong release decision | Transport codecs reject bad CRC/malformed frames; source ids recorded; calibration gate | Physical bus access is site responsibility (Z1) |
| Forged command | Stolen operator key, replay | Unsafe actuation | Signed operations, nonce/anti-replay, envelope and policy checks, single-use permits | Key custody depends on operator HSM/procedure |
| Unauthorised admin | Exposed admin port, weak credential | Full compromise | Local peer-UID socket; mTLS-only remote admin with client CA; scoped Biscuit tokens | Certificate lifecycle is deployment evidence |
| Audit tampering | Direct database write | Lost accountability | Hash-chained log and report audit; verification tooling; checkpoints | Root/DB access by host admin is out of scope |
| Supply-chain compromise | Malicious dependency or update | Backdoor | Lockfile, deny/audit gates, SBOM/VEX, signed artifacts, reproducibility workflow | Build-host compromise needs organisational controls |
| Denial of service | Flood of commands, disk fill, alert flood | Monitoring blind spot | Rate limits, bounded queues, quarantine, alert dedup and dead letters | Capacity planning is site-specific |
| Key extraction | Filesystem or memory access | Identity theft | Keys outside repository, zeroization, no private-key export via API | TPM/secure element depends on hardware profile |
| Data disclosure | Stolen backup or export | Confidentiality breach | Optional encrypted database, signed exports, access control | Backup encryption is deployment evidence |

## 3. Requirement mapping (SL 2 / SL 3)

`requirements.csv` maps each applicable IEC 62443-4-2 foundational requirement (FR 1–7)
and the 4-1 lifecycle practices to: the target SL, the implementation status as
`met`, `partial` or `gap`, the evidence reference, and the gap id. Do not read `met` as
certified: it means the cited evidence exists in the baseline.

Summary by FR:

| FR | SL 2 expectation | Status | Principal evidence |
| --- | --- | --- | --- |
| FR 1 Identification and authentication | Unique identities, authenticated sessions, role separation | partial | Signed enrolment, token schema, role registry |
| FR 2 Use control | Authorised actions only, least privilege, session integrity | met | Guard admission, envelope/policy, scoped tokens |
| FR 3 System integrity | Integrity verification, tamper detection, anti-replay | met | Signed operations/bundles, hash-chained logs, replay windows |
| FR 4 Data confidentiality | Protect data at rest/in transit where required | partial | SQLCipher option, TLS paths, secrets handling |
| FR 5 Restricted data flow | Zone boundaries, deny-by-default flows | partial | mTLS-only remote admin, outbound-only cloud, explicit zones |
| FR 6 Timely response to events | Audit trail, alerting, response capability | met | Security event catalog, alerting, exports |
| FR 7 Resource availability | DoS resistance, graceful degradation, recovery | partial | Bounded queues, modes, reconciliation; capacity is site-specific |
| 4-1 lifecycle | SDL, requirements, verification, defect/update management | partial | CI gates, CLAIMS registry, SBOM/VEX, vulnerability policy |

## 4. Evidence index

| Evidence | Reference |
| --- | --- |
| Claims and their gated tests | `CLAIMS.md` |
| System invariants | `docs/system-invariants.md` |
| Threat model and adversary scenarios | `docs/THREAT_MODEL.md`, `docs/adversary-scenarios.md` |
| Security events | `docs/security-event-catalog.md` |
| Token and enrolment model | `docs/token-schema.md`, `docs/root-ceremony.md` |
| Remote admin and hardening | `docs/operator-guide.md`, `docs/packaging.md` |
| HIL/validation results | `docs/evidence/hil/cc22-sensor-controller-validation/` |
| Supply chain | `.github/workflows/sbom.yml`, `deny.toml`, `LICENSING.md` |
| Vulnerability handling and support | `docs/compliance/vulnerability-handling.md`, `docs/compliance/support-period-policy.md` |

## 5. Gap list and assessor actions

See `../audit-kit/gaps.csv` for the full register. Assessment-blocking items:

| Gap | Why it blocks an assessor sign-off | Action |
| --- | --- | --- |
| GAP-REV-002 | No accredited assessment has been performed | Engage an accredited body; give them this dossier and the evidence index |
| GAP-CUST-001/002 | Product and process hazards are customer-specific | Customer supplies HACCP/product data before assessment |
| GAP-ENV-001 | Enclosure/environmental qualification is site-specific | Qualify the installed enclosure or record an accepted residual risk |
| GAP-SUP-001 | 24/7 staffing is contractual | Sign the SLA; then provide staffing evidence |
| GAP-DATA-001 | Retention/legal basis is jurisdiction-specific | Complete the DPIA with the customer |

## 6. Assessor checklist

- [ ] Zones/conduits match the installed topology; unlisted conduits are documented.
- [ ] Every `met` row's evidence exists and supports the claim; sampled at least 1 in 5.
- [ ] Every `gap` row has an owner, a target date and an accepted or mitigated risk.
- [ ] SL targets are explicitly accepted by the operator for their deployment.
- [ ] Cryptographic key custody and update delivery are verified in operation.
- [ ] Findings recorded in `review/assessor-review-record.md`; residual risks accepted in writing.
