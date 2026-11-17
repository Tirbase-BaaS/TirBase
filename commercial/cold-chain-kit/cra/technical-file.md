# CRA technical file — TirBase cold-chain gateway

**Status:** DRAFT. This file is organised to the structure a CRA technical file needs, so
an assessor can verify it. It is not a declaration of conformity and must not be treated
as one until `review/counsel-review-record.md` and `review/assessor-review-record.md` are
approved and the operator has completed its own conformity route.

**Product:** TirBase gateway with guard, applied to cold-chain monitoring and control.
**Version:** release under validation (record the exact tag/digest in `manifest.json`).
**Manufacturer/economic operator:** the entity named in the signed agreement, not the
open-source maintainers unless separately contracted.

## 1. Product description and intended use

- Edge gateway validating sensor input and enforcing signed, authorised control actions
  for cold rooms, reefers, transport boxes and connected storage sites.
- Supported field transports: DS18B20 1-Wire, 4–20 mA, BLE GATT, BACnet/IP, Modbus
  RTU and Modbus TCP.
- Intended environment: fixed or mobile cold-chain sites with intermittent connectivity;
  local-first operation with optional outbound reporting.
- Not intended for: safety-instrumented functions, SIL-rated protection, medical device
  control, or any use where gateway failure can cause direct physical harm. See
  `../EXCLUSIONS.md`.

## 2. Risk assessment

`risks.csv` is the risk register: threat, affected asset, likelihood/impact, existing
mitigation, residual risk, and the requirement it maps to. It builds on
`docs/THREAT_MODEL.md` and the CC-22 validation evidence. Likelihood and impact are
qualitative (low/medium/high) and must be re-scored for the customer's deployment.

## 3. Security requirements and conformity evidence

| CRA Annex I area | Evidence in this kit or repository |
| --- | --- |
| Secure by default | `docs/operator-guide.md`, deny-all command posture, mTLS-only remote admin |
| Authentication and authorisation | `docs/token-schema.md`, `SECURITY.md`, guard admission |
| Confidentiality | encrypted-database option, TLS paths, secret handling |
| Integrity | signed artefacts, hash-chained security and report audit |
| Availability | bounded queues, modes, reconciliation, failure-injection catalogue |
| Minimised attack surface | loopback-only health/metrics, no inbound cloud listener, driver isolation |
| Monitoring | `docs/security-event-catalog.md`, alerting with delivery audit |
| Vulnerability handling | `docs/compliance/vulnerability-handling.md`, `SECURITY.md` |
| Update capability | signed updates, SBOM/VEX, reproducibility workflow |
| User information | operator guide, hardening checklist, this kit |

Each row is reviewed per release; the dated review result goes in the release record.
Evidence is provided by reference and rendered on request; source is not part of this kit.

## 4. Vulnerability handling

- **Reporting:** the security contact in `SECURITY.md`; encrypted reports on request.
- **Triage:** severity assessed with exploitability and deployment relevance; affected
  versions identified from the SBOM and release range.
- **Remediation:** fix, backport or documented mitigation; coordinated disclosure with the
  reporter; advisory published with affected/fixed versions.
- **Timelines:** acknowledgement and triage targets are in the vulnerability-handling
  document; contractual SLAs, where signed, take precedence.
- **Records:** advisory, affected components, CVEs where assigned, and customer
  notification evidence are retained by the manufacturer/operator.

## 5. Support period

- Minimum **24 months** of security patches from GA for each supported major/LTS line, per
  `docs/compliance/support-period-policy.md`.
- End-of-support is communicated at least 6 months before EoSS, with an upgrade path.
- Customer-specific support (24/7 coverage, response targets) is contractual:
  `../licensing/24x7-SLA-TEMPLATE.md`.

## 6. SBOM and supply chain

- CycloneDX SBOM and VEX are generated per tagged release by `.github/workflows/sbom.yml`
  and attached to the release; the build is reproducible, and release artefacts are signed.
- Dependency policy and licence gates: `deny.toml`, `LICENSING.md`, `scripts/`.
- For a customer-specific build, the matching SBOM is attached to the delivery; absence is
  tracked as `GAP-SBOM-001`.

## 7. Conformity evidence index

| Evidence | Location |
| --- | --- |
| Claims and gated tests | `CLAIMS.md` |
| Validation campaign | `docs/evidence/hil/cc22-sensor-controller-validation/` |
| Calibration/uncertainty | `../calibration/` |
| IEC 62443 dossier | `../iec62443/SL2-SL3-dossier.md` |
| Security policies | `SECURITY.md`, `docs/compliance/` |
| Release artefacts, SBOM/VEX | release assets for the delivered tag |
| Independent review | `../review/assessor-review-record.md` (pending) |

## 8. Known limitations and residual risks

Listed with owners in `../audit-kit/gaps.csv` and scored in `risks.csv`. The largest are:
physical field-bus access (site control), key custody (operator HSM/procedure), field
update governance (contractual), and the absence of an independent assessment
(GAP-REV-002). None is represented as closed.
