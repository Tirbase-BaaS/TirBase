# Support Period and Security-Update Policy (Evidence Aid)

> **Disclaimer (cannot-claim-compliance):** This document is an internal evidence aid only. It does **not** constitute, claim, or imply certification, conformity assessment, or compliance with the EU Cyber Resilience Act, IEC 62443, or any other standard or regulation. No external publication, customer representation, or regulatory submission may be made using this document without prior review and written approval by qualified legal counsel.

**Release reviewed against:** `<fill at release>`  
**Last reviewed (UTC):** `<YYYY-MM-DD>`  
**Policy owner:** `<product/security owner>`

## 1. Purpose

This policy states the **minimum period** for which TirBase security patches will be provided for supported releases, and defines the support model used to plan, publish, and communicate security updates.

## 2. Definitions

- **Security patch:** A release or hotfix intended to remediate a vulnerability, security regression, or security-relevant defect.
- **Supported release line:** A version/branch line eligible to receive security patches under this policy.
- **End of Security Support (EoSS):** The date after which security patches are no longer guaranteed for a release line.
- **Critical/High severity:** As triaged under `docs/compliance/vulnerability-handling.md`.

## 3. Minimum security-patch period

- **Minimum security-patch support period:** **24 months** from the General Availability (GA) date of each supported **major or designated LTS release line**.
- **Security patches will be provided for supported release lines throughout this minimum period** for vulnerabilities assessed as exploitable/relevant to that release line, subject to technical feasibility and coordinated disclosure constraints.
- **No security patches are guaranteed after EoSS**, except where required by contract, applicable law, or an explicitly published emergency exception approved by the policy owner and legal counsel.

> If a shorter or longer contractual/support commitment applies to a specific customer or distribution, that commitment must be documented separately; this document defines the repository/project minimum baseline, not a customer-specific warranty.

## 4. Support model (baseline)

| Release type | Eligibility for security patches | Minimum period | Notes |
|---|---|---|---|
| Designated LTS / supported major line | Yes | 24 months from GA | Primary target for backported security fixes |
| Current non-LTS minor/patch releases | Best effort | Until superseded by the next patch/minor on the same supported line | Users should update to latest patch on supported line |
| Pre-release / nightly / development builds | No guarantee | N/A | Security fixes may land on main branch without backport guarantees |
| End-of-life / EoSS releases | No | N/A | Upgrade to a supported release line |

## 5. Security update delivery commitments (process)

- Triage and handling follow `docs/compliance/vulnerability-handling.md`.
- Security fixes are delivered via source releases and associated release artifacts (including SBOM/VEX, signatures/provenance, and attestations where applicable).
- Backport decisions consider severity, exploitability, affected deployment configurations, and regression risk.
- Known unpatched vulnerabilities after EoSS (or accepted risks) must be documented in release/advisory notes and dependency review records as appropriate.

## 6. Communication

- Security advisories/releases will identify affected versions, fixed versions, severity, and mitigations/workarounds.
- EoSS dates for supported release lines must be published in release documentation/changelog when a line is designated or retired.
- This policy may be updated; material changes must record the effective date and the releases impacted.

## 7. Review checklist (per release)

- [ ] Supported release lines and GA/EoSS dates are current
- [ ] Minimum 24-month security-patch period remains satisfied for active supported lines
- [ ] Outstanding security issues and backport decisions documented
- [ ] Changes reviewed before any external publication

---
*Evidence aid only. Not a compliance or certification claim. External publication requires prior legal counsel review.*
