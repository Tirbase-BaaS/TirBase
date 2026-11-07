# Security Policy

<!-- CLAIM-3.5 -->

TirBase targets European critical infrastructure — cold chain, energy edge, water, logistics, and
similar safety-adjacent environments. We treat coordinated disclosure as a first-class obligation.

---

## Supported Versions

We address security issues in the current `main` branch only. Older tags receive no backported
fixes unless explicitly agreed with the reporter.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred channel

Use **GitHub Private Security Advisories**:

> <https://github.com/tirbase/TriBase/security/advisories/new>

This keeps the report confidential while allowing us to collaborate with you on a fix before any
public disclosure.

### Alternative contact

If you cannot use GitHub Security Advisories, send encrypted email to:

```
security@tirbase.dev
```

PGP key: publish your report first and we will provide a public PGP key on request (key
distribution is in progress; check back here for an updated fingerprint).

---

## What to Include

A useful report contains:

1. A concise description of the vulnerability and the affected component(s).
2. Steps to reproduce or a minimal proof-of-concept.
3. The impact you believe this would have in a real deployment (e.g., command injection, token
   forgery, bypass of the Command Guard, etc.).
4. Your assessment of exploitability (local only, network reachable, requires valid credentials,
   etc.).
5. Any suggested fix or mitigating configuration, if you have one.

We will credit you in the release notes unless you prefer to remain anonymous.

---

## Response Timeline

| Milestone | Maximum time |
|---|---|
| **Acknowledgement** | **5 business days** from receipt |
| Triage and severity assessment | 10 business days from receipt |
| Patch or mitigation available | Negotiated case-by-case; target ≤ 45 days for critical issues |
| **Coordinated public disclosure** | **90 days** from initial acknowledgement |

The 90-day disclosure window may be shortened by mutual agreement if a fix lands sooner. It may be
extended once — by up to 14 days — if an active patch is in progress and a firm release date is
confirmed. We will not extend beyond that without the reporter's explicit consent.

If the vulnerability is actively exploited in the wild we reserve the right to disclose sooner in
coordination with affected parties.

---

## Scope

In scope for coordinated disclosure:

- `tirbase-core` — CRDT engine, authentication, revocation, transport.
- `tirbase-guard` — Command Guard stages 0–18, envelope enforcement, rate limiting.
- `tirbase-gateway` — binary entry point, admin socket, health endpoint.
- `tirbase-admin` — CLI: enrollment, token minting, key rotation.
- `tirbase-drivers` — driver trait and any bundled driver implementations.
- `tirbase-types` — fixed-point value types, ID newtypes.
- CI/CD pipeline configuration and supply-chain controls.
- Cryptographic design (Biscuit token flow, root CA ceremony, CRDT signing).

Out of scope (without prior agreement):

- Vulnerabilities that require physical access to the hardware running TirBase.
- Vulnerabilities in the host OS or kernel that TirBase does not exacerbate.
- Denial-of-service attacks that require being an authenticated `CommandIssuer` sending valid but
  resource-exhausting payloads (handled via rate limiting, out of scope for CVE assignment).
- Issues in third-party dependencies — please report those upstream; we will coordinate if needed.

---

## Process After Receipt

1. We acknowledge your report within 5 business days and assign an internal tracking ID.
2. We reproduce the issue and assess severity (CVSS score + contextual impact for
   safety-adjacent deployments).
3. We develop and test a fix on a private branch.
4. We coordinate a release date with you and, where applicable, with CERT/CC or relevant CERTs
   for the affected infrastructure sectors.
5. We publish a GitHub Security Advisory and a CHANGELOG entry crediting you.
6. We update `CLAIMS.md` and any relevant documentation.

---

## Responsible Disclosure Commitment

We commit to:

- Responding in good faith to every report submitted in good faith.
- Never taking legal action against researchers who follow this policy.
- Keeping you informed of progress at least every 14 days during active triage.
- Crediting your work publicly unless you prefer otherwise.

We ask reporters to:

- Give us the agreed window before publishing or sharing details publicly.
- Avoid accessing, modifying, or deleting data beyond what is necessary to demonstrate the issue.
- Not use the vulnerability for any purpose beyond demonstrating it to us.

---

## Security Architecture References

- `docs/THREAT_MODEL.md` — full threat model including assets, actors, failure modes, and
  non-goals.
- `CLAIMS.md` — machine-readable registry of security and correctness claims, each linked to a
  passing integration test.
- `docs/audits/` — gate audit documents.

---

*This policy follows the [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/CVD/Executive+Summary) model recommended by CERT/CC.*
