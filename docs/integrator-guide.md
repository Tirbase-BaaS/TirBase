# Integrator Guide (TirBase)

For teams integrating TirBase into a site: hardware, networking, drivers, profiles, and APIs.

## Installation and deployment (high level)

- Follow `docs/packaging.md`, `docs/reference-hardware.md`, and deployment manifests under `deploy/` / `ops/` as applicable.
- Use signed artifacts and verify checksums/signatures per release process (`docs/releases/*`, `sign.yml` outputs).
- Configure `config.toml` carefully: listen addresses, TLS/mTLS, trust roots, rate limits, storage paths. Validate in staging first.

## Profiles and policy

- Install a signed `EnvelopeProfile` before production command ingress (deny-all posture otherwise) — see gateway behavior and `docs/THREAT_MODEL.md`.
- Use `tirbase-admin` / documented admin APIs for enrollment, minting, policy operations with appropriate roles (M-of-N where required).

## Drivers and devices

- Driver isolation model: `docs/THREAT_MODEL.md` §4 (B2). Only use supported drivers; add new drivers only with review, fuzzing, and security sign-off.
- Reference driver docs: `docs/drivers/*` (e.g. Modbus register map format).

## APIs and SDKs

- Admin HTTP API: documented OpenAPI/spec artifacts in repo (see `docs/api/` or generated specs). Use `tirbase-sdk` (TS/Python) where available.
- Vertical APIs (F-08): follow API docs and tenant scoping rules.

## Testing before go-live

- Run conformance/simulation tests (`tirbase-sim`) for your scenario set.
- Execute HIL checklist for physical integrations (`docs/hil-lab-checklist.md`) when hardware is in loop.
- Complete a privacy/DPIA review record before pilot (`docs/compliance/dpia-templates.md`).

## Troubleshooting

- Start with `docs/runbooks/` for operational faults.
- Collect logs securely (redaction awareness) and open issues per `CONTRIBUTING.md` / internal process.
