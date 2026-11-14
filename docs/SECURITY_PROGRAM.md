# TirBase Security Programme (F-12)

> **Status:** Living document. This file operationalises the security programme for TirBase (AGPL-3.0-only core, open repo).
> **Dependencies:** F-01 (licensing/build), F-03 (identity/policy foundations).  
> **Scope:** cold chain, POS, stadium, and the shared edge platform (gateway + guard + core ledger + drivers + admin + exports/adapters + operator UI surfaces).

This document complements:
- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) (assets, actors, boundaries, failure modes)
- [`SECURITY.md`](../SECURITY.md) (coordinated disclosure)
- [`docs/pentest-scope.md`](pentest-scope.md), [`docs/security-findings.md`](security-findings.md)
- [`docs/compliance/vulnerability-handling.md`](compliance/vulnerability-handling.md)
- [`docs/releases/dependency-review.md`](releases/dependency-review.md), [`docs/releases/v0.1.0.md`](releases/v0.1.0.md)
- [`deny.toml`](../deny.toml), [`audit.toml`](../audit.toml), licence workflows (`.github/workflows/licence.yml`)

---

## 1. Threat model per vertical

### 1.1 Shared platform (applies to all verticals)

**Primary assets:** cryptographic key material, `Applied_Effects_Ledger` (PrimaryLedger), security event log (PrimaryLedger), monotonic/anti-rollback counters, policy bundles and `EnvelopeProfile`s, Biscuit tokens, time ratchet and anti-replay state, signed OTA/self-update artifacts and boot state (A/B), export bundles.

**Trust boundaries (authoritative list):** (B1) command ingress converging on `CommandGuard::evaluate` (mesh/cloud/local admin → guard); (B2) driver process boundary (gateway↔driver via inherited `AF_UNIX SOCK_SEQPACKET`, `SO_PEERCRED`, seccomp/Landlock/no-new-privs); (B3) local admin socket (`SO_PEERCRED`) and remote admin mTLS; (B4) mesh transport (Noise XX/IK upgrade path, signed deltas, revocation recheck); (B5) cloud API (mTLS, pre-crypto token bucket); (B6) WASM migration sandbox (wasmi, fuel, deterministic profile, postconditions); (B7) SQLite persistence (`synchronous=FULL`, WAL; optional SQLCipher). OTA/admin control plane adds: (B8) OTA bundle ingest (signed Ed25519, domain separation, hash/size, anti-downgrade, channel policy, offline path) and A/B boot pointer integrity.

**Top adversaries:** external unauthenticated network attacker; compromised cloud/vendor holding a single role credential; compromised mesh peer with stolen node identity; malicious/compromised driver process; insider with partial M-of-N quorum material.

### 1.2 Cold chain (temperature-controlled logistics / storage)

**Representative assets/flows:** temperature setpoints, door/sensor commands, excursion alerts, cold-chain readings/site records (F-08 vertical API), audit exports for compliance.

**Key threats (examples):**
- **Malicious command via legitimate channel:** attacker with stolen `CommandIssuer` tries to raise setpoints above `EnvelopeProfile` bounds or bypass dwell/rate limits → mitigated by B1 bounds, M-of-N for critical params, anti-replay, authenticated expiry, security events.
- **Bad config/update:** malicious policy/profile widens temperature bounds → requires PolicyAuthority + M-of-N governance per policy rules; tightening floors enforced; profiles signed.
- **Sensor/driver spoofing:** compromised driver or forged frames → B2 isolation; register-map parsing fuzzed; values still constrained by envelope and type/units at guard.
- **Data integrity / export tampering:** altered excursion logs → PrimaryLedger + hash-chained security events; export signing/sealing paths (see `tirbase-gateway/src/backup*`, export modules) treated as file parsers for fuzzing where applicable.

**Required controls checklist (must be present):** signed `EnvelopeProfile` with temperature bounds and critical flags where required; rate/dwell/cross-parameter constraints as modeled; driver sandbox + fuzzed protocol/register parsers; immutable audit trail for accept/reject and actuation lifecycle.

### 1.3 POS (point-of-sale / transaction edge)

**Representative assets/flows:** POS orders/lines/resources (F-08), device/terminal commands, payment-adjacent actuation is **out of scope for safety claims** (no SIL), configuration and refund/void policy enforcement via policy + envelope where actuation exists.

**Key threats (examples):**
- **Privilege escalation via admin/API:** unauthorized mutations to POS resources → B3 mTLS/`SO_PEERCRED` + role checks on admin/vertical API; audit logging.
- **Replay/order duplication:** replayed signed operations → anti-replay/idempotency controls at guard and/or application layer; sequence/epoch rules per subsystem.
- **Malicious update/config:** pushes that alter operational limits → OTA/policy signing, anti-downgrade, channel policy, staged rollout with health gates and auto-pause.

**Required controls checklist:** mTLS + least-privilege roles for remote admin; input validation on all JSON/TOML/file parsers (fuzzed); rate limits; explicit non-goals documented (no PCI-DSS claim in this repo unless stated).

### 1.4 Stadium / venue operations

**Representative assets/flows:** venue/gate resources (F-08), crowd/entry actuation commands (if any), time-sensitive mode changes.

**Key threats (examples):**
- **Partitioned operation abuse:** stale or delayed commands applied unsafely after partition → `now_est`/ratchet, authenticated expiry, lockdown/degraded modes, mesh revocation propagation and recheck at merge.
- **Mass command injection:** flood of valid-format commands → per-issuer/per-source rate limits (B1, B5), quotas, security events.
- **Compromised operator workstation:** stolen credentials → short TTL tokens, M-of-N for critical actions, audit trail and runbooks (`docs/runbooks/*`).

**Required controls checklist:** time and expiry enforcement; documented degradation/lockdown behavior; fuzzed ingress parsers; pen-test coverage aligned to failure modes 1/2/5.

### 1.5 Cross-vertical mapping (minimum)

| Vertical | Primary trust boundaries | Must-have artefacts |
|----------|--------------------------|---------------------|
| Cold chain | B1,B2,B3,B4,B7,B8 | Signed profile + bounds, driver fuzz, export integrity |
| POS | B1,B3,B5,B7,B8 | mTLS admin, API authz, parser fuzz, OTA policy |
| Stadium | B1,B3,B4,B5,B7,B8 | Expiry/ratchet, partition runbooks, rate limits |
| Shared | All | THREAT_MODEL.md, SECURITY.md, security event log, SBOM/VEX, CI gates |

---

## 2. STRIDE / LINDDUN-style analysis (system components)

This section is a structured checklist (not a substitute for a full formal model). Review quarterly or on major architecture changes.

### 2.1 Devices (field devices + drivers)

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| Protocol parsers (Modbus, MQTT, register maps) | Tampering, DoS (parser bugs) | — | Fuzz targets in `tirbase-drivers/fuzz` (`modbus_frame`, `mqtt_frame`, `register_map_parse`); CI smoke (`.github/workflows/ci.yml`); `scripts/check-fuzz-targets.sh`. |
| Driver isolation | Elevation of privilege, Tampering | — | Gateway↔driver `AF_UNIX SOCK_SEQPACKET`, `SO_PEERCRED`, seccomp-BPF, `no-new-privs`, Landlock (see THREAT_MODEL §4). |
| Malicious driver | Information disclosure, Tampering, DoS | — | No device fds cross boundary; external sockets blocked by seccomp; least data over IPC. |

### 2.2 Gateway

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| Admin API (local/remote mTLS) | Spoofing, Elevation of privilege | Linkability of admin actions (log review) | `SO_PEERCRED`, mTLS, role/privilege checks in `tirbase-gateway/src/admin*`; audit via security events. |
| Config/profile/OTA file parsing | Tampering → RCE/parsing bugs | — | `config.rs` (TOML/JSON), `ota.rs`, `profiles.rs`, `backup.rs`, `reference_cli.rs` parse untrusted inputs — **fuzz coverage tracked below**; prefer allowlists and strict schema validation. |
| Cloud anchor / outbound sync | Tampering, Repudiation | — | Signed messages, mTLS, anchoring checks (`cloud_anchor.rs`). |

### 2.3 Guard (`tirbase-guard`)

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| Envelope/profile parsing | Tampering, DoS | — | Fuzz: `envelope_profile_parse` (`tirbase-guard/fuzz`). |
| Command message parsing / evaluation | Spoofing, Tampering, Repudiation, Elevation of privilege | — | Fuzz: `command_message_parse`; single `CommandGuard::evaluate` ingress path; security events on accept/reject; trybuild compile-fail guards (per THREAT_MODEL). |
| Policy/version enforcement | Tampering, Elevation of privilege | — | Signed bundles, monotonic versions, anti-rollback counters. |

### 2.4 Ledger (`tirbase-core`, persistence)

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| CRDT deltas / fragments | Tampering, Repudiation, DoS | — | Fuzz: `automerge_delta_decode`, `fragment_reassembly`; signed deltas, revocation recheck at merge (THREAT_MODEL §4). |
| Applied effects / security log | Tampering, Repudiation | — | PrimaryLedger, WAL `synchronous=FULL`, hash-chained security events, export tooling reviewed. |
| Quarantine / restore flows | Tampering, DoS | — | Quotas, typed reason codes, restore procedures (`docs/runbooks/restore.md`). |

### 2.5 Exports, backups, and file interchange

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| Backup manifests, sealed exports, delta JSONL | Tampering, DoS | Data minimization in exports (LINDDUN) | `tirbase-gateway/src/backup.rs` parsing paths — candidates for fuzz targets (see §3). |
| Security log export / redaction | Information disclosure | Unlinkability/minimization | `security_log_export.rs`, redaction logic in `telemetry.rs` — review for PII leakage; fuzz where untrusted structured input is parsed. |
| OTA offline bundles (`manifest.json` + artifact) | Tampering, Elevation of privilege | — | `ota.rs`: signature, hash, size, downgrade, channels; unit/integration tests in repo. |

### 2.6 Adapters and integrations

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| Cloud HTTP/anchor endpoints | Spoofing, Tampering, Repudiation | — | mTLS, signed envelopes, per-source rate limits (B5). |
| External tooling / reference CLI | Tampering | — | `reference_cli.rs` parses fixtures (test/tooling); treat fixture parsing as trusted-input class in most cases, but fuzz only if fed untrusted data in production paths. |

### 2.7 UI (operator surfaces: gateway admin HTTP, console)

| Concern | STRIDE focus | LINDDUN focus | Controls / evidence |
|---------|--------------|---------------|---------------------|
| Admin HTTP API surface | Spoofing, Elevation of privilege, Information disclosure | — | Authn/authz at boundary; avoid verbose errors leaking internals; CSP/headers responsibility of deployment (`docs/packaging.md`, console build). |
| Console app (`console/`) | XSS, CSRF (if cookie-based) | Tracking/telemetry | Prefer token-based auth, avoid `eval`; dependency review via npm lockfiles and `console/scripts/check-licence.mjs` in CI where present. |

---

## 3. Fuzz targets — coverage and “every parser” policy

### 3.1 Current registered fuzz targets (CI smoke + `scripts/check-fuzz-targets.sh`)

| Crate | Target | Input class (untrusted) |
|-------|--------|-------------------------|
| `tirbase-core` | `automerge_delta_decode` | Automerge delta bytes |
| `tirbase-core` | `fragment_reassembly` | Fragmented message reassembly |
| `tirbase-drivers` | `modbus_frame` | Modbus frame bytes |
| `tirbase-drivers` | `mqtt_frame` | MQTT frame bytes |
| `tirbase-drivers` | `register_map_parse` | Register map / descriptor parsing |
| `tirbase-guard` | `envelope_profile_parse` | Envelope/profile untrusted parse |
| `tirbase-guard` | `command_message_parse` | Command message untrusted parse |

Root mirrors under `fuzz/` are validated by the same script.

### 3.2 File/device parsers identified (inventory — action list)

**Device parsers (drivers):** covered by the three targets above. Any new driver MUST add a fuzz target before merging if it parses untrusted bytes/frames/files.

**File/structured parsers (non-exhaustive; extend when adding code):**
- Gateway `config.rs`: TOML config load, JSON trust-root/profile fixtures — **recommend** fuzz targets `gateway_config_toml_parse`, `gateway_trust_root_json_parse` (or split) with seed corpora; currently **not** in `check-fuzz-targets.sh`.
- `tirbase-gateway/src/ota.rs`: `read_json` of `boot.json` / manifests — **recommend** `ota_boot_state_json_parse`, `ota_manifest_json_parse`.
- `tirbase-gateway/src/backup.rs`: backup manifest JSON, sealed export JSON, delta JSONL — **recommend** fuzz targets for manifest and for JSONL line parsing.
- `tirbase-gateway/src/profiles.rs`: TOML profile parsing — **recommend** fuzz target.
- `tirbase-gateway/src/security_log_export.rs`: parses serialized fields in some paths — assess whether any untrusted external input reaches parsers; add fuzz if yes.
- `tirbase-gateway/src/key_rotation.rs`, `cloud_anchor.rs`, `reference_cli.rs`: parse JSON from files/streams — assess trust class; fuzz if attacker-controlled.

**Policy:** “every device and file parser” means **every parser that consumes untrusted or attacker-adjacent input** (network, files from untrusted sources, OTA bundles, imported backups, peer messages). Purely trusted build-time or operator-authenticated local files still warrant review but fuzzing priority is untrusted ingress.

### 3.3 CI and nightly execution

- **CI (blocking on PR/main):** `.github/workflows/ci.yml` job `fuzz-smoke` runs `scripts/check-fuzz-targets.sh`, builds fuzz targets in `fuzz/`, `tirbase-core/fuzz`, `tirbase-drivers/fuzz`, `tirbase-guard/fuzz`, and executes each registered target with a short smoke run (see workflow for `-max_total_time` / `-runs`). Job `fuzz-target-registry` re-runs the registry check.
- **Nightly:** `.github/workflows/nightly-mutants.yml` exists for mutants; if a dedicated nightly fuzz job is not yet present, **add** one that runs longer fuzz corpora (e.g. hours) or `cargo fuzz run … -- -max_total_time=…` and uploads crash artifacts. **Requirement (F-12 done-when):** “Fuzz targets run in CI or nightly.” — until a nightly workflow is added, extend `fuzz-smoke` cadence is insufficient alone; **track as follow-up** and add `.github/workflows/fuzz-nightly.yml` (recommended) running on schedule with artifact upload on crash.

### 3.4 Adding a new fuzz target (checklist)

1. Add target under the owning crate’s `fuzz/` (or root `fuzz/` if it is the canonical integration harness) with a minimal harness.
2. Add committed seed corpus under `fuzz/corpus/<target>/` (non-empty).
3. Update `scripts/check-fuzz-targets.sh` (`REQUIRED` list and any root mirrors).
4. Wire into `ci.yml` `fuzz-smoke` (build + short run) and into any nightly fuzz workflow.
5. Document the parser/input class in this file (§3.2) or a referenced design note.

---

## 4. Secure update, SBOM/CVE intake, disclosure policy, and advisory process

### 4.1 Secure update (OTA and self-update)

- **Implemented controls (code):** signed OTA bundles with Ed25519 (domain-separated signing bytes), artifact SHA-256 and size checks, anti-downgrade vs committed version, release channels including `tenant_pinned`, A/B boot pointer with atomic writes and boot reconciliation (revert uncommitted pending to known-good), staged rollout with health gates and automatic pause, offline bundle ingest (`manifest.json` + `artifact.bin`) — see `tirbase-types/src/ota.rs`, `tirbase-gateway/src/ota.rs`, admin API. Self-update/config update paths exist separately (`self_update.rs`) with their own signing/rollback semantics; **all** update surfaces MUST require signature verification before apply and MUST preserve rollback to a known-good state on failure.
- **Operational requirements:**
  - Production signing keys kept offline/hsm-backed per ceremony/runbook (`docs/runbooks/key-management.md`, `docs/root-ceremony.md`); never committed to repo.
  - Channel promotion (dev→staging→pilot→production) requires documented approval; tenant-pinned changes require tenant operator acknowledgement where applicable.
  - After any security update, publish advisory (4.4) and update SBOM/VEX if components change (4.2).

### 4.2 SBOM and release artifacts

- **Generation:** `cargo-cyclonedx` in `.github/workflows/sbom.yml` produces `tirbase-<tag>.cdx.json`; VEX file `docs/releases/vex-statements.json` (or generated stub) produces `*.vex.cdx.json`; NOTICE generated via `scripts/release/generate-notice.py`.
- **VEX + deny gate:** `scripts/release/check_vex_deny.py` merges VEX into a release deny config and runs `cargo deny check all-features` against it (release job).
- **Signing/provenance:** `.github/workflows/sign.yml` (cosign keyless OIDC, SLSA provenance) as referenced in dependency review record.
- **Rule:** every published release MUST have attached SBOM, VEX, NOTICE, and verification/signature artifacts per `docs/releases/v0.1.0.md` and `docs/releases/dependency-review.md`.

### 4.3 CVE intake

1. **Sources monitored:** GitHub Security Advisories / Dependabot alerts (where enabled), `cargo audit` (CI job `cargo-audit` in `ci.yml`, config `audit.toml`), `cargo deny advisories` (CI `cargo-deny`), release-time deny with VEX, upstream project mailing lists for critical deps (e.g. crypto, TLS, wasmtime/libp2p stack) — **assign an owner** per release cycle.
2. **Triage SLA (targets):** Critical/High affecting shipped artifacts triaged within **2 business days** of becoming known; Medium within **7 business days**; Low/Info tracked in backlog. Aligns with `SECURITY.md` response timelines for reporter-driven issues.
3. **Recording:** add rows to `docs/security-findings.md` (external) or an internal tracker issue; for dependency advisories, record in release `docs/releases/dependency-review.md` (“Transitive dependencies with CVE/advisory history”) including status (fixed / ignored with rationale / mitigated) and upstream links.
4. **`audit.toml` / `deny.toml` ignores:** temporary ignores MUST include `reason` (deny) and a comment/context (audit) and a removal plan (upgrade path or upstream issue). Expired or unjustified ignores are a release blocker.

### 4.4 Disclosure policy and advisory process

- **Primary policy:** [`SECURITY.md`](../SECURITY.md) (GitHub Security Advisories preferred, `security@tirbase.dev` fallback, timelines, scope).
- **Advisory publication (maintainers):**
  1. Confirm impact and affected versions/tags.
  2. Prepare fix on private branch; run full CI including licence, deny, audit, fuzz smoke, relevant integration tests.
  3. Draft GitHub Security Advisory (GHSA) with CVSS/context, affected versions, mitigations, fixed versions.
  4. Coordinate disclosure date with reporter (and CERTs if relevant sector impact) per SECURITY.md (default 90 days, extensions by agreement).
  5. Publish advisory, tag/release with SBOM/VEX/signatures, update `CHANGELOG.md`, `CLAIMS.md` if claims change, and `docs/security-findings.md`.
- **Internal severity mapping:** use CVSS v3.1 base score plus deployment context (safety-adjacent, offline/mesh) to set operational priority; **no HIGH/CRITICAL unresolved** before public security claims relying on those controls (PV-29.3) — see `docs/security-findings.md`.

---

## 5. Penetration-test scope and remediation tracker

- **Scope (canonical):** [`docs/pentest-scope.md`](pentest-scope.md) defines failure modes 1, 2, 5, in-scope interfaces, out-of-scope, method/reporting expectations, and baseline (sim/adversary scenarios). Any material change to ingress, OTA, policy signing, or mesh trust MUST trigger a scope review.
- **Remediation tracker (canonical):** [`docs/security-findings.md`](security-findings.md). Rules:
  - Every external finding gets a unique ID, severity, status, remediation PR/link, verification evidence, and claim/PV impact.
  - **Blocker:** any **HIGH** or **CRITICAL** status Open/In progress blocks public security claims that depend on the affected control (PV-29.3).
  - After each engagement, update engagement status table and `CLAIMS.md` per CLAIM-54.4.
- **Cadence (recommended):** at minimum before major GA milestones and after significant security architecture changes; ad hoc after critical advisories affecting exposed surfaces.

---

## 6. Secrets management and supply-chain review for new dependencies

### 6.1 Secrets management

**Principles:**
- **No secrets in git:** private keys, tokens, passwords, `.env` with credentials MUST NOT be committed. Use `.gitignore` and secret scanning in CI where available.
- **Signing keys:** root/offline ceremony keys per `docs/root-ceremony.md`; OTA/update signer keys stored in HSM or secured vault; access logged. Runtime nodes use provisioned keys/material per `docs/runbooks/key-management.md`.
- **CI secrets:** GitHub Actions secrets for release signing tokens only as required; prefer OIDC (cosign keyless). Rotate on personnel changes or suspected exposure.
- **Operator/admin credentials:** mTLS client certs and Biscuit tokens distributed out-of-band per runbooks; short TTLs; revoke via documented procedures.
- **Logging:** never log private key material or full tokens; redact in telemetry (`tirbase-gateway/src/telemetry.rs` patterns).

**Inventory (maintainers):** document where production secrets live (vault path/HSM) in an internal runbook not committed publicly if it reveals topology; this file states policy only.

### 6.2 Supply-chain review for new dependencies (mandatory before merge)

A **new dependency** (new crate in `Cargo.toml` / lockfile, or new npm package in `console/`) MUST NOT merge without:

1. **Licence review (F-01):** passes `cargo deny check licenses` and `scripts/check-licence-*` / `licence.yml` constraints; Apache-only crates must remain AGPL-free per `scripts/check-agpl-free.py`. New exception entries require updating `licence-exceptions.toml`, `deny.toml`, and `docs/licensing-exceptions.md` with owner/reason/scope/expiry.
2. **Advisory review:** `cargo audit` and `cargo deny advisories` clean, or any ignore is justified in `audit.toml`/`deny.toml` **and** recorded in the release dependency review process (`docs/releases/dependency-review.md`). For console/npm, run equivalent audit (e.g. `npm audit`) and document in PR.
3. **Security relevance assessment:** flag if the crate touches crypto, auth, TLS/network parsing, filesystem, subprocess, or `unsafe`; require extra scrutiny (maintainer, source repo, download counts, audit history). Update `docs/releases/dependency-review.md` categories at next release as appropriate.
4. **Build/runtime impact:** note MSRV/target impact (armv7/aarch64) and binary size/memory if relevant to edge constraints (`docs/memory-budget.md`).
5. **PR evidence:** in the PR description, state: purpose, licence, advisory status, security-relevance note, and whether `deny.toml`/`audit.toml`/exception files changed.

**Enforcement (recommended CI):** keep `licence.yml`, `ci.yml` (`cargo-deny`, `cargo-audit`) as required checks. Add GitHub **Dependency Review** action on pull requests to flag new vulnerable dependencies and licence policy violations where supported. **“A new dependency cannot merge without licence and advisory review”** is satisfied operationally by required CI checks plus this policy; document any waiver explicitly in the PR and in `security-findings.md` if risk-accepted.

### 6.3 Dependency update cadence

- Run `cargo update` / targeted upgrades on a regular cadence (e.g. monthly) with CI green; prioritize security advisories immediately.
- For `wasmtime`, `libp2p`, `tokio`, `rustls`/TLS stacks, review changelogs for memory-safety and protocol fixes even if no CVE assigned.

---

## 7. References (quick links)

- Threat model: `docs/THREAT_MODEL.md`  
- Adversary scenarios / invariants: `docs/adversary-scenarios.md`, `docs/system-invariants.md`  
- Crypto review scope: `docs/crypto-review-scope.md`  
- Runbooks: `docs/runbooks/`  
- Fuzz registry check: `scripts/check-fuzz-targets.sh`  

*End of F-12 security programme document.*