# Dependency Review Record (per release)

**Claim:** CLAIM-42.7 / PV-14.4 
**Maintained at:** every release tag (update this record before publishing the GitHub Release)

## Release metadata

- Release tag/version: `<fill at release>`
- Commit SHA: `<fill at release>`
- Review date (UTC): `<YYYY-MM-DD>`
- Reviewer(s): `<name/handle>`
- SBOM asset: `tirbase-<tag>.cdx.json` (attached to GitHub Release)
- VEX asset: `tirbase-<tag>.vex.cdx.json` (attached to GitHub Release)

## Scope of review

This record covers, for the release above:
1. **All direct dependencies** (workspace members and `[dependencies]`/build/dev as applicable).
2. **All transitive dependencies with CVE history** (known advisories, including any accepted/ignored in `deny.toml`/`audit.toml` with justification).
3. **All crates containing `unsafe` blocks** (cross-referenced with `cargo-geiger` release report attached to the release).
4. **All crates implementing cryptographic, authentication, or network functionality** (direct and transitive where security-relevant).

## Direct dependencies

| Crate | Version | Purpose | Security-relevant (crypto/auth/network/unsafe) | Notes |
|---|---:|---|---|---|
| _populate from `cargo metadata` / `Cargo.toml` at release time_ | | | | |

## Transitive dependencies with CVE/advisory history

| Crate | Version | Advisory/CVE | Status (fixed/ignored/mitigated) | Rationale / tracking |
|---|---:|---|---|---|
| _populate from `cargo audit`/`cargo deny` and SBOM at release time_ | | | | |

> Any advisory ignored in `deny.toml` or `audit.toml` MUST be listed here with an explicit rationale and, where applicable, an upstream tracking reference.

## Crates containing `unsafe` blocks

- Source of truth: `geiger-report-<tag>.json/.txt` attached to the GitHub Release (CLAIM-42.5).
- Summary at release:
 - Total crates with unsafe (used): `<fill>`
 - Workspace crates with unsafe: `<fill>`
 - New/changed unsafe relative to previous release: `<fill>` (review required)

| Crate | Unsafe usage (summary) | Workspace/direct/transitive | Review notes |
|---|---|---|---|
| _populate from release geiger report_ | | | |

## Cryptographic, authentication, and network functionality

| Crate | Domain | Direct/transitive | Review notes (algorithm/protocol/config, known risks) |
|---|---|---|---|
| _e.g. ed25519-dalek, ring/rustls stack, biscuit-auth, libp2p, tokio-rustls, etc._ | crypto / auth / network | | |

## Release gate evidence (PV-14)

- [ ] SBOM + VEX attached to GitHub Release (`sbom.yml`, CLAIM-42.1)
- [ ] Release `cargo-deny` ran with VEX-aware deny config; no VEX-flagged crate shipped (CLAIM-42.4)
- [ ] Artifacts keylessly signed with cosign (OIDC) and signature verified; SLSA provenance recorded (`sign.yml`, CLAIM-42.2)
- [ ] Reproducibility attestation published; two independent builds compared (`reproducibility.yml`, CLAIM-42.3)
- [ ] Full `cargo-geiger` report attached to release (CLAIM-42.5)
- [ ] Full-workspace `cargo-mutants` met ≥80% kill rate on security-critical modules (CLAIM-42.6)

## Sign-off

- [ ] Review complete for this release
- [ ] Deviations/accepted risks documented above
- [ ] Record committed alongside release artifacts

