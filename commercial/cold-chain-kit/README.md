# Cold-chain commercial kit — proprietary

**Licence:** Proprietary. Copyright (c) the TirBase maintainers. All rights reserved.
Distribution is permitted only under a signed commercial agreement. This kit is **not**
part of the AGPL-3.0 runtime and contains no source code; it ships documents, CSV
control maps and templates only.

**Status of this copy:** DRAFT — legal counsel review and accredited-assessor review
are **pending** (see `review/`). Do not make compliance, certification or regulatory
claims from this kit until both records are approved.

## What this kit is

A delivery-ready evidence package for a cold-chain deployment of the TirBase
gateway, built from the CC-08…CC-22 programme:

| Part | Contents |
| --- | --- |
| `audit-kit/` | GDP/HACCP/FSMA control-to-evidence map, gap register, SOPs, checklists, retention guidance |
| `iec62443/` | IEC 62443 SL2/SL3 dossier: zones, conduits, threat model, requirement mapping, evidence, gap list |
| `cra/` | CRA technical file: risk assessment, vulnerability handling, support period, SBOM, conformity evidence |
| `sensors/` | Certified sensor/controller list with firmware ranges and certificate references |
| `calibration/` | Calibration and validation procedure, reference probes, uncertainty budget, acceptance criteria |
| `licensing/` | OEM licence and 24/7 SLA templates (counsel-reviewed is pending) |
| `EXCLUSIONS.md` | Explicit list of what this kit does not cover |
| `review/` | Counsel and assessor review records and the sign-off log |

## Delivery rules

1. The kit is generated from `scripts/build-cold-chain-kit.py`. It refuses to produce
   a **release** archive unless `manifest.json` records `counsel` and `assessor`
   reviews as approved, and a draft archive is watermarked `DRAFT`.
2. The archive contains only `.md`, `.csv`, `.json`, `.txt` and the proprietary
   `LICENSE` file — never Rust, JS, WASM, binaries, keys, tokens, configs with
   secrets, or customer data.
3. Evidence is cited **by reference** to repository documents and test identifiers.
   Customers receive links/identifiers and, on request, rendered evidence; they do
   not receive the AGPL runtime source unless they are entitled to it separately.
4. Every control row in `audit-kit/control-to-evidence.csv` carries either an
   evidence reference that resolves to an existing document, or a `GAP-*` id that
   exists in `audit-kit/gaps.csv`. The packaging check enforces this.

## Reproduction

```bash
python3 scripts/check-cold-chain-kit.py            # verify structure, coverage, no secrets/source
python3 scripts/build-cold-chain-kit.py --draft    # dist/tirbase-cold-chain-kit-<version>-DRAFT.tar.gz
python3 scripts/build-cold-chain-kit.py --release  # requires approved reviews
```

## Version

Kit version `0.1.0-draft`, aligned to the open-source release under validation. The
manifest records the evidence baseline, not a customer certificate.
