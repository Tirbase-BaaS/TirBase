# Venue compliance kit — proprietary

**Licence:** Proprietary; see `LICENSE`. This kit is not part of the AGPL
runtime and contains documents/templates only.

**Status of this copy:** DRAFT — counsel/privacy review is **pending**. Do not
make compliance, certification or surveillance-lawfulness claims from this kit.
It is a customer-completion pack built on the open ST-13 baseline.

## Contents

| Part | Purpose |
|---|---|
| `dpia/` | Customer-completion templates for ticket, credential, CCTV and access DPIAs |
| `data-flow-map.md` | Baseline flows, boundaries and transfer prompts |
| `retention-schedule.csv` | Retention codes aligned to the open field register |
| `cctv-retention-and-access.md` | Operational CCTV metadata retention and access procedure |
| `subject-access-and-deletion.md` | DSAR/deletion runbook, including legal hold |
| `reporting-templates.md` | Local-authority/regulator/police request templates |
| `review/` | Customer privacy-review record and kit review log |
| `EXCLUSIONS.md` | What the kit does not cover |
| `manifest.json` | Version, parts and review state |

## Delivery rules

1. The kit is generated/delivered from `commercial/venue-compliance-kit/`; it
   contains no Rust, JS, WASM, binaries, secrets or customer data.
2. The packaging gate refuses a release archive unless the manifest records an
   approved privacy/counsel review with reviewer and date; a draft is marked
   `DRAFT`.
3. Evidence is cited by reference to the open ST-13 docs and test identifiers;
   the customer receives the templates and references, not AGPL source.
4. Every retention code in `retention-schedule.csv` must exist in the open
   `data/venue-retention-schedule.csv` and field register.
5. The customer's DPO/legal reviewer signs `review/privacy-review-record.md`;
   this kit does not sign for them.

## Reproduction

```bash
python3 scripts/check-venue-compliance-kit.py
python3 scripts/check-venue-compliance-kit.py --release
```

The first command validates the draft; the second additionally requires approved
review state.
