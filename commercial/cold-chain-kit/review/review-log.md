# Review log

Append-only record of every review, re-review and risk acceptance for the kit. The
packaging gate reads `../manifest.json`; this log is the human-readable history.

| Date (UTC) | Record | Reviewer / body | Kit version | Outcome | Notes |
| --- | --- | --- | --- | --- | --- |
| 2026-11-16 | initial draft | maintainers (self-review) | 0.1.0-draft | draft only | Structure, control map and evidence links checked; no legal or accreditation review performed |
| _(pending)_ | REV-COUNSEL-001 | _(counsel)_ | _( )_ | _( )_ | Legal review of wording and templates |
| _(pending)_ | REV-ASSESSOR-001 | _(accredited body)_ | _( )_ | _( )_ | Assessment of SL2/SL3 and CRA claims |

## Self-review checklist (completed for the draft)

- [x] Every control row has an evidence reference or a gap id.
- [x] Every gap id referenced by a control exists in the gap register.
- [x] No source code, binary, key, token, seed or customer data in the kit.
- [x] Every transport in the CC-22 matrix appears in the sensor list and calibration kit.
- [x] Exclusions name the certification, safety, data and commercial boundaries.
- [x] The packaging gate refuses a release archive without both external approvals.

## Risk acceptances

| Date | Risk / gap | Accepted by | Basis | Review date |
| --- | --- | --- | --- | --- |
| _(pending)_ | GAP-REV-002 until assessment | _( )_ | Draft delivery only; no compliance claim | _( )_ |
