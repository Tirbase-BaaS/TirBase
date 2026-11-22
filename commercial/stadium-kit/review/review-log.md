# Kit review log

Every change to the kit's safety argument, authority templates, insurance evidence,
hardware register or signed records is logged here. A release must be traceable to
a log entry.

| Version | Date | Author | Change | Hazard/SR affected | Reviews required | Status |
|---|---|---|---|---|---|---|
| 0.1.0 | 2026-11-22 | vendor | Initial draft: safety case, insurance evidence, authority templates, integrator certification, managed operations, hardware policy | All | Independent safety + counsel | draft — reviews pending |

## Rules

1. A change to a hazard, risk rating, requirement, gate failure mode or exclusion
   requires a new version and re-review.
2. A template wording change that affects a legal or reporting obligation requires
   counsel review.
3. A hardware or firmware baseline change requires re-attestation and an asset
   register update.
4. Review records are referenced by version; an unsigned record never counts as a
   review.
5. The packaging gate reads the current manifest review state, not this log; the
   log explains how that state was reached.
