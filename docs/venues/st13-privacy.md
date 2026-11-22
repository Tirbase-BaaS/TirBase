# ST-13 — Venue privacy, DPIA and CCTV retention

**Status:** complete (open privacy runtime + baseline DPIA pack; commercial
customer kit drafted). **Licence:** AGPL runtime and open docs; the customer
compliance kit is proprietary. **Depends on:** ST-11 command center, F-15
privacy procedures.

This section joins the venue command plane to a field-level privacy boundary.
It is deliberately narrower than a general surveillance platform:

- **No raw video.** CCTV evidence is metadata only; video, if used, remains in
  the venue VMS under the operator's separate DPIA.
- **Retention is enforced.** A CCTV metadata read fails at its 7/30/90-day
  deadline, and the purge caller removes expired records.
- **Legal hold wins.** A subject, event or venue hold extends retention and
  blocks deletion; the deletion report names the held events.
- **Subject rights are scoped.** A privacy officer can export or delete a
  pseudonymous subject's metadata; ordinary operators and auditors cannot.
- **Every field is registered.** Ticket, credential, CCTV and access fields each
  have a purpose, lawful-basis template, retention code, access rule and
  deletion method.

## Pack

| Deliverable | Location |
|---|---|
| Four DPIAs | [`docs/compliance/venue-dpia/`](../compliance/venue-dpia/README.md) |
| Data-flow map and retention schedule | [`venue-data-flow-retention.md`](../compliance/venue-data-flow-retention.md) |
| CCTV retention/access | [`venue-cctv-retention.md`](../compliance/venue-cctv-retention.md) |
| SAR and deletion | [`venue-subject-access-deletion.md`](../compliance/venue-subject-access-deletion.md) |
| Local-authority templates | [`venue-local-authority-reporting.md`](../compliance/venue-local-authority-reporting.md) |
| Pilot sign-off | [`venue-pilot-privacy-signoff.md`](../compliance/venue-pilot-privacy-signoff.md) |
| Runtime | `tirbase-venue-privacy` (`venue-privacy` binary) |
| Field register | [`data/venue-privacy-register.csv`](../../data/venue-privacy-register.csv) |
| Commercial kit | [`commercial/venue-compliance-kit/`](../../commercial/venue-compliance-kit/README.md) |

## Verification

```bash
cargo test -p tirbase-venue-privacy
python3 scripts/check-venue-privacy.py
python3 scripts/check-venue-compliance-kit.py
```

`cargo test` proves the enforcement (retention, hold, access, subject rights,
no-media refusal). The Python gate checks the register, DPIAs, schedule,
sign-off and proprietary kit. Neither test makes a legal-compliance or
surveillance-lawfulness claim; that remains the venue operator's DPO/counsel
decision and a commercial assessment.
