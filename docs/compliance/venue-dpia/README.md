# Venue DPIAs — ticket, credential, CCTV and access (ST-13)

> **Status:** baseline DPIAs complete for the ST-13 software pilot. They are not
> legal advice and do not replace a venue operator's DPO or local counsel. A
> customer pilot requires the operator to localise and sign the pack. See the
> completed software-pilot record at
> [`venue-pilot-privacy-signoff.md`](../venue-pilot-privacy-signoff.md).

This pack assesses the four venue data domains separately because their risks
and lawful bases differ:

| Domain | Assessment | Primary data | Retention ceiling |
|---|---|---|---|
| Ticketing | [`ticket.md`](ticket.md) | ticket id, holder reference, scan metadata | 30 days after the event |
| Credential | [`credential.md`](credential.md) | credential id, pseudonymous holder, public key, revocation | 30 days after revocation/expiry |
| CCTV | [`cctv.md`](cctv.md) | **metadata only** — camera/zone/time/kind/note | 7, 30 or 90 days by class |
| Access | [`access.md`](access.md) | decision, lane, outcome, operator attribution | 90 days; 365 days for restricted audit |

The field-level source of truth is
[`data/venue-privacy-register.csv`](../../../data/venue-privacy-register.csv).
Every field row has a domain, purpose, lawful-basis template, retention code,
retention detail, access rule and deletion method. The open test
`every_personal_data_field_has_purpose_retention_and_access` parses that CSV and
fails if any required cell is missing or a retention code is unknown.

The data-flow map and retention schedule are in
[`venue-data-flow-retention.md`](../venue-data-flow-retention.md). CCTV
enforcement is in [`venue-cctv-retention.md`](../venue-cctv-retention.md).
Subject access and deletion are in
[`venue-subject-access-deletion.md`](../venue-subject-access-deletion.md).
Local-authority templates are in
[`venue-local-authority-reporting.md`](../venue-local-authority-reporting.md).

## 1. Method

For each domain:

1. Inventory every field in the register (purpose limitation).
2. Apply the necessity/proportionality test and the minimisation rule: no raw
   video, no biometrics, no payment-card data, no free-text special-category
   data.
3. Map collection → use → storage → disclosure → deletion, including backups
   and exports.
4. Identify risks to data subjects and mitigations, then record residual risk.
5. Set the retention code and access rule; verify the code is enforced, not just
   written down.
6. Obtain the venue DPO/legal sign-off before a pilot with personal data.

## 2. Shared scope

**Data subjects:** ticket holders, credential holders, visitors, contractors,
gate operators, security staff, safety officers, auditors and DPO staff.

**Roles:** controller/processor allocation is contractual and venue-specific.
TirBase is normally a processor for the venue operator; the operator remains the
controller for admission, CCTV and safety purposes. This must be confirmed in
the customer agreement before a pilot.

**Lawful-basis template:** venue admission contract, legitimate interests
(security/safety), legal obligation (audit/legal hold) or explicit consent only
where the operator has a valid consent process. Special-category data is not
processed by this runtime.

**Transfers:** local venue deployment; no cloud transfer by default. If a
connector or cloud sync is enabled, record the destination, transfer mechanism
and safeguards in the customer DPIA. The commercial kit contains the
customer-completion template.

## 3. Common risks and controls

| Risk | Control |
|---|---|
| Re-identification from a ticket/credential reference | Holder references are deployment-salted pseudonyms after privacy preparation; names/emails are not delivered. |
| CCTV becomes a video-surveillance store | The CCTV API is metadata-only; no frame, clip, thumbnail, embedding or biometric field exists, and media markers are refused. |
| Data kept "just in case" | Per-field retention codes; CCTV reads fail at the deadline and the purge job deletes expired metadata. |
| Legal hold silently loses evidence | Active holds extend retention and block purge/subject deletion; release is audited. |
| Unauthorised viewing | Role-scoped reads (security, safety, auditor, privacy officer, venue manager) and an append-only access log. |
| Subject cannot obtain or erase data | A privacy-officer-only export and deletion path, scoped to a pseudonymous subject and reporting held events. |
| Excess data in free-text | Notes are bounded and scanned for media/biometric markers; support text is not copied into CCTV. |

## 4. Before a customer pilot

- [ ] Complete the operator-specific sections in the four domain DPIAs.
- [ ] Add every local field/integration to the register; do not deploy an
      undocumented field.
- [ ] Confirm controller/processor roles, lawful bases, residency and transfer
      safeguards with counsel.
- [ ] Set the CCTV retention classes and confirm the purge schedule.
- [ ] Record DSAR and breach contacts and local statutory deadlines.
- [ ] Complete and sign [`venue-pilot-privacy-signoff.md`](../venue-pilot-privacy-signoff.md).
- [ ] Attach the sign-off to the pilot folder and project tracking.

**Done when:** every personal-data field has a purpose, retention and access
rule; CCTV retention is enforced by the runtime; the pilot folder contains a
recorded privacy sign-off. The first is checked by the register test, the second
by `cargo test -p tirbase-venue-privacy`, and the third by the signed record and
`pilot_privacy_signoff_and_dpia_pack_are_recorded`.
