# 24/7 support SLA — TEMPLATE (counsel review pending)

> **Template only.** Targets and credits must be negotiated and reviewed by counsel before
> signature (GAP-REV-001). Staffing evidence is required before any 24/7 commitment
> (GAP-SUP-001).

**Supplier:** [entity] **Customer:** [entity]
**Service:** cold-chain gateway support, including security incident response
**Term:** [dates] **Coverage:** 24×7×365, all time zones listed in Schedule 1

## 1. Severity definitions

| Severity | Definition | Examples |
| --- | --- | --- |
| S1 Critical | Monitoring unavailable or readings unreliable at a site with product at risk; suspected security compromise | Gateway down, audit chain verification failure, key compromise, repeated alarm delivery failure |
| S2 High | Degraded monitoring or control, or a single-sensor failure with a workaround | One sensor/transport failing, alerts delayed, calibration blocking release |
| S3 Medium | Limited impact with an acceptable workaround | Reporting/export defect, non-critical integration issue |
| S4 Low | Cosmetic, documentation, or feature request | Typos, enhancement requests |

## 2. Response and resolution targets

| Severity | Initial response | Workaround / mitigation | Resolution target |
| --- | --- | --- | --- |
| S1 | 30 minutes | 4 hours | 24 hours or agreed plan |
| S2 | 2 hours | 8 business hours | 5 business days |
| S3 | 1 business day | 5 business days | next maintenance release |
| S4 | 3 business days | n/a | prioritised backlog |

Times are measured from a complete ticket (contact, site, version, symptoms, logs/export
with secrets removed). Security incidents follow the vulnerability-handling process and
may require coordinated disclosure timings that override these targets.

## 3. Channels and escalation

1. Primary: [portal/email]; secondary: [phone]. P1 also requires a phone call.
2. Escalation matrix: L1 → L2 → duty manager → executive sponsor, with names, numbers and
   times in Schedule 1. Contacts reviewed quarterly.
3. Customer must acknowledge and provide access within [hours]; otherwise targets pause.

## 4. Supplier obligations

- Maintain a staffed on-call rota with evidence of coverage.
- Triage with the severity definitions; reclassification requires mutual agreement.
- Provide status updates at [interval] for S1/S2 and a post-incident report within
  [days] for S1.
- Deliver security fixes per the support period policy; notify the customer of relevant
  advisories and affected versions.
- Never request or store customer secrets outside the agreed secure channel.

## 5. Customer obligations

- Maintain supported versions, apply security updates within [days] of release, and keep
  backups per the retention guidance.
- Provide accurate asset inventory, contact details and reproducible evidence.
- Ensure physical and network access needed for diagnosis.

## 6. Exclusions

Out of scope: custom development, on-site attendance unless purchased, third-party device
or network faults, unsupported versions, misuse, and events outside the supplier's
reasonable control. Exclusions do not remove security-incident obligations.

## 7. Service credits

If monthly availability or response targets are missed, credits: [schedule, e.g. 5 %/10 %
of monthly fee], claimed within [days], capped at [%]. Credits are the sole remedy for
missed targets, without limiting security obligations or termination rights.

## 8. Reporting and review

Monthly report: tickets by severity, response/resolution times, availability, open
problems, advisories. Quarterly service review with actions. Annual DR/restore test
evidence shared on request.

## 9. Term, termination and data

Term and renewal: [ ]. Termination for material breach with [cure period]. On exit: return
or destroy customer data, provide a signed export, and confirm destruction in writing.
Data protection terms: [DPA reference].
