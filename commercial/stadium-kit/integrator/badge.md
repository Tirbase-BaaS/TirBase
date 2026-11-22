# Integrator badge

## Levels

| Badge | Entitlement | Requirements |
|---|---|---|
| Installer | Install and commission lanes under supervision | Modules 1–5, exam pass |
| Commissioning engineer | Sign the commissioning checklist for a venue | All modules, practical pass, two supervised commissions |
| Operations lead | Train venue staff and lead drills | Commissioning engineer plus one full event cycle |
| Trainer | Deliver training and assess badges | Operations lead plus vendor nomination and a moderation record |

## Issuance

- Issued by the vendor or an approved trainer only.
- Bound to a named person and their employer at issue.
- Records badge id, level, issue and expiry date, exam score and practical result.
- A person may hold one active badge.

## Registry

`badge-registry.csv` is the authoritative list. Fields:

`badge_id,holder,organisation,level,issued_est,expires_est,exam_score,status`

`status` is `active`, `suspended`, `expired` or `revoked`.

## Suspension and revocation

- **Suspended** while an incident or a competence question is investigated.
- **Revoked** for a safety-critical exam failure, a false commissioning record, a
  life-safety bypass, or working outside the licence.
- A revoked holder cannot be re-badged for 12 months and only after a full course.
- Commissioning sign-offs by a revoked holder are reviewed and re-performed where
  necessary.

## Verification

Venue staff can verify a badge by id against the registry supplied with the kit.
The registry is updated on issue, suspension, revocation and expiry; a stale
registry is an audit finding.

## On site

- Badge id recorded on the commissioning checklist and the handover.
- Photo identity checked against the badge holder.
- No badge, no commissioning signature.
