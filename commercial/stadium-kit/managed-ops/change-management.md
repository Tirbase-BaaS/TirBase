# Managed venue operations — change management

## Change classes

| Class | Examples | Approval | Window |
|---|---|---|---|
| Standard | Credential rotation, monitoring threshold, template wording with no safety effect | Operations lead | Anytime |
| Normal | Policy update, mapping change, connector configuration, firmware minor | Integrator plus venue operations | Outside event, with rollback |
| Major | Firmware baseline change, gate hardware, capacity envelope, lockdown procedure, new connector | Change board plus venue safety owner | Planned; re-commission affected lanes |
| Emergency | Security patch or a fix during an incident | Commander plus on-call; retrospective review | Immediate |

## Required record

`change_id, requester, class, description, affected systems, risk, test evidence,
rollback plan, approver, window, result`.

## Rules

1. No change to a safety requirement, hazard rating or commissioning state without
   safety-owner approval and, for major changes, re-review.
2. No firmware outside the supported baseline (`hardware/firmware-support.md`).
3. A mapping change requires a conflict check and an unmapped-id test.
4. A policy or revocation change requires a sync and an offline decision test
   before gates open.
5. A change freeze applies from 60 minutes before ingress to the end of egress,
   except emergency changes approved by the commander.
6. Every change has a rollback that has been exercised or is trivially reversible.
7. After a change, verify with a test scan, a replay, a revoked credential and the
   affected connector.

## Emergency change

Record the decision, the risk accepted and the approver at the time; complete the
normal record and a review within two working days. An emergency change that
touches a safety control triggers a safety review.

## Post-change

Update the asset register, the commissioning state, the audit baseline and the
safety-case evidence index where the change affects a claim.
