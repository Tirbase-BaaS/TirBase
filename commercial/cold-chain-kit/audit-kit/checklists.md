# Cold-chain operator checklists

Print or copy into the site's quality system. Each checklist records who completed it and
when; unsigned checklists are not evidence.

## 1. Site commissioning

- [ ] Sites, rooms, containers and gateways registered with unique ids.
- [ ] Every storage location has a mapped sensor with a valid calibration.
- [ ] Critical limits and alarm thresholds configured and approved (SOP-01).
- [ ] Alarm routes tested end to end, including the escalation deadline.
- [ ] Gateway hardened: remote admin mTLS only, health/metrics on loopback, no default
      credentials, signed profile installed.
- [ ] Backup schedule and a successful restore test recorded.
- [ ] Operators trained on SOP-01…SOP-05; training records filed.
- [ ] Commissioning report exported, signed and filed with the control map.

## 2. Training

- [ ] Role and permissions match the job function (least privilege).
- [ ] SOP-01, SOP-02, SOP-04, SOP-05 read and acknowledged by each operator.
- [ ] Alarm acknowledgement and escalation exercised in a drill.
- [ ] Electronic-signature policy explained where enabled.
- [ ] Refresher date scheduled; competence assessed, not just attendance.

## 3. Change control

- [ ] Change described, with the affected controls and risk assessment.
- [ ] Configuration/profile change reviewed by a second person and approved.
- [ ] Rollback plan and test evidence attached.
- [ ] Calibration impact assessed; sensors re-verified where affected.
- [ ] Alarm rules tested after the change.
- [ ] Change record exported and linked to this checklist.

## 4. Incident review

- [ ] Incident timeline reconstructed from the audit export (no edited records).
- [ ] Product impact assessed and disposition recorded.
- [ ] Root cause and CAPA agreed, owners and dates assigned.
- [ ] Detection and response times compared with the SLA.
- [ ] SOP or configuration updated if the cause was procedural/technical.
- [ ] Review minutes filed; repeat causes escalated to management review.

## 5. Hardening

- [ ] Remote admin reachable only over mTLS with a trusted client CA.
- [ ] No inbound cloud listener enabled; outbound channel allow-listed.
- [ ] Admin socket reachable only by the gateway's own UID/root.
- [ ] Secrets stored outside the repository and outside exported records.
- [ ] Database encryption enabled where the deployment requires it.
- [ ] Update channel signed and rollback rehearsed.
- [ ] Time source controlled; clock jumps monitored.

## 6. Internal audit (quarterly)

- [ ] Sample five control rows; confirm the cited evidence exists and is current.
- [ ] Verify calibration due dates and reference checks.
- [ ] Verify the audit chain and one signed export's digest.
- [ ] Confirm retention schedule applied; no records past destruction without authority.
- [ ] Confirm gaps in `gaps.csv` have owners and progress, or a recorded risk acceptance.
- [ ] Report findings to management; track actions to closure.
