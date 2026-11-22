# DPIA — venue CCTV metadata

**Domain:** CCTV · **Register fields:** `cctv.*` · **Status:** baseline complete
for software pilot; operator localisation required.

## 1. Description of processing

This assessment covers **CCTV event metadata only**: an event id, camera id,
zone, event family, occurrence time, optional pseudonymous subject reference and
a bounded operator note. The venue privacy runtime does **not** ingest, store,
forward or expose video frames, clips, thumbnails, face embeddings or biometric
templates. A VMS may remain the video controller; TirBase receives a metadata
event or a metadata-only camera-context request.

**Data flow**

```text
camera / VMS / alarm                         (video stays in the VMS)
  └─ metadata event: camera + zone + time + kind + subject_ref + note
       → CctvStore (metadata only; no media fields)
       → role-scoped read / audit access log
       → purge at 7 / 30 / 90 days unless a legal hold applies
       → subject export or deletion by privacy officer
```

## 2. Necessity and proportionality

| Question | Assessment |
|---|---|
| Is CCTV metadata necessary? | Yes for incident correlation, safety response and security review. |
| Is raw video necessary? | No: the runtime does not process video. Video remains a separate VMS/surveillance decision for the operator. |
| Is subject identification necessary? | Only a pseudonymous reference for incident follow-up; no name or face template. |
| Is the retention proportionate? | Yes: 7 days operational, 30 days security/anomaly, 90 days safety. |
| Could the note capture special-category data? | Notes are bounded and scanned for media/biometric markers; operators are instructed not to enter health or other special-category detail. |

## 3. Fields, purpose, retention and access

| Register field | Purpose | Retention | Access |
|---|---|---|---|
| `cctv.event_id` | Correlate alarm to metadata | class ceiling (7/30/90 days) | security operator, auditor |
| `cctv.camera_id` | Identify observing camera | class ceiling | security operator, auditor |
| `cctv.zone_id` | Locate observed zone | class ceiling | security operator, auditor |
| `cctv.event_kind` | Select purpose/retention | class ceiling | security operator, auditor |
| `cctv.subject_ref` | Link event to pseudonym | class ceiling | security operator, auditor |
| `cctv.note` | Context without video | class ceiling | security operator, auditor |
| `cctv.operator_actor_id` | Attribute access | 365 days restricted audit | privacy officer, auditor |
| `cctv.access_log_actor` | Detect unauthorised viewing | 365 days restricted audit | privacy officer, auditor |
| `cctv.hold_id` | Prove retention suspension | until hold released + matter closed | privacy officer, auditor |

The **CCTV access matrix** is:

| Role | Security | Access anomaly | Safety | Operational | Export/delete |
|---|---|---|---|---|---|
| security operator | read | read | no | read | no |
| safety officer | read | no | read | no | no |
| auditor | read | read | read | read | no |
| privacy officer | read | read | read | read | yes |
| venue manager | no | no | no | read | no |

## 4. Retention enforcement

Retention is **not only documented**. The AGPL `tirbase-venue-privacy` store:

- refuses a read after `occurred_est + class ceiling` unless an active hold
  covers the event (`CctvStore::read`);
- `purge_expired` removes expired metadata and reports events retained under
  hold;
- `subject_export` and `delete_subject` use the same deadline/hold logic;
- every action is appended to a bounded, payload-free access log;
- the binary `venue-privacy purge` is the operational sweep caller.

Tests: `cctv_retention_is_enforced_at_read_and_purge`,
`cctv_legal_hold_blocks_deletion_and_extends_retention`,
`cctv_access_is_role_scoped_and_audited`,
`raw_video_and_biometrics_are_refused`. See
[`venue-cctv-retention.md`](../venue-cctv-retention.md).

## 5. Risks and mitigations

| Risk | Likelihood/impact | Mitigation | Residual |
|---|---|---|---|
| Function creep into video analytics | Medium/high | Metadata-only API; no media fields; connector `CameraContext` is metadata-only; tests refuse media markers | Low |
| Unauthorised viewing | Medium/high | Role matrix; venue scope; access log; privacy-officer-only export/delete | Medium — insider policy remains |
| Excessive retention | High/medium | Enforced deadlines; purge report; legal-hold exception | Low |
| Note contains health/biometric detail | Medium/high | Bounded note, marker refusal, operator guidance, DPIA sign-off | Medium — human data entry |
| Re-identification from camera + time | Medium/medium | Zone/camera metadata restricted; no raw video; short operational retention | Medium — inherent to CCTV |
| Legal hold destroys evidence | Low/high | Holds block purge/deletion; release audited | Low |

## 6. Data-subject rights and legal hold

A subject-access request is handled by the privacy officer against the
pseudonymous subject reference. Only retained metadata is returned; video, if
any, remains with the VMS controller and is outside this runtime. Deletion
removes unheld metadata; held metadata is reported and kept until the hold is
released. The procedure is in
[`venue-subject-access-deletion.md`](../venue-subject-access-deletion.md).

## 7. Outcome

**Approved for software pilot only**, where the pilot processes metadata and no
customer video. A customer CCTV pilot requires the operator's separate video
DPIA, lawful basis, signage, VMS contract, retention and access review. This
runtime does not make a surveillance-lawfulness decision for the operator.

| Sign-off field | Value |
|---|---|
| DPIA owner | venue privacy engineering |
| Operator DPO | _to be completed by customer_ |
| Review date | 2026-11-22 (baseline) |
| Next review | annually; on camera/VMS/retention change |
