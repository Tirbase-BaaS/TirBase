# CCTV event retention and access control (ST-13)

**Scope:** CCTV **metadata** events. Raw video is out of scope and is not
accepted by the runtime.

## 1. No raw video by default

The venue privacy model has no video payload. `CctvEvent` contains only:

`event_id`, `venue_id`, `camera_id`, `zone_id`, `event_kind`, `occurred_est`,
optional pseudonymous `subject_ref`, optional bounded `note`.

No frame, clip, thumbnail, embedding, face template, biometric marker or media
URL field exists. The constructor rejects `data:image`, `data:video`, `base64`,
`video/mp4`, `face_embedding` and `biometric` markers in every text field, and
`deny_unknown_fields` rejects a `media` extension. The connector
`CameraContext` is likewise metadata-only. A VMS that holds video is a separate
controller/processor decision for the venue.

## 2. Retention classes

| Event kind | Class | Maximum from occurrence |
|---|---|---|
| security, access anomaly | `CCTV_SECURITY_30D` | 30 days |
| safety | `CCTV_SAFETY_90D` | 90 days |
| operational | `CCTV_OPERATIONAL_7D` | 7 days |

A legal hold extends retention for its scope. The maximum is a ceiling, not a
target; delete earlier where the purpose is spent.

## 3. Enforcement, not documentation

The AGPL crate `tirbase-venue-privacy` implements the policy:

```text
CctvStore::read(actor, event_id, now)
  ├─ unknown → denied + audited
  ├─ wrong venue → denied + audited
  ├─ role cannot read kind → denied + audited
  ├─ expired and not held → Expired; payload not returned
  └─ allowed → audited; metadata returned

CctvStore::purge_expired(officer, now)
  ├─ expired, no hold → remove
  ├─ expired, held → keep and report
  └─ write purge audit record

CctvStore::delete_subject(officer, subject, request_id, now)
  ├─ unheld events → delete
  ├─ held events → retain and report hold ids
  └─ write deletion audit record
```

The operational caller is `venue-privacy purge` (and the library API for a
command-center/HTTP integration). It persists events, holds and the access log
to a JSON state file with an atomic replace. The tests
`cctv_retention_is_enforced_at_read_and_purge` and
`cctv_legal_hold_blocks_deletion_and_extends_retention` fail if a read is
allowed after expiry or a held event is purged.

## 4. Access control matrix

| Role | Security | Access anomaly | Safety | Operational | Export/delete/hold |
|---|---|---|---|---|---|
| security operator | read | read | — | read | — |
| safety officer | read | — | read | — | — |
| auditor | read | read | read | read | — |
| privacy officer | read | read | read | read | yes |
| venue manager | — | — | — | read | — |

Every allowed and denied action appends a payload-free `CctvAccessRecord`
(actor, role, action, target id, time, allowed). The audit record does not copy
the event note or subject reference. The access log is retained for 365 days in
restricted audit and is itself subject to legal hold.

## 5. Operating procedure

1. **Ingest:** only the privacy officer role (or a service holding that role)
   may insert metadata. Reject duplicate event ids.
2. **Daily purge:** run `venue-privacy purge` at least daily and on startup.
   Check `expired_seen`, `purged` and `retained_under_hold`; investigate any
   held event whose hold has ended.
3. **Legal hold:** open with `venue-privacy hold <id> <scope> <value> <reason>`;
   record the matter id and approver separately. Release only after counsel
   confirms; `release` is audited. Do not delete a held state file.
4. **Access review:** review the access log weekly for denied reads and unusual
   privacy-officer exports. Export the log without event payloads.
5. **Subject request:** use `venue-privacy export`/`delete`; see
   [`venue-subject-access-deletion.md`](venue-subject-access-deletion.md).
6. **State protection:** restrict the state file to the privacy service account,
   encrypt the volume/backup, and include it in the backup retention schedule.
   A lost state file must not be restored from an untrusted copy.

## 6. Evidence and limitations

- Evidence: `tirbase-venue-privacy/tests/st13_privacy.rs` and the register
  completeness test.
- The runtime enforces metadata retention; it cannot delete video held in a VMS.
  The operator must configure the VMS retention separately and record that in
  its CCTV DPIA.
- The in-memory/JSON store is single-writer. A multi-process deployment must
  provide a single writer or a transactional database; the library contract is
  unchanged.
- No claim is made about surveillance-lawfulness, signage or camera placement;
  those remain the operator's DPIA and local-law obligations.

## 7. Verification commands

```bash
cargo test -p tirbase-venue-privacy
python3 scripts/check-venue-privacy.py
```

The first proves enforcement and legal-hold behavior; the second checks the
embedded register, retention codes, DPIA pack, sign-off record and kit.
