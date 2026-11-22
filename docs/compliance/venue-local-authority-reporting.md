# Venue local-authority reporting templates (ST-13)

These templates are for a venue operator's DPO/legal team. They are not legal
advice and do not authorise disclosure. Verify the authority, legal basis,
scope and deadline before sending. Record every request and disclosure in the
privacy request log; preserve relevant data under a legal hold where required.

## 1. Request triage

| Request | Typical authority | First action | Do not |
|---|---|---|---|
| Personal-data breach | supervisory authority (e.g. ICO) | assess risk; notify within the statutory deadline (72 hours where applicable) | wait for full root cause before an initial notification |
| Police CCTV/access request | police force | verify identity, legal power and scope; route to counsel | hand over raw video or a full export on an informal request |
| Licensing review | local licensing authority | verify statutory power; provide only the specified records | disclose unrelated subjects' data |
| Fire/safety serious incident | fire and rescue / health & safety authority | preserve safety records and CCTV metadata; notify per local rules | alter or delete records |
| Subject/third-party complaint | regulator/ombudsman | log, preserve, respond through counsel | contact the complainant directly without advice |
| Tax/audit request | tax authority | verify legal basis; minimise | export unrelated personal data |

## 2. Personal-data breach notification

```text
To: [supervisory authority / venue DPO]
From: [venue / controller]
Date/time (UTC): [ ]
Reference: [breach id]

1. Nature of the breach
   [ ] confidentiality [ ] integrity [ ] availability
   What happened: [ ]
   Data domains: [ticket / credential / CCTV metadata / access / audit]
   Approximate number of data subjects: [ ]
   Approximate number of records: [ ]
   Special-category data: [no / describe — this runtime baseline has none]

2. Likely consequences
   [ ]

3. Measures taken or proposed
   [containment, revocation, purge, access restriction, notification]

4. DPO / contact
   Name: [ ]
   Role: [ ]
   Contact: [ ]

5. Cross-border / processor involvement
   [ ]

6. Attachments
   [timeline, affected field ids from the register, access-log extract]
```

**Do not include** raw CCTV video, credential secrets, another subject's data or
privileged investigation notes. Use field ids and counts.

## 3. Police request for CCTV/access metadata

```text
Authority: [force / unit]
Officer name, collar/ID: [ ]
Legal power / warrant reference: [ ]
Date/time of request: [ ]
Venue: [ ]
Scope requested: [camera/zone/time window/event ids/subject reference]
Offence/investigation reference: [ ]

Response:
[ ] authority and scope verified by counsel
[ ] data minimised to the request
[ ] third-party data redacted
[ ] legal hold opened: [hold id]
[ ] disclosure log updated
[ ] method/time of secure transfer: [ ]

Metadata supplied: [event ids / decision ids]
Video supplied: [none — VMS request must be made separately / VMS reference]
Withheld/redacted and why: [ ]
Authorised by: [ ]
```

This runtime never supplies raw video. If video exists, route the request to the
VMS controller and record the referral.

## 4. Licensing authority request

```text
Authority: [licensing authority]
Legal basis / notice reference: [ ]
Licence/premises: [ ]
Period in scope: [ ]
Records requested: [incident/access/safety/attendance metadata]
Response:
[ ] request within statutory power
[ ] records minimised and redacted
[ ] no unrelated subject data
[ ] disclosure logged
[ ] legal hold/retention updated
Supplied by: [ ]  Date: [ ]
```

## 5. Fire / health-and-safety serious incident

```text
Authority: [fire and rescue / HSE or local equivalent]
Incident reference: [ ]
Date/time: [ ]
Venue/zone/gate: [ ]
People affected: [counts only]
Data available: [safety events / access decisions / CCTV metadata / maintenance records]
Immediate preservation:
[ ] legal hold on CCTV metadata (hold id: [ ])
[ ] access/incident audit preserved
[ ] VMS preservation request sent (video is outside this runtime)
[ ] no deletion or alteration
Notification made by: [ ]  Date/time: [ ]
```

## 6. Disclosure safeguards

1. Verify the authority's identity and legal power; if in doubt, do not disclose.
2. Minimise to the stated purpose; prefer metadata and field ids over full
   records.
3. Redact other data subjects, staff personal data, security-sensitive detail
   and privileged material.
4. Open a legal hold before any potentially relevant deletion.
5. Log the request, decision, discloser, recipient, scope, legal basis and time.
6. Use an encrypted channel and confirm receipt.
7. Tell the DPO and counsel immediately about a suspected breach or unlawful
   request.

## 7. Evidence

Attach the register field ids, retention code, access-log extract and legal-hold
id. Do not attach the deployment pseudonymisation salt or raw video.
