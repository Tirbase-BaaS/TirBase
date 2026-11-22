# Customer data-flow map

Complete the bracketed facts for the venue. The open baseline is
`docs/compliance/venue-data-flow-retention.md`.

```text
[issuer/scanner] → ticket/credential → gate decision → audit
                                      → privacy redaction → [connector?]
[CCTV/VMS] → metadata only → CctvStore → role access → purge/hold
[subject request] → privacy officer → export/delete → hold report
```

## 1. Systems and locations

| System | Purpose | Location/region | Controller/processor | Retention |
|---|---|---|---|---|
| Gate/access controller | admission | [ ] | [ ] | 90 days |
| Credential store | verification/revocation | [ ] | [ ] | 30 days post-revocation |
| CCTV metadata store | incident correlation | [ ] | [ ] | 7/30/90 days |
| Audit store | accountability | [ ] | [ ] | 365 days |
| Connector/cloud | [ ] | [ ] | [ ] | source retention |

## 2. Transfers

- Export/support access: [ ]
- Cloud/mesh sync: [ ] no [ ] yes — destination: [ ]
- Cross-border mechanism: [ ]
- Subprocessors: [ ]

## 3. Boundaries

- Raw video in TirBase? [ ] no (required) [ ] yes — unsupported
- Biometrics? [ ] no (baseline) [ ] yes — stop; separate DPIA
- Payment-card data? [ ] no (baseline) [ ] yes — out of scope; separate PCI review

## 4. Review

- Data-flow owner: [ ]
- Last reviewed: [ ]
- Trigger for update: field/connector/VMS/jurisdiction change.
