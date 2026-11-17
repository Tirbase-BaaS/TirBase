# Retention guidance for cold-chain records

**This is guidance, not legal advice.** Apply the longer of: the applicable regulation,
the customer contract, the product shelf life, and the defaults below. Record the site's
chosen periods in the quality system.

## 1. Minimum defaults

| Record class | Minimum | Typical driver |
| --- | --- | --- |
| Temperature readings and alarm events | 2 years | FSMA preventive-control records; GDP expectations |
| Excursion records, dispositions and CAPA | Product shelf life + 2 years | Product release defence; GDP |
| Calibration records and certificates | Life of instrument + 2 years | Accreditation and audit |
| Audit trail and chain checkpoints | Life of system + 2 years | ALCOA+ enduring/available |
| Release decisions and e-signatures | Product shelf life + 2 years | GDP; electronic-records rules |
| Training records | Employment + 2 years | Quality-system policy |
| Security/incident logs | 2 years | CRA/IEC 62443 operational evidence |
| Configuration/change records | Life of system + 2 years | Validation and change control |

## 2. What the runtime retains

- Ledger entries, report generations, signatures and the audit chain are retained and
  never pruned by the reporting module.
- Export **bodies** may be pruned after their retention window; manifests, digests and
  signatures are kept so a pruned export remains verifiable.
- Deleting a database destroys evidence: take and verify a snapshot before decommissioning.

## 3. Preservation and erasure

1. Preserve records under legal hold if litigation or an investigation is known.
2. For personal data, apply the data-protection procedure: erase or pseudonymise where
   lawful, record the action and the authority, and keep the minimum audit evidence that
   the erasure happened.
3. On contract termination, export the customer's records (signed export plus manifest),
   verify the digest, hand over, and only then destroy with a certificate of destruction.

## 4. Retention review

Review the schedule annually and on regulatory change. Retention is only defensible if the
records are retrievable: test a retrieval of the oldest in-scope record each year and
record the result.
