# What this kit does not cover

This list is deliberately explicit. If a customer requirement is not in the kit and not in
a signed agreement, it is out of scope.

## Compliance and certification

- **No certification or conformity claim.** The kit does not certify IEC 62443 SL2/SL3,
  CRA conformity, GDP/HACCP/FSMA compliance, or any accreditation. Only an accredited
  assessor or regulator can do that (GAP-REV-002).
- **No legal advice.** Wording and templates are drafts pending counsel review
  (GAP-REV-001).
- **No HACCP plan, hazard analysis or product stability assessment.** Those are
  customer-specific (GAP-CUST-001, GAP-CUST-002).
- **No facility registrations, licences or regulatory filings** (GAP-CUST-005).

## Product and safety

- **Not a safety instrumented system.** No SIL rating; not for functions where failure can
  cause direct physical harm. Safety interlocks remain external.
- **No qualification of the customer's enclosure, power, or installation.** Environmental
  limits are deployment-specific (GAP-ENV-001).
- **No guarantee of a specific temperature accuracy for an uncalibrated device.** Accuracy
  statements apply only after the calibration procedure passes.
- **No physical HIL execution in this delivery.** The software bench results are included;
  the commercial lab campaign must be run and evidenced separately (GAP-LAB-001).

## IT, data and operations

- **No provision of source code.** The AGPL runtime is licensed separately; this kit cites
  evidence by reference. No secrets, keys, seeds or customer data are included.
- **No hosting, network design, firewall configuration or SIEM integration.**
- **No backup media, off-site storage or disaster-recovery site.**
- **No customer-specific retention schedule or legal basis** (GAP-DATA-001).
- **No 24/7 staffing until a signed SLA exists** (GAP-SUP-001).

## Commercial

- **No warranty, indemnity, or liability terms beyond the signed agreement.**
- **No certification marks, logos, or right to use the TirBase trademark except as the
  trademark policy permits.**
- **No sublicensing or OEM distribution rights** unless the OEM licence is signed.
- **No third-party device certification.** Vendor certificates, PICS and firmware
  compatibility are the vendor's and operator's evidence (GAP-CUST-004).

## Explicit pending items

| Item | Status | Blocking |
| --- | --- | --- |
| Counsel review of all compliance wording and templates | pending | Release delivery |
| Accredited assessor review of SL2/SL3 and CRA claims | pending | External claims |
| Physical lab campaign against customer instruments | not started in this delivery | Asserting physical validation |
| Customer-specific sensor certificates | operator-supplied | Certified-device claims |
