# Support Escalation and Incident Communication Templates (F-15)

## Support escalation ladder (suggested)

| Level | Who | Triggers (examples) | Target response (guidance) |
|-------|-----|---------------------|----------------------------|
| L1 | Customer support / on-call operator | Health alarms, known runbook fixes, user how-to | Acknowledge per SLA; follow runbooks |
| L2 | Integration/support engineer | Config issues, driver faults, restore assistance, non-security bugs | Per contract SLA |
| L3 | Engineering/security | Suspected compromise, key material exposure, persistent invariant violations, zero-day-like behavior | Immediate triage; follow `SECURITY.md` for vulnerabilities |

Escalate to **security** immediately if: unauthorized admin access suspected, signing keys potentially exposed, tampered logs detected, or active exploitation indicators.

## Incident communication — internal (initial notice)

**Subject:** [TirBase Incident] <short title> — <severity> — <site/customer ID if applicable>

**Body template:**
- **Time detected (UTC):** 
- **Detected by:** 
- **Systems affected:** (gateway IDs, sites, tenants)
- **Observed symptoms:** 
- **Current impact:** (safety-adjacent? data integrity? availability?)
- **Actions taken so far:** 
- **Next steps and ETA for next update:** 
- **Incident commander:** 

## Customer communication — status update (template)

**Subject:** TirBase service update — <customer/site> — <status>

We are investigating/reporting an issue affecting <scope>.  
- **What happened:** <factual, no speculation beyond evidence>  
- **Impact:** <who/what is affected>  
- **Current mitigation:** <steps taken>  
- **Next update by:** <UTC time>  

Avoid sharing exploit details publicly before a coordinated fix/advisory if security-related (follow `SECURITY.md`).

## Security advisory coordination (pointer)

For vulnerabilities, use GitHub Security Advisories or `security@tirbase.dev` per `SECURITY.md`. Do not post PoCs or exploit details in public tickets until coordinated disclosure is agreed.

## Post-incident

- Complete postmortem within agreed timeframe.
- Update runbooks and `docs/security-findings.md` / advisories as applicable.
- If personal data may be affected, involve DPO/legal and follow breach notification laws and `docs/compliance/data-protection-procedures.md`.
