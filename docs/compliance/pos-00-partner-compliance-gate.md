# POS-00 — Partner and Compliance Gate (Decision Record)

> **This is a decision record, not a compliance claim, certification, or legal opinion.**
> It records whether the POS programme may begin. It does not itself establish that any POS
> feature, fiscal module, or payment path is compliant, certified, or in scope.

**Record ID:** POS-00-GATE-0001
**Opened (UTC):** 2026-11-16
**Superseded (UTC):** 2026-11-16
**Decision:** **SUPERSEDED — commercial/compliance gate deferred by the repository owner**
**Gate owner:** Product (repository owner)

## 1. Decision

The original NO-GO in this record is superseded by an explicit owner decision to defer the
commercial and compliance gate and begin POS domain-model engineering. This is **not** a GO:
none of the six inputs in §2 exists, and no Product/Compliance/Legal signature exists. The record
says so, so that nobody later mistakes prototype work for an approved POS product.

What the deferral permits:

- POS-01 through POS-15 domain-model and adapter engineering in the open tree, as non-production
  code.

What the deferral does **not** permit:

- No live payment credentials, processor accounts, or terminal certifications.
- No real card data (PAN/CVV) anywhere, in code, tests, fixtures, or logs.
- No fiscal certification or compliance claims (KassenSichV/TSE, RT, NF525, Veri\*factu).
- No customer deployment, pilot, or money movement.
- No POS-16 through POS-21 work (closed connectors, fiscal modules, PCI bundle, commercial kit).

Those remain blocked until a real GO record exists.

## 2. Gate inputs (still open)

Each row must carry a named artefact and a named accountable person. The deferral does not fill
any row; it records that work proceeds while they are open.

| # | Gate input | Evidence required | Recorded value | State |
|---|---|---|---|---|
| 1 | Signed merchant or reseller partner, named channel, named buyer | Countersigned partner agreement naming the reseller/merchant entity, the sales channel, and the first buyer | None on file | **OPEN** |
| 2 | Compliance owner for fiscal rules and PCI scope | Named individual accepting accountability for fiscal rule interpretation and for defining/limiting PCI scope; written acceptance | None named | **OPEN** |
| 3 | Target countries and fiscal regimes | Explicit country list, with the fiscal regime and certification path per country | None approved | **OPEN** |
| 4 | Payment terminals/processors and integration model | Named terminal models and processors, plus the integration model and who owns certification per model | None selected | **OPEN** |
| 5 | Offline reconciliation, chargeback, and support model | Written model covering offline authorisation limits, reconnect reconciliation, chargeback ownership/evidence, and support ownership | None agreed | **OPEN** |
| 6 | Legal review of money handling, refunds, and record retention | Counsel-reviewed memo covering custody of funds, refund authority, chargeback liability, and retention periods | Not reviewed | **OPEN** |

## 3. Approved scope

The deferral approves no country, regime, processor, terminal, currency, or customer deployment.
Engineering scope is limited to jurisdiction-neutral domain models that assume none of them.

| Scope item | Approved value |
|---|---|
| Countries | none — model must stay jurisdiction-neutral |
| Fiscal regimes | none |
| Processors | none |
| Terminal models | none |
| Integration models | none |
| Currencies | ISO 4217 codes only as data; no jurisdiction default |
| Customer scenarios | none |

Any POS prompt that names a country, regime, processor, terminal, currency default, or customer
scenario is out of scope under this record.

## 4. First three customer scenarios

Still not recorded, because there is no partner or buyer. They are left blank rather than invented.

| # | Customer / buyer | Channel | Country | Scenario | Status |
|---|---|---|---|---|---|
| 1 | — | — | — | — | **BLOCKED — no partner** |
| 2 | — | — | — | — | **BLOCKED — no partner** |
| 3 | — | — | — | — | **BLOCKED — no partner** |

## 5. Sign-off

Product, Compliance, and Legal have not signed, and this record does not claim they did. The
repository owner has accepted the deferral for prototype scope only.

| Role | Name | Position | Signature | Date (UTC) |
|---|---|---|---|---|
| Product (repository owner) | — | Gate deferred for prototype-only POS model work; accepts the open risks in §2 | Recorded from owner instruction; signature pending | 2026-11-16 |
| Compliance | — | Not signed | — | — |
| Legal | — | Not signed | — | — |

## 6. Conditions to restore the full gate

A GO record replaces this one only when it:

1. Fills every row in §2 with a named artefact and accountable person.
2. Names the three customer scenarios in §4, with partner, channel, country, and buyer.
3. Is signed by Product, Compliance, and Legal.
4. Explicitly limits POS-01 through POS-21 to the approved countries, regimes, processors, and
   terminals.
5. States whether POS prompts stay open-source (AGPL/Apache) or move to the closed commercial
   tree, consistent with `LICENSING.md`.

Until then, POS-16 through POS-21 are refused at the backlog level, and POS-01 through POS-15 must
not be represented as production-ready, certified, or payment-enabled.

## 7. Change log

| Date (UTC) | Change | By |
|---|---|---|
| 2026-11-16 | Record opened; all six gate inputs missing; decision NO-GO; POS backlog blocked | Gate owner (unassigned) |
| 2026-11-16 | Superseded: owner deferred the commercial/compliance gate for prototype-only POS domain engineering; inputs remain open; no signatures claimed | Repository owner |
