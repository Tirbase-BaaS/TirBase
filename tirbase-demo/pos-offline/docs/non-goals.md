# Non-goals

This pack demonstrates domain-level defenses in a prototype. It does **not**
do any of the following, and must not be presented as doing them.

## No fiscal certification

The pack contains no fiscal module, fiscal signature, country-specific receipt
rule, tax-authority interface or certification evidence. A defended scenario is
not a certified fiscal record. POS-00 explicitly leaves fiscal regimes and
certification paths unapproved.

## No PCI scope reduction

The pack contains no card-data field, PAN, CVV, track data, tokenization
service, processor SDK or acquirer connection. Running it does not reduce PCI
DSS scope, does not validate a payment terminal and does not establish that any
payment component is in scope or out of scope.

## No acquirer settlement

No money moves. There is no authorization, capture, clearing, settlement,
chargeback or reconciliation against a real acquirer or processor. The
"capture", "refund" and "void" commands are in-memory model transitions using
opaque test tokens; they are not payment instructions.

## No production or compliance claim

The pack is not a production POS, pilot, customer deployment or audit artefact.
It does not replace the partner, compliance and legal gate inputs in
`docs/compliance/pos-00-partner-compliance-gate.md`; all remain open.

## No physical-device qualification

Simulated scale, scanner, printer and KDS transports are not hardware
qualification. The F-13 HIL campaign remains outstanding.

## No jurisdiction or customer scenario

Currency codes are data, not a default. The pack names no country, fiscal
regime, processor, terminal model or customer. It must not be used to claim
coverage of any of them.
