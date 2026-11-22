# Readers

## Requirements

A supported reader must:

1. Read the venue's credential technology and present an opaque credential id to
   the gate controller; it must not transmit a card secret or biometric template
   to TirBase.
2. Be supported by the controller firmware in the attested range.
3. Have a documented tamper indication and a weather rating for the installed
   location.
4. Be replaceable from spares without re-commissioning the lane's policy.
5. Have a published EOL date and a supported firmware position.

## Not supported

- Readers that require a vendor cloud service for every read, unless the lane has
  a documented offline mode.
- Readers that export biometric templates or raw card data to the venue network.
- Readers outside the attested firmware range.

## Register

| Model | Technology | Interface | Firmware | EOL | Status |
|---|---|---|---|---|---|
| *(none)* |  |  |  |  | pending |

## Installation checks

- [ ] Credential read verified with a valid and an invalid credential.
- [ ] Tamper alert reaches the operator.
- [ ] Reader swap from spares performed and lane re-tested.
- [ ] No card secret or biometric data is visible in the gate logs.

## Privacy

Credential identifiers are pseudonymised where the connector supports it, and
holder references are never resolved to a name in the gate log. This is part of
SR-12 and the customer DPIA.
