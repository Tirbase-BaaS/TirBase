# TirBase Gateway Admin Python client

Generated from `docs/api/gateway-admin-openapi.yaml` by
`scripts/generate-gateway-sdk.mjs`. Do not edit
`tirbase_gateway_client.py`; regenerate it instead.

Licence: Apache-2.0.

```python
from tirbase_gateway_client import GatewayAdminClient

client = GatewayAdminClient("https://gateway.example:8443", token="<biscuit-hex>")
site = client.create_cold_chain_site({"tenant": "acme", "name": "Cold Room 1"})
readings = client.list_cold_chain_readings(site["object"]["id"], query={"tenant": "acme"})
```

The client uses only the Python standard library. It sends
`Authorization: Bearer <token>` and raises `AdminError` for non-2xx responses.
TLS client certificates are supplied by configuring an `ssl.SSLContext` on a
custom opener; the generated module intentionally does not pin a second TLS
implementation.
