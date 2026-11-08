# Root CA Ceremony and Trust-Root Rotation

> **Status:** Implemented.  This document describes the offline procedure for
> generating, signing, installing, rotating, and revoking root CA keys for a
> TirBase deployment.  The on-disk artefact it produces is a
> `tirbase_guard::trust_root::TrustRootRecord`, verified and installed by
> `tirbase-gateway` at boot (CLAIM-8.1, CLAIM-8.2, CLAIM-8.3, CLAIM-8.4).
>
> **Requirement:** PV-3.4 (root threshold, revocation, rollback protection) and
> PV-3.5 (this ceremony document).

---

## 1. Why a ceremony?

The root CA is the only key that can authorise a new trust root.  Every other
role key — `PolicyAuthority`, `RevocationManager`, `UpdateSigner`, `Auditor`,
`TimeAnchor`, and `CommandIssuer` — is trusted only because the current
trust-root record lists it.  If the root key is generated on the gateway, or if
the trust-root file can be replaced silently, an attacker who compromises the
gateway can rewrite the entire authorisation model.

The ceremony therefore separates three things:

1. **Root key generation** happens on an air-gapped machine, never on a
   production gateway.
2. **Trust-root signing** is a threshold operation: at least `k` of the `n`
   root key holders must sign the same record.
3. **Installation** is performed by the gateway, which refuses any record whose
   version is not strictly greater than the version already committed to the
   local monotonic counter.

---

## 2. Roles and artefacts

| Artefact | Produced by | Stored where |
|---|---|---|
| Root CA key pair (Ed25519 seed + public key) | Air-gapped ceremony host / HSM | Offline media or HSM; never on the gateway |
| `trust-root.json` (`TrustRootRecord`) | Ceremony host | Read-only media delivered to the gateway |
| Rotation record (also a `TrustRootRecord`) | Ceremony host | Read-only media; optional `trust_root_rotation_path` |
| `root-ca-version` counter | Gateway, on first install | `monotonic_counters` table in `primary.db` |
| Root CA registry | Gateway, at boot | In-memory `RootCaRegistry` |

The root CA registry is **not** a separate file.  It is reconstructed from the
active keys in the installed `TrustRootRecord` on every boot
(`build_root_ca_registry` in `tirbase-gateway/src/main.rs`).

---

## 3. Ceremony prerequisites

- At least two independent root key holders.  `k = 1` is supported for small
  deployments, but the gateway emits a startup warning because a single key can
  rotate the root (PV-3.4; scenario S11).
- A quorum policy: choose `k` and `n` before generating any key.  Recommended:
  `n >= 3`, `k = 2` (survives one lost or compromised custodian).
- An air-gapped host with a trusted operating system image, verified entropy
  source, and no network interfaces connected.
- Two or more write-once/read-only media for the signed record, or an HSM that
  can export only signatures.
- A trusted, authenticated-time reading for the record's `expiry_est`.  The
  gateway evaluates expiry against `now_est` from its `TimeRatchet`, not against
  the host wall clock (PV-22).
- The current trust-root version.  The new record **must** carry a strictly
  greater `version`; the gateway rejects equal or lower versions as a rollback.

---

## 4. Generate the root CA keys

Generate each root key on the air-gapped host.  TirBase uses Ed25519 root keys:
a 32-byte seed and the corresponding 32-byte public key.

Reference generation (Rust, using the workspace keypair helper):

```rust
use tirbase_core::identity::keypair;

let (seed, public_key) = keypair::generate_keypair()?;
// seed: [u8; 32], public_key: [u8; 32]
// Store the seed in the HSM/offline medium. Record the public key and DID:
let did = tirbase_core::identity::did::derive_did(&public_key);
```

Record for each holder:

```text
holder:        <name / custody ID>
did:           did:key:z6Mk...
public_key:    <64 hex characters>
seed location: <HSM slot / sealed envelope ID>
```

Do **not** write the seed to `gateway.toml`, a log, shell history, or the
ceremony transcript.  The gateway only needs public keys.

If an HSM is used, the HSM must support Ed25519 signing over an arbitrary
message.  The private key never leaves the HSM; only signatures are exported.

---

## 5. Build the trust-root body

Create the unsigned body of the record.  The schema is
`TrustRootRecord` (`tirbase-guard/src/trust_root.rs`):

```json
{
  "version": 1,
  "root_ca_public_keys": ["<hex 32-byte key 1>", "<hex 32-byte key 2>", "..."],
  "threshold_k": 2,
  "role_thresholds": {
    "PolicyAuthority": {
      "required_m": 2,
      "required_n": 3,
      "authorized_signers": [
        { "did": "did:key:z6Mk...", "public_key": [/* 32 bytes */] }
      ]
    },
    "RevocationManager": { "...": "..." },
    "TimeAnchor": { "...": "..." }
  },
  "device_class_floors": {
    "safety-plc": [
      {
        "param_name": "temperature",
        "min_floor": { "mantissa": -20000, "exponent": -2, "unit_id": 1 },
        "max_ceiling": { "mantissa": 15000, "exponent": -2, "unit_id": 1 }
      }
    ]
  },
  "expiry_est": 1800000000,
  "revoked_root_ca_keys": [],
  "signatures": []
}
```

Rules enforced by `TrustRootRecord::validate` and
`verify_threshold_signatures`:

- `threshold_k >= 1`;
- at least `threshold_k` active (non-revoked) root keys are present;
- the record is not expired at `now_est`;
- at least `threshold_k` distinct active root keys sign the record;
- a signature whose DID does not derive from an active root key is ignored,
  and a revoked key can never contribute to the threshold.

`device_class_floors` are the authoritative tightening floors.  Policy bundles
may not relax them; a bundle's own floor fields are ignored
(`docs/adversary-scenarios.md`, S28).

### Role registry

`role_thresholds` is the role registry required by PV-3.2/PV-3.3.  For each
`CommandRole`, it lists the authorised DID public keys and the co-signature
threshold.  The verifier checks the DID against this list **before** verifying
the signature: a cryptographically valid signature from an unregistered DID is
rejected with `TrustRootError::RoleNotAuthorized` (CLAIM-8.3a).  A
`PolicyAuthority` cannot add itself; only a new root-signed trust root can
change the registry.

---

## 6. Sign the record (k-of-n)

The bytes signed by each root key are domain-separated:

```text
"TirBase/v1/TrustRootRecord" || 0x00 || SHA-256( CBOR(unsigned body) )
```

where the unsigned body is every field except `signatures`.  The exact
construction is `TrustRootRecord::signing_bytes`.

Each holder signs those bytes with their root key and the ceremony operator
collects one `TrustRootSignature` per holder:

```json
{
  "signer_did": "did:key:z6Mk...",
  "signature": { "Ed25519": [/* 64 bytes */] }
}
```

Requirements:

- signatures are over the **same** canonical body — any field change
  invalidates all previous signatures;
- at least `threshold_k` **distinct** DIDs must sign; duplicate signatures from
  one holder do not count;
- a signature from a key that is not active in this record is ignored;
- P-256 signatures are not accepted by the v1 trust root.

After collecting signatures, run `verify_threshold_signatures` locally before
leaving the ceremony room.  A record that fails this check must not be
installed.

---

## 7. Deliver and install the record

1. Copy the signed `trust-root.json` to read-only media.
2. Verify its SHA-256 hash out-of-band against the ceremony transcript.
3. Place it at a path readable by the gateway and set:

   ```toml
   trust_root_path = "/etc/tirbase/trust-root.json"
   ```

4. Boot the gateway.  The boot path:
   - parses the record;
   - verifies the root threshold signatures;
   - opens the named monotonic counter `trust_root_version` in
     `counter_db_path` (normally `primary.db`);
   - rejects the record with `TrustRootRollbackRejected` if
     `record.version < committed_version`;
   - commits the version with `set_if_greater`;
   - rebuilds the in-memory `RootCaRegistry` from the active keys;
   - emits the `k=1` startup warning when `threshold_k == 1`.

   The log line is:

   ```text
   trust root installed with rollback protection version=… committed_version=… threshold_k=…
   ```

5. Run the optional root CA self-test (`root_ca_self_test_token_path`).  The
   gateway proves a token fails before the root keys are registered and
   succeeds after.  This exercises the real token verification path against the
   registry built from the trust root (CLAIM-8.1).

---

## 8. Rotate the root keys

Rotation is the normal way to:

- add a new root key holder;
- remove a departing holder;
- revoke a compromised root key;
- change `k` or `n`;
- renew an approaching `expiry_est`.

Procedure:

1. Repeat sections 4–6 with the **new** key set.  Increment `version` by at
   least one.
2. Sign the new record with at least `threshold_k` of the **new** active keys.
   If the rotation is also a revocation, list the compromised key in
   `revoked_root_ca_keys`; the old key must no longer appear as active and must
   not contribute to the threshold.
3. Ensure the new record still has at least `threshold_k` active keys after the
   revocation.  A rotation that would leave fewer active keys than `k` is
   rejected.
4. Deliver the new record and either:
   - replace `trust_root_path` and reboot, or
   - set `trust_root_rotation_path` for a boot-time rotation.  The gateway calls
     `TrustRootManager::rotate`, which requires
     `new.version > committed_version` and rejects any rollback before
     committing.
5. Confirm the log line:

   ```text
   trust root rotated; revoked root keys are no longer accepted version=… committed_version=… revoked_root_keys=…
   ```

6. Destroy the old root key material according to custody policy, unless it is
   retained for audit under a documented hold.

### Rollback protection

The committed version lives in the `monotonic_counters` table (software
counter, Level 1; backed by the hardware counter binding where available).
Restoring an old `trust-root.json` — or restoring an old `primary.db` without a
signed epoch bump — cannot lower the committed trust-root version.  The boot
fails with `TrustRootRollbackRejected` (High severity) and the gateway does not
start with the stale record (CLAIM-8.2; scenario S22/INV-10).

---

## 9. Revoke a root key

Revocation is a rotation that lists the key in `revoked_root_ca_keys`:

1. Build a new record with `version = committed + 1`.
2. Keep the revoked key out of `root_ca_public_keys` (or list it in
   `revoked_root_ca_keys`; `active_root_ca_keys()` excludes both cases).
3. Ensure the remaining active keys still satisfy `threshold_k`.
4. Sign with the remaining active keys.
5. Install as in section 7.

Once installed, tokens signed by the revoked root key fail verification: the
registry only registers active keys (CLAIM-8.1, CLAIM-8.2).

If the compromise is suspected to be active, treat the deployment as
compromised until the rotation is installed: an attacker holding `k` root keys
can mint a competing trust root at any version greater than the committed one.
This is why the ceremony requires `k >= 2` for production deployments.

---

## 10. Operational checklist

**Before the ceremony**

- [ ] Quorum `k`/`n` chosen and recorded.
- [ ] Air-gap verified; no network interfaces on the ceremony host.
- [ ] HSM/offline media prepared and labelled.
- [ ] Current `trust_root_version` recorded from the gateway.
- [ ] `expiry_est` calculated from authenticated time.
- [ ] Role registry DIDs reviewed against the current authorisation matrix.

**During the ceremony**

- [ ] Every root key generated on the air-gapped host.
- [ ] Seeds never written to the transcript or gateway configuration.
- [ ] Signed body hash recorded in the transcript.
- [ ] `verify_threshold_signatures` passes with the intended `k`.
- [ ] A revoked key is excluded from the active set and still leaves `>= k`
      active keys.
- [ ] Signed record copied to read-only media; hash verified out-of-band.

**After installation**

- [ ] Boot log shows `trust root installed with rollback protection`.
- [ ] `threshold_k` matches the ceremony record; a `k=1` warning is expected
      only for an explicitly accepted single-key deployment.
- [ ] `trust_root_version` in `monotonic_counters` equals the new version.
- [ ] The root CA self-test rejects before registration and verifies after.
- [ ] Old root key material destroyed or placed under documented audit hold.
- [ ] Ceremony transcript and signed record archived.

---

## 11. References

- `tirbase-guard/src/trust_root.rs` — `TrustRootRecord`, role registry,
  threshold verification, `TrustRootManager` rollback protection.
- `tirbase-core/src/auth/root_ca.rs` — multi-key `RootCaRegistry`, k-of-n
  rotation, revocation, `k=1` warning.
- `tirbase-gateway/src/main.rs` — boot install, rotation, self-test, and
  `TrustRootRollbackRejected` emission.
- `tirbase-core/src/events.rs` — `TrustRootRollbackRejected` reason code.
- `docs/security-event-catalog.md` — event catalogue entry.
- PV-3.2, PV-3.3, PV-3.4, PV-3.5; scenarios S11 and S22; INV-10.
