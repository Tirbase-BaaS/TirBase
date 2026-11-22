# ST-03 — Access control: OSDP, Wiegand and DESFire

Crate: `tirbase-venue-access` (AGPL-3.0-only). Depends on ST-01
(`tirbase-venue`) for topology, ticket types, access policies and
anti-passback. Reader transports are owned by the caller: this crate builds and
consumes bytes, it never opens a socket or serial port.

## Scope and feature gates

| Feature | Enabled content |
| --- | --- |
| `osdp` | OSDP frame codec, SCS12/SCS13 secure channel, polling, status, tamper, PD simulator |
| `wiegand` | Wiegand 26/34-bit capture decoder with parity and timing checks, capture simulator |
| `desfire` | DESFire EV2/EV3 AES authentication, authenticated file read, card simulator |
| `all-readers` | All three |

Credential mapping, reader health, the offline cache and revocation are always
built. Cargo feature unification means a consumer that enables `all-readers`
gets every wire protocol; deployments that only use OSDP should enable just
`osdp`.

## Primitives

`crypto.rs` depends on `aes` (MIT/Apache-2.0) for the block cipher only. CMAC
(RFC 4493), CBC, EOM padding, constant-time comparison and key fingerprints are
implemented in-crate so the exact constructions used by both protocols are
reviewable in one file.

`AesKey` holds a zeroizing buffer, prints as `AesKey(<redacted>; N bytes)` and
exposes only `fingerprint()` (hex SHA-256 over a domain separator and the key)
for logging or storage.

## OSDP

* **Frames**: `SOM 0x53 | ADDR | LEN(whole packet, LE) | CTRL | payload |
  CRC-16(LE)`. `CTRL` bits: 0–1 sequence, 2 CRC present, 3 security block
  present. The 8-bit checksum form is refused (`UnsupportedChecksum`) — CRC is
  mandatory.
* **CRC**: poly `0x1021`, init `0x1FFF`, no reflection, no final XOR. Test
  vector: `crc16(b"123456789") == 0x6E26`.
* **Secure channel**: SCS12 (AES-128, 4-byte CMAC) and SCS13 (AES-256, 8-byte
  CMAC).
  ```
  S-ENC = CMAC(K, 0x01 || RND.C || RND.PD)
  S-MAC = CMAC(K, 0x02 || RND.C || RND.PD)
  C-MAC = CMAC(S-MAC, RND.C || RND.PD)[..8]
  R-MAC = CMAC(S-MAC, RND.PD || RND.C)
  ```
  Handshake: `CHLNG` → `CCRYPT` (verify R-MAC) → `SCRYPT` (C-MAC) → `RMAC_I`
  (starts the chain). Secure blocks carry the SCS code and a SID (`0` clear,
  `1` encrypted with AES-CBC under `S-ENC`, IV = complement of the chain) and a
  CMAC over the chain, the frame header and the ciphertext.
* One MAC chain is advanced by every frame in both directions. A dropped,
  reordered, replayed or modified block fails the next MAC check; a wrong MAC
  increments `OsdpPoller::secure_failures()`.
* **Status and tamper**: `LSTATR` decodes PD tamper, power-cycle, power fault,
  battery low, REX and aux input. `OsdpPoller::tamper_events()` counts reports
  showing tamper; `ReaderHealth::observe_tamper` latches the reader and
  `clear_tamper(true)` is the only way to clear it.
* **Keys**: the base key is held only during the handshake and dropped when the
  chain is established. `keyset_payload` builds a `KEYSET` payload from a key
  the caller owns; no key is logged or persisted.
* **Refusal of write paths**: no `OUT`, `LED`, `BUZ`, `RMODE` or `TEXT`
  command exists in this crate.

## Wiegand

A capture is a list of `WiegandPulse { line, width_us, gap_after_us }`.
Decoding rejects:

* pulse width outside `[min_width_us, max_width_us]` (default 20–200 µs);
* inter-pulse gap outside `[min_gap_us, max_gap_us]` (default 100 µs–20 ms);
* trailing gap shorter than `min_frame_gap_us` (default 20 ms), which would
  merge two cards into one capture;
* any length other than 26 or 34 bits;
* a leading even-parity or trailing odd-parity mismatch;
* an all-zero blank card.

Field layout: 26-bit = 1 parity + 8 facility + 16 card + 1 parity; 34-bit =
1 + 16 + 16 + 1. Both parity halves are equal length, the field split is not.

## MIFARE DESFire EV2/EV3

Read-only subset: `AuthenticateEV2First` (`0x71`, additional frame `0xAF`) and
`ReadData` (`0xBD`) in `CommMode.Full`. EV3 is wire-compatible with this path.

```
SV1 = 0x01 || RndA[0..2] || RndB[0..8] || RndA[2..8] || RndB[8..16]
SV2 = 0x02 || RndA[0..2] || RndB[0..8] || RndA[2..8] || RndB[8..16]
SesAuthENCKey = CMAC(Kx, SV1)
SesAuthMACKey = CMAC(Kx, SV2)
```

Command MAC: `CMAC(SesAuthMACKey, 0x00 || Cmd || CmdCtr || Data)` truncated to 8;
response MAC: `CMAC(SesAuthMACKey, 0x00 || Cmd || CmdCtr || Status || Data)`.
Data IV: `AES-ECB(SesAuthENCKey, A55A || TI || CmdCtr || 0^8)`. Command counter
starts at 0 and increments before each command.

No `ChangeKey`, `WriteData`, `DeleteFile`, `Format` or configuration command is
implemented or parsed; an unknown command is rejected.

## Credentials, keys and revocation

* `CredentialRegistry` stores a hex SHA-256 **fingerprint** of the card
  material plus the ST-01 ticket type. Raw card identifiers are not retained,
  and the fingerprint domain includes the source (OSDP/DESFire/26-bit
  Wiegand/34-bit Wiegand), so identical bytes from different readers do not
  share an identity.
* `KeyHandle` stores a key id, its purpose and a one-way fingerprint — never
  the key. `KeyRegistry` holds only these handles.
* `RevocationList` is versioned. `apply(delta)` is monotonic: a lower
  `to_version` is `RevocationRegression`, a `base_version` that is not the
  current version is `RevocationOutOfOrder`, and a matching `to_version` is
  `AlreadyCurrent` (safe to replay).
* `OfflineCache` persists the revocation list, its version, cached grants and
  the secure-channel flag as JSON. `AccessController::restore_cache` restores
  it after a restart and refuses a cache belonging to another reader.
  Revocation is evaluated **before** the cached grant, so a revoked card stays
  revoked while the reader is offline.

## Resolution order

`AccessController::authorize`:

1. refuse while tamper is latched;
2. look the card up by fingerprint (unknown → `UnknownCredential`);
3. check the validity window and cardholder active flag;
4. check revocation;
5. offline: honour only a cached, unexpired grant for the same gate,
   otherwise `NoCachedGrant`;
6. online: resolve exactly one ST-01 access policy, record the anti-passback
   entry, cache the grant for four hours and return `AccessGrant`.

## Tests and fuzz

`tests/st03_access.rs` (18 tests with `--all-readers`) covers:

* a secure-channel reader authenticating, polling and reading a credential that
  then resolves to a venue grant;
* a tampered secure block and a tampered PD reply both rejected by MAC;
* status-reported tamper latching the reader until an authorised reset;
* recorded poll/ACK frames and the CRC check value;
* Wiegand 26/34-bit captures, bad parity (both bits) and every timing failure;
* DESFire EV2 and EV3 authentication plus file read, wrong key, unauthenticated
  read;
* revocation surviving an offline restart, cached offline grant use, missing
  cache refusal, monotonic revocation deltas;
* registry and key-handle serialization containing no raw card or key material;
* seeded malformed-input loops over every decoder.

`fuzz/fuzz_targets/venue_access_frames.rs` fuzzes the OSDP frame/poller paths,
the DESFire card handler and reader response path, and Wiegand capture decoding.

## Limits

* No live reader, PD or card was exercised: all tests use the deterministic
  simulators in `sim.rs`. A HIL campaign against OSDP and DESFire hardware is a
  deployment step.
* This is not a certified OSDP or DESFire stack. It implements the subset the
  venue reader needs, with the constructions documented above; an
  interoperability run against a vendor panel/card is required before field
  use.
