# Time Synchronisation, Time Zones, and Time Confidence

> **Status:** Implemented. F-06. This document states the time model, the
> drift bounds, what happens on a clock jump, and how sites schedule local
> events across DST. Authenticated command/approval expiry continues to be
> enforced by the guard's `TimeRatchet` (PV-22).

---

## 1. Two clock domains

| Domain | Source | Used for |
|---|---|---|
| Monotonic | `CLOCK_BOOTTIME` via `TimeSource::monotonic_now` | expiry, anti-replay, rate limits, lease deadlines |
| Wall clock | `TimeSource::wall_hint` (untrusted, may jump) | human-facing records, exports, audit display |

No security decision may compare a wall-clock value to an expiry. Command,
token, trust-root and approval expiry use `now_est` from `TimeRatchet`:

```text
now_est = last_beacon_time + (mono_now − mono_at_beacon)     (same boot)
now_est = persisted_floor                                   (after reboot)
```

`persisted_floor` is the highest accepted beacon time ever committed and never
decreases except through the M-of-N `TimeAnchor` operator reset.

---

## 2. Time sources

| Source | Admission | Typical use |
|---|---|---|
| Gateway `TimeAnchor` beacon | Signed, validated by `TimeRatchet::advance`; large jumps need M-of-N | Primary source, including offline mesh deployments |
| GPS with message authentication (e.g. Galileo OSNMA) | Authenticated sample, then ratchet admission | GNSS-equipped remote sites |
| NTP | Only via NTS (authenticated); treated as one sample, never a clock set | Connected deployments; feeds a TimeAnchor |
| Local monotonic | Always available | Offline continuity only; confidence degrades |

`tirbase_core::timesync::select_sample` rejects unauthenticated samples,
samples from a previous boot, samples older than the configured age, samples
below the persisted floor (rollback), and samples that jump further forward
than a single source may. External sources never set `now_est` directly.

---

## 3. Drift bounds

Offline confidence uses `DriftBound`:

| Parameter | Default | Meaning |
|---|---|---|
| `max_ppm` | 50 | Worst-case oscillator drift after the last anchor |
| `max_absolute_ms` | 250 | Uncertainty already present at the anchor |

```text
uncertainty_ms(elapsed) = 250 + elapsed_secs × 50 / 1000
```

That is **+50 ms per 1 000 s** (about +4.32 s/day). A record captured offline
carries this bound in its `TimeConfidence::Offline` marker. Calibrated
hardware may tighten the bound; loosening it requires a configuration change
and is visible in every record produced under it.

---

## 4. Clock jumps

| Event | Behaviour |
|---|---|
| Wall clock moves backwards | `now_est` is unaffected (monotonic domain); no expiry is revived |
| Wall clock jumps forward | `now_est` is unaffected; beacons are still required to move the floor |
| Beacon below the floor | Rejected as replay (`BeaconNotAdvancing`) |
| Beacon jumps > `max_forward_jump_secs` (24 h) | Rejected unless the configured M-of-N `TimeAnchor` quorum signs (`InsufficientAnchorQuorum`) |
| Operator must correct a corrupted floor | `TimeResetPayload` with M-of-N `TimeAnchor` signatures; the only backwards path |
| Persist fails | The advance does not take effect (durable before accepted) |

Every rejection emits a security event (`BeaconRejected`,
`BeaconSignatureInvalid`, `BeaconJumpTooLarge`) into the hash-chained log.

---

## 5. Time zones and DST

All stored timestamps are UTC. A site/store/venue registers a
`SiteTimeZone` (standard offset plus an optional `DstRule`); schedules are
evaluated in that zone, not in the gateway's host zone.

Rules are explicit: "nth weekday of month at local time" (for example US
Eastern, second Sunday March / first Sunday November; EU, last Sunday
March / October). This covers the zones used by deployments without an IANA
database dependency; unusual jurisdictions configure their own rule.

Scheduling guarantees exactly **one** occurrence per event per local date:

| Local time | Resolution | Run |
|---|---|---|
| Exists once | `Unique` | at that UTC instant |
| Spring-forward gap (02:30 does not exist) | `Skipped` | once, at the transition instant (03:00 local) |
| Autumn overlap (01:30 occurs twice) | `Ambiguous` | once, at the first occurrence (daylight offset) |

`occurrences_between` de-duplicates by `(event id, local date)`, so a DST day
can neither skip nor duplicate a scheduled job.

---

## 6. Signed time evidence

Records that leave the device — exports, audit entries, offline captures —
carry `TimeEvidence`:

```json
{
  "wall_time_secs": 1800003600,
  "mono_secs": 5000,
  "boot_id": 7,
  "ratchet_floor_secs": 1800000000,
  "confidence": { "state": "offline", "elapsed_since_anchor_secs": 3600, "drift_bound_ms": 430 }
}
```

`SignedTimeEvidence` signs
`"TirBase/v1/TimeEvidence" || 0x00 || SHA-256(JSON(evidence))` with the
export/audit key. A verifier checks the signature and that the signer DID
derives from the supplied public key. Tampering with any field, including the
confidence marker, breaks verification.

`TimeConfidence` values:

| Marker | Meaning |
|---|---|
| `verified` | Backed by an authenticated source inside its uncertainty |
| `offline` | No source; derived from the monotonic ratchet with the drift bound above |
| `unverified` | No trustworthy wall time (rebooted, no source, or anomaly); critical operations require a challenge |

---

## 7. Expiry across reboot and long offline periods

- **Long offline, no reboot:** `now_est` keeps advancing from the monotonic
  clock, so approvals and commands expire on schedule. Freshness becomes
  `Unverified` after the staleness window (1 h), which forces a challenge for
  critical parameters but does not extend any expiry.
- **Reboot:** the monotonic subtraction is meaningless, so `now_est` is the
  persisted floor and freshness is `Unverified`. A numerically expired approval
  stays expired. An approval issued in an earlier boot is **invalidated by the
  reboot** (`ApprovalRejection::InvalidatedByReboot`) and must be re-issued;
  it is never silently revived.
- **First boot:** floor is 0 and freshness is `Unverified` until a beacon with
  the required quorum is accepted.

---

## 8. References

- `tirbase-guard/src/time.rs` — `TimeRatchet`, freshness, beacon admission.
- `tirbase-gateway/src/time_anchor.rs` — signed COSE_Sign1 beacons.
- `tirbase-core/src/timesync/` — source admission, drift bounds, time
  evidence, site zones and DST scheduling.
- `docs/design-notes/time-anchor-external-sources.md` — NTS / Roughtime /
  OSNMA evaluation.
- `docs/runbooks/time-anchor-failure.md` — operational recovery.
