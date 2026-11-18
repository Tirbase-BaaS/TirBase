# POS-09 — Offline POS scenario pack (Implementation Record)

> **Prototype record, not a compliance claim, certification, or legal opinion.**
> POS-09 packages offline-conflict scenarios permitted by the deferral in
> [`POS-00`](pos-00-partner-compliance-gate.md). It is not production-ready, not
> certified, and contains no payment connectivity or settlement path.

**Record ID:** POS-09-OFFLINE-PACK-0001
**Date (UTC):** 2026-11-17
**Licence:** pack data and structural tests `Apache-2.0`; gateway integration
test `AGPL-3.0-only`
**Pack:** `tirbase-demo/pos-offline`
**Depends:** POS-00, POS-02 through POS-08
**Gate status carried forward:** POS-00 remains **SUPERSEDED — gate deferred**;
all six gate inputs are still open and no signature exists.

## 1. Scope

| # | Requirement | Where |
|---|---|---|
| 1 | Six scenarios: reconnect double charge, replayed refund, split-bill conflict, offline price change, void after capture, duplicate KDS ticket | `tirbase-demo/pos-offline/scenarios/` |
| 2 | Each declares initial state, partition timeline, commands, approvals, expected ledger/permit and invariant | `pos_pack` schema, `pack.toml`, scenario files, `expected/outcomes.toml` |
| 3 | Apache structural tests and AGPL gateway integration tests | `tirbase-demo/tests/pos_offline_pack_structure.rs`, `tirbase-gateway/tests/pos_offline_scenarios.rs` |
| 4 | Docs with non-goals: no fiscal certification, no PCI scope reduction, no acquirer settlement | `tirbase-demo/pos-offline/docs/non-goals.md` |
| 5 | Run script producing observable defended output | `tirbase-demo/pos-offline/run.sh` |

The pack itself is data only. `run.sh` is its sole executable, and every other
file is `.toml` or `.md`. The loader in `tirbase-demo/src/pos_pack.rs` is
Apache-2.0 and never links `tirbase-pos`; execution happens only in the AGPL
gateway test.

## 2. Pack format

`pack.toml` declares `schema_version = 1`, `kind = "pos_offline"`, the
Apache-2.0 licence, the launcher, docs, expected-output file and six scenario
documents. Each scenario declares:

- **Initial state** — currency, terminal, operator, approver, epoch, check,
  total, tip, check status, intent status, intent and payment identifiers, plus
  pricing, split or KDS state where the scenario needs it.
- **Partition timeline** — per actor, an offline interval with a reason.
- **Commands** — ordered `capture`, `refund`, `void`, `split_check`,
  `publish_price`, `close_check` or `kds_submit` operations with actor, time,
  amount/nonce/counter or target details, expected permit and denial code.
- **Approvals** — action, amount, reason, requester, approver and validity
  window; self-approval is rejected by the loader.
- **Expected permit/ledger** — one permit per command and sorted `key=value`
  ledger rows in `expected/outcomes.toml`, checked for exact coverage.
- **Invariant** — a named property asserted by the defended run.

The loader rejects unknown fields, duplicate ids, overlapping partitions,
missing approvals for denied commands, denials on non-denied commands, permit/
ledger mismatches and any missing required scenario.

## 3. Scenarios

| Scenario | Initial state | Attack | Defended outcome | Invariant |
|---|---|---|---|---|
| `double_charge_on_reconnect` | Authorized intent, 2400 USD | Retry capture after WAN return, then fresh nonce | First capture executes, identical retry replays, fresh nonce denied `envelope.intent_state`; one capture and 2400 captured | `one_capture_per_intent` |
| `replayed_refund` | Captured intent, closed check | Replay queued full refund, then new nonce | Approved refund executes once; replay returns the recorded intent; fresh nonce denied `envelope.intent_state` | `one_refund_per_intent` |
| `split_bill_conflict` | One 1000 USD line | Two terminals split the same line offline | Canonical `(lamport, actor)` order keeps `till-1`'s target, rejects `till-2`, and conserves money | `split_conflict_has_one_winner_and_conserves_money` |
| `offline_price_change` | Price v1 1000, v2 1500 effective at 2000 ms | Publish new price during outage | Check closed at 1000 keeps `price-v1` and 1000; check closed at 3000 pins `price-v2` and 1500 | `closed_check_keeps_its_pinned_price` |
| `void_after_capture` | Captured intent, closed check | Void without approval, then approved void and fresh nonce | No-approval void denied `void.approval_required`; approved void executes once; replay accepted without a second void; fresh nonce denied `envelope.intent_state` | `captured_void_requires_approval_and_happens_once` |
| `duplicate_kds_ticket` | One grill ticket, sequence 7 | Resubmit after lost acknowledgement | First submit accepted; duplicate answered from the journal; one frame and one ticket | `duplicate_ticket_is_delivered_once` |

The payment scenarios realise a declared captured initial state through the
same POS-06 envelope path and count that setup capture and nonce in the ledger.
No state transition bypasses the envelope.

## 4. Structural and integration checks

The Apache structural test:

- loads the pack through the shared schema and validates every declaration;
- requires all six scenario ids and exact expected coverage;
- checks permits match commands and ledger rows are sorted `key=value`;
- verifies the data-only layout, no symlinks, no executable data files and no
  shebangs;
- checks docs state the three required non-goals.

The AGPL gateway test loads the same pack and executes it against the real
models:

- `PaymentDesk`, `PaymentEnvelope`, `PaymentIntentStore` for capture, refund
  and void;
- `PosBook` split/merge and canonical rebuild for the split conflict;
- `VersionStore` and `Order::open_pinned` for the offline price change;
- `KdsEndpoint<SimulatedKds>` for the duplicate ticket.

It compares observed permits and ledger rows to `expected/outcomes.toml`
exactly and prints one `PASS` line per scenario.

## 5. Acceptance evidence

| POS-09 "done when" | Evidence |
|---|---|
| Reconnect does not double charge | `reconnect_never_records_a_second_capture` and `all_offline_pos_scenarios_are_defended` — one capture event, 2400 captured, replay and denial observed |
| Replayed refund/void is denied | `replayed_refund_and_void_are_denied` — exactly one refund/void event, replay observed, fresh nonce denied |
| Split-bill conflict resolves deterministically | `split_conflict_resolves_deterministically` — repeated runs agree, `till-1` wins, totals conserved |
| The pack is data-only | `pack_contains_no_executable_code` and `pack_declares_every_layout_file`; `scripts/check-pack-purity.py` accepts the pack |

## 6. Non-goals

- **No fiscal certification.** No fiscal signature, country rule, tax-authority
  interface or certification evidence.
- **No PCI scope reduction.** No PAN/CVV, tokenization service, processor SDK or
  acquirer connection; running the pack does not reduce PCI DSS scope.
- **No acquirer settlement.** No authorization, capture, clearing, settlement,
  chargeback or reconciliation against a real acquirer. The model transitions
  use opaque test tokens.
- No production deployment, customer scenario, jurisdiction default, physical
  device qualification or replacement for the POS-00 gate.

## 7. Limits

- The pack executes in-memory POS models only; it is not an offline payment
  terminal and cannot move money.
- The split scenarios use the POS-02 deterministic book, not a production
  replication transport.
- The price scenario uses a single item and zero tax; it demonstrates pinning,
  not tax calculation.
- The KDS scenario uses the POS-08 simulator, not a physical display.
