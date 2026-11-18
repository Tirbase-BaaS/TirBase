# Offline POS scenario pack

This Apache-2.0 pack is the POS-09 reference data for offline conflicts in the
prototype `tirbase-pos` model. It is **data only**: every file except the
launcher `run.sh` is TOML or Markdown. It contains no executable code, no
credentials, no card data and no customer data.

The pack depends on POS-02 through POS-08:

| Area | Scenario | Model exercised |
|---|---|---|
| Payment reconnect | `double_charge_on_reconnect` | POS-03 intent store, POS-06 payment envelope/nonce |
| Refund replay | `replayed_refund` | POS-05 refund guard, POS-06 replay window |
| Split conflict | `split_bill_conflict` | POS-02 replicated operation book |
| Offline price change | `offline_price_change` | POS-04 catalog/price/tax versions and pinning |
| Void after capture | `void_after_capture` | POS-05 capture void approval, POS-06 replay |
| Duplicate kitchen ticket | `duplicate_kds_ticket` | POS-08 KDS idempotent ticket ID |

## Pack layout

```text
pack.toml                 manifest (schema_version = 1, kind = pos_offline)
scenarios/*.toml          one scenario per file
expected/outcomes.toml    expected permit and ledger rows
sim/config.toml           declarative terminal/time configuration
run.sh                    the only executable
docs/README.md            this file
docs/non-goals.md         explicit non-goals
```

Each scenario declares:

- `initial`: currency, terminal, operator, approver, epoch, check, total, tip,
  check status, intent status, intent, payment and optional pricing/split/KDS
  state;
- `partitions`: offline intervals per actor with a reason;
- `approvals`: refund or captured-payment void approvals, including requester,
  approver, amount, reason and validity window;
- `commands`: ordered capture/refund/void/split/price/close/KDS commands, each
  with actor, time and expected permit;
- `invariant`: the named property the defended run must satisfy.

`expected/outcomes.toml` declares one permit per command and the final ledger
as sorted `key=value` rows. The Apache structural test checks the declarations;
the AGPL gateway test executes them through `tirbase-pos` and compares both
the permits and the ledger exactly.

## Running

From the repository root:

```sh
tirbase-demo/pos-offline/run.sh
```

The script prints the pack summary and runs:

```sh
cargo test -p tirbase-demo --test pos_offline_pack_structure -- --nocapture
cargo test -p tirbase-gateway --test pos_offline_scenarios -- --nocapture
```

The gateway test prints one defended-result line per scenario:

```text
PASS double_charge_on_reconnect permit=[accepted, replayed, denied] ledger=[...]
```

## Defended outcomes

- A capture retried after reconnect executes once; an identical retry is
  replayed and a fresh nonce against the captured intent is denied.
- An identical refund replay is a replay; a fresh nonce against the refunded
  intent is denied.
- Two offline splits of the same line converge on one winner and conserve money.
- A check closed before an offline price change keeps its pinned price; a new
  check pins the new version.
- A captured-payment void requires approval, executes once and rejects a fresh
  nonce after the intent is voided.
- A duplicate KDS ticket is answered from the journal, so the display receives
  one frame.

## Status

Prototype engineering under the POS-00 deferral. This pack is not production
software, not a compliance artefact and not evidence of payment certification.
See [non-goals](non-goals.md).
