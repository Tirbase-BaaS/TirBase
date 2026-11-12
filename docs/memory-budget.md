# Memory Budget Ledger

This document tracks every configured cache/buffer cap and the process RSS budget
they are measured against. The authoritative values live in
`tirbase-core/src/crdt/memory_budget.rs`
(`DAG_NODE_CACHE_BYTES`, `ICO_INDEX_BYTES`, `REASSEMBLY_BUFFERS_BYTES`,
`PENDING_QUEUE_GLOBAL_BYTES`, `RATE_QUARANTINE_MEMORY_BYTES`,
`RSS_BUDGET_BYTES`); update both together.

## Configured Caps (PV-6.5)

| Component | Configured Cap | Notes |
| --- | --- | --- |
| DAG node cache | 32 MiB | tirbase-core cache management (`memory_budget::DAG_NODE_CACHE_BYTES`) |
| ICO index | 8 MiB | Index cache (`memory_budget::ICO_INDEX_BYTES`) |
| reassembly buffers | 16 MiB | Fragment reassembly buffers (`memory_budget::REASSEMBLY_BUFFERS_BYTES`) |
| pending queue (global) | 64 MiB | Bounded pending queue, (`memory_budget::PENDING_QUEUE_GLOBAL_BYTES`) |
| rate quarantine (in-memory per-sender counters) | 1 MiB | Counter state, not payload buffers (`memory_budget::RATE_QUARANTINE_MEMORY_BYTES`) |
| **Total configured caps** | **121 MiB** | `memory_budget::total_configured_caps_bytes` |

## RSS Budget

| Item | Value |
| --- | --- |
| Process RSS budget baseline | 256 MiB (`memory_budget::RSS_BUDGET_BYTES`) |
| 90% ledger rule | 230.4 MiB |
| Total configured caps | 121 MiB |
| Headroom under the 90% rule | 109.4 MiB |

The 256 MiB baseline is **provisional**: (measure-first baseline on
reference hardware) is still Planned, and will replace it with a measured value.
Until then the number above is the budget the gate asserts against and the
denominator for the 90% rule.

## Measurement Gate

Unlike a static arithmetic check, the gate loads the caches and measures the
process:

```text
cargo test -p tirbase-core --test memory_budget_gate -- --ignored --nocapture
```

`tests/memory_budget_gate.rs` allocates and page-touches every cap in the table,
records the bytes through the production `MemoryBudgetCaches` metrics handles,
and reads peak RSS via `getrusage(RUSAGE_SELF).ru_maxrss`. It asserts:

1. the sum of the configured caps ≤ 90% of `RSS_BUDGET_BYTES`;
2. peak RSS actually grows once the caches are loaded (the measurement is real);
3. peak RSS ≤ `RSS_BUDGET_BYTES`.

The CI job `memory-budget-check` (`.github/workflows/ci.yml`) runs this test as a
blocking step, so a ledger that no longer describes what the process allocates,
or a regression past the budget, fails CI.
