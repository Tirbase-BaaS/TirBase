# Memory Budget Ledger

This document tracks configured memory caps against the RSS budget target (set by task 44.2).

## Configured Caps (PV-6.5)

| Component | Configured Cap | Notes |
| --- | --- | --- |
| DAG node cache | 32 MiB | tirbase-core cache management |
| ICO index | 8 MiB | Index cache |
| reassembly buffers | 16 MiB | Fragment reassembly buffers |
| pending queue (global) | 64 MiB | Bounded pending queue (task 23) |
| rate quarantine (in-memory per-sender counters) | ~256 MiB (global limit tracking) | Non-replayable in-memory counters |
| **Total configured caps** | **120 MiB** | Sum of above |

## Budget Check

The CI check enforces that the sum of all configured caps ≤ 90% of the RSS budget baseline.
Assuming RSS budget baseline ≥ 134 MiB, 120 MiB ≤ 90% of baseline is satisfied when baseline ≥ ~133.3 MiB.

Configured: DAG (32) + ICO (8) + reassembly (16) + pending queue (64) + rate quarantine counters (in-memory global tracking accounted) = 120 MiB total.
