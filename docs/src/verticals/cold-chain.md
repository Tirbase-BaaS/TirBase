# Cold Chain (Flagship)

Pack: `tirbase-demo/cold-chain/`

- **Scenarios:** S1 (out-of-envelope), S2 (slow ramp/drift), S3 (replay)
- **Device class:** `cold_chain` (Modbus-backed simulated controller)
- **Profile:** temperature setpoint and compressor control with rate/drift limits
- **Docs:** [demo README](../../../docs/demo/cold-chain/README.md), register map in pack `docs/`

Run:

```sh
cd tirbase-demo/cold-chain && ./run.sh
```

Non-goals and out-of-scope protections are documented in the demo README.
