#!/usr/bin/env python3
"""CLAIM-40.2 / PV-12.7: enforce >=80% mutation kill rate per critical module group.

Runs cargo-mutants per group (guard, ledger, replay, validation) and parses
mutants.out/outcomes.json. Kill rate = caught / (caught + missed + timeout) * 100.
Unviable mutations are excluded. CI fails if any group is below threshold or has
no testable mutants.
"""
from __future__ import annotations
import argparse, json, os, shutil, subprocess, sys
from pathlib import Path

THRESHOLD = 80.0

# Module groups mapped to cargo-mutants file scopes. Each group must reach >=80%.
# Paths are relative to workspace root.
GROUPS = {
    "guard": [
        "tirbase-guard/src/guard.rs",
        "tirbase-guard/src/admit.rs",
        "tirbase-guard/src/commit.rs",
        "tirbase-guard/src/envelope.rs",
        "tirbase-guard/src/policy.rs",
        "tirbase-guard/src/permit.rs",
        "tirbase-guard/src/driver_proxy.rs",
        "tirbase-guard/src/command.rs",
        "tirbase-guard/src/time.rs",
        "tirbase-guard/src/node_mode.rs",
        "tirbase-guard/src/lockdown.rs",
        "tirbase-guard/src/single_writer_lease.rs",
    ],
    "ledger": [
        "tirbase-gateway/src/db/applied_effects_ledger.rs",
        "tirbase-gateway/src/db/ledger_reconciliation.rs",
        "tirbase-gateway/src/db/ledger_recovery.rs",
        "tirbase-core/src/durability/cloud_ledger.rs",
        "tirbase-core/src/crdt/rate_quarantine.rs",
        "tirbase-core/src/crdt/schema_quarantine.rs",
    ],
    "replay": [
        "tirbase-guard/src/anti_replay.rs",
        "tirbase-gateway/src/db/anti_replay_windows.rs",
        "tirbase-core/src/crdt/pending_queue.rs",
    ],
    "validation": [
        "tirbase-core/src/crdt/hardening.rs",
        "tirbase-core/src/crdt/verify.rs",
        "tirbase-core/src/crdt/merge.rs",
        "tirbase-guard/src/envelope.rs",
        "tirbase-guard/src/command.rs",
    ],
}


def parse_outcomes(outcomes_path: Path) -> tuple[int,int,int,int]:
    data = json.loads(outcomes_path.read_text())
 # cargo-mutants outcomes.json schema has evolved; handle common forms.
    outcomes = data.get("outcomes") or data.get("mutants") or []
    caught = missed = timeout = unviable = 0
    for m in outcomes:
        summary = (m.get("summary") or m.get("outcome") or "").lower()
 # normalize
        if summary in ("caught","killed"): caught += 1
        elif summary in ("missed","survived"): missed += 1
        elif summary in ("timeout","time_out"): timeout += 1
        elif summary in ("unviable","build_failed","unviable_mutant"): unviable += 1
        else:
 # some versions nest differently
            res = str(m).lower()
            if "caught" in res or "killed" in res: caught += 1
            elif "missed" in res or "survived" in res: missed += 1
            elif "timeout" in res: timeout += 1
            elif "unviable" in res: unviable += 1
    return caught, missed, timeout, unviable


def run_group(name: str, files: list[str], extra_args: list[str], timeout: int) -> float:
 # remove stale outcomes
    outdir = Path("mutants.out")
    if outdir.exists():
        shutil.rmtree(outdir)
    existing = [f for f in files if Path(f).exists()]
    if not existing:
        print(f"FAIL [{name}]: no module files found from {files}", file=sys.stderr)
        return -1.0
    cmd = ["cargo", "mutants", "--timeout", str(timeout), "--jobs", "2", "--no-shuffle"]
    for f in existing:
        cmd += ["--file", f]
    cmd += extra_args
    print(f"\n=== cargo-mutants group={name} files={len(existing)} ===")
    print("+", " ".join(cmd), flush=True)
    env = os.environ.copy()
    proc = subprocess.run(cmd, env=env)
    outcomes_path = outdir / "outcomes.json"
    if not outcomes_path.exists():
        print(f"FAIL [{name}]: outcomes.json not produced (cargo-mutants exit {proc.returncode})", file=sys.stderr)
        return -1.0
    caught, missed, timeout_m, unviable = parse_outcomes(outcomes_path)
    testable = caught + missed + timeout_m
    if testable == 0:
        print(f"FAIL [{name}]: no testable mutants (caught={caught} missed={missed} timeout={timeout_m} unviable={unviable})", file=sys.stderr)
        return -1.0
    kill_rate = (caught / testable) * 100.0
    print(f"RESULT [{name}]: caught={caught} missed={missed} timeout={timeout_m} unviable={unviable} kill_rate={kill_rate:.2f}% threshold={THRESHOLD}%")
    if kill_rate < THRESHOLD:
        print(f"FAIL [{name}]: kill rate {kill_rate:.2f}% < {THRESHOLD}%", file=sys.stderr)
    return kill_rate


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--groups", default="guard,ledger,replay,validation")
    ap.add_argument("--extra", nargs="*", default=[])
    ap.add_argument("--dry-run", action="store_true", help="print groups only")
    args = ap.parse_args()
    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    if args.dry_run:
        for g in groups:
            print(g, GROUPS.get(g, []))
        return 0
    failed = False
    for g in groups:
        if g not in GROUPS:
            print(f"unknown group {g}", file=sys.stderr); return 2
        rate = run_group(g, GROUPS[g], args.extra, args.timeout)
        if rate < THRESHOLD:
            failed = True
    if failed:
        print("\nFAIL [CLAIM-40.2]: one or more critical module groups below 80% kill rate", file=sys.stderr)
        return 1
    print("\nPASS [CLAIM-40.2]: all critical module groups >= 80% mutation kill rate")
    return 0

if __name__ == "__main__":
    sys.exit(main())
