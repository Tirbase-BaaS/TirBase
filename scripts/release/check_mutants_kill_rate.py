#!/usr/bin/env python3
"""Enforce release-time mutation kill rate for security-critical modules.

Task 42.6 / CLAIM-42.6 / PV-2.4:
- Run against cargo-mutants output directory containing outcomes.json.
- Require >= min kill rate across mutants whose source file path starts with any
  configured critical prefix.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mutants-dir", required=True)
    ap.add_argument("--min-kill-rate", type=float, default=0.80)
    ap.add_argument("--critical-prefix", action="append", default=[])
    args = ap.parse_args()

    outcomes_path = Path(args.mutants_dir) / "outcomes.json"
    if not outcomes_path.exists():
        print(f"ERROR: mutants outcomes not found: {outcomes_path}", file=sys.stderr)
        return 2

    data = json.loads(outcomes_path.read_text(encoding="utf-8"))
    outcomes = data.get("outcomes") or []
    prefixes = tuple(args.critical_prefix)

    def is_critical(o: dict) -> bool:
        scenario = o.get("scenario") or {}
        mutant = scenario.get("Mutant") or scenario.get("mutant") or {}
        # cargo-mutants formats vary; try common fields
        path = ""
        for key in ("file", "path", "source_path"):
            if key in mutant and mutant[key]:
                path = str(mutant[key])
                break
        span = mutant.get("span") or {}
        if not path:
            path = str(span.get("file") or span.get("file_name") or "")
        path = path.replace("\\", "/")
        return any(path.startswith(p) or ("/" + p) in path for p in prefixes)

    considered = 0
    killed = 0
    missed = 0
    for o in outcomes:
        if not is_critical(o):
            continue
        summary = (o.get("summary") or o.get("outcome") or "").lower()
        # Count mutants where a test result is meaningful.
        if summary in {"unviable", "skipped"}:
            continue
        considered += 1
        if summary in {"caught", "killed", "timeout"}:
            killed += 1
        elif summary in {"missed", "survived"}:
            missed += 1
        else:
            # Unknown outcome: treat conservatively as not killed.
            missed += 1

    if considered == 0:
        print("ERROR: no security-critical mutants found to evaluate; check prefixes and mutants output", file=sys.stderr)
        return 2

    rate = killed / considered
    print(f"Security-critical mutants: considered={considered} killed={killed} missed={missed} kill_rate={rate:.3f} (min {args.min_kill_rate:.2f})")
    if rate + 1e-12 < args.min_kill_rate:
        print("ERROR: release mutation-testing gate failed (kill rate below threshold)", file=sys.stderr)
        return 1
    print("OK: release mutation-testing gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
