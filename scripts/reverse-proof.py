#!/usr/bin/env python3
"""Remove-the-caller negative proofs for security-critical claims.

Reads `docs/security-critical-callers.toml`. For each proof:

1. runs the cited test on the unmodified tree and requires it to PASS;
2. replaces the production wiring snippet with the proof's mutation and
   requires the same test to FAIL;
3. restores the file from git and requires the test to PASS again.

Step 2 is the actual proof: if the test still passes with the caller removed,
the claim is not evidenced by that caller and the proof fails.

Usage:
  python3 scripts/reverse-proof.py --list
  python3 scripts/reverse-proof.py                  # every proof
  python3 scripts/reverse-proof.py --only CLAIM-G1.9
  python3 scripts/reverse-proof.py --skip-baseline  # only mutate + expect fail

Safety: refuses to start when the mutated file has uncommitted changes; restores
the file through `git checkout -- <file>` in a finally block.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    print("ERROR: Python 3.11+ is required for tomllib", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "security-critical-callers.toml"


def load_proofs() -> list[dict]:
    with MANIFEST.open("rb") as fh:
        data = tomllib.load(fh)
    proofs = data.get("proof", [])
    if not proofs:
        raise SystemExit(f"ERROR: no [[proof]] entries in {MANIFEST}")
    for proof in proofs:
        for key in ("claim", "file", "find", "replace", "test"):
            if key not in proof:
                raise SystemExit(f"ERROR: proof {proof.get('claim', '?')} is missing '{key}'")
    return proofs


def run(command: str, *, expect_success: bool, label: str) -> bool:
    print(f"  {label}: $ {command}", flush=True)
    proc = subprocess.run(command, shell=True, cwd=ROOT)
    ok = (proc.returncode == 0) == expect_success
    state = "pass" if proc.returncode == 0 else f"fail (exit {proc.returncode})"
    print(f"  {label}: {state} — {'ok' if ok else 'UNEXPECTED'}", flush=True)
    return ok


def git_clean(path: str) -> bool:
    proc = subprocess.run(
        ["git", "diff", "--quiet", "--", path], cwd=ROOT
    )
    return proc.returncode == 0


def restore(path: str) -> None:
    subprocess.run(["git", "checkout", "--", path], cwd=ROOT, check=False)


def apply_mutation(proof: dict) -> None:
    path = ROOT / proof["file"]
    text = path.read_text()
    occurrences = text.count(proof["find"])
    if occurrences != 1:
        raise SystemExit(
            f"ERROR: {proof['claim']}: find snippet occurs {occurrences} times in "
            f"{proof['file']} (must be exactly 1); update the proof manifest"
        )
    path.write_text(text.replace(proof["find"], proof["replace"], 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list proofs and exit")
    parser.add_argument("--only", metavar="CLAIM", help="run only this claim id")
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="skip the pre/post passing runs (mutation-fails check only)",
    )
    args = parser.parse_args()

    proofs = load_proofs()
    if args.only:
        proofs = [p for p in proofs if p["claim"] == args.only]
        if not proofs:
            print(f"ERROR: no proof for {args.only}", file=sys.stderr)
            return 2
    if args.list:
        for p in proofs:
            print(f"{p['claim']:14} {p['file']:45} {p['test']}")
        return 0

    failures: list[str] = []
    for proof in proofs:
        claim, path = proof["claim"], proof["file"]
        print(f"\n== {claim}: {proof.get('summary', '')}")
        if not git_clean(path):
            failures.append(f"{claim}: {path} has uncommitted changes; refusing to mutate")
            print(f"  SKIP: {path} has uncommitted changes", file=sys.stderr)
            continue
        try:
            if not args.skip_baseline and not run(
                proof["test"], expect_success=True, label="baseline"
            ):
                failures.append(f"{claim}: baseline test does not pass; proof is invalid")
                continue

            try:
                apply_mutation(proof)
            except SystemExit as exc:
                failures.append(str(exc))
                continue

            if not run(proof["test"], expect_success=False, label="caller removed"):
                failures.append(
                    f"{claim}: test still passes with the caller removed — claim is not "
                    "evidenced by this caller"
                )
                continue
        finally:
            restore(path)

        if not args.skip_baseline and not run(
            proof["test"], expect_success=True, label="restored"
        ):
            failures.append(f"{claim}: test does not pass after restore")
        else:
            print(f"  PROVEN: removing this caller breaks {claim}")

    if failures:
        print("\nReverse-proof FAILURES:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nOK: {len(proofs)} remove-the-caller proof(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
