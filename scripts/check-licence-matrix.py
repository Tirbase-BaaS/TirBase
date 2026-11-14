#!/usr/bin/env python3
"""Cargo.toml licence matrix gate (F-01).

Cross-checks every first-party Cargo manifest against the authoritative
component matrix in LICENSING.md:

  * every crate directory has a row in the matrix;
  * every crate's `license` field equals the matrix licence;
  * only the two project licences (AGPL-3.0-only, Apache-2.0) are used;
  * every matrix row that names a Cargo crate still exists.

Usage:
    python3 scripts/check-licence-matrix.py [--root DIR] [--licensing FILE]
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import sys
import tomllib
from pathlib import Path

ALLOWED_LICENCES = {"AGPL-3.0-only", "Apache-2.0"}
PRUNE_DIRS = {
    ".git",
    "target",
    "node_modules",
    "dist",
    "wasm-test",
    ".freebuff",
    ".kiro",
    # Negative fixtures intentionally contain deliberately wrong manifests.
    "licence-fixtures",
}
BACKTICK_RE = re.compile(r"`([^`]+)`")


def parse_matrix(licensing: Path) -> list[tuple[str, str, str]]:
    """Return (component, path, licence) rows from the LICENSING.md table."""
    rows: list[tuple[str, str, str]] = []
    text = licensing.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 3:
            continue
        component, path_cell, licence_cell = cells[0], cells[1], cells[2]
        if component.lower() == "component" or set(component) <= set("-: "):
            continue
        licence = licence_cell.strip("` ")
        if not licence:
            continue
        for token in BACKTICK_RE.findall(path_cell):
            normalised = token.rstrip("/")
            # Scoped npm package names are not crate directories.
            if normalised and not normalised.startswith("@"):
                rows.append((component, normalised, licence))
    return rows


def discover_crates(root: Path) -> dict[str, tuple[str, str]]:
    """Map crate directory (posix, relative) -> (package name, licence)."""
    crates: dict[str, tuple[str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNE_DIRS)
        if "Cargo.toml" not in filenames:
            continue
        manifest = Path(dirpath) / "Cargo.toml"
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = data.get("package")
        if not package:
            # Virtual workspace manifest; members are checked individually.
            continue
        relative = manifest.parent.relative_to(root).as_posix()
        licence = package.get("license")
        crates[relative] = (package.get("name", relative), licence or "")
    return crates


def matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument(
        "--licensing", default=None, help="LICENSING.md path (default: <root>/LICENSING.md)"
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    licensing = Path(args.licensing).resolve() if args.licensing else root / "LICENSING.md"
    if not licensing.is_file():
        print(f"ERROR: licence matrix not found at {licensing}", file=sys.stderr)
        return 2

    rows = parse_matrix(licensing)
    if not rows:
        print(f"ERROR: no component rows parsed from {licensing}", file=sys.stderr)
        return 2

    crates = discover_crates(root)
    errors: list[str] = []

    for relative, (name, licence) in sorted(crates.items()):
        if not licence:
            errors.append(f"{relative}: Cargo.toml for '{name}' has no `license` field")
            continue
        if licence not in ALLOWED_LICENCES:
            errors.append(
                f"{relative}: '{name}' declares unsupported licence '{licence}' "
                f"(allowed: {', '.join(sorted(ALLOWED_LICENCES))})"
            )
        matching = [row for row in rows if matches(relative, row[1])]
        if not matching:
            errors.append(
                f"{relative}: '{name}' is not listed in {licensing.name} component matrix"
            )
            continue
        expected = matching[0][2]
        if licence != expected:
            errors.append(
                f"{relative}: '{name}' Cargo.toml licence '{licence}' does not match "
                f"LICENSING.md '{expected}'"
            )

    # Stale rows: a matrix path that looks like a Cargo crate directory in this
    # tree but was not discovered (for example after a rename).
    for component, pattern, _licence in rows:
        if "*" in pattern:
            continue
        candidate = root / pattern
        if candidate.is_dir() and (candidate / "Cargo.toml").is_file():
            if pattern not in crates:
                errors.append(
                    f"{pattern}: LICENSING.md row '{component}' names a Cargo crate "
                    f"that was not discovered"
                )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"\nFAIL: {len(errors)} licence-matrix violation(s) across "
            f"{len(crates)} Cargo manifest(s).",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(crates)} Cargo manifest(s) match the LICENSING.md component matrix."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
