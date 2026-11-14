#!/usr/bin/env python3
"""SPDX header gate (F-01).

Every first-party Rust and TypeScript/JavaScript source file must carry an
SPDX licence identifier in its first six lines, and that identifier must match
the licence declared by the nearest ancestor Cargo.toml / package.json.

Usage:
    python3 scripts/check-spdx-headers.py [ROOT]

Removing an SPDX header from a covered source file makes this gate exit 1.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

SUFFIXES = {".rs", ".ts", ".js", ".mjs"}
PRUNE_DIRS = {
    ".git",
    "target",
    "node_modules",
    "dist",
    "wasm-test",
    ".freebuff",
    ".kiro",
    # Negative fixtures deliberately contain headerless / mismatched sources.
    "licence-fixtures",
}
# Generated build outputs are not first-party sources. These are matched as
# root-relative paths so a real source directory named `wasm` is still scanned.
PRUNE_PATHS = {"tirbase-sdk/wasm"}
DEFAULT_LICENCE = "AGPL-3.0-only"
ALLOWED_LICENCES = {"AGPL-3.0-only", "Apache-2.0"}
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
HEADER_WINDOW = 6


def normalise_licence(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    # A manifest may use an SPDX expression; this gate's component matrix is
    # intentionally one licence per crate.
    return value or None


def discover_declared_licences(root: Path) -> dict[Path, str]:
    """Map directory -> licence declared by a Cargo.toml or package.json."""
    declared: dict[Path, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        directory = Path(dirpath)
        if "Cargo.toml" in filenames:
            manifest = directory / "Cargo.toml"
            try:
                data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError) as exc:
                raise SystemExit(f"ERROR: cannot parse {manifest}: {exc}")
            package = data.get("package", {})
            licence = normalise_licence(package.get("license"))
            if licence:
                declared[directory] = licence
        if "package.json" in filenames:
            manifest = directory / "package.json"
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemExit(f"ERROR: cannot parse {manifest}: {exc}")
            licence = normalise_licence(data.get("license"))
            if licence:
                declared[directory] = licence
    return declared


def expected_licence(path: Path, root: Path, declared: dict[Path, str]) -> str:
    directory = path.parent
    while True:
        if directory in declared:
            return declared[directory]
        if directory == root or directory.parent == directory:
            break
        directory = directory.parent
    return DEFAULT_LICENCE


def first_header(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for _ in range(HEADER_WINDOW):
                line = handle.readline()
                if not line:
                    break
                match = SPDX_RE.search(line)
                if match:
                    return match.group(1)
    except OSError as exc:
        raise SystemExit(f"ERROR: cannot read {path}: {exc}")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="tree to scan (default: .)")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    declared = discover_declared_licences(root)
    missing: list[Path] = []
    wrong: list[tuple[Path, str, str]] = []
    checked = 0

    for dirpath, dirnames, filenames in os.walk(root):
        directory = Path(dirpath)
        relative_dir = directory.relative_to(root).as_posix()
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in PRUNE_DIRS
            and f"{relative_dir}/{d}".lstrip("./") not in PRUNE_PATHS
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix not in SUFFIXES:
                continue
            checked += 1
            actual = first_header(path)
            relative = path.relative_to(root)
            if actual is None:
                missing.append(relative)
                continue
            expected = expected_licence(path, root, declared)
            if actual != expected:
                wrong.append((relative, actual, expected))

    for relative in missing:
        print(
            f"ERROR: {relative}: missing '// SPDX-License-Identifier: <licence>' "
            f"in the first {HEADER_WINDOW} lines",
            file=sys.stderr,
        )
    for relative, actual, expected in wrong:
        print(
            f"ERROR: {relative}: SPDX identifier '{actual}' does not match the "
            f"declared licence '{expected}'",
            file=sys.stderr,
        )

    if missing or wrong:
        print(
            f"\nFAIL: {len(missing)} file(s) missing an SPDX header, "
            f"{len(wrong)} with the wrong identifier (of {checked} checked).",
            file=sys.stderr,
        )
        return 1

    print(f"OK: all {checked} covered source files carry a matching SPDX header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
