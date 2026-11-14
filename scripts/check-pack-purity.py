#!/usr/bin/env python3
"""Data-only pack purity gate (F-01).

Reference packs are distributed under Apache-2.0 so customers can copy them
into proprietary products. A pack must therefore contain data only. The single
declared exception is the pack-format launcher `run.sh` at the pack root; any
other executable or code-bearing file makes the gate fail.

A pack is a directory that contains `sim/config.toml`.

Usage:
    python3 scripts/check-pack-purity.py [--packs-dir DIR]
"""

from __future__ import annotations

import argparse
import stat
import sys
from pathlib import Path

ALLOWED_SUFFIXES = {
    ".toml",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".txt",
}
ALLOWED_NAMES = {".gitkeep"}
LAUNCHER = Path("run.sh")
CODE_SUFFIXES = {
    ".rs",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".sh",
    ".bash",
    ".wasm",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".o",
    ".a",
    ".class",
    ".jar",
}
ELF_MAGIC = b"\x7fELF"


def is_pack(directory: Path) -> bool:
    return (directory / "sim" / "config.toml").is_file()


def is_executable(path: Path) -> bool:
    return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def first_line(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.readline(200)
    except OSError:
        return b""


def check_pack(pack: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(pack.rglob("*")):
        relative = path.relative_to(pack)
        if path.is_symlink():
            errors.append(f"{relative}: symlinks are not allowed in a pack")
            continue
        if path.is_dir():
            continue

        if relative == LAUNCHER:
            # The declared pack-format launcher is the only executable entry.
            continue

        if relative.suffix.lower() in CODE_SUFFIXES:
            errors.append(f"{relative}: executable/code file in a data-only pack")
            continue
        if is_executable(path):
            errors.append(f"{relative}: file has an executable bit set")
            continue
        if relative.suffix.lower() not in ALLOWED_SUFFIXES and relative.name not in ALLOWED_NAMES:
            errors.append(
                f"{relative}: unsupported file type in a data-only pack "
                f"(allowed: {', '.join(sorted(ALLOWED_SUFFIXES | ALLOWED_NAMES))})"
            )
            continue

        try:
            with path.open("rb") as handle:
                magic = handle.read(4)
        except OSError as exc:
            errors.append(f"{relative}: cannot read file ({exc})")
            continue
        if magic == ELF_MAGIC:
            errors.append(f"{relative}: compiled binary in a data-only pack")
            continue
        if relative.suffix.lower() in {".md", ".json", ".yaml", ".yml", ".csv", ".txt", ".toml"}:
            if first_line(path).startswith(b"#!"):
                errors.append(f"{relative}: shebang detected in a data file")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--packs-dir",
        default="tirbase-demo",
        help="directory whose immediate children are packs (default: tirbase-demo)",
    )
    args = parser.parse_args()

    packs_root = Path(args.packs_dir).resolve()
    if not packs_root.is_dir():
        print(f"ERROR: packs directory not found: {packs_root}", file=sys.stderr)
        return 2

    packs = sorted(path for path in packs_root.iterdir() if path.is_dir() and is_pack(path))
    if not packs:
        print(f"ERROR: no packs (sim/config.toml) found under {packs_root}", file=sys.stderr)
        return 2

    failures: dict[str, list[str]] = {}
    for pack in packs:
        errors = check_pack(pack)
        if errors:
            failures[pack.name] = errors

    if failures:
        for pack_name, errors in failures.items():
            for error in errors:
                print(f"ERROR: pack '{pack_name}/{error}'", file=sys.stderr)
        print(
            f"\nFAIL: {len(failures)} pack(s) contain executable code; packs must be data-only.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(packs)} pack(s) are data-only (only run.sh is executable).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
