#!/usr/bin/env python3
"""Enumerate production stateful struct definitions and check the state inventory.

This replaces the old STATE-INVENTORY marker check: instead of trusting
hand-written markers, the gate derives the list from the source itself.  Every
named-field `struct` in production code must have a row in
`docs/state-inventory.md` that names both the struct and its file.

Usage:
    python3 scripts/state_inventory_scan.py --check [INVENTORY_PATH]
    python3 scripts/state_inventory_scan.py --list
    python3 scripts/state_inventory_scan.py --write [INVENTORY_PATH]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SOURCE_ROOTS = (
    "tirbase-core/src",
    "tirbase-guard/src",
    "tirbase-gateway/src",
    "tirbase-drivers/src",
)

BEGIN_MARKER = "<!-- BEGIN GENERATED STRUCT INVENTORY -->"
END_MARKER = "<!-- END GENERATED STRUCT INVENTORY -->"

STRUCT_RE = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)"
)
CFG_TEST_ATTR_RE = re.compile(r"#\s*\[\s*cfg\s*\(([^]]*)\)\s*\]")


@dataclass(frozen=True, order=True)
class StatefulStruct:
    name: str
    path: str


def strip_noise(text: str) -> str:
    """Blank out comments and string/char literals, preserving offsets/newlines.

    Braces inside literals or comments must not affect block matching, but we
    keep every character's position so indices into the stripped text can be
    used to slice the original file.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            if j == -1:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and nxt == "*":
            # Rust block comments nest.
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "'":
            # Character literal (`'a'`) vs lifetime (`'a`).  Only strip the
            # former; lifetimes do not contain braces or quotes.
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
                if j < n and text[j] == "'":
                    j += 1
            elif j + 1 < n and text[j + 1] == "'":
                j += 2
            else:
                i += 1
                continue
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def matching_brace(text: str, open_index: int) -> int:
    """Return the index of the `}` matching the `{` at open_index, or -1."""
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def excluded_ranges(stripped: str) -> list[tuple[int, int]]:
    """Find items/modules gated by `#[cfg(...test...)]`."""
    ranges: list[tuple[int, int]] = []
    for match in CFG_TEST_ATTR_RE.finditer(stripped):
        cond = match.group(1)
        if "test" not in cond:
            continue
        # Attribute may be part of a cfg(any(test, ...)) group; only skip when
        # the condition actually enables the item for tests (not `not(test)`).
        if re.search(r"\bnot\s*\(\s*test\s*\)", cond):
            continue
        j = match.end()
        while j < len(stripped) and stripped[j] in " \t\r\n":
            j += 1
        # Skip further attributes on the same item.
        while stripped.startswith("#", j):
            close = stripped.find("]", j)
            if close == -1:
                break
            j = close + 1
            while j < len(stripped) and stripped[j] in " \t\r\n":
                j += 1
        if re.match(r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\b", stripped[j:]):
            brace = stripped.find("{", j)
            if brace == -1:
                continue
            end = matching_brace(stripped, brace)
            if end != -1:
                ranges.append((match.start(), end + 1))
        elif re.match(r"(?:pub(?:\s*\([^)]*\))?\s+)?struct\b", stripped[j:]):
            semi = stripped.find(";", j)
            brace = stripped.find("{", j)
            if brace != -1 and (semi == -1 or brace < semi):
                end = matching_brace(stripped, brace)
                if end != -1:
                    ranges.append((match.start(), end + 1))
            elif semi != -1:
                ranges.append((match.start(), semi + 1))
    return ranges


def in_ranges(pos: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in ranges)


def scan_file(path: Path, repo_root: Path) -> list[StatefulStruct]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = strip_noise(text)
    ranges = excluded_ranges(stripped)
    rel = path.relative_to(repo_root).as_posix()
    found: list[StatefulStruct] = []
    for match in STRUCT_RE.finditer(stripped):
        if in_ranges(match.start(), ranges):
            continue
        brace = stripped.find("{", match.end())
        if brace == -1:
            continue
        # A `;` before the next `{` means a tuple/unit struct, not a stateful
        # named-field container.
        semi = stripped.find(";", match.end())
        if semi != -1 and semi < brace:
            continue
        end = matching_brace(stripped, brace)
        if end == -1:
            continue
        body = stripped[brace + 1 : end]
        if not body.strip():
            continue
        found.append(StatefulStruct(match.group(1), rel))
    return found


def scan(repo_root: Path) -> list[StatefulStruct]:
    results: set[StatefulStruct] = set()
    for root in SOURCE_ROOTS:
        root_path = repo_root / root
        if not root_path.is_dir():
            continue
        for path in sorted(root_path.rglob("*.rs")):
            parts = path.relative_to(repo_root).parts
            if "tests" in parts:
                continue
            results.update(scan_file(path, repo_root))
    return sorted(results)


def row(struct: StatefulStruct) -> str:
    return f"| `{struct.name}` | `{struct.path}` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |"


def generate_section(structs: list[StatefulStruct]) -> str:
    lines = [
        BEGIN_MARKER,
        "",
        "The rows below are generated from the production source by",
        "`scripts/state_inventory_scan.py`.  Every named-field struct in the",
        "source roots must appear here.  Regenerate with:",
        "",
        "```bash",
        "python3 scripts/state_inventory_scan.py --write",
        "```",
        "",
        "| Structure | Location | Classification |",
        "|---|---|---|",
    ]
    lines.extend(row(s) for s in structs)
    lines.extend(["", END_MARKER])
    return "\n".join(lines)


def read_inventory(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def registered_pairs(inventory: str) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for line in inventory.splitlines():
        names = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", line)
        paths = re.findall(r"`([^`]*\.rs)`", line)
        for name in names:
            for p in paths:
                pairs.add((name, p))
                pairs.add((name, os.path.normpath(p)))
    return pairs


def check(inventory_path: Path, structs: list[StatefulStruct]) -> int:
    inventory = read_inventory(inventory_path)
    pairs = registered_pairs(inventory)
    missing = [
        s
        for s in structs
        if (s.name, s.path) not in pairs and (s.name, os.path.normpath(s.path)) not in pairs
    ]
    if missing:
        print(
            "ERROR: stateful struct(s) found in production source but not registered in "
            f"{inventory_path}:",
            file=sys.stderr,
        )
        for s in missing:
            print(f"  - {s.name} ({s.path})", file=sys.stderr)
        print(
            "Fix: add a row naming both the struct and its file, or regenerate the "
            "generated section with `python3 scripts/state_inventory_scan.py --write`.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {len(structs)} production stateful struct(s) are registered in {inventory_path}."
    )
    return 0


def write(inventory_path: Path, structs: list[StatefulStruct]) -> int:
    inventory = read_inventory(inventory_path)
    section = generate_section(structs)
    if BEGIN_MARKER in inventory and END_MARKER in inventory:
        start = inventory.index(BEGIN_MARKER)
        end = inventory.index(END_MARKER) + len(END_MARKER)
        updated = inventory[:start] + section + inventory[end:]
    else:
        updated = inventory.rstrip() + "\n\n" + section + "\n"
    inventory_path.write_text(updated, encoding="utf-8")
    print(f"Wrote {len(structs)} struct row(s) to {inventory_path}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", nargs="?", const="docs/state-inventory.md", metavar="PATH")
    mode.add_argument("--write", nargs="?", const="docs/state-inventory.md", metavar="PATH")
    mode.add_argument("--list", action="store_true")
    parser.add_argument(
        "inventory",
        nargs="?",
        default="docs/state-inventory.md",
        help="inventory document path (default: docs/state-inventory.md)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    structs = scan(repo_root)
    if not structs:
        print("ERROR: no production stateful structs found; scanner misconfigured.", file=sys.stderr)
        return 1

    if args.list:
        for s in structs:
            print(f"{s.name}\t{s.path}")
        return 0

    inventory_path = Path(args.check or args.write or args.inventory)
    if not inventory_path.is_absolute():
        inventory_path = repo_root / inventory_path
    if not inventory_path.is_file():
        print(f"ERROR: State inventory not found at '{inventory_path}'", file=sys.stderr)
        return 1

    if args.write:
        return write(inventory_path, structs)
    return check(inventory_path, structs)


if __name__ == "__main__":
    raise SystemExit(main())
