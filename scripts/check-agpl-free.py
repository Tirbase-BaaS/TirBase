#!/usr/bin/env python3
"""AGPL-free dependency graph gate for Apache-licensed crates (F-01).

For every workspace crate licensed Apache-2.0, walks its normal and build
dependency graph (dev-dependencies excluded, because they are not part of a
downstream distribution) and fails if any reachable package is AGPL.

Usage:
    python3 scripts/check-agpl-free.py [--root DIR]
    python3 scripts/check-agpl-free.py --metadata resolved-metadata.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

AGPL_RE = re.compile(r"\bAGPL\b", re.IGNORECASE)


def load_metadata(root: Path, metadata_file: Path | None) -> dict:
    if metadata_file is not None:
        try:
            return json.loads(metadata_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"ERROR: cannot read metadata fixture {metadata_file}: {exc}")

    command = ["cargo", "metadata", "--format-version", "1", "--locked"]
    try:
        result = subprocess.run(
            command, cwd=root, check=True, capture_output=True, text=True
        )
    except FileNotFoundError:
        raise SystemExit("ERROR: cargo is not installed")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"ERROR: `{' '.join(command)}` failed:\n{exc.stderr}")
    return json.loads(result.stdout)


def normal_or_build_edges(node: dict) -> list[str]:
    edges: list[str] = []
    for dep in node.get("deps", []):
        kinds = dep.get("dep_kinds") or [{"kind": None}]
        if all(kind.get("kind") == "dev" for kind in kinds):
            continue
        edges.append(dep["pkg"])
    return edges


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="workspace root (default: .)")
    parser.add_argument(
        "--metadata",
        default=None,
        help="use a pre-generated `cargo metadata` JSON file (used by fixtures)",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    metadata = load_metadata(root, Path(args.metadata) if args.metadata else None)
    packages = {package["id"]: package for package in metadata.get("packages", [])}
    nodes = {node["id"]: node for node in (metadata.get("resolve") or {}).get("nodes", [])}
    workspace_members = set(metadata.get("workspace_members", []))

    apache_roots = [
        package
        for package_id, package in packages.items()
        if package_id in workspace_members
        and "Apache-2.0" in (package.get("license") or "")
    ]
    if not apache_roots:
        print("ERROR: no Apache-licensed workspace crates found to check", file=sys.stderr)
        return 2
    if not nodes:
        print("ERROR: metadata has no resolve graph (run without --no-deps)", file=sys.stderr)
        return 2

    violations: list[str] = []
    unknown: list[str] = []

    for root_package in sorted(apache_roots, key=lambda package: package["name"]):
        root_id = root_package["id"]
        visited: set[str] = set()
        parent: dict[str, str | None] = {root_id: None}
        stack = [root_id]
        while stack:
            package_id = stack.pop()
            if package_id in visited:
                continue
            visited.add(package_id)
            package = packages.get(package_id)
            if package is None:
                unknown.append(f"{root_package['name']}: unresolved package id {package_id}")
                continue

            licence = package.get("license")
            if licence is None and package_id != root_id:
                unknown.append(
                    f"{root_package['name']}: dependency '{package['name']} "
                    f"{package['version']}' has no licence metadata, so it cannot be "
                    f"proven AGPL-free"
                )
            elif licence and AGPL_RE.search(licence):
                chain = [package["name"]]
                cursor = parent.get(package_id)
                while cursor is not None:
                    chain.append(packages[cursor]["name"])
                    cursor = parent.get(cursor)
                chain.reverse()
                violations.append(
                    f"{root_package['name']} -> {chain[0]} ({licence}) via "
                    + " -> ".join(chain[1:])
                )
                continue

            node = nodes.get(package_id)
            if node is None:
                continue
            for dep_id in normal_or_build_edges(node):
                if dep_id not in parent:
                    parent[dep_id] = package_id
                stack.append(dep_id)

    if unknown:
        for message in sorted(set(unknown)):
            print(f"ERROR: {message}", file=sys.stderr)
    if violations:
        for message in sorted(set(violations)):
            print(f"ERROR: AGPL dependency: {message}", file=sys.stderr)

    if unknown or violations:
        print(
            f"\nFAIL: Apache crates must have AGPL-free normal/build dependency "
            f"graphs ({len(set(violations))} violation(s), "
            f"{len(set(unknown))} unprovable package(s)).",
            file=sys.stderr,
        )
        return 1

    checked = ", ".join(sorted(package["name"] for package in apache_roots))
    print(f"OK: Apache crate dependency graphs are AGPL-free ({checked}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
