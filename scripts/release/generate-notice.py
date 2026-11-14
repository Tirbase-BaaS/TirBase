#!/usr/bin/env python3
"""Generate the release NOTICE file from the locked Cargo graph (F-01).

The NOTICE lists every first-party and third-party component that ships in a
release, its version, and the licence it declares. It is produced from
`cargo metadata --locked`, so the attribution cannot drift from `Cargo.lock`.

Usage:
    python3 scripts/release/generate-notice.py --output release-artifacts/NOTICE \
        --version v0.1.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def load_metadata(path: Path | None) -> dict:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cargo metadata failed:\n{result.stderr.strip()}")
    return json.loads(result.stdout)


def component_line(package: dict) -> str:
    licence = package.get("license") or package.get("license_file")
    return f"- {package['name']} {package['version']} — {licence}"


def render(metadata: dict, project: str, version: str) -> str:
    workspace_ids = set(metadata.get("workspace_members", []))
    packages = metadata.get("packages", [])

    missing = sorted(
        f"{p['name']} {p['version']}"
        for p in packages
        if not (p.get("license") or p.get("license_file"))
    )
    if missing:
        raise ValueError(
            "packages without licence metadata cannot be attributed: "
            + ", ".join(missing)
        )

    first_party = sorted(
        (p for p in packages if p["id"] in workspace_ids),
        key=lambda p: (p["name"].lower(), p["version"]),
    )
    third_party = sorted(
        (p for p in packages if p["id"] not in workspace_ids),
        key=lambda p: (p["name"].lower(), p["version"]),
    )

    lines = [
        f"{project}",
        f"Release: {version}",
        "",
        "This product includes software developed by the TriBase project and",
        "third-party components. The first-party runtime is licensed under",
        "AGPL-3.0-only; the integration surface (tirbase-types,",
        "tirbase-driver-api, tirbase-demo, and the SDKs) is licensed under",
        "Apache-2.0. See LICENSING.md and LICENSE for the authoritative terms.",
        "",
        "Licence exceptions are recorded in licence-exceptions.toml and",
        "documented in docs/licensing-exceptions.md.",
        "",
        "First-party components",
        "----------------------",
    ]
    lines.extend(component_line(p) for p in first_party)
    lines.extend(["", "Third-party components", "----------------------"])
    lines.extend(component_line(p) for p in third_party)
    lines.extend(
        [
            "",
            "This NOTICE is generated from Cargo.lock by",
            "scripts/release/generate-notice.py. Do not edit it by hand.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="path of the NOTICE file to write")
    parser.add_argument("--project", default="TriBase")
    parser.add_argument("--version", default="unreleased")
    parser.add_argument(
        "--metadata",
        default=None,
        help="read cargo metadata JSON from this file instead of running cargo",
    )
    args = parser.parse_args()

    try:
        metadata = load_metadata(Path(args.metadata) if args.metadata else None)
        text = render(metadata, args.project, args.version)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    components = text.count("\n- ")
    print(f"OK: wrote {output} with {components} attributed component(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
