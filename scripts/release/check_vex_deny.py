#!/usr/bin/env python3
"""Generate a release-specific cargo-deny config that also bans crates flagged in VEX.

CLAIM-42.4 / PV-14.4:
- Start from the per-PR deny.toml.
- Read a CycloneDX VEX document and treat any vulnerability marked as affected
  (or not explicitly not_affected/fixed) as a release-blocking signal for the
  component it names.
- Emit a release deny config that adds those component names to [bans].deny so
  cargo-deny fails the release if they are present in the dependency graph.
- Also fail fast if a flagged component is present in Cargo.lock (defense in depth).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BLOCKING_STATES = {"affected", "under_investigation", "in_triage", "exploitable", "unknown"}
NON_BLOCKING_STATES = {"not_affected", "fixed"}


def load_flagged_components(vex_path: Path) -> list[dict]:
    data = json.loads(vex_path.read_text(encoding="utf-8"))
    flagged: list[dict] = []
    for vuln in data.get("vulnerabilities", []) or []:
        vid = vuln.get("id") or vuln.get("bom-ref") or "UNKNOWN"
        affects = vuln.get("affects") or []
        for affect in affects:
            ref = affect.get("ref") or ""
 # CycloneDX component refs often look like "pkg:cargo/name@version" or "name@version"
            name = ref
            m = re.search(r"pkg:[^/]+/([^@/]+)", ref)
            if m:
                name = m.group(1)
            elif "@" in ref:
                name = ref.split("@", 1)[0].split("/")[-1]
 # Prefer explicit component name from nested analysis when present
            for analysis in affect.get("analysis") or []:
                state = (analysis.get("state") or "").lower()
                if state in NON_BLOCKING_STATES:
                    name = ""
                elif state in BLOCKING_STATES and not name:
                    name = ref
 # If any version/state entries indicate affected/unknown, block.
            versions = affect.get("versions") or []
            states = {((v.get("status") or v.get("state") or "").lower()) for v in versions}
            states.discard("")
            if states and states.issubset(NON_BLOCKING_STATES):
                continue
            if not name:
                continue
            flagged.append({"name": name, "id": vid, "ref": ref})
 # Also accept top-level components list when authoring simplified VEX
        for comp in vuln.get("components") or []:
            cname = comp.get("name") or ""
            state = (comp.get("analysis", {}) or {}).get("state", "affected").lower()
            if cname and state not in NON_BLOCKING_STATES:
                flagged.append({"name": cname, "id": vid, "ref": cname})
 # de-dup by name
    uniq = {}
    for f in flagged:
        uniq.setdefault(f["name"], f)
    return sorted(uniq.values(), key=lambda x: x["name"])


def lock_contains(lock_text: str, crate_name: str) -> bool:
 # Cargo.lock package blocks: name = "crate"
    return re.search(rf'^name\s*=\s*"{re.escape(crate_name)}"\s*$', lock_text, re.M) is not None


def append_bans(base_toml: str, flagged: list[dict]) -> str:
    if not flagged:
        return base_toml + "\n# release-deny: no VEX-flagged crates\n"
    lines = [
        base_toml.rstrip(),
        "",
        "# --- Release-time VEX bans (generated, CLAIM-42.4 / PV-14.4) ---",
        "# Crates flagged by VEX statements are denied for this release.",
    ]
    for f in flagged:
        reason = f"VEX-flagged component ({f['id']}) must not ship in this release"
        lines.append(f'deny = [{{ name = "{f["name"]}", reason = "{reason}" }}]')
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-deny", required=True)
    ap.add_argument("--vex", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--lock", default="Cargo.lock")
    args = ap.parse_args()

    base = Path(args.base_deny).read_text(encoding="utf-8")
    flagged = load_flagged_components(Path(args.vex))
    lock_text = Path(args.lock).read_text(encoding="utf-8") if Path(args.lock).exists() else ""

    present = [f for f in flagged if lock_contains(lock_text, f["name"])]
    out = append_bans(base, flagged)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(out, encoding="utf-8")

    if present:
        names = ", ".join(f["name"] for f in present)
        print(f"ERROR: VEX-flagged crate(s) present in Cargo.lock: {names}", file=sys.stderr)
        return 2

    if flagged:
        print("VEX-flagged crates recorded as release bans (not present in Cargo.lock): " + ", ".join(f["name"] for f in flagged))
    else:
        print("No VEX-flagged crates found; release deny config mirrors base policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
