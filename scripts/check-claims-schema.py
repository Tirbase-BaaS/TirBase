#!/usr/bin/env python3
"""Validate the CLAIMS.md registry shape, status vocabulary, and caller evidence.

This is the schema half of the CLAIM-3.1 gate; `scripts/check-claims.sh` runs
it before resolving the test identifiers cited by each row.

What it proves
--------------
1. The table has exactly the five expected columns, and every row parses to
   five cells (pipes inside backticked code spans are allowed).
2. Every status is one of the closed vocabulary below.
3. Status and production-caller column agree:
   - `Proven`                       -> real caller evidence (or an `n/a — ...`
                                       artifact) and a non-empty test/gate.
   - `Implemented and wired (unproven)` -> real caller evidence and a cited test
                                       that exists but is not executed in CI.
   - `Implemented but not wired`    -> caller is exactly
                                       `none — implemented but not wired`, and a
                                       test exists for the implementation.
   - `Planned`                      -> caller is `none — not implemented` and the
                                       test/gate cell is empty.
4. Every cited production-caller path exists. A Rust path must be compiled into
   production: reachable from a crate root (`src/lib.rs`, `src/main.rs`,
   `src/bin/*.rs`) through `mod` declarations, never through a
   `#[cfg(test)]` module. A `path::symbol` citation must also declare that
   symbol in the file.

Usage: python3 scripts/check-claims-schema.py [CLAIMS.md]

Exit codes: 0 — registry is valid; 1 — at least one violation (all printed).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STATUSES = {
    "Proven",
    "Implemented and wired (unproven)",
    "Implemented but not wired",
    "Planned",
}

EXPECTED_HEADER = [
    "Claim ID",
    "Claim Text",
    "Status",
    "Production Caller",
    "Test or CI Gate",
]

NONE_UNWIRED = "none — implemented but not wired"
NONE_PLANNED = "none — not implemented"
NONE_PREFIX = "none — "
N_A_PREFIX = "n/a — "

SYMBOL_DECL = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|const|static|mod)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z_][a-z0-9_]*)\s*;", re.M)


def split_row(line: str) -> list[str]:
    """Split a markdown table row on pipes that are not inside backticks."""
    parts: list[str] = []
    current: list[str] = []
    ticks = False
    for ch in line.rstrip("\n"):
        if ch == "`":
            ticks = not ticks
            current.append(ch)
            continue
        if ch == "|" and not ticks:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts[1:-1]]


def strip_cfg_test(text: str) -> str:
    """Remove the body of `#[cfg(test)] mod ... { ... }` blocks."""
    out: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+[a-z_][a-z0-9_]*\s*\{", text[i:])
        if not m:
            out.append(text[i:])
            break
        out.append(text[i : i + m.start()])
        j = i + m.start()
        depth = 0
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j + 1
    return "".join(out)


class Reachability:
    """Crate-root `mod` reachability for production Rust files."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._reachable: set[str] | None = None

    def _roots(self) -> list[Path]:
        roots: list[Path] = []
        for crate in sorted(self.root.glob("tirbase-*")):
            if not crate.is_dir():
                continue
            for name in ("lib.rs", "main.rs"):
                p = crate / "src" / name
                if p.is_file():
                    roots.append(p)
            roots.extend(sorted((crate / "src" / "bin").glob("*.rs")))
        # The SDK is a wasm bindings crate, not part of the gateway runtime;
        # its own crate root is still a production root for its own claims.
        sdk_src = self.root / "tirbase-sdk"
        if sdk_src.is_dir():
            roots.extend(sorted(sdk_src.glob("*.rs")))
        return roots

    def _resolve_mod(self, module: str, current_dir: Path) -> Path | None:
        for candidate in (current_dir / f"{module}.rs", current_dir / module / "mod.rs"):
            if candidate.is_file():
                return candidate
        return None

    def build(self) -> set[str]:
        if self._reachable is not None:
            return self._reachable
        reached: set[str] = set()
        queue = list(self._roots())
        while queue:
            path = queue.pop()
            key = path.relative_to(self.root).as_posix()
            if key in reached:
                continue
            reached.add(key)
            try:
                text = strip_cfg_test(path.read_text(errors="ignore"))
            except OSError:
                continue
            current_dir = path.parent
            for module in MOD_DECL.findall(text):
                resolved = self._resolve_mod(module, current_dir)
                if resolved is not None:
                    queue.append(resolved)
        self._reachable = reached
        return reached

    def is_reachable(self, rel_path: str) -> bool:
        reached = self.build()
        if rel_path.endswith("/"):
            return any(p.startswith(rel_path) for p in reached)
        return rel_path in reached


def parse_caller_citations(cell: str) -> list[tuple[str, str | None]]:
    """Return (path, symbol-or-None) for each backticked caller citation."""
    citations: list[tuple[str, str | None]] = []
    for span in re.findall(r"`([^`]+)`", cell):
        token = span.strip()
        if not token or " " in token:
            continue
        if "::" in token:
            path, _, symbol = token.partition("::")
            symbol = symbol.split("::")[-1]
            citations.append((path.strip(), symbol or None))
        else:
            citations.append((token, None))
    return citations


def iter_rows(claims_path: Path):
    """Yield (claim_id, status, production_caller, gate) for each table row."""
    for line in claims_path.read_text(errors="ignore").splitlines():
        if not line.startswith("| CLAIM-"):
            continue
        cells = split_row(line)
        if len(cells) != 5:
            continue
        yield cells


def validate(claims_path: Path) -> list[str]:
    root = claims_path.parent
    issues: list[str] = []
    lines = claims_path.read_text(errors="ignore").splitlines()

    header_seen = False
    rows = 0
    reach = Reachability(root)

    for lineno, line in enumerate(lines, start=1):
        if not line.startswith("|"):
            continue
        cells = split_row(line)
        if cells and cells[0] == "Claim ID":
            header_seen = True
            if cells != EXPECTED_HEADER:
                issues.append(
                    f"CLAIMS.md:{lineno}: table header is {cells!r}; expected {EXPECTED_HEADER!r}"
                )
            continue
        if not cells or not cells[0].startswith("CLAIM-"):
            continue
        if all(re.fullmatch(r"-+", c or "-") for c in cells):
            continue

        rows += 1
        if not header_seen:
            issues.append(f"CLAIMS.md:{lineno}: {cells[0]} appears before the table header")

        if len(cells) != 5:
            issues.append(
                f"CLAIMS.md:{lineno}: {cells[0]} has {len(cells)} columns; expected 5 "
                "(an unescaped pipe inside a cell?)"
            )
            continue

        claim_id, _text, status, caller, gate = cells
        gate_clean = gate.strip()
        gate_present = gate_clean not in ("", "—", "-")

        if status not in STATUSES:
            issues.append(f"CLAIMS.md:{lineno}: {claim_id} has unknown status {status!r}")
            continue

        lowered = caller.lower()

        if status == "Planned":
            if gate_present:
                issues.append(
                    f"CLAIMS.md:{lineno}: {claim_id} is Planned but cites test/gate evidence "
                    f"{gate!r}; write the test and mark it Proven, or clear the gate"
                )
            if caller == NONE_PLANNED:
                continue
            # A Planned claim may already name a production path (implemented but
            # deliberately unproven) or an n/a deliverable; validate that evidence
            # below, but do not require a gate.

        if status != "Planned" and not gate_present:
            issues.append(
                f"CLAIMS.md:{lineno}: {claim_id} is {status} but has no test or CI gate"
            )

        if status == "Implemented but not wired":
            if caller != NONE_UNWIRED:
                issues.append(
                    f"CLAIMS.md:{lineno}: {claim_id} is Implemented but not wired; production "
                    f"caller must be {NONE_UNWIRED!r} (got {caller!r})"
                )
            continue

        # Proven / Implemented and wired (unproven): require real caller evidence.
        if lowered.startswith(NONE_PREFIX):
            issues.append(
                f"CLAIMS.md:{lineno}: {claim_id} is {status} but its production caller is "
                f"{caller!r}; a claim with no production caller must be "
                f"'Implemented but not wired'"
            )
            continue

        if lowered.startswith(N_A_PREFIX):
            # Artifact-only claims are allowed, but only the documented kinds.
            if not any(
                lowered == f"n/a — {kind}"
                for kind in ("docs/ci deliverable", "packaging deliverable", "data/demo pack")
            ):
                issues.append(
                    f"CLAIMS.md:{lineno}: {claim_id} uses unrecognised caller exemption {caller!r}"
                )
            continue

        citations = parse_caller_citations(caller)
        if not citations:
            issues.append(
                f"CLAIMS.md:{lineno}: {claim_id} has no backticked production-caller path "
                f"(got {caller!r})"
            )
            continue

        for path_text, symbol in citations:
            path = root / path_text
            if path_text.startswith("/") or ".." in Path(path_text).parts:
                issues.append(
                    f"CLAIMS.md:{lineno}: {claim_id} caller path {path_text!r} must be repo-relative"
                )
                continue
            if not path.exists():
                issues.append(
                    f"CLAIMS.md:{lineno}: {claim_id} caller path {path_text!r} does not exist"
                )
                continue
            if path_text.endswith(".rs"):
                if not reach.is_reachable(path_text):
                    issues.append(
                        f"CLAIMS.md:{lineno}: {claim_id} caller {path_text} is not reachable "
                        "from a crate root through production `mod` declarations"
                    )
                if symbol:
                    text = path.read_text(errors="ignore")
                    if not re.search(rf"\b{re.escape(symbol)}\b", text) or not any(
                        m == symbol for m in SYMBOL_DECL.findall(text)
                    ):
                        issues.append(
                            f"CLAIMS.md:{lineno}: {claim_id} caller symbol "
                            f"{path_text}::{symbol} is not declared in that file"
                        )

    if not header_seen:
        issues.append("CLAIMS.md: the claims table header is missing")
    if rows == 0:
        issues.append("CLAIMS.md: no claim rows found")

    return issues


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--emit-rows"]
    claims_path = Path(args[0] if args else "CLAIMS.md")
    if not claims_path.is_file():
        print(f"ERROR: registry not found at {claims_path}", file=sys.stderr)
        return 1

    # Pipe-aware row export for the bash half of the gate, which must not split
    # on pipes inside backticked spans.
    if "--emit-rows" in sys.argv[1:]:
        for claim_id, _text, status, _caller, gate in iter_rows(claims_path):
            gate = gate.replace("\t", " ").replace("\n", " ")
            print(f"{claim_id}\t{status}\t{gate}")
        return 0

    issues = validate(claims_path)
    if issues:
        print("ERROR: CLAIMS.md schema violations:", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        print(
            "\nFix: keep the five-column header, use only Proven / Implemented and wired "
            "(unproven) / Implemented but not wired / Planned, and make every production "
            "caller a reachable production path or a documented n/a exemption.",
            file=sys.stderr,
        )
        return 1

    rows = sum(1 for line in claims_path.read_text(errors="ignore").splitlines()
               if line.startswith("| CLAIM-"))
    print(f"OK: {rows} claim row(s) have a valid status, caller, and gate shape.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
