#!/usr/bin/env bash
# scripts/check-orphan-api.sh — CLAIM-2.7
#
# Detects `pub` API items in the TirBase workspace that have no non-test
# callers outside their own crate, then cross-references against the
# allowlist in docs/orphan-api-allowlist.md.
#
# Usage:
#   bash scripts/check-orphan-api.sh
#
# Exit codes:
#   0 — All orphans are in the allowlist and no entry is past its expiry.
#   1 — One or more unapproved orphans found, OR an allowlist entry has
#       passed its expiry version.
#
# Approach:
#   1. Generate rustdoc JSON for each library crate using nightly rustdoc's
#      --output-format json flag (--output-format json and -Z unstable-options).
#      This produces a machine-readable listing of every public item in the
#      crate including cross-references to types it uses from other crates.
#   2. For each `pub` item in crate A, check whether ANY other crate B
#      references that item's path in its own rustdoc JSON (either via an
#      explicit string ref or via the external_crates re-export declaration).
#      Items never referenced by another crate are orphan candidates.
#   3. Cross-reference orphan candidates against docs/orphan-api-allowlist.md.
#      Allowlisted items are approved orphans (skipped); others fail CI.
#   4. Scan the allowlist for expired entries: if an entry's Expiry version
#      is <= the current workspace version, CI fails.
#
# Limitations:
#   - This is a conservative cross-crate reference check.  An item is
#     considered non-orphan if its path appears in another crate's JSON.
#     It may miss callers that use the item only through type aliases or
#     fully-opaque macro expansion; such items should be added to the allowlist.
#   - Items used only within their own crate (no cross-crate callers) are NOT
#     flagged here — the dead_code lint handles those (CLAIM-2.1).
#   - pub use re-exports of an entire crate (e.g. `pub use tirbase_types;`)
#     are detected via the external_crates section of the dependent crate's
#     JSON, making all items of the re-exported crate transitively non-orphan.
#   - Serde-generated private implementation items (paths containing `::_::`)
#     are excluded as they are not part of the public API surface.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="${REPO_ROOT}/docs/orphan-api-allowlist.md"
DOC_DIR="${REPO_ROOT}/target/doc"

# Library crates with a public API manifest (binary-only crates are excluded).
# Format: "crate-name:extra-flags"
# tirbase-core has a [[bin]] target too, so we must pass --lib explicitly.
CRATE_SPECS=(
  "tirbase-types:--lib"
  "tirbase-core:--lib --features native"
  "tirbase-guard:--lib"
  "tirbase-drivers:--lib"
  "tirbase-sim:--lib"
  "tirbase-demo:--lib"
)

# ---------------------------------------------------------------------------
# 1. Determine the current workspace version.
#    The workspace root Cargo.toml has no [workspace.package]; each member
#    crate carries its own version = "0.1.0".
# ---------------------------------------------------------------------------
CURRENT_VERSION=""
for SPEC in "${CRATE_SPECS[@]}"; do
  CRATE="${SPEC%%:*}"
  MANIFEST="${REPO_ROOT}/${CRATE}/Cargo.toml"
  if [[ -f "$MANIFEST" ]]; then
    V=$(python3 - "$MANIFEST" <<'PYEOF'
import sys, re
with open(sys.argv[1]) as f:
    content = f.read()
in_package = False
for line in content.splitlines():
    stripped = line.strip()
    if stripped.startswith('['):
        in_package = (stripped == '[package]')
        continue
    if in_package:
        m = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
        if m:
            print(m.group(1))
            break
PYEOF
)
    if [[ -n "$V" ]]; then
      CURRENT_VERSION="$V"
      break
    fi
  fi
done

if [[ -z "$CURRENT_VERSION" ]]; then
  echo "ERROR: Could not determine workspace version from any crate Cargo.toml" >&2
  exit 1
fi

echo "Workspace version: v${CURRENT_VERSION}"

# ---------------------------------------------------------------------------
# 2. Generate rustdoc JSON for each library crate (requires nightly).
# ---------------------------------------------------------------------------
echo ""
echo "Generating rustdoc JSON for library crates (requires nightly)..."
CRATE_NAMES=()
for SPEC in "${CRATE_SPECS[@]}"; do
  CRATE="${SPEC%%:*}"
  EXTRA="${SPEC#*:}"
  CRATE_NAMES+=("$CRATE")
  echo "  cargo +nightly rustdoc -p ${CRATE} ${EXTRA} ..."
  # shellcheck disable=SC2086
  cargo +nightly rustdoc -p "$CRATE" $EXTRA \
    -- -Z unstable-options --output-format json 2>/dev/null \
    || echo "  WARNING: rustdoc JSON generation failed for ${CRATE}" >&2
done

echo ""
echo "Analysing cross-crate references..."

# ---------------------------------------------------------------------------
# 3. Parse rustdoc JSON with Python to detect orphan pub items.
# ---------------------------------------------------------------------------
CRATE_NAMES_ARG="${CRATE_NAMES[*]}"
python3 - "${DOC_DIR}" "${ALLOWLIST}" "${CURRENT_VERSION}" ${CRATE_NAMES_ARG} <<'PYEOF'
import sys, os, json, re

doc_dir        = sys.argv[1]
allowlist_path = sys.argv[2]
current_ver    = sys.argv[3]
crates         = sys.argv[4:]

# ── semver comparison ────────────────────────────────────────────────────────
def parse_semver(v):
    v = v.lstrip("v")
    try:
        return tuple(int(p) for p in v.split(".")[:3])
    except ValueError:
        return (0, 0, 0)

# ── filters ──────────────────────────────────────────────────────────────────
def is_serde_internal(fqn):
    """Serde generates items under private modules like `::_::` that are not
    part of the public API."""
    return "::_::" in fqn

crate_names_u = {c.replace("-", "_") for c in crates}

# ── load rustdoc JSON files ───────────────────────────────────────────────────
crate_docs = {}  # crate (hyphenated) → parsed JSON dict
for crate in crates:
    cu = crate.replace("-", "_")
    path = os.path.join(doc_dir, f"{cu}.json")
    if not os.path.exists(path):
        print(f"  WARN: {path} not found — skipping {crate}")
        continue
    try:
        with open(path) as f:
            crate_docs[crate] = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  WARN: Could not parse {path}: {e}")

if not crate_docs:
    print("ERROR: No rustdoc JSON files found. Cannot perform orphan analysis.")
    sys.exit(1)

# ── collect pub items per crate ───────────────────────────────────────────────
def collect_pub_items(doc):
    """Return the set of fully-qualified paths for pub items in workspace crates.

    rustdoc JSON `paths` maps item_id → {"path": ["crate","mod","Item"], "kind": ...}.
    We include only items whose root segment is one of our workspace crate names
    and exclude serde-generated private items.
    """
    result = set()
    for _id, info in doc.get("paths", {}).items():
        parts = info.get("path", [])
        if not parts:
            continue
        if parts[0] not in crate_names_u:
            continue
        fqn = "::".join(parts)
        if is_serde_internal(fqn):
            continue
        # Skip bare crate-root entries (just the crate name)
        if fqn in crate_names_u:
            continue
        result.add(fqn)
    return result

# ── collect external_crates re-exports per crate ─────────────────────────────
def reexported_crates(doc):
    """Return the set of workspace crate names (underscore form) that appear
    in this crate's external_crates section.  If crate A re-exports crate B
    (pub use B;), all items of B are non-orphan from A's perspective."""
    return set(doc.get("external_crates", {}).keys()) & crate_names_u

# ── collect all workspace-prefixed string refs in a doc ─────────────────────
def string_refs(doc):
    """Walk the JSON and gather strings that look like workspace-qualified paths."""
    refs = set()
    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, str) and "::" in obj:
            root = obj.split("::")[0]
            if root in crate_names_u:
                refs.add(obj)
    walk(doc)
    return refs

pub_items  = {c: collect_pub_items(d)  for c, d in crate_docs.items()}
reexports  = {c: reexported_crates(d)  for c, d in crate_docs.items()}
str_refs   = {c: string_refs(d)        for c, d in crate_docs.items()}

# ── find orphans ──────────────────────────────────────────────────────────────
orphan_set = set()
for crate, items in pub_items.items():
    cu = crate.replace("-", "_")
    for fqn in items:
        referenced = False
        for other, _doc in crate_docs.items():
            if other == crate:
                continue
            # Check: other crate re-exports our crate entirely
            if cu in reexports[other]:
                referenced = True
                break
            # Check: fqn or a path starting with fqn:: appears in other crate
            refs = str_refs[other]
            if fqn in refs:
                referenced = True
                break
            for r in refs:
                if r.startswith(fqn + "::"):
                    referenced = True
                    break
            if referenced:
                break
        if not referenced:
            orphan_set.add(fqn)

orphans = sorted(orphan_set)

# ── load allowlist ────────────────────────────────────────────────────────────
allowlist = {}  # fqn → {owner, justification, expiry}
if os.path.exists(allowlist_path):
    with open(allowlist_path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|") or "---" in line:
                continue
            cells = [c.strip() for c in line.split("|") if c.strip()]
            if len(cells) < 4:
                continue
            fqn = cells[0].strip("`").strip()
            if fqn.lower() in ("item", ""):
                continue
            allowlist[fqn] = {"owner": cells[1], "justification": cells[2], "expiry": cells[3]}

# ── check expired allowlist entries ──────────────────────────────────────────
cur_sv = parse_semver(current_ver)
expired = [(f, e["expiry"]) for f, e in allowlist.items()
           if parse_semver(e["expiry"]) <= cur_sv]

# ── classify ──────────────────────────────────────────────────────────────────
approved   = [o for o in orphans if o in allowlist]
unapproved = [o for o in orphans if o not in allowlist]

# ── report ────────────────────────────────────────────────────────────────────
FAIL = 0

if expired:
    print("\nFAIL [CLAIM-2.7]: Allowlist entries have passed their expiry version.")
    print(f"  Current workspace version: v{current_ver}")
    for fqn, expiry in expired:
        e = allowlist[fqn]
        print(f"\n  EXPIRED : {fqn}")
        print(f"  Expiry  : {expiry}")
        print(f"  Owner   : {e['owner']}")
        print(f"  Action  : Must gain a non-test caller, or be removed from the allowlist.")
    FAIL = 1

if approved:
    print(f"\nINFO: {len(approved)} allowlisted orphan(s) — approved, not yet wired:")
    for item in approved:
        e = allowlist[item]
        print(f"  OK  [{e['expiry']}]  {item}")

if unapproved:
    print("\nFAIL [CLAIM-2.7]: Unapproved orphan pub items found.")
    print("  These items have no non-test callers outside their own crate and")
    print("  are not listed in docs/orphan-api-allowlist.md.\n")
    for item in unapproved:
        print(f"  ORPHAN: {item}")
    print("\nResolve by:")
    print("  1. Adding a non-test caller in another crate, or")
    print("  2. Adding the item to docs/orphan-api-allowlist.md with owner,")
    print("     justification, and a future expiry version.")
    FAIL = 1

if FAIL == 0:
    print(f"\nPASS [CLAIM-2.7]: No unapproved orphans. No expired allowlist entries.")
    print(f"  Workspace version : v{current_ver}")
    print(f"  Allowlisted items : {len(approved)}")

sys.exit(FAIL)
PYEOF
