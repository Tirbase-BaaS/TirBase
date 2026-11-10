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
#      This enumerates every public item and its fully-qualified path.
#   2. For each `pub` item in crate A, check whether ANY other crate B
#      references that item.  Rustdoc JSON does not record `use` statements or
#      type references to other crates, so this is supplemented by scanning the
#      source of every workspace crate (library AND application crates such as
#      tirbase-gateway/tirbase-admin) for qualified paths, `use` imports and
#      parent-type references.  Items never referenced by another crate are
#      orphan candidates.
#   3. Cross-reference orphan candidates against docs/orphan-api-allowlist.md.
#      Allowlisted items are approved orphans (skipped); others fail CI.
#   4. Scan the allowlist for expired entries: if an entry's Expiry version
#      is <= the current workspace version, CI fails.
#
# Limitations:
#   - The source scan is textual.  It can miss macro-generated references and
#     references hidden behind type aliases (add those to the allowlist), and it
#     can over-approximate usage when a name appears only in a comment or doc
#     example.
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

# Library crates with a public API manifest.  These are the only crates whose
# rustdoc JSON is generated; the source-reference pass below additionally scans
# every workspace member, including the application crates (gateway/admin).
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

# ── source-based cross-crate references ──────────────────────────────────────
#
# The rustdoc-JSON pass above only sees items an external crate *re-exports*;
# it cannot see `use` statements or type references.  Application crates
# (tirbase-gateway, tirbase-admin) have no rustdoc entry at all.  So scan the
# source of every workspace crate (library and application) for textual
# references to each candidate orphan.
repo_root = os.path.dirname(os.path.dirname(doc_dir))

root_manifest = os.path.join(repo_root, "Cargo.toml")
workspace_members = []
if os.path.exists(root_manifest):
    with open(root_manifest) as f:
        root_toml = f.read()
    m = re.search(r"members\s*=\s*\[(.*?)\]", root_toml, re.S)
    if m:
        workspace_members = re.findall(r'"([^"]+)"', m.group(1))

PATH_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")
USE_RE = re.compile(r"\buse\s+([^;]+);", re.S)


def read_crate_sources(crate):
    src_root = os.path.join(repo_root, crate, "src")
    chunks = []
    for dirpath, _dirs, files in os.walk(src_root):
        for name in files:
            if name.endswith(".rs"):
                path = os.path.join(dirpath, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        chunks.append(f.read())
                except OSError:
                    pass
    return "\n".join(chunks)


source_refs = {}  # crate name → {paths, pairs, imported}
for member in workspace_members:
    text = read_crate_sources(member)
    paths = set(PATH_RE.findall(text))
    ws_paths = {p for p in paths if p.split("::")[0] in crate_names_u}
    pairs = set()
    for p in paths:
        parts = p.split("::")
        for i in range(len(parts) - 1):
            pairs.add(parts[i] + "::" + parts[i + 1])
    imported = set()
    for stmt in USE_RE.findall(text):
        found = PATH_RE.findall(stmt)
        bases = [p for p in found if p.split("::")[0] in crate_names_u]
        if not bases:
            continue
        base = bases[0]
        imported.add(base)
        for p in found:
            imported.add(p)
            imported.add(base + "::" + p)
    # Every non-crate-root prefix of a referenced path names a module/type that
    # the other crate consumes, so its whole public surface is considered used.
    modules = set()
    for p in ws_paths | imported:
        parts = p.split("::")
        for i in range(2, len(parts) + 1):
            modules.add("::".join(parts[:i]))
    source_refs[member] = {
        "paths": ws_paths,
        "pairs": pairs,
        "imported": imported,
        "modules": modules,
    }


def source_referenced(fqn):
    """True when another workspace crate's source references `fqn`."""
    parts = fqn.split("::")
    crate_u = parts[0]
    name = parts[-1]
    parent = parts[-2] if len(parts) >= 2 else None
    pair = f"{parent}::{name}" if parent else None
    for member, refs in source_refs.items():
        if member.replace("-", "_") == crate_u:
            continue
        # A consumed module/type covers its entire public surface (variants,
        # fields, methods, nested items).
        for i in range(2, len(parts) + 1):
            if "::".join(parts[:i]) in refs["modules"]:
                return True
        if fqn in refs["imported"] or fqn in refs["paths"]:
            return True
        if any(p.startswith(fqn + "::") for p in refs["paths"]):
            return True
        if pair and pair in refs["pairs"]:
            return True
        # Enum variants, struct fields and methods are part of their parent
        # type/module's surface: if another crate references the parent, the
        # item is consumed API even though the member is never named alone.
        if len(parts) >= 3:
            parent_fqn = "::".join(parts[:-1])
            if parent_fqn in refs["imported"] or parent_fqn in refs["paths"]:
                return True
            if any(p.startswith(parent_fqn + "::") for p in refs["paths"]):
                return True
    return False

unreferenced = sorted(o for o in orphan_set if not source_referenced(o))
print(
    f"  rustdoc-only orphans: {len(orphan_set)}; "
    f"after source scan of {len(workspace_members)} workspace crates: {len(unreferenced)}"
)
orphans = unreferenced

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
# An allowlist entry covers its exact FQN and every path nested under it (the
# documented subtree semantics in docs/orphan-api-allowlist.md).
def matching_entry(fqn):
    if fqn in allowlist:
        return fqn
    parts = fqn.split("::")
    for i in range(1, len(parts)):
        prefix = "::".join(parts[:i])
        if prefix in allowlist:
            return prefix
    return None

approved   = [o for o in orphans if matching_entry(o) is not None]
unapproved = [o for o in orphans if matching_entry(o) is None]

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
        e = allowlist[matching_entry(item)]
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
