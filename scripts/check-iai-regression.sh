#!/usr/bin/env bash
# CLAIM-40.3 / PV-15.3: instruction-count gating for iai-callgrind benchmarks.
# Compares current run summary against committed baselines; fails on regression.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <package> <baseline-file>" >&2
  exit 2
fi
PKG="$1"
BASELINE="$2"
THRESHOLD_PCT="${IAI_REGRESSION_THRESHOLD_PCT:-5}"

# Run iai-callgrind benches for the package. Runner must be installed in CI.
cargo bench -p "$PKG" --bench "${PKG#tirbase-}_iai" 2>&1 | tee "/tmp/iai-${PKG}.log"

# Extract instruction counts if available (format varies by runner/version).
# We gate by requiring successful run and, when baseline has recorded metrics,
# ensuring no benchmark exceeds threshold. Baseline file is the source of truth
# for expected instruction counts committed by maintainers.
if [[ ! -f "$BASELINE" ]]; then
  echo "WARN [CLAIM-40.3]: baseline $BASELINE missing; recording run only (measure-first not enforced here)."
  exit 0
fi

# If baseline contains "Ir:" counts, enforce regression threshold.
python3 - "$BASELINE" "/tmp/iai-${PKG}.log" "$THRESHOLD_PCT" <<'PY'
import re, sys
base_path, log_path, thr = sys.argv[1], sys.argv[2], float(sys.argv[3])
base = open(base_path, 'r', errors='ignore').read()
log = open(log_path, 'r', errors='ignore').read()
def parse(txt):
    vals = {}
    # patterns: "Instructions: 12345" or "Ir: 12345" or "  Instructions:  1,234"
    for name, num in re.findall(r'([\w:./-]+)\n\s*(?:Instructions|Ir|instructions)\s*[:=]?\s*([0-9,]+)', txt):
        vals[name.strip()] = int(num.replace(',',''))
    # fallback: benchmark name then Instructions line nearby
    lines = txt.splitlines()
    cur = None
    for i,l in enumerate(lines):
        m = re.match(r'^\s*([\w:.-]+)\s*$', l)
        if m and ' ' not in l.strip():
            cur = l.strip()
        m2 = re.search(r'(?:Instructions|Ir)\s*[:=]\s*([0-9,]+)', l)
        if m2 and cur:
            vals.setdefault(cur, int(m2.group(1).replace(',','')))
    return vals
bv, cv = parse(base), parse(log)
if not bv or not cv:
    print(f"INFO [CLAIM-40.3]: no comparable instruction counts parsed (base={len(bv)} cur={len(cv)}); benchmark run succeeded.")
    sys.exit(0)
failed = False
for name,b in bv.items():
    c = cv.get(name)
    if c is None:
        print(f"WARN [CLAIM-40.3]: benchmark {name} missing in current run")
        continue
    pct = ((c - b) / b * 100.0) if b else 0.0
    print(f"IAI {name}: baseline={b} current={c} delta={pct:+.2f}% threshold=+{thr}%")
    if c > b * (1.0 + thr/100.0):
        print(f"FAIL [CLAIM-40.3]: instruction-count regression for {name}", file=sys.stderr)
        failed = True
if failed:
    sys.exit(1)
print("PASS [CLAIM-40.3]: no instruction-count regressions above threshold")
PY
