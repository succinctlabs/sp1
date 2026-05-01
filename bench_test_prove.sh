#!/usr/bin/env bash
# Benchmark `bench_prove_trusted_evaluations` on the current branch vs a
# comparison ref. The test itself does internal warmup + 5 timed iterations
# per invocation, printing one line per iteration; this script invokes the
# test multiple times per branch, parses those lines, and aggregates.
#
# Strategy:
#   * Build the test binary once per branch (uses a separate worktree for the
#     comparison ref so the current working directory is untouched).
#   * Invoke the test INVOCATIONS times per branch, alternating which branch
#     goes first each iteration so any time-correlated drift (thermals, other
#     load) hits both equally.
#   * Each invocation contributes 5 timed samples (the test does its own 2
#     in-process warmup iterations and skips them in its own output).
#   * Print mean / stdev / sem / min / max for each branch and the absolute +
#     relative delta (current - compare).
#
# Env knobs:
#   INVOCATIONS   : test invocations per branch (default 10 -> 50 samples)
#   MAIN_REF      : ref to compare against
#                   (default rdalal/bench-prove-trusted-evaluations, since
#                    main itself does not have the bench test)
#   WORKTREE_DIR  : persistent worktree path for the comparison ref
#                   (default $HOME/.cache/sp1-bench-main-worktree)
#   FRESH_BUILD   : if 1, blow away the worktree's target/ before building
#
# The worktree for $MAIN_REF is persistent across runs so cargo can do
# incremental builds. Set FRESH_BUILD=1 to force a clean rebuild.

set -euo pipefail

INVOCATIONS=${INVOCATIONS:-10}
MAIN_REF=${MAIN_REF:-rdalal/bench-prove-trusted-evaluations}
WORKTREE_DIR=${WORKTREE_DIR:-$HOME/.cache/sp1-bench-main-worktree}
FRESH_BUILD=${FRESH_BUILD:-0}
PKG="sp1-gpu-shard-prover"
TEST_FILTER="prover::tests::bench_prove_trusted_evaluations"

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" == "HEAD" ]]; then
    CURRENT_BRANCH=$(git rev-parse --short HEAD)
fi

echo "=== sp1-gpu-shard-prover::$TEST_FILTER ==="
echo "Branch A (current): $CURRENT_BRANCH"
echo "Branch B (compare): $MAIN_REF"
echo "Worktree:           $WORKTREE_DIR  (persistent)"
echo "Invocations per branch: $INVOCATIONS  (each yields 5 timed samples)"
echo

# Ensure the persistent worktree exists and is at $MAIN_REF.
if git worktree list --porcelain | awk '/^worktree /{print $2}' | grep -Fxq "$WORKTREE_DIR"; then
    echo "Reusing worktree at $WORKTREE_DIR; updating to $MAIN_REF ..."
    git -C "$WORKTREE_DIR" fetch --quiet origin || true
    git -C "$WORKTREE_DIR" checkout --quiet --detach "$MAIN_REF"
else
    if [[ -e "$WORKTREE_DIR" ]]; then
        echo "ERROR: $WORKTREE_DIR exists but is not a registered git worktree." >&2
        echo "Remove it manually or set WORKTREE_DIR to a different path." >&2
        exit 1
    fi
    echo "Creating worktree for $MAIN_REF at $WORKTREE_DIR ..."
    mkdir -p "$(dirname "$WORKTREE_DIR")"
    git fetch --quiet origin || true
    git worktree add --detach "$WORKTREE_DIR" "$MAIN_REF" >/dev/null
fi

if [[ "$FRESH_BUILD" == "1" ]]; then
    echo "FRESH_BUILD=1 -- removing $WORKTREE_DIR/target ..."
    rm -rf "$WORKTREE_DIR/target"
fi

# Build the test binary in $1 and echo its path on stdout.
build_test_bin() {
    local dir="$1"
    (
        cd "$dir"
        cargo test --release --no-run -p "$PKG" --message-format=json 2>/dev/null
    ) | python3 -c '
import json, sys
exe = None
for line in sys.stdin:
    line = line.strip()
    if not line or not line.startswith("{"):
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if msg.get("reason") != "compiler-artifact":
        continue
    if not (msg.get("profile") or {}).get("test"):
        continue
    target = msg.get("target") or {}
    if target.get("name") not in ("sp1-gpu-shard-prover", "sp1_gpu_shard_prover"):
        continue
    if "lib" not in (target.get("kind") or []):
        continue
    if msg.get("executable"):
        exe = msg["executable"]
print(exe or "")
'
}

# Run the test binary once and emit each non-warmup iteration's elapsed time
# (in seconds) on its own line on stdout. Stderr is silenced.
run_one() {
    local bin="$1"
    "$bin" --exact "$TEST_FILTER" --nocapture 2>/dev/null \
        | python3 -c '
import re, sys
# Match lines like:
#   [3] prove_trusted_evaluations: 123.456ms
# but skip warmup lines:
#   [0] prove_trusted_evaluations: 123.456ms (warmup)
pat = re.compile(
    r"^\[\d+\]\s+prove_trusted_evaluations:\s+([0-9]+(?:\.[0-9]+)?)(s|ms|µs|us|ns)\s*$"
)
units = {"s": 1.0, "ms": 1e-3, "µs": 1e-6, "us": 1e-6, "ns": 1e-9}
for line in sys.stdin:
    line = line.rstrip("\n")
    m = pat.match(line)
    if not m:
        continue
    val = float(m.group(1)) * units[m.group(2)]
    print(f"{val:.9f}")
'
}

echo "Building branch A ($CURRENT_BRANCH) ..."
BIN_A=$(build_test_bin "$REPO_ROOT")
if [[ -z "$BIN_A" || ! -x "$BIN_A" ]]; then
    echo "ERROR: could not locate test binary for current branch" >&2
    exit 1
fi
echo "  $BIN_A"

echo "Building branch B ($MAIN_REF) ..."
BIN_B=$(build_test_bin "$WORKTREE_DIR")
if [[ -z "$BIN_B" || ! -x "$BIN_B" ]]; then
    echo "ERROR: could not locate test binary for main worktree" >&2
    exit 1
fi
echo "  $BIN_B"

echo
echo "Sampling ($INVOCATIONS invocations per branch, interleaved) ..."
times_a=()
times_b=()

# Capture an invocation's per-iteration timings into the named bash array.
# Usage: collect <bin> <array_name> <label>
collect() {
    local bin="$1"
    local -n arr="$2"
    local label="$3"
    local count=0
    local sum=0
    while IFS= read -r t; do
        arr+=("$t")
        count=$((count + 1))
        sum=$(awk -v s="$sum" -v t="$t" 'BEGIN { printf("%.9f", s + t) }')
    done < <(run_one "$bin")
    if (( count == 0 )); then
        echo "  $label: ERROR — got 0 samples (test probably failed)" >&2
        echo "  Re-run with: $bin --exact $TEST_FILTER --nocapture" >&2
        exit 1
    fi
    local avg
    avg=$(awk -v s="$sum" -v n="$count" 'BEGIN { printf("%.4f", s / n) }')
    printf "  %s: %d samples, avg %ss\n" "$label" "$count" "$avg"
}

for i in $(seq 1 "$INVOCATIONS"); do
    if (( i % 2 == 1 )); then
        collect "$BIN_A" times_a "iter $i  A"
        collect "$BIN_B" times_b "iter $i  B"
    else
        collect "$BIN_B" times_b "iter $i  B"
        collect "$BIN_A" times_a "iter $i  A"
    fi
done

echo
python3 - "$CURRENT_BRANCH" "$MAIN_REF" "${times_a[@]}" "--" "${times_b[@]}" <<'PY'
import sys, statistics, math

argv = sys.argv[1:]
label_a, label_b = argv[0], argv[1]
rest = argv[2:]
sep = rest.index("--")
a = [float(x) for x in rest[:sep]]
b = [float(x) for x in rest[sep+1:]]

def stats(name, xs):
    mean = statistics.mean(xs)
    stdev = statistics.stdev(xs) if len(xs) > 1 else 0.0
    sem = stdev / math.sqrt(len(xs)) if len(xs) > 1 else 0.0
    print(f"{name}: n={len(xs)} mean={mean:.4f}s stdev={stdev:.4f}s sem={sem:.4f}s "
          f"min={min(xs):.4f}s max={max(xs):.4f}s")
    return mean, stdev, sem

print(f"Branch A ({label_a}):")
ma, sa, ea = stats("  A", a)
print(f"Branch B ({label_b}):")
mb, sb, eb = stats("  B", b)

delta = ma - mb
rel = delta / mb * 100 if mb else 0.0
# Welch's t-style combined SEM for difference of means.
combined_sem = math.sqrt(ea*ea + eb*eb)
print()
print(f"Delta (A - B): {delta:+.4f}s  ({rel:+.2f}%)  ±{combined_sem:.4f}s (1 sem)")
if combined_sem > 0:
    z = abs(delta) / combined_sem
    print(f"|delta| / sem = {z:.2f}  (rule of thumb: >2 is suggestive, >3 is solid)")
PY
