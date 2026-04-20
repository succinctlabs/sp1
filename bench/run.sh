#!/usr/bin/env bash
# SP1 CPU prover benchmark harness.
# Usage: bench/run.sh <fib|keccak|big> [--profile] [--iterations N] [--threads N]
#
# Runs sp1-perf in CPU mode N times (default 3), picks the median prove_ms,
# and appends a result line to bench/leaderboard.ndjson.
#
# Requirements:
#   - Fixtures fetched via bench/fixtures/fetch.sh
#   - samply installed (only for --profile)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Defaults ---
ITERATIONS=3
PROFILE=false
THREADS=""
NOTES=""

# --- Parse args ---
WORKLOAD=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)    PROFILE=true; shift ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --threads)    THREADS="$2"; shift 2 ;;
        --notes)      NOTES="$2"; shift 2 ;;
        -*)           echo "Unknown flag: $1" >&2; exit 1 ;;
        *)
            if [[ -z "$WORKLOAD" ]]; then
                WORKLOAD="$1"; shift
            else
                echo "Unexpected argument: $1" >&2; exit 1
            fi
            ;;
    esac
done

if [[ -z "$WORKLOAD" ]]; then
    echo "Usage: bench/run.sh <fib|keccak|big> [--profile] [--iterations N] [--threads N] [--notes TEXT]" >&2
    exit 1
fi

FIXTURE_DIR="$SCRIPT_DIR/fixtures/$WORKLOAD"
if [[ ! -f "$FIXTURE_DIR/program.bin" || ! -f "$FIXTURE_DIR/stdin.bin" ]]; then
    echo "Fixtures not found for '$WORKLOAD'. Run bench/fixtures/fetch.sh first." >&2
    exit 1
fi

# --- Environment ---
# Check for AVX-512 support
if lscpu 2>/dev/null | grep -q avx512; then
    export RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C target-feature=+avx512ifma,+avx512vl"
else
    export RUSTFLAGS="-C opt-level=3 -C target-cpu=native"
fi

# Pin thread count: default to physical cores (not logical/SMT).
# The prover also defaults to physical cores via slop_futures::rayon::init_global_pool(),
# but we set it explicitly here for reproducibility across runs.
if [[ -z "$THREADS" ]]; then
    if [[ -f /sys/devices/system/cpu/cpu0/topology/thread_siblings_list ]]; then
        # Linux: count unique core IDs
        THREADS=$(cat /sys/devices/system/cpu/cpu*/topology/core_id | sort -u | wc -l)
    elif command -v sysctl &>/dev/null; then
        # macOS
        THREADS=$(sysctl -n hw.physicalcpu 2>/dev/null || echo 4)
    else
        THREADS=$(nproc 2>/dev/null || echo 4)
    fi
fi
export RAYON_NUM_THREADS="$THREADS"

# Suppress noisy tracing output — we parse --json stdout
export RUST_LOG="${RUST_LOG:-warn}"

SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
HOST="$(hostname)"

echo "=== SP1 Bench: $WORKLOAD ==="
echo "  sha=$SHA branch=$BRANCH threads=$THREADS iterations=$ITERATIONS"
echo "  RUSTFLAGS=$RUSTFLAGS"
echo ""

# --- Build once ---
echo "Building sp1-perf (release) ..."
cargo build --release -p sp1-perf --bin sp1-perf --manifest-path "$REPO_ROOT/Cargo.toml" 2>&1
SP1_PERF="$REPO_ROOT/target/release/sp1-perf"
echo ""

# --- Warm-up run (discarded) ---
echo "Warm-up run ..."
"$SP1_PERF" --program "$FIXTURE_DIR/program.bin" --stdin "$FIXTURE_DIR/stdin.bin" --mode cpu --json 2>/dev/null >/dev/null || true
echo ""

# --- Measured runs ---
declare -a PROVE_TIMES=()

for i in $(seq 1 "$ITERATIONS"); do
    echo "Run $i/$ITERATIONS ..."
    JSON_LINE=$("$SP1_PERF" --program "$FIXTURE_DIR/program.bin" --stdin "$FIXTURE_DIR/stdin.bin" --mode cpu --json 2>/dev/null)

    prove_ms=$(echo "$JSON_LINE" | python3 -c "import sys,json; print(json.load(sys.stdin)['prove_duration'])")
    PROVE_TIMES+=("$prove_ms")
    echo "  prove_ms=$prove_ms"
done

# --- Compute median ---
MEDIAN=$(printf '%s\n' "${PROVE_TIMES[@]}" | sort -n | awk 'NR==1{lo=$1} NR==int((NR+1)/2){med=$1} END{print med}')

# Compute stddev
STDDEV=$(printf '%s\n' "${PROVE_TIMES[@]}" | awk '{sum+=$1; sumsq+=$1*$1; n++} END{mean=sum/n; printf "%.2f", sqrt(sumsq/n - mean*mean)}')

echo ""
echo "Results: median=${MEDIAN}ms stddev=${STDDEV}ms (n=$ITERATIONS)"

# --- Append to leaderboard ---
LEADERBOARD="$SCRIPT_DIR/leaderboard.ndjson"
ENTRY=$(python3 -c "
import json, sys
print(json.dumps({
    'sha': '$SHA',
    'branch': '$BRANCH',
    'workload': '$WORKLOAD',
    'threads': int('$THREADS'),
    'prove_ms_median': float('$MEDIAN'),
    'prove_ms_stddev': float('$STDDEV'),
    'host': '$HOST',
    'notes': '$NOTES',
    'iterations': int('$ITERATIONS'),
    'all_prove_ms': [$(IFS=,; echo "${PROVE_TIMES[*]}")]
}))
")
echo "$ENTRY" >> "$LEADERBOARD"
echo "Logged to $LEADERBOARD"

# --- Profile (optional) ---
if [[ "$PROFILE" == "true" ]]; then
    echo ""
    echo "Profiling run with samply ..."
    PROFILE_OUT="$SCRIPT_DIR/profile-${WORKLOAD}-${SHA}.json"
    samply record -o "$PROFILE_OUT" -- "$SP1_PERF" \
        --program "$FIXTURE_DIR/program.bin" \
        --stdin "$FIXTURE_DIR/stdin.bin" \
        --mode cpu 2>/dev/null
    echo "Profile written to $PROFILE_OUT"
fi
