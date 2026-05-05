#!/usr/bin/env bash
#
# Compare sp1-gpu criterion microbenchmarks between your current working
# state and another git ref.
#
# How it works:
#
#   - The "current" side runs `cargo bench` in your main checkout — so
#     your uncommitted edits are benched as-is, and your already-warm
#     target/ cache is reused (no fresh CUDA build for the current side).
#
#   - The other ref runs in a persistent worktree under
#     sp1-gpu/.bench-worktrees/<ref>/ which is reused across invocations,
#     so the second-run cost on the ref side is small. Use the `clear`
#     subcommand to delete these worktrees when you want to free disk.
#
#   - A small Python helper reads criterion's per-batch sample data from
#     both target/criterion/ trees, runs Welch's t-test on the difference
#     in mean, and prints a side-by-side table with a 95% CI on the
#     percentage change.
#
# Side effects on your main checkout:
#
#   - target/criterion/<bench>/current-r*/ ends up with your "current"
#     baselines after the run. Harmless and tiny; remove with
#     `rm -rf target/criterion` whenever you want.
#
# ----------------------------------------------------------------------------
# QUICK START — copy/paste these commands.
#
# All commands below assume you are at the repo root (the directory that
# contains this script's parent path, "sp1-gpu/"). If you're unsure, run:
#
#     cd /home/user/sp1            # or wherever you cloned the repo
#     pwd                          # should print the repo root
#
# ----------------------------------------------------------------------------
# 1) ONE-TIME SETUP
#
# Nothing required — python3 is the only dependency.
#
# ----------------------------------------------------------------------------
# 2) FIRST-RUN SANITY CHECK (recommended)
#
# Run a single bench against your current commit (HEAD). Deltas should be
# near zero — that's how you confirm everything is wired up. The current
# side reuses your main target/ (fast); the ref side has to build its
# worktree from scratch (slow, but that worktree is then cached for reuse):
#
#     sp1-gpu/scripts/bench-compare.sh HEAD commit
#
# (The bench named "commit" is the smallest one in the suite.)
#
# ----------------------------------------------------------------------------
# 3) COMMON USAGE
#
# Compare your current changes (committed AND uncommitted) against main,
# running ALL benches:
#
#     sp1-gpu/scripts/bench-compare.sh
#
# Compare against main but run only ONE bench (much faster while iterating):
#
#     sp1-gpu/scripts/bench-compare.sh zerocheck
#
# Compare against a specific branch instead of main:
#
#     sp1-gpu/scripts/bench-compare.sh some-other-branch
#
# Compare against a specific commit (use a SHA, full or short):
#
#     sp1-gpu/scripts/bench-compare.sh 21aa2f468
#
# Compare against a specific branch, running just one bench:
#
#     sp1-gpu/scripts/bench-compare.sh main jagged
#
# Run multiple rounds with alternating side order to get a tighter CI and
# de-bias against run-order effects (each extra round adds one full pass):
#
#     sp1-gpu/scripts/bench-compare.sh --repeat 3
#     sp1-gpu/scripts/bench-compare.sh --repeat 3 main jagged
#
# Pick a trace source for the benches that support multiple ones (commit,
# jagged, prove_trusted_evaluations, zerocheck). Default per bench: random
# at log-area 25 for the any-source ones, real/fibonacci for zerocheck.
# Supported real programs: fibonacci, ed25519, keccak256, sha2.
#
#     sp1-gpu/scripts/bench-compare.sh --source real/keccak256
#     sp1-gpu/scripts/bench-compare.sh --source /tmp/layout.json main jagged
#     sp1-gpu/scripts/bench-compare.sh --source random:24                # 2^24
#     sp1-gpu/scripts/bench-compare.sh --source random:22,24,26          # sweep
#
# FULLY EXPLICIT FORMS (every option supplied; nothing left to defaults).
# The argument order is: [flags...] [ref] [bench_name].
#
#   # Compare current vs `some-branch`, run only `commit`, 3 alternating
#   # rounds, with the keccak256 real trace as the input.
#   sp1-gpu/scripts/bench-compare.sh --repeat 3 --source real/keccak256 \
#       some-branch commit
#
#   # Same flags, against an explicit SHA, against the `jagged` bench.
#   sp1-gpu/scripts/bench-compare.sh --repeat 5 --source random \
#       21aa2f468 jagged
#
#   # Random trace at a specific log-area, all benches.
#   sp1-gpu/scripts/bench-compare.sh --repeat 1 --source random:24 \
#       main
#
#   # Sweep three random sizes on `commit`. One sample baseline per size.
#   sp1-gpu/scripts/bench-compare.sh --repeat 1 --source random:22,24,26 \
#       main commit
#
#   # `zerocheck` vs `main`, 1 round (the default), with the sha2 real trace.
#   sp1-gpu/scripts/bench-compare.sh --repeat 1 --source real/sha2 \
#       main zerocheck
#
#   # JSON-layout source spelled out explicitly.
#   sp1-gpu/scripts/bench-compare.sh --repeat 1 --source /tmp/layout.json \
#       main jagged
#
# ----------------------------------------------------------------------------
# 4) CACHE MANAGEMENT
#
# Each comparison creates one worktree under sp1-gpu/.bench-worktrees/
# (one per ref you've ever compared against) and KEEPS it so re-runs are
# fast. They can take 10s of GB of disk. To free that space:
#
#     sp1-gpu/scripts/bench-compare.sh clear            # remove everything
#     sp1-gpu/scripts/bench-compare.sh clear main       # remove just one
#
# ----------------------------------------------------------------------------
# 5) GETTING HELP
#
#     sp1-gpu/scripts/bench-compare.sh --help
#
# ----------------------------------------------------------------------------

set -euo pipefail

usage() {
    local prog
    prog="$(basename "$0")"
    cat <<EOF
Usage: $prog [--repeat N] [--source ARG] [ref] [bench_name]
       $prog clear [label]

Compare your current working state against another git ref.

Arguments:
  ref           Git ref (branch, commit, tag, ...) to compare against.
                Defaults to: main.
  bench_name    Optional: run only the named bench. Default: run all.

Options:
  --repeat N    Run N rounds, alternating which side is benched first
                (-r N also works). With N>1 the per-round samples are
                pooled before the t-test, which both tightens the CI
                and de-biases against run-order effects. Default: 1.

  --source ARG  Pick a trace source for benches that support multiple
                ones (commit / jagged / prove_trusted_evaluations /
                zerocheck). Forwarded as the first positional arg to
                each bench, so it doubles as Criterion's filter:

                  --source random              # default size, 2^25
                  --source random:24           # single, 2^24
                  --source random:22,24,26     # sweep three sizes
                  --source real/<program>      # e.g. real/keccak256
                  --source /path/to/layout.json

                Supported real programs: fibonacci, ed25519, keccak256,
                sha2. (Add entries to `real_programs()` in
                sp1-gpu-jagged-tracegen test_utils to extend.)

                Without this flag, each bench picks its own default
                (random at 2^25 for the any-source benches,
                real/fibonacci for zerocheck). hadamard ignores the flag
                entirely (its inputs aren't a trace) and always runs its
                single fixed config.

Forms:
  $prog                          # current vs main, all benches
  $prog <bench>                  # current vs main, one bench
  $prog <ref>                    # current vs <ref>, all benches
  $prog <ref> <bench>            # current vs <ref>, one bench
  $prog --repeat 3 <ref>         # 3 alternating rounds, all benches
  $prog --source real/sha2 <ref> # all benches with sha2 real trace

  $prog clear                    # remove all bench worktrees
  $prog clear <label>            # remove one worktree (e.g. "main")

The "current" side runs in your main checkout — it includes whatever is in
your working tree right now, committed or not. The other ref runs in a
persistent worktree that is reused across invocations.

Available benches:
  zerocheck                  (sp1-gpu-zerocheck)         real-only
  prove_trusted_evaluations  (sp1-gpu-shard-prover)      any source
  jagged                     (sp1-gpu-jagged-sumcheck)   any source
  hadamard                   (sp1-gpu-jagged-sumcheck)   single config
  commit                     (sp1-gpu-commit)            any source

Worktree cache: <repo>/sp1-gpu/.bench-worktrees/
Requires:       python3
EOF
}

# (crate, bench_name) pairs. Bench names must be unique across the list so the
# filter can match on bench name alone.
BENCHES=(
    "sp1-gpu-zerocheck:zerocheck"
    "sp1-gpu-shard-prover:prove_trusted_evaluations"
    "sp1-gpu-jagged-sumcheck:jagged"
    "sp1-gpu-jagged-sumcheck:hadamard"
    "sp1-gpu-commit:commit"
)

is_known_bench() {
    local name="$1"
    for entry in "${BENCHES[@]}"; do
        [[ "${entry##*:}" == "$name" ]] && return 0
    done
    return 1
}

if ! command -v git &>/dev/null; then
    echo "error: git not found." >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKTREE_CACHE="$REPO_ROOT/sp1-gpu/.bench-worktrees"
MARKER=".sp1-gpu-bench-marker"
CURRENT_LABEL="current"

# ----------------------------------------------------------------------------
# Phase 1: extract flags from the argv list. After this loop, "$@" contains
# only the positional arguments.
# ----------------------------------------------------------------------------
REPEAT=1
SOURCE_ARG=""
NEW_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage; exit 0 ;;
        --repeat|-r)
            if [[ $# -lt 2 ]]; then
                echo "error: $1 requires a value" >&2; exit 1
            fi
            REPEAT="$2"; shift 2 ;;
        --repeat=*|-r=*)
            REPEAT="${1#*=}"; shift ;;
        --source|-s)
            if [[ $# -lt 2 ]]; then
                echo "error: $1 requires a value" >&2; exit 1
            fi
            SOURCE_ARG="$2"; shift 2 ;;
        --source=*|-s=*)
            SOURCE_ARG="${1#*=}"; shift ;;
        --)
            shift; NEW_ARGS+=("$@"); break ;;
        *)
            NEW_ARGS+=("$1"); shift ;;
    esac
done
set -- "${NEW_ARGS[@]:-}"
[[ ${#NEW_ARGS[@]} -eq 0 ]] && set --

case "$REPEAT" in
    ''|*[!0-9]*|0)
        echo "error: --repeat must be a positive integer (got '$REPEAT')" >&2
        exit 1 ;;
esac

# Sanitize ref names for criterion baseline names and path components
# (alnum/_/./-).
sanitize() { printf '%s' "$1" | tr -c '[:alnum:]_.-' '_'; }

# List paths of worktrees that this script created, by checking for the marker.
list_bench_worktrees() {
    git -C "$REPO_ROOT" worktree list --porcelain 2>/dev/null \
        | awk '/^worktree /{print substr($0, 10)}' \
        | while IFS= read -r path; do
            [[ -f "$path/$MARKER" ]] && printf '%s\n' "$path"
          done
}

remove_worktree() {
    local path="$1"
    [[ -z "$path" ]] && return 0
    echo "Removing worktree: $path"
    if ! git -C "$REPO_ROOT" worktree remove --force "$path" 2>/dev/null; then
        rm -rf "$path"
    fi
}

cmd_clear() {
    local target="${1:-}"

    git -C "$REPO_ROOT" worktree prune

    local removed=0
    if [[ -n "$target" ]]; then
        local sanitized
        sanitized="$(sanitize "$target")"
        local path="$WORKTREE_CACHE/$sanitized"
        if [[ -e "$path" ]] || \
           git -C "$REPO_ROOT" worktree list --porcelain | grep -Fxq "worktree $path"; then
            remove_worktree "$path"
            removed=1
        else
            echo "No worktree found for label '$target' (looked at $path)."
        fi
    else
        while IFS= read -r path; do
            remove_worktree "$path"
            removed=$((removed + 1))
        done < <(list_bench_worktrees)
        [[ "$removed" -eq 0 ]] && echo "No bench worktrees to remove."
    fi

    git -C "$REPO_ROOT" worktree prune
    rmdir "$WORKTREE_CACHE" 2>/dev/null || true
    echo "Done. Removed $removed worktree(s)."
}

# ----------------------------------------------------------------------------
# Phase 2: dispatch on positional args.
# ----------------------------------------------------------------------------
if [[ "${1:-}" == "clear" ]]; then
    case $# in
        1) cmd_clear "" ;;
        2) cmd_clear "$2" ;;
        *) usage; exit 1 ;;
    esac
    exit 0
fi

if [[ $# -gt 2 ]]; then
    usage
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "error: python3 not found." >&2
    exit 1
fi

DEFAULT_REF="main"
REF=""
BENCH_FILTER=""

case $# in
    0)
        REF="$DEFAULT_REF"
        ;;
    1)
        if is_known_bench "$1"; then
            REF="$DEFAULT_REF"; BENCH_FILTER="$1"
        else
            REF="$1"
        fi
        ;;
    2)
        REF="$1"
        if ! is_known_bench "$2"; then
            echo "error: '$2' is not a known bench name" >&2
            echo "available:" >&2
            for e in "${BENCHES[@]}"; do echo "  ${e##*:}" >&2; done
            exit 1
        fi
        BENCH_FILTER="$2"
        ;;
esac

# Validate the comparison ref.
if ! git -C "$REPO_ROOT" rev-parse --verify --quiet "$REF^{commit}" >/dev/null; then
    echo "error: '$REF' is not a valid git ref" >&2
    exit 1
fi

# Filter to a single bench if requested.
if [[ -n "$BENCH_FILTER" ]]; then
    FILTERED=()
    for entry in "${BENCHES[@]}"; do
        if [[ "${entry##*:}" == "$BENCH_FILTER" ]]; then
            FILTERED+=("$entry")
        fi
    done
    BENCHES=("${FILTERED[@]}")
fi

# Reserve "current" as the label for the in-place side — collide gracefully.
REF_LABEL="$(sanitize "$REF")"
if [[ "$REF_LABEL" == "$CURRENT_LABEL" ]]; then
    REF_LABEL="${REF_LABEL}-other"
fi

mkdir -p "$WORKTREE_CACHE"
git -C "$REPO_ROOT" worktree prune

echo "Comparing: $CURRENT_LABEL  vs  $REF  (rounds: $REPEAT)"
[[ -n "$BENCH_FILTER" ]] && echo "Bench filter: $BENCH_FILTER"
[[ -n "$SOURCE_ARG" ]]   && echo "Source:       $SOURCE_ARG"

# ----------------------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------------------

# Build a single `cargo bench` arg list covering all selected benches.
# Batching keeps cargo's feature graph unified across benches, avoiding
# partial recompiles between separate `cargo bench -p X` invocations.
build_cargo_args() {
    local baseline="$1"
    local -n out_args="$2"  # nameref to caller's array

    out_args=( bench )
    local crate
    while IFS= read -r crate; do
        out_args+=( -p "$crate" )
    done < <(printf '%s\n' "${BENCHES[@]}" | cut -d: -f1 | sort -u)
    local entry
    for entry in "${BENCHES[@]}"; do
        out_args+=( --bench "${entry##*:}" )
    done
    # Args after `--` go to each bench harness. SOURCE_ARG is read positionally
    # by the trace-source helpers and also serves as Criterion's filter (they
    # build bench IDs that contain the same string). --save-baseline is a
    # Criterion flag.
    out_args+=( -- )
    [[ -n "$SOURCE_ARG" ]] && out_args+=( "$SOURCE_ARG" )
    out_args+=( --save-baseline "$baseline" )
}

# Remove every baseline directory under $target_dir/criterion that matches
# `<label_prefix>-r*`. Without this, the formatter picks up stale baselines
# from previous runs (e.g. bench IDs that have since been renamed), which
# show up as ghost rows in the comparison output.
wipe_baselines() {
    local target_dir="$1"
    local label_prefix="$2"
    [[ -d "$target_dir" ]] || return 0
    find "$target_dir" -depth -type d -name "${label_prefix}-r*" \
        -exec rm -rf {} + 2>/dev/null || true
}

# Ensure a worktree at $wt_path is checked out to a commit whose tree is
# $target_tree. If the worktree is already at that tree, this is a no-op.
ensure_worktree_at_tree() {
    local target_tree="$1"
    local sha_for_create="$2"
    local wt_path="$3"

    local current_tree=""
    if git -C "$REPO_ROOT" worktree list --porcelain | grep -Fxq "worktree $wt_path"; then
        current_tree="$(git -C "$wt_path" rev-parse HEAD^{tree})"
    fi

    if [[ -n "$current_tree" && "$current_tree" == "$target_tree" ]]; then
        echo "Worktree at $wt_path already at tree $target_tree; reusing as-is."
    elif [[ -n "$current_tree" ]]; then
        echo "Updating worktree at $wt_path to $sha_for_create (tree $current_tree -> $target_tree)"
        git -C "$wt_path" checkout --detach "$sha_for_create"
    else
        if [[ -e "$wt_path" ]]; then
            echo "Removing stale directory at $wt_path"
            rm -rf "$wt_path"
        fi
        echo "Creating worktree at $wt_path for $sha_for_create"
        git -C "$REPO_ROOT" worktree add --detach "$wt_path" "$sha_for_create"
    fi
    touch "$wt_path/$MARKER"
}

# Per-round runner for the "current" side (in main checkout).
run_current_round() {
    local baseline="$1"
    local round="$2"
    local cargo_args=()
    build_cargo_args "$baseline" cargo_args
    echo
    echo "--- round $round/$REPEAT @ $CURRENT_LABEL  (saved as $baseline) ---"
    ( cd "$REPO_ROOT" && cargo "${cargo_args[@]}" )
}

# Per-round runner for the ref side (in cached worktree). Sets
# SP1_SKIP_PROGRAM_BUILD when the SP1 guest programs were already built
# at this tree on a previous run, breaking the test-artifacts recompile
# cascade.
run_ref_round() {
    local baseline="$1"
    local round="$2"
    local cargo_args=()
    build_cargo_args "$baseline" cargo_args
    echo
    if [[ "$REF_SKIP_PROGRAMS" -eq 1 ]]; then
        echo "--- round $round/$REPEAT @ $REF_LABEL  (saved as $baseline)  (SP1_SKIP_PROGRAM_BUILD=true) ---"
        ( cd "$WT_REF" && SP1_SKIP_PROGRAM_BUILD=true cargo "${cargo_args[@]}" )
    else
        echo "--- round $round/$REPEAT @ $REF_LABEL  (saved as $baseline) ---"
        ( cd "$WT_REF" && cargo "${cargo_args[@]}" )
    fi
    # Programs built (or already were); skip on subsequent rounds.
    REF_SKIP_PROGRAMS=1
    printf '%s\n' "$REF_TREE" > "$REF_BUILT_MARKER"
}

# ----------------------------------------------------------------------------
# Set up the ref worktree once.
# ----------------------------------------------------------------------------
REF_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "$REF^{commit}")"
REF_TREE="$(git -C "$REPO_ROOT" rev-parse --verify "$REF^{tree}")"
WT_REF="$WORKTREE_CACHE/$REF_LABEL"

echo
echo "================================================================"
echo " Setting up ref worktree: $WT_REF"
echo "================================================================"
ensure_worktree_at_tree "$REF_TREE" "$REF_SHA" "$WT_REF"

REF_BUILT_MARKER="$WT_REF/.sp1-programs-built-tree"
REF_SKIP_PROGRAMS=0
if [[ -f "$REF_BUILT_MARKER" ]] && [[ "$(cat "$REF_BUILT_MARKER" 2>/dev/null)" == "$REF_TREE" ]]; then
    REF_SKIP_PROGRAMS=1
fi

# ----------------------------------------------------------------------------
# Wipe stale baselines from previous runs so the formatter only sees data
# this invocation just produced. Working-tree edits between runs (renames,
# new/deleted bench IDs, source changes) would otherwise leave dangling
# rows in the comparison.
# ----------------------------------------------------------------------------
wipe_baselines "$REPO_ROOT/target/criterion" "$CURRENT_LABEL"
wipe_baselines "$WT_REF/target/criterion"    "$REF_LABEL"

# ----------------------------------------------------------------------------
# Run N rounds with alternating side order.
# Round k odd -> current then ref;  k even -> ref then current.
# ----------------------------------------------------------------------------
CURRENT_BASELINES=()
REF_BASELINES=()
for ((k=1; k<=REPEAT; k++)); do
    CURRENT_BASELINES+=("${CURRENT_LABEL}-r${k}")
    REF_BASELINES+=("${REF_LABEL}-r${k}")
done

for ((k=1; k<=REPEAT; k++)); do
    cur_baseline="${CURRENT_LABEL}-r${k}"
    ref_baseline="${REF_LABEL}-r${k}"
    if (( k % 2 == 1 )); then
        run_current_round "$cur_baseline" "$k"
        run_ref_round "$ref_baseline" "$k"
    else
        run_ref_round "$ref_baseline" "$k"
        run_current_round "$cur_baseline" "$k"
    fi
done

# ----------------------------------------------------------------------------
# Compare. The Python helper reads target/criterion/<bench>/<baseline>/
# directly from both sides, pools per-batch samples across rounds, and
# runs Welch's t-test on the difference in mean.
# ----------------------------------------------------------------------------
echo
echo "================================================================"
echo " Comparison: $CURRENT_LABEL  vs  $REF"
echo "================================================================"

FORMATTER="$REPO_ROOT/sp1-gpu/scripts/_bench_compare_format.py"
if [[ ! -f "$FORMATTER" ]]; then
    echo "error: formatter not found at $FORMATTER" >&2
    exit 1
fi

# Comma-separated baseline lists for the formatter.
join_csv() { local IFS=,; printf '%s' "$*"; }

python3 "$FORMATTER" \
    --target-a   "$REPO_ROOT/target/criterion" \
    --baselines-a "$(join_csv "${CURRENT_BASELINES[@]}")" \
    --label-a    "$CURRENT_LABEL" \
    --target-b   "$WT_REF/target/criterion" \
    --baselines-b "$(join_csv "${REF_BASELINES[@]}")" \
    --label-b    "$REF"
