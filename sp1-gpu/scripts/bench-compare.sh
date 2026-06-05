#!/usr/bin/env bash
#
# Compare sp1-gpu Criterion microbenchmarks between your current working
# tree and another git ref.
#
# Full usage docs, examples, prerequisites, GPU clock-locking notes, and
# cache-management commands live in this folder's README:
#
#     sp1-gpu/scripts/README.md
#
# Quick reference:
#     sp1-gpu/scripts/bench-compare.sh --help
#
# Quick examples:
#     sp1-gpu/scripts/bench-compare.sh                            # current vs main, all benches
#     sp1-gpu/scripts/bench-compare.sh main jagged                # one bench
#     sp1-gpu/scripts/bench-compare.sh --repeat 3 some-branch     # 3 rounds vs a branch
#     sp1-gpu/scripts/bench-compare.sh --source real/keccak256    # pick a trace input
#     sp1-gpu/scripts/bench-compare.sh clear                      # free worktree cache

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
                zerocheck / gkr / hadamard). Forwarded as the first
                positional arg to each bench, so it doubles as
                Criterion's filter:

                  --source random                       # default size, 2^25
                  --source random:24                    # single, 2^24
                  --source random:22,24,26              # sweep three sizes
                  --source random:24,cluster=all-chips  # override cluster
                  --source real/<program>               # e.g. real/keccak256
                  --source /path/to/layout.json

                Supported real programs: fibonacci, fibonacci_blake3,
                ed25519, keccak256, sha2, ssz_withdrawals, tendermint,
                groth16, groth16_blake3, plonk, plonk_blake3. (Add
                entries to real_programs() in sp1-gpu-jagged-tracegen
                test_utils to extend.)

                Without this flag, every source-aware bench defaults to
                random at 2^25 with cluster=core (≈ base RISC-V).
                cluster=all-chips populates every chip on the machine —
                worst-case stress test, not comparable to any real shard.
                hadamard accepts random:N for size sweeps but rejects
                json / real (its inputs aren't a chip trace);
                cluster= is parsed but has no effect for hadamard. When
                --source is json/real and hadamard is in the selection,
                the script drops it with a one-line note so the rest of
                the comparison still runs; an explicit
                "$prog hadamard --source real/X" errors out instead.

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
  zerocheck                  (sp1-gpu-zerocheck)         any source
  prove_trusted_evaluations  (sp1-gpu-shard-prover)      any source
  jagged                     (sp1-gpu-jagged-sumcheck)   any source
  hadamard                   (sp1-gpu-jagged-sumcheck)   random only
  commit                     (sp1-gpu-commit)            any source
  gkr                        (sp1-gpu-logup-gkr)         any source

Worktree cache: <repo>/sp1-gpu/.bench-worktrees/
Requires:       python3, jq

For full docs (examples, GPU clock locking, cache management) see:
    sp1-gpu/scripts/README.md
EOF
}

# (crate, bench_name) pairs. Bench names must be unique across the list so the
# filter can match on bench name alone.
BENCHES=(
    "sp1-gpu-zerocheck:zerocheck"
    "sp1-gpu-shard-prover:prove_trusted_evaluations"
    "sp1-gpu-shard-prover:verify_trusted_evaluations"
    "sp1-gpu-jagged-sumcheck:jagged"
    "sp1-gpu-jagged-sumcheck:hadamard"
    "sp1-gpu-commit:commit"
    "sp1-gpu-logup-gkr:gkr"
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
set -- "${NEW_ARGS[@]+"${NEW_ARGS[@]}"}"

if ! [[ "$REPEAT" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: --repeat must be a positive integer (got '$REPEAT')" >&2
    exit 1
fi

# Sanitize ref names for criterion baseline names and path components
# (alnum/_/./-).
sanitize() { printf '%s' "$1" | tr -c '[:alnum:]_.-' '_'; }

# Worktree label for a given ref. "current" is reserved for the in-place side,
# so a ref that sanitizes to "current" gets bumped to "current-other".
ref_label() {
    local label
    label="$(sanitize "$1")"
    [[ "$label" == "$CURRENT_LABEL" ]] && label="${label}-other"
    printf '%s' "$label"
}

# All paths git has registered as worktrees of this repo (one per line).
all_worktree_paths() {
    git -C "$REPO_ROOT" worktree list --porcelain 2>/dev/null \
        | awk '/^worktree /{print substr($0, 10)}'
}

# Test whether $1 is exactly the path of a registered worktree.
is_registered_worktree() {
    local target="$1" p
    while IFS= read -r p; do
        [[ "$p" == "$target" ]] && return 0
    done < <(all_worktree_paths)
    return 1
}

# Paths of worktrees this script created, identified by the marker file.
list_bench_worktrees() {
    local p
    while IFS= read -r p; do
        [[ -f "$p/$MARKER" ]] && printf '%s\n' "$p"
    done < <(all_worktree_paths)
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
        local label
        label="$(ref_label "$target")"
        local path="$WORKTREE_CACHE/$label"
        if [[ -e "$path" ]] || is_registered_worktree "$path"; then
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

if ! command -v jq &>/dev/null; then
    echo "error: jq not found (needed to parse 'cargo bench --no-run' output)." >&2
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

# hadamard only accepts the `random` source kind. With a json/real source,
# drop it from a multi-bench run rather than letting it abort the whole
# comparison. If the user explicitly asked for hadamard with an
# incompatible source, error out instead of silently skipping everything.
if [[ -n "$SOURCE_ARG" ]] && [[ "$SOURCE_ARG" == real/* || "$SOURCE_ARG" == *.json ]]; then
    KEPT=()
    SKIPPED_HADAMARD=0
    for entry in "${BENCHES[@]}"; do
        if [[ "${entry##*:}" == "hadamard" ]]; then
            SKIPPED_HADAMARD=1
        else
            KEPT+=("$entry")
        fi
    done
    if (( SKIPPED_HADAMARD == 1 )); then
        if (( ${#KEPT[@]} == 0 )); then
            echo "error: hadamard doesn't accept '--source $SOURCE_ARG' (only random)" >&2
            exit 1
        fi
        echo "Note: skipping hadamard (incompatible with --source $SOURCE_ARG)"
        BENCHES=("${KEPT[@]}")
    fi
fi

REF_LABEL="$(ref_label "$REF")"

mkdir -p "$WORKTREE_CACHE"
git -C "$REPO_ROOT" worktree prune

echo "Comparing: $CURRENT_LABEL  vs  $REF  (rounds: $REPEAT)"
[[ -n "$BENCH_FILTER" ]] && echo "Bench filter: $BENCH_FILTER"
[[ -n "$SOURCE_ARG" ]]   && echo "Source:       $SOURCE_ARG"

# ----------------------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------------------

# Compile every selected bench in one `cargo bench --no-run` call and return
# a (bench_name -> executable_path) map via a nameref. The single batched
# compile keeps cargo's feature graph unified, and — together with running
# the captured binaries directly per round — means the freshness check and
# any build-script reruns (sp1-gpu-sys's CMake build, env-var-sensitive
# rebuilds, etc.) happen exactly once per side instead of once per round.
compile_benches() {
    local cwd="$1"
    local label="$2"
    local -n bins_out="$3"

    local -a cargo_args=( bench --no-run --message-format=json )
    local crate
    while IFS= read -r crate; do
        cargo_args+=( -p "$crate" )
    done < <(printf '%s\n' "${BENCHES[@]}" | cut -d: -f1 | sort -u)
    local entry
    for entry in "${BENCHES[@]}"; do
        cargo_args+=( --bench "${entry##*:}" )
    done

    echo
    echo "================================================================"
    echo " Compiling benches @ $label"
    echo "================================================================"

    local tmp
    tmp="$(mktemp)"
    if ! ( cd "$cwd" && cargo "${cargo_args[@]}" >"$tmp" ); then
        rm -f "$tmp"
        echo "error: 'cargo bench --no-run' failed for $label" >&2
        exit 1
    fi

    local name exe
    while IFS=$'\t' read -r name exe; do
        [[ -n "$name" && -n "$exe" ]] || continue
        bins_out["$name"]="$exe"
    done < <(jq -r '
        select(.reason == "compiler-artifact"
               and (.target.kind | index("bench"))
               and .executable != null)
        | "\(.target.name)\t\(.executable)"
    ' "$tmp")
    rm -f "$tmp"

    for entry in "${BENCHES[@]}"; do
        name="${entry##*:}"
        if [[ -z "${bins_out[$name]:-}" ]]; then
            echo "error: no compiled binary found for bench '$name' on $label" >&2
            exit 1
        fi
        echo "  $name -> ${bins_out[$name]}"
    done
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
    if is_registered_worktree "$wt_path"; then
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

# Per-round runner. Invokes each pre-compiled bench binary directly, so no
# cargo freshness check / relink happens between rounds.
run_round() {
    local cwd="$1"
    local label="$2"
    local baseline="$3"
    local round="$4"
    local -n bins="$5"

    echo
    echo "--- round $round/$REPEAT @ $label  (saved as $baseline) ---"

    local entry name bin
    local -a bench_args
    for entry in "${BENCHES[@]}"; do
        name="${entry##*:}"
        bin="${bins[$name]}"
        # `--bench` is what cargo passes to a Criterion binary to put it in
        # measurement mode. Without it Criterion 0.5+ defaults to test mode
        # (one quick run, no samples written), which is the right default for
        # `cargo test --benches` but means a direct invocation produces no
        # sample.json — and the formatter then has nothing to compare.
        bench_args=( --bench )
        [[ -n "$SOURCE_ARG" ]] && bench_args+=( "$SOURCE_ARG" )
        bench_args+=( --save-baseline "$baseline" )
        ( cd "$cwd" && "$bin" "${bench_args[@]}" )
    done
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

# ----------------------------------------------------------------------------
# Wipe stale baselines from previous runs so the formatter only sees data
# this invocation just produced. Working-tree edits between runs (renames,
# new/deleted bench IDs, source changes) would otherwise leave dangling
# rows in the comparison.
# ----------------------------------------------------------------------------
wipe_baselines "$REPO_ROOT/target/criterion" "$CURRENT_LABEL"
wipe_baselines "$WT_REF/target/criterion"    "$REF_LABEL"

# ----------------------------------------------------------------------------
# Compile each side once, capture per-bench binary paths, then invoke the
# binaries directly per round. This bypasses cargo's per-invocation freshness
# check (and any sp1-gpu-sys build.rs / CMake re-runs) for rounds 2+.
# ----------------------------------------------------------------------------
declare -A CURRENT_BINS=()
declare -A REF_BINS=()
compile_benches "$REPO_ROOT" "$CURRENT_LABEL" CURRENT_BINS
compile_benches "$WT_REF"    "$REF_LABEL"     REF_BINS

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
        run_round "$REPO_ROOT" "$CURRENT_LABEL" "$cur_baseline" "$k" CURRENT_BINS
        run_round "$WT_REF"    "$REF_LABEL"     "$ref_baseline" "$k" REF_BINS
    else
        run_round "$WT_REF"    "$REF_LABEL"     "$ref_baseline" "$k" REF_BINS
        run_round "$REPO_ROOT" "$CURRENT_LABEL" "$cur_baseline" "$k" CURRENT_BINS
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
