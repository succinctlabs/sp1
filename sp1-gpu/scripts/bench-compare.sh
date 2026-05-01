#!/usr/bin/env bash
#
# Compare sp1-gpu criterion microbenchmarks between the current working
# state and another git ref.
#
# The working state (index + working tree + untracked-non-ignored files) is
# snapshotted into a throwaway commit and checked out into a "current"
# worktree. The other ref is checked out into its own worktree. Each
# worktree runs the criterion benches with --save-baseline; baselines are
# exported to JSON; critcmp diffs them at the end.
#
# Worktrees live under sp1-gpu/.bench-worktrees/ and are reused across
# runs (so cargo and the CUDA build cache don't restart from scratch every
# time). Use the `clear` subcommand to remove them.
#
# ----------------------------------------------------------------------------
# QUICK START — copy/paste these commands.
#
# All commands below assume you are at the repo root (the directory that
# contains this script's parent path, "sp1-gpu/"). If you're unsure, run:
#
#     cd /home/user/sp1            # or wherever you cloned the repo
#     pwd                           # should print the repo root
#
# ----------------------------------------------------------------------------
# 1) ONE-TIME SETUP
#
# Install the comparison tool (only needed the first time, ever):
#
#     cargo install critcmp
#
# ----------------------------------------------------------------------------
# 2) FIRST-RUN SANITY CHECK (recommended)
#
# Run a single bench and compare your current state against itself. Deltas
# should be near zero — that's how you confirm everything is wired up.
# This still does a full CUDA build twice (slow), but it's the cheapest
# possible end-to-end test:
#
#     sp1-gpu/scripts/bench-compare.sh HEAD commit
#
# ("HEAD commit" means: ref=HEAD, bench=commit. The bench named "commit"
# is the smallest one — see the list further below.)
#
# ----------------------------------------------------------------------------
# 3) COMMON USAGE
#
# Compare your current changes (committed AND uncommitted) against main,
# running ALL benches. This is the typical command:
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
# ----------------------------------------------------------------------------
# 4) CACHE MANAGEMENT
#
# Each comparison creates two worktrees under sp1-gpu/.bench-worktrees/
# and KEEPS them so re-runs are fast. They can take 10s of GB of disk.
# To free that space:
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
Usage: $prog [ref] [bench_name]
       $prog clear [label]

Compare the current working state against another git ref.

Arguments:
  ref           Git ref (branch, commit, tag, ...) to compare against.
                Defaults to: main.
  bench_name    Optional: run only the named bench. Default: run all.

Forms:
  $prog                          # current vs main, all benches
  $prog <bench>                  # current vs main, one bench
  $prog <ref>                    # current vs <ref>, all benches
  $prog <ref> <bench>            # current vs <ref>, one bench

  $prog clear                    # remove all bench worktrees
  $prog clear <label>            # remove one worktree (e.g. "current", "main")

The "current" snapshot includes staged + unstaged + untracked-but-not-ignored
files (so new bench files, in-flight edits, etc., are picked up). If the
tree is clean, "current" is just HEAD.

Available benches:
  zerocheck                  (sp1-gpu-zerocheck)
  prove_trusted_evaluations  (sp1-gpu-shard-prover)
  jagged                     (sp1-gpu-jagged-sumcheck)
  hadamard                   (sp1-gpu-jagged-sumcheck)
  commit                     (sp1-gpu-commit)

Worktree cache: <repo>/sp1-gpu/.bench-worktrees/
Requires:       critcmp  (install with: cargo install critcmp)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

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

if ! command -v critcmp &>/dev/null; then
    echo "error: critcmp not found. Install with: cargo install critcmp" >&2
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

# Reserve "current" as the label for the snapshot — collide gracefully.
REF_LABEL="$(sanitize "$REF")"
if [[ "$REF_LABEL" == "$CURRENT_LABEL" ]]; then
    REF_LABEL="${REF_LABEL}-other"
fi

# Compute the tree SHA for the current working state (index + working tree +
# untracked-but-not-ignored files). Uses a temp GIT_INDEX_FILE so the user's
# real index is never touched. Tree SHAs are content-addressed, so this is
# stable across runs when nothing has changed.
compute_snapshot_tree() {
    local tmp_index
    tmp_index="$(mktemp -t sp1-gpu-bench-index-XXXXXX)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp_index'" RETURN

    GIT_INDEX_FILE="$tmp_index" git -C "$REPO_ROOT" read-tree HEAD
    GIT_INDEX_FILE="$tmp_index" git -C "$REPO_ROOT" add -A
    GIT_INDEX_FILE="$tmp_index" git -C "$REPO_ROOT" write-tree
}

mkdir -p "$WORKTREE_CACHE"
EXPORT_DIR="$(mktemp -d -t sp1-gpu-bench-exports-XXXXXX)"
trap 'rm -rf "$EXPORT_DIR"' EXIT INT TERM

git -C "$REPO_ROOT" worktree prune

echo "Comparing: $CURRENT_LABEL  vs  $REF"
[[ -n "$BENCH_FILTER" ]] && echo "Bench filter: $BENCH_FILTER"

# Return the tree SHA the given worktree's HEAD points at, or "" if the
# worktree doesn't exist / isn't registered.
worktree_tree_sha() {
    local wt_path="$1"
    if git -C "$REPO_ROOT" worktree list --porcelain | grep -Fxq "worktree $wt_path"; then
        git -C "$wt_path" rev-parse HEAD^{tree}
    else
        printf ''
    fi
}

# Ensure a worktree at $wt_path is checked out to a commit whose tree is
# $target_tree. If the worktree is already at that tree, this is a no-op
# (no checkout, no file mtime churn — cargo's incremental cache stays warm).
# $sha_for_create is used only when we need to create or update — for the
# 'current' side it's a freshly-built snapshot commit, for the ref side
# it's the ref's commit SHA.
ensure_worktree_at_tree() {
    local target_tree="$1"
    local sha_for_create="$2"
    local wt_path="$3"

    local current_tree
    current_tree="$(worktree_tree_sha "$wt_path")"

    if [[ -n "$current_tree" && "$current_tree" == "$target_tree" ]]; then
        echo "Worktree at $wt_path already at tree $target_tree; reusing as-is."
        touch "$wt_path/$MARKER"
        return 0
    fi

    if [[ -n "$current_tree" ]]; then
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

# Prepare the 'current' worktree to point at the working-tree snapshot.
# Computes the snapshot tree first; only mints a new commit object if
# the worktree isn't already at that tree.
prepare_current_worktree() {
    local wt_path="$1"

    echo "Computing working-state tree..."
    local snap_tree
    snap_tree="$(compute_snapshot_tree)"

    local current_tree
    current_tree="$(worktree_tree_sha "$wt_path")"
    if [[ -n "$current_tree" && "$current_tree" == "$snap_tree" ]]; then
        echo "Working state unchanged since last run (tree $snap_tree); reusing 'current' worktree."
        touch "$wt_path/$MARKER"
        return 0
    fi

    # Need a commit to checkout. If the snapshot tree matches HEAD's tree,
    # reuse HEAD; otherwise, mint a snapshot commit.
    local head_tree sha
    head_tree="$(git -C "$REPO_ROOT" rev-parse HEAD^{tree})"
    if [[ "$snap_tree" == "$head_tree" ]]; then
        sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
        echo "Working tree clean; 'current' = HEAD ($sha)."
    else
        sha="$(git -C "$REPO_ROOT" commit-tree "$snap_tree" -p HEAD -m "bench-compare snapshot")"
        echo "Working tree has changes; snapshot commit: $sha"
    fi

    ensure_worktree_at_tree "$snap_tree" "$sha" "$wt_path"
}

# Run all selected benches in a single `cargo bench` invocation per worktree.
# Batching avoids feature-unification churn between separate `cargo bench -p X`
# calls, which would otherwise force partial recompiles between benches.
#
# Also sets SP1_SKIP_PROGRAM_BUILD=true if guest programs were already built
# at this tree on a previous run. test-artifacts/build.rs is self-invalidating
# (it writes ELF outputs into directories it watches via rerun-if-changed),
# so without the skip it triggers a ~5-crate / ~8s recompile cascade on
# every rerun — even when nothing has changed.
run_benches() {
    local label="$1"
    local wt_path="$2"
    local export_path="$3"

    # Collect unique crates and the bench list.
    local -a cargo_args=( bench )
    local crate
    while IFS= read -r crate; do
        cargo_args+=( -p "$crate" )
    done < <(printf '%s\n' "${BENCHES[@]}" | cut -d: -f1 | sort -u)
    local entry
    for entry in "${BENCHES[@]}"; do
        cargo_args+=( --bench "${entry##*:}" )
    done
    cargo_args+=( -- --save-baseline "$label" )

    # Decide whether we can skip the SP1 guest-program rebuild. We can only
    # skip if we've successfully built programs at this exact tree before.
    local tree built_marker
    tree="$(git -C "$wt_path" rev-parse HEAD^{tree})"
    built_marker="$wt_path/.sp1-programs-built-tree"
    local skip_programs=0
    if [[ -f "$built_marker" ]] && [[ "$(cat "$built_marker" 2>/dev/null)" == "$tree" ]]; then
        skip_programs=1
    fi

    echo
    if [[ "$skip_programs" -eq 1 ]]; then
        echo "--- running ${#BENCHES[@]} bench(es) @ $label  (SP1_SKIP_PROGRAM_BUILD=true) ---"
        ( cd "$wt_path" && SP1_SKIP_PROGRAM_BUILD=true cargo "${cargo_args[@]}" )
    else
        echo "--- running ${#BENCHES[@]} bench(es) @ $label ---"
        ( cd "$wt_path" && cargo "${cargo_args[@]}" )
    fi

    # Record success for this tree so subsequent runs can skip program build.
    printf '%s\n' "$tree" > "$built_marker"

    echo
    echo "Exporting baselines from $label..."
    ( cd "$wt_path" && critcmp --export "$label" ) > "$export_path"
}

REF_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "$REF^{commit}")"
REF_TREE="$(git -C "$REPO_ROOT" rev-parse --verify "$REF^{tree}")"

WT_CURRENT="$WORKTREE_CACHE/$CURRENT_LABEL"
WT_REF="$WORKTREE_CACHE/$REF_LABEL"
EXPORT_CURRENT="$EXPORT_DIR/${CURRENT_LABEL}.json"
EXPORT_REF="$EXPORT_DIR/${REF_LABEL}.json"

echo
echo "================================================================"
echo " Worktree: $CURRENT_LABEL  ->  $WT_CURRENT"
echo "================================================================"
prepare_current_worktree "$WT_CURRENT"

echo
echo "================================================================"
echo " Worktree: $REF_LABEL  ->  $WT_REF"
echo "================================================================"
ensure_worktree_at_tree "$REF_TREE" "$REF_SHA" "$WT_REF"

run_benches "$CURRENT_LABEL" "$WT_CURRENT" "$EXPORT_CURRENT"
run_benches "$REF_LABEL" "$WT_REF" "$EXPORT_REF"

echo
echo "================================================================"
echo " Comparison: $CURRENT_LABEL  vs  $REF"
echo "================================================================"
critcmp "$EXPORT_CURRENT" "$EXPORT_REF"
