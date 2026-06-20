#!/usr/bin/env bash
#
# set-version.sh — set the SP1 workspace version.
#
# Updates, in the root Cargo.toml:
#   1. [workspace.package] version  (inherited by every crate that uses
#      `version.workspace = true`, so all member crates pick it up).
#   2. The `version = "..."` field of every workspace dependency that is a
#      local member (i.e. has a `path = ...`). External deps such as p3-* and
#      crates.io packages have no `path` and are left untouched.
#
# Usage:
#   ./set-version.sh <new-version> [path/to/Cargo.toml]
#
# Example:
#   ./set-version.sh 6.3.0

set -euo pipefail

NEW_VERSION="${1:-}"
if [[ -z "$NEW_VERSION" ]]; then
  echo "usage: $0 <new-version> [path/to/Cargo.toml]" >&2
  exit 1
fi

# Loose semver sanity check: MAJOR.MINOR.PATCH with an optional -pre/+build suffix.
if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: '$NEW_VERSION' does not look like a semver version (e.g. 6.3.0)" >&2
  exit 1
fi

# Default to the Cargo.toml next to this script (the workspace root).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${2:-$SCRIPT_DIR/Cargo.toml}"

if [[ ! -f "$MANIFEST" ]]; then
  echo "error: manifest not found: $MANIFEST" >&2
  exit 1
fi

# Read the current workspace version from [workspace.package]. It is the only
# line that starts with `version = "` (member-dep versions are nested inside
# `{ version = ... }`, and `rust-version` starts with a different token).
OLD_VERSION="$(sed -nE 's/^version = "([^"]+)"/\1/p' "$MANIFEST" | head -n1)"
if [[ -z "$OLD_VERSION" ]]; then
  echo "error: could not find [workspace.package] version in $MANIFEST" >&2
  exit 1
fi

if [[ "$OLD_VERSION" == "$NEW_VERSION" ]]; then
  echo "version is already $NEW_VERSION; nothing to do."
  exit 0
fi

# Escape regex metacharacters in the old version (it contains dots) so it is
# matched literally, and escape replacement metacharacters in the new version.
escape_re()  { printf '%s' "$1" | sed -e 's/[.[\*^$()+?{}|\/]/\\&/g'; }
escape_repl() { printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'; }
OLD_RE="$(escape_re "$OLD_VERSION")"
NEW_REPL="$(escape_repl "$NEW_VERSION")"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

sed -E \
  -e "s/^version = \"${OLD_RE}\"/version = \"${NEW_REPL}\"/" \
  -e "/path *=/ s/version = \"${OLD_RE}\"/version = \"${NEW_REPL}\"/" \
  "$MANIFEST" > "$tmp"

# Report how many member-dependency lines changed (excludes the package line).
DEP_COUNT="$(grep -cE "path *=.*version = \"${NEW_REPL}\"|version = \"${NEW_REPL}\".*path *=" "$tmp" || true)"

mv "$tmp" "$MANIFEST"
trap - EXIT

# Update Cargo.lock files. The workspace version is recorded in each lockfile,
# so bumping it changes the lock entries for the local member crates. Sweep the
# tree rooted at the manifest's directory, refresh every Cargo.lock, and record
# which ones actually changed (checksum before vs. after).
ROOT="$(cd "$(dirname "$MANIFEST")" && pwd)"
UPDATED_LOCKS=()
while IFS= read -r lockfile; do
  lockdir="$(dirname "$lockfile")"
  before="$(cksum < "$lockfile")"
  if ( cd "$lockdir" && cargo update --workspace --offline ); then
    if [[ "$(cksum < "$lockfile")" != "$before" ]]; then
      # Tag locks that git won't track (e.g. patch-testing/**/program/Cargo.lock
      # via patch-testing/.gitignore) — those are rewritten on disk but never
      # appear in `git status`, so flag them to avoid a confusing mismatch.
      if git -C "$lockdir" check-ignore -q "$lockfile" 2>/dev/null; then
        UPDATED_LOCKS+=("$lockfile  (gitignored)")
      else
        UPDATED_LOCKS+=("$lockfile")
      fi
    fi
  else
    echo "  warning: 'cargo update' failed in $lockdir" >&2
  fi
done < <(find "$ROOT" -path '*/target' -prune -o -name Cargo.lock -type f -print)

echo "Updated $MANIFEST: $OLD_VERSION -> $NEW_VERSION"
echo "  [workspace.package] version bumped (inherited by version.workspace = true crates)"
echo "  $DEP_COUNT workspace member dependency entries updated"
echo "  ${#UPDATED_LOCKS[@]} Cargo.lock file(s) updated:"
for lock in "${UPDATED_LOCKS[@]}"; do
  echo "    $lock"
done
