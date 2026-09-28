#!/usr/bin/env bash

set -euo pipefail

base_sha=$1
head_sha=$2
has_slop_change=false
has_non_slop_change=false
gpu_changed=false
cpu_or_slop_changed=false

while IFS= read -r path; do
  case "$path" in
    slop/*) has_slop_change=true ;;
    Cargo.toml | Cargo.lock | .github/*) ;;
    *) has_non_slop_change=true ;;
  esac

  if [[ "$path" == sp1-gpu/* ]]; then
    gpu_changed=true
  fi
  if [[ "$path" == crates/* || "$path" == slop/* ]]; then
    cpu_or_slop_changed=true
  fi
done < <(git diff --name-only "$base_sha" "$head_sha")

slop_only=false
if [[ "$has_slop_change" == true && "$has_non_slop_change" == false ]]; then
  slop_only=true
fi

run_gpu=true
if [[ "$cpu_or_slop_changed" == true && "$gpu_changed" == false ]]; then
  run_gpu=false
fi

echo "slop_only=$slop_only" >> "$GITHUB_OUTPUT"
echo "run_gpu=$run_gpu" >> "$GITHUB_OUTPUT"
