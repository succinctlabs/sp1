#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(git rev-parse --show-toplevel)
packages=()
while IFS= read -r package_argument; do
  packages+=("$package_argument")
done < <(
  cargo metadata --format-version 1 --no-deps |
    jq -r --arg prefix "$workspace_root/slop/" \
      '.packages[] | select(.manifest_path | startswith($prefix)) | "-p\n\(.name)"'
)

if (( ${#packages[@]} == 0 )); then
  echo "No SLOP packages found" >&2
  exit 1
fi

before_separator=()
after_separator=()
found_separator=false
for argument in "$@"; do
  if [[ "$argument" == "--" && "$found_separator" == false ]]; then
    found_separator=true
  elif [[ "$found_separator" == false ]]; then
    before_separator+=("$argument")
  else
    after_separator+=("$argument")
  fi
done

if [[ "$found_separator" == true ]]; then
  exec cargo "${before_separator[@]}" "${packages[@]}" -- "${after_separator[@]}"
fi

exec cargo "${before_separator[@]}" "${packages[@]}"
