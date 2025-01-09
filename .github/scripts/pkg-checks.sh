#!/bin/bash

set -x

# Move into the workspace root
pushd "$(git rev-parse --show-toplevel)" || exit 1

# Initialize error flag
error_occurred=0

# Loop over all the packages in the workspace
while IFS= read -r pkg_json; do
    echo "pkg_json: $pkg_json"

    # Extract fields
    publish=$(echo "$pkg_json" | jq -r '.publish // empty')
    manifest_path=$(echo "$pkg_json" | jq -r '.manifest_path')
    
    # Skip if the package is marked as not published
    if [ -n "$publish" ]; then
        echo "Skipping unpublished package at $manifest_path"
        continue
    fi

    echo "Checking $manifest_path"

    # Get the package directory
    pkg_dir=$(dirname "$manifest_path")
    pushd "$pkg_dir" || exit 1

    # Capture the stdin/stdout of `cargo package`
    package_output=$(cargo package 2>&1)

    # Check if cargo package failed
    if [ $? -ne 0 ]; then
        echo "Error: Packaging failed"
        echo "$package_output"

        if echo "$package_output" | grep -iq "cargo.lock"; then
            echo "SP1: Only Cargo.lock was modified, this is fine."
        else
            echo "Error not related to Cargo.lock, marking as failed."
            exit 1
        fi
    fi

    popd
done < <(cargo metadata --format-version=1 --no-deps | jq -c '.packages[] | {publish: .publish, manifest_path: .manifest_path}')

popd