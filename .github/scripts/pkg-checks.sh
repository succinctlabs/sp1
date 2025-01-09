#!/bin/bash

# Move into the workspace root
pushd "$(git rev-parse --show-toplevel)" || exit 1

# Loop over all the packages in the workspace
cargo metadata --format-version=1 --no-deps | \
jq -c '.packages[] | {publish: .publish, manifest_path: .manifest_path}' | \
while IFS= read -r pkg_json; do
    echo "pkg_json: $pkg_json"

    # Extract fields
    publish=$(echo "$pkg_json" | jq -r '.publish // empty')
    manifest_path=$(echo "$pkg_json" | jq -r '.manifest_path')
    
    # Skip if the package is marked as not published
    # Note: `publish` is null if true. So we corece to empty if null.
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

    # Check if the output mentions `Cargo.lock`
    # If it does, then we skip this package but still print the whole output just in case.
    # This can happen in cbindgen builds, and does not cause an issue for the release.
    if [ $? -ne 0 ]; then
        echo "Error: Packaging failed"
        echo "$package_output"

        if ! echo "$package_output" | grep -q "Cargo.lock"; then
            echo "$package_output"
            exit 1
        fi

        echo "SP1: Only Cargo.lock was modified, this is fine."
    fi

    popd || exit 1
done

popd || exit 1