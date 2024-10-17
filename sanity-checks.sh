#!/bin/bash

# Debug mode is now disabled by default
DEBUG=false

# Debug function
debug() {
    if [ "$DEBUG" = true ]; then
        echo "[DEBUG] $1" >&2
    fi
}

# Function to check if a version is already published
check_version() {
    local crate_name=$1
    local version=$2
    if [ -z "$crate_name" ] || [ -z "$version" ]; then
        echo "Error: Crate name or version is empty" >&2
        return 1
    fi
    local url="https://crates.io/api/v1/crates/${crate_name}/${version}"
    debug "Checking URL: $url"
    local response=$(curl -s "$url")
    if echo "$response" | jq -e '.version.num' > /dev/null 2>&1; then
        return 1  # Version exists
    fi
    return 0  # Version doesn't exist
}

# Function to process a Cargo.toml file
process_cargo_toml() {
    local cargo_toml=$1
    debug "Processing Cargo.toml: $cargo_toml"
    
    # Extract crate name from Cargo.toml
    CRATE_NAME=$(awk -F '=' '/^name *=/ {gsub(/[" ]/, "", $2); print $2; exit}' "$cargo_toml")
    if [ -z "$CRATE_NAME" ]; then
        echo "Error: Could not extract crate name from $cargo_toml" >&2
        return 1
    fi

    # Extract version from Cargo.toml
    VERSION=$(awk -F '=' '/^version *=/ {gsub(/[" {}]/, "", $2); print $2; exit}' "$cargo_toml")
    if [ -z "$VERSION" ]; then
        echo "Error: Could not extract version from $cargo_toml" >&2
        return 1
    fi
    
    # Handle workspace version
    if [[ "$VERSION" == "workspace" || "$VERSION" == *"workspace=true"* ]]; then
        WORKSPACE_VERSION=$(awk -F '=' '/^version *=/ {gsub(/[" ]/, "", $2); print $2; exit}' Cargo.toml)
        if [ -z "$WORKSPACE_VERSION" ]; then
            echo "Error: Could not extract workspace version from Cargo.toml" >&2
            return 1
        fi
        VERSION=$WORKSPACE_VERSION
    fi

    # Check if the version is already published
    if check_version "$CRATE_NAME" "$VERSION"; then
        STATUS="✅ Ready"
    else
        STATUS="❌ Already published"
    fi
    
    echo "$CRATE_NAME|$VERSION|$STATUS"
    return 0
}

# Recursively find and process all Cargo.toml files
find_and_process_cargo_toml() {
    local dir=$1
    for item in "$dir"/*; do
        if [ -d "$item" ]; then
            find_and_process_cargo_toml "$item"
        elif [ -f "$item" ] && [ "$(basename "$item")" == "Cargo.toml" ]; then
            process_cargo_toml "$item"
        fi
    done
}

# Print results as a table
print_table() {
    local -r delimiter="${1}"
    local -r data="$(removeEmptyLines "${2}")"

    if [[ "${delimiter}" != '' && "$(isEmptyString "${data}")" = 'false' ]]
    then
        local -r numberOfLines="$(wc -l <<< "${data}")"

        if [[ "${numberOfLines}" -gt '0' ]]
        then
            local table=''
            local i=1

            for ((i = 1; i <= "${numberOfLines}"; i = i + 1))
            do
                local line=''
                line="$(sed "${i}q;d" <<< "${data}")"

                local numberOfColumns='0'
                numberOfColumns="$(awk -F "${delimiter}" '{print NF}' <<< "${line}")"

                # Add line delimiter
                if [[ "${i}" -eq '1' ]]
                then
                    table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
                fi

                # Add header or row
                table="${table}\n"

                local j=1

                for ((j = 1; j <= "${numberOfColumns}"; j = j + 1))
                do
                    table="${table}$(printf '#| %s' "$(cut -d "${delimiter}" -f "${j}" <<< "${line}")")"
                done

                table="${table}#|\n"

                # Add line delimiter
                if [[ "${i}" -eq '1' ]] || [[ "${numberOfLines}" -gt '1' && "${i}" -eq "${numberOfLines}" ]]
                then
                    table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
                fi
            done

            if [[ "$(isEmptyString "${table}")" = 'false' ]]
            then
                echo -e "${table}" | column -s '#' -t | awk '/^\+/{gsub(" ", "-", $0)}1'
            fi
        fi
    fi
}

# Helper functions for print_table (unchanged)
function removeEmptyLines() {
    local -r content="${1}"
    echo -e "${content}" | sed '/^\s*$/d'
}

function repeatString() {
    local -r string="${1}"
    local -r numberToRepeat="${2}"

    if [[ "${string}" != '' && "${numberToRepeat}" =~ ^[1-9][0-9]*$ ]]
    then
        local -r result="$(printf "%${numberToRepeat}s")"
        echo -e "${result// /${string}}"
    fi
}

function isEmptyString() {
    local -r string="${1}"

    if [[ "$(trimString "${string}")" = '' ]]
    then
        echo 'true' && return 0
    fi

    echo 'false' && return 1
}

function trimString() {
    local -r string="${1}"
    sed 's,^[[:blank:]]*,,' <<< "${string}" | sed 's,[[:blank:]]*$,,'
}

# Start processing from the crates directory
results=$(find_and_process_cargo_toml "crates")

# Print results as a table
echo "Crate Versions Check Results:"
print_table '|' "Crate Name|Version|Status\n${results}"

# Check if any crate is not ready for release
if echo "${results}" | grep -q "❌"; then
    echo "Error: Some crate versions are not ready for release"
    exit 1
fi

echo "All crate versions are ready for release."
exit 0