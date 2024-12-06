#!/bin/bash

set -e

# Loop over each folder in 'programs/' and extract the binary name
# from the "name" field of Cargo.toml
CARGO_TOML='[package]
name = "patch-testing-tests"
version = "1.0.0" 
edition = "2021" 
publish = false

[dependencies]
sp1-sdk = { path = "../../crates/sdk" }

[build-dependencies]
sp1-build = { path = "../../crates/build" }'

rm -rf tests

# Write the cargo toml 
mkdir -p tests
mkdir -p tests/src
echo "$CARGO_TOML" > tests/Cargo.toml

touch tests/src/lib.rs
touch tests/build.rs

generate_test_template() {
    local binary_name="$1"
    local underscored=$(echo $binary_name | tr '-' '_')

    # Ensure the binary name is provided
    if [[ -z "$binary_name" ]]; then
        echo "Error: Binary name is required."
        return 1
    fi

    # Generate the template
    cat <<EOF
    #[test]
    fn test_${underscored}() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("${binary_name}");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
EOF

}

BUILD_COMMANDS='fn main() {\n'

for folder in programs/*; do
    if [[ -d "$folder" && -f "$folder/Cargo.toml" ]]; then
        echo "Generating tests for $folder"

        # Extract the binary name from Cargo.toml using awk
        binary_name=$(awk -F'"' '/^name =/ {print $2}' "$folder/Cargo.toml" || echo "unknown")

        if [[ "$binary_name" != "unknown" ]]; then
            echo "Binary name: $binary_name"

            # Generate the test file
            echo "Generating test file for $binary_name"

            generate_test_template "$binary_name" >> tests/src/lib.rs

            # Make sure we setup the build script
            BUILD_COMMANDS="$BUILD_COMMANDS sp1_build::build_program(\"../$folder\");\n"

        else
            echo "No binary name found in $folder/Cargo.toml"
        fi
    else
        echo "Skipping $folder (not a directory or missing Cargo.toml)"
    fi
done

BUILD_COMMANDS+='}'

echo "Creating build.rs"
echo -e $BUILD_COMMANDS > tests/build.rs
