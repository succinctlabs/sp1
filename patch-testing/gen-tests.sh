#!/bin/bash

set -e

CARGO_TOML='[package]
name = "patch-testing-tests"
version = "1.0.0" 
edition = "2021" 
publish = false

[dependencies]
sp1-sdk = { path = "../../crates/sdk" }

[build-dependencies]
sp1-build = { path = "../../crates/build" }'

generate_test_template() {
    local binary_name="$1"
    local underscored=$(echo $binary_name | tr '-' '_')

    # Ensure the binary name is provided
    if [[ -z "$binary_name" ]]; then
        echo "Error: Binary name is required."
        return 1
    fi

    cat <<EOF
    #[test]
    fn test_${underscored}() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("${binary_name}");
        let stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
EOF
}

# Silent pushd
_pushd() {
  pushd $1 &> /dev/null
}

# Silent popd
_popd() {
  popd &> /dev/null
}

# Make sure were in the right directory
cd $(dirname $0)

# Remove the tests directory
rm -rf tests

# Write the cargo toml 
mkdir -p tests
mkdir -p tests/src
echo "$CARGO_TOML" > tests/Cargo.toml

# Setup the test and build scripts
touch tests/src/lib.rs
touch tests/build.rs

TEST_PROGRAM_WORKSPACE=$(readlink -f programs)

# Open the build.rs
echo -e 'fn main() {\n' > tests/build.rs

_pushd programs
# Extract metadata for all binaries
METADATA=$(cargo metadata --no-deps --format-version 1 | jq -c '.packages[].targets[]')
_popd

# Loop over each binary target
echo "$METADATA" | while IFS= read -r bin; do
  BIN_NAME=$(echo "$bin" | jq -r '.name')
  BIN_SRC=$(echo "$bin" | jq -r '.src_path')

  echo "Processing $BIN_NAME @ $BIN_SRC"

  # Strip TEST_PROGRAM_WORKSPACE from BIN_SRC
  RELATIVE_SRC=$(echo "$BIN_SRC" | sed "s|$TEST_PROGRAM_WORKSPACE/||" | cut -d'/' -f1)

  # Generate the test
  generate_test_template "$BIN_NAME" >> tests/src/lib.rs

  # Append build command
  echo -e "sp1_build::build_program(\"../programs/$RELATIVE_SRC\");" >> tests/build.rs
done

# Close the build.rs
echo -e "}" >> tests/build.rs

# Format the code 
_pushd tests
cargo fmt --all &> /dev/null 
_popd

if [[ -z "$NO_RUN" ]]; then
  echo "Running tests in release mode..."
  # Run the tests
  cargo test --manifest-path tests/Cargo.toml --release
fi
