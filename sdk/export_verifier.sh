#!/bin/bash
set -e

# Define the output directory
OUTPUT_DIR="../contracts/src"

# Call the Rust function to export the verifier
cargo run --package sp1-sdk --bin export_verifier --release -- --output-dir $OUTPUT_DIR

echo "Verifier exported to $OUTPUT_DIR/SP1Verifier.sol"