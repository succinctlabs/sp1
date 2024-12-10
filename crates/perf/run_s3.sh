#!/bin/bash

# Check the number of arguments
if [ $# -lt 2 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <s3_path> <cpu|cuda|network>"
    exit 1
fi

s3_path=$1
kind=$2

# Download files from S3
aws s3 cp s3://sp1-testing-suite/$s3_path/program.bin program.bin
aws s3 cp s3://sp1-testing-suite/$s3_path/stdin.bin stdin.bin

# Check for AVX-512 support
if lscpu | grep -q avx512; then
  # If AVX-512 is supported, add the specific features to RUSTFLAGS
  export RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C target-feature=+avx512ifma,+avx512vl"
else
  # If AVX-512 is not supported, just set target-cpu=native
  export RUSTFLAGS="-Copt-level=3 -C target-cpu=native"
fi

# Set environment variables
export RUST_BACKTRACE=1
export RUST_LOG=debug

# Run sp1-perf
cargo run -p sp1-perf --bin sp1-perf -- --program program.bin --stdin stdin.bin --mode $kind
