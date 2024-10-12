#!/bin/bash

# Check if both arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <s3_path> <cpu|cuda>"
    exit 1
fi

s3_path=$1
stage=$2

# Download files from S3
aws s3 cp s3://sp1-testing-suite/$s3_path/program.bin /tmp/program.bin
aws s3 cp s3://sp1-testing-suite/$s3_path/stdin.bin /tmp/stdin.bin

# Set environment variables
export RUSTFLAGS="-Copt-level=3 -Ctarget-cpu=native"
export RUST_BACKTRACE=1
export RUST_LOG=debug

# Run moongate-perf
cargo run --release -p sp1-perf -- --program /tmp/program.bin --stdin /tmp/stdin.bin --mode $stage