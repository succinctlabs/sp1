#!/usr/bin/env bash

NUM_HASHES=$1
APCS=$2

MANUAL_FLAG=""
SUFFIX=""
if [ "$3" == "manual" ]; then
  MANUAL_FLAG="--manual"
  SUFFIX="_manual"
fi

name=${NUM_HASHES}_hashes_${APCS}_apcs${SUFFIX}

# HACK: currently, Cargo generates a new Cargo.lock and then it doesn't compile anymore...
git checkout ../../Cargo.lock

RUST_LOG_FORMAT=json RUST_LOG=debug cargo run -r -- --num-hashes $NUM_HASHES --apcs $APCS $MANUAL_FLAG &> log_${name}.txt
cat log_${name}.txt | ../../parse_logs.py > results_${name}.csv
