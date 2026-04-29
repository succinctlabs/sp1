#!/usr/bin/env bash
# Fetch benchmark fixture ELFs and stdins from S3.
# Usage: bench/fixtures/fetch.sh
#
# Requires: AWS CLI configured with access to s3://sp1-testing-suite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Workload definitions: local_name -> s3_path
declare -A WORKLOADS=(
    [fib]="v6/fibonacci-20k"
    [keccak]="v6/keccak256-100kb"
    [big]="v6/ssz-withdrawals"
)

for name in "${!WORKLOADS[@]}"; do
    s3_path="${WORKLOADS[$name]}"
    dest="$SCRIPT_DIR/$name"
    mkdir -p "$dest"

    if [[ -f "$dest/program.bin" && -f "$dest/stdin.bin" ]]; then
        echo "[$name] already fetched, skipping (delete $dest to re-fetch)"
        continue
    fi

    echo "[$name] fetching from s3://sp1-testing-suite/$s3_path ..."
    aws s3 cp "s3://sp1-testing-suite/$s3_path/program.bin" "$dest/program.bin"
    aws s3 cp "s3://sp1-testing-suite/$s3_path/stdin.bin" "$dest/stdin.bin"
    echo "[$name] done"
done

echo "All fixtures ready in $SCRIPT_DIR"
