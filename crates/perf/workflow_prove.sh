#! /bin/bash

# Get the current git branch.
GIT_REF=$(git rev-parse --abbrev-ref HEAD)
NETWORK_CONCURRENT_REPEAT_COUNT=10

# Define the list of CPU workloads.
CPU_WORKLOADS=(
    "ssz-withdrawals"
    "loop-10k"
    "fibonacci-20k"
    "keccak256-300kb"
    "sha256-300kb"
    "rsp-20526626"
    "zk-email"
    "eddsa-verify"
)

# Define the list of CUDA workloads.
CUDA_WORKLOADS=(
    "ssz-withdrawals"
    "loop-10k"
    "fibonacci-20k"
    "keccak256-300kb"
    "sha256-300kb"
    "rsp-20526626"
    "zk-email"
    "eddsa-verify"
    "op-succinct-10 < input/145164200-145164220.bin"
)

# Define the list of network workloads.
NETWORK_WORKLOADS=(
    "ssz-withdrawals"
    "loop-100m"
    "fibonacci-200m"
    "keccak256-3mb"
    "sha256-3mb"
    "rsp-20526626"
    "zk-email"
    "eddsa-verify"
    "op-succinct-10 < input/145164200-145164220.bin"
)

function json_array() {
    printf '%s\n' "$@" | jq -R . | jq -s 'map(select(length > 0))'
}

gh workflow run suite.yml \
    --ref $GIT_REF \
    -f cpu_workloads="$(json_array "${CPU_WORKLOADS[@]}")" \
    -f cuda_workloads="$(json_array "${CUDA_WORKLOADS[@]}")" \
    -f network_workloads="$(json_array "${NETWORK_WORKLOADS[@]}")" \
    -f network_concurrent_repeat_count="$NETWORK_CONCURRENT_REPEAT_COUNT"
