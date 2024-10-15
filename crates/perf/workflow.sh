#! /bin/bash

# Get the current git branch.
GIT_REF=$(git rev-parse --abbrev-ref HEAD)

# Define the list of CPU workloads.
CPU_WORKLOADS=(
    "fibonacci-17k"
    "ssz-withdrawals"
    "tendermint"
    "rsp-20526624"
    "rsa"
    "regex"
    "chess"
    "json"
    "blobstream-01j6z63fgafrc8jeh0k12gbtvw"
    "blobstream-01j6z95bdme9svevmfyc974bja"
    "blobstream-01j6z9ak0ke9srsppgywgke6fj"
    "vector-01j6xsv35re96tkgyda115320t"
    "vector-01j6xzy366ff5tbkzcrs8pma02"
    "vector-01j6y06de0fdaafemr8b1t69z3"
    "raiko-a7-10"  
)

# Define the list of CUDA workloads.
CUDA_WORKLOADS=(
    "fibonacci-17k"
    "ssz-withdrawals"
    "tendermint"
    "rsp-20526624"
    "rsa"
    "regex"
    "chess"
    "json"
    "blobstream-01j6z63fgafrc8jeh0k12gbtvw"
    "blobstream-01j6z95bdme9svevmfyc974bja"
    "blobstream-01j6z9ak0ke9srsppgywgke6fj"
    "vector-01j6xsv35re96tkgyda115320t"
    "vector-01j6xzy366ff5tbkzcrs8pma02"
    "vector-01j6y06de0fdaafemr8b1t69z3"
    "raiko-a7-10"   
)

# Define the list of network workloads.
NETWORK_WORKLOADS=(
    # "fibonacci-17k"
    # "ssz-withdrawals"
    # "tendermint"
    # "rsp-20526624"
    # "rsa"
    # "regex"
    # "chess"
    # "json"
    # "blobstream-01j6z63fgafrc8jeh0k12gbtvw"
    # "blobstream-01j6z95bdme9svevmfyc974bja"
    # "blobstream-01j6z9ak0ke9srsppgywgke6fj"
    # "vector-01j6xsv35re96tkgyda115320t"
    # "vector-01j6xzy366ff5tbkzcrs8pma02"
    # "vector-01j6y06de0fdaafemr8b1t69z3"
    # "raiko-a7-10"
    # "op-succinct-op-sepolia-1818303090-18303120"
    # "op-succinct-op-sepolia-18200000-18200030" 
    # "op-succinct-op-sepolia-18250000-18250030"
    # "op-succinct-op-sepolia-18303044-18303074"
    # "op-succinct-op-sepolia-range-17685896-17685897"
    # "op-succinct-op-sepolia-range-17985900-17985905"
    # "op-succinct-op-sepolia-range-18129400-18129401"
)

# Create a JSON object with the list of workloads.
WORKLOADS=$(jq -n \
    --arg cpu "$(printf '%s\n' "${CPU_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg cuda "$(printf '%s\n' "${CUDA_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg network "$(printf '%s\n' "${NETWORK_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    '{cpu_workloads: $cpu, cuda_workloads: $cuda, network_workloads: $network}')

# Run the workflow with the list of workloads.
echo $WORKLOADS | gh workflow run suite.yml --ref $GIT_REF --json
