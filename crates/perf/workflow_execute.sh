#! /bin/bash

# Get the current git branch.
GIT_REF=$(git rev-parse --abbrev-ref HEAD)

# Define the list of simple executor workloads.
SIMPLE_WORKLOADS=(
    "fibonacci-17k"
    "ssz-withdrawals"
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
)

# Define the list of checkpoint executor workloads.
CHECKPOINT_WORKLOADS=(
    "fibonacci-17k"
    "ssz-withdrawals"
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
)

# Define the list of trace executor workloads.
TRACE_WORKLOADS=(
    "fibonacci-17k"
    "ssz-withdrawals"
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
    #
)

# Create a JSON object with the list of workloads.
WORKLOADS=$(jq -n \
    --arg simple "$(printf '%s\n' "${SIMPLE_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg checkpoint "$(printf '%s\n' "${CHECKPOINT_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg trace "$(printf '%s\n' "${TRACE_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    '{simple_workloads: $simple, checkpoint_workloads: $checkpoint, trace_workloads: $trace}')

# Run the workflow with the list of workloads.
echo $WORKLOADS | gh workflow run executor-suite.yml --ref $GIT_REF --json