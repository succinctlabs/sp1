#!/usr/bin/env bash
set -euo pipefail

LOCAL_DIR="/tmp/shard-replay"
CONFIG=""
K=15
BUCKET="sp1-gpu-shard-dumps"
TESTING_BUCKET="sp1-testing-suite"
EXTRA_CARGO_ARGS=""

usage() {
    echo "Usage: $0 --config <path> [--k <num>] [--bucket <bucket>] [--cargo-args <args>]"
    echo ""
    echo "Downloads shard records from S3 and runs replay_shards locally."
    echo ""
    echo "Options:"
    echo "  --config       Path to JSON config file (required)"
    echo "  --k            Total number of records to download (default: 15)"
    echo "  --bucket       S3 bucket for shard dumps (default: sp1-gpu-shard-dumps)"
    echo "  --cargo-args   Extra arguments passed to cargo run (e.g. '--features foo')"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --config) CONFIG="$2"; shift 2;;
        --k) K="$2"; shift 2;;
        --bucket) BUCKET="$2"; shift 2;;
        --cargo-args) EXTRA_CARGO_ARGS="$2"; shift 2;;
        -h|--help) usage;;
        *) echo "Unknown argument: $1"; usage;;
    esac
done

if [[ -z "$CONFIG" ]]; then
    usage
fi

if ! command -v jq &>/dev/null; then
    echo "Error: jq is required but not installed."
    exit 1
fi

mkdir -p "$LOCAL_DIR"

# Build list of combos from config: "program|input" pairs.
combos=()
num_entries=$(jq length "$CONFIG")
for ((i = 0; i < num_entries; i++)); do
    program=$(jq -r ".[$i].program" "$CONFIG")
    num_inputs=$(jq ".[$i].inputs | length" "$CONFIG")
    if [[ $num_inputs -eq 0 ]]; then
        combos+=("${program}|")
    else
        for ((j = 0; j < num_inputs; j++)); do
            input=$(jq -r ".[$i].inputs[$j]" "$CONFIG")
            combos+=("${program}|${input}")
        done
    fi
done

num_combos=${#combos[@]}
echo "Found $num_combos combo(s)"

if [[ $num_combos -eq 0 ]]; then
    echo "No combos found in config"
    exit 1
fi

# Distribute k records across combos (ceiling division).
per_combo=$(( (K + num_combos - 1) / num_combos ))

# Track which programs we've already downloaded vk/elf for.
declare -A downloaded_programs

for combo_str in "${combos[@]}"; do
    IFS='|' read -r program input <<< "$combo_str"

    program_dir="$LOCAL_DIR/$program"
    mkdir -p "$program_dir"

    # Download vk.bin and program.bin once per program.
    if [[ -z "${downloaded_programs[$program]:-}" ]]; then
        vk_path="$program_dir/vk.bin"
        if [[ ! -f "$vk_path" ]]; then
            echo "Downloading vk for $program"
            aws s3 cp "s3://$BUCKET/$program/vk.bin" "$vk_path"
        else
            echo "Skipping existing vk for $program"
        fi

        elf_path="$program_dir/program.bin"
        if [[ ! -f "$elf_path" ]]; then
            echo "Downloading elf for $program"
            aws s3 cp "s3://$TESTING_BUCKET/$program/program.bin" "$elf_path"
        else
            echo "Skipping existing elf for $program"
        fi

        downloaded_programs[$program]=1
    fi

    # Determine S3 prefix and local dir for records.
    if [[ -z "$input" ]]; then
        s3_prefix="s3://$BUCKET/$program/"
        record_dir="$program_dir"
    else
        s3_prefix="s3://$BUCKET/$program/input/$input/"
        record_dir="$program_dir/input/$input"
        mkdir -p "$record_dir"
    fi

    label="$program"
    [[ -n "$input" ]] && label="$program/input/$input"

    # List available records on S3.
    echo "Listing records at $s3_prefix"
    all_records=$(aws s3 ls "$s3_prefix" 2>/dev/null | awk '/record_.*\.bin/ {print $NF}' || true)

    if [[ -z "$all_records" ]]; then
        echo "  No records found for $label, skipping"
        continue
    fi

    num_available=$(echo "$all_records" | wc -l)
    num_to_download=$((per_combo < num_available ? per_combo : num_available))

    # Randomly select records (exclude already-downloaded ones).
    selected=$(echo "$all_records" | shuf -n "$num_to_download")
    echo "  Selected $num_to_download / $num_available records for $label"

    while IFS= read -r rec; do
        local_rec="$record_dir/$rec"
        if [[ ! -f "$local_rec" ]]; then
            echo "  Downloading $rec"
            aws s3 cp "${s3_prefix}${rec}" "$local_rec"
        else
            echo "  Skipping existing $rec"
        fi
    done <<< "$selected"
done

total_records=$(find "$LOCAL_DIR" -name 'record_*.bin' | wc -l)
echo ""
echo "Download complete: $total_records record(s) in $LOCAL_DIR"
echo ""
echo "Running replay_shards with --local-dir $LOCAL_DIR ..."
echo ""

# shellcheck disable=SC2086
RUST_LOG=debug nsys profile --cuda-memory-usage=true cargo run --release -p sp1-gpu-perf --bin replay-shards --features experimental $EXTRA_CARGO_ARGS -- \
    --config "$CONFIG" \
    --local-dir "$LOCAL_DIR" \
    --k "$K"
