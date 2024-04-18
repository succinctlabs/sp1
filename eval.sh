#!/bin/bash
set -e

declare -a programs=("fibonacci" "ssz-withdrawals" "tendermint")
declare -a hash_functions=("poseidon" "blake3" "keccak256")
declare -a shard_sizes=("262144" "524288" "1048576" "2097152" "4194304")
declare -i runs=5

root_directory=$(pwd)

benchmark_path="${root_directory}/benchmark.csv"

for program in "${programs[@]}"; do
    echo "Processing program: $program"

    program_directory="${root_directory}/examples/$program/program"
    if [ ! -d "$program_directory" ]; then
        echo "Program directory $program_directory not found!"
        continue
    fi

    cd "$program_directory"

    if ! RUSTFLAGS="-C passes=loweratomic -C link-arg=-Ttext=0x00200800 -C panic=abort" \
        CARGO_NET_GIT_FETCH_WITH_CLI=true \
        cargo prove build; then
        echo "Failed to build $program, skipping..."
        continue
    fi

    echo "Building $program done"
    elf_path="${program_directory}/elf/riscv32im-succinct-zkvm-elf"

    cd "${root_directory}/eval"
    for hash_fn in "${hash_functions[@]}"; do
        for shard_size in "${shard_sizes[@]}"; do
            echo "Running $program with hash function $hash_fn and shard size $shard_size, $runs times"
            if ! CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS='-C target-cpu=native' cargo run -p sp1-eval --release -- \
                --program $program --hashfn $hash_fn --shard-size $shard_size --benchmark-path "$benchmark_path" --elf-path "$elf_path" --runs $runs; then
                echo "Error running evaluation for $program with hash function $hash_fn and shard size $shard_size"
            fi
        done
    done

    cd "$root_directory"
done