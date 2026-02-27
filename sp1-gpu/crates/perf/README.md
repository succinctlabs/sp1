# sp1-gpu-perf

Performance benchmarks and testing utilities for SP1-GPU.

Provides benchmarking tools for measuring GPU prover performance, including end-to-end proving times and component-level metrics. This crate is used for development and optimization, not published to crates.io.

## Usage

### `node` — End-to-end benchmark

Runs the full proving pipeline for a program.

```bash
cargo run --release -p sp1-gpu-perf --bin node -- --program v6/fibonacci-200m --mode core
```

### `dump_shards` — Dump shard records to S3

Executes a program and proves it in core mode, then uploads the serialized shard records and verifying key to S3. This is the first step in the shard replay workflow — it captures the intermediate shard data so that individual shards can be re-proved later without re-executing the program.

```bash
# Dump all shards
cargo run --release -p sp1-gpu-perf --bin dump_shards -- --program v6/fibonacci-200m

# Dump a random subset of 10 shards
cargo run --release -p sp1-gpu-perf --bin dump_shards -- --program v6/fibonacci-200m --k 10

# Dump shards for a program with a specific input
cargo run --release -p sp1-gpu-perf --bin dump_shards -- --program v6/dec4-failures/rsp --param 23843375
```

| Flag | Default | Description |
|------|---------|-------------|
| `--program` | *(required)* | S3 path for the program (e.g. `v6/fibonacci-200m`) |
| `--param` | `""` | Optional parameter for program input |
| `--bucket` | `sp1-gpu-shard-dumps` | S3 bucket to upload to |
| `--k` | *(all)* | Only upload a random selection of k shards |

### `download_shards` — Download shard records from S3

Downloads shard records, verifying keys, and ELF binaries from S3 to a local directory. Uses a JSON config file to specify which programs (and optionally which inputs) to download from. Distributes the requested number of records across all program/input combinations.

```bash
# Download 15 records (default) using a config file
cargo run --release -p sp1-gpu-perf --bin download_shards -- --config config.json

# Download 30 records with a specific seed and output directory
cargo run --release -p sp1-gpu-perf --bin download_shards -- \
    --config config.json --k 30 --seed 123 --output-dir ./my-shards
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | *(required)* | Path to JSON config file |
| `--k` | `15` | Total number of records to download |
| `--seed` | `42` | RNG seed for record selection |
| `--bucket` | `sp1-gpu-shard-dumps` | S3 bucket for shard dumps |
| `--output-dir` | system temp dir | Local output directory |

The config file is a JSON array of program entries:

```json
[
  {
    "program": "v6/dec4-failures/rsp",
    "inputs": ["23843375"]
  },
  {
    "program": "v6/fibonacci-200m",
    "inputs": []
  }
]
```

The output directory path is printed to stdout on completion.

### `replay_shards` — Replay shard records through the GPU prover

Re-proves previously dumped shard records through the GPU prover and reports per-shard timing. This is useful for benchmarking shard proving performance in isolation, without re-executing programs or running the full proving pipeline.

```bash
cargo run --release -p sp1-gpu-perf --bin replay_shards -- \
    --config config.json --local-dir /tmp/shard-replay
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | *(required)* | Path to JSON config file (same format as `download_shards`) |
| `--local-dir` | *(required)* | Local directory containing pre-downloaded shard data (output of `download_shards`) |

### Typical workflow

```bash
# 1. Dump shards for your programs of interest
cargo run --release -p sp1-gpu-perf --bin dump_shards -- --program v6/fibonacci-200m

# 2. Download a subset of shards locally
LOCAL_DIR=$(cargo run --release -p sp1-gpu-perf --bin download_shards -- --config config.json --k 15)

# 3. Replay the shards through the GPU prover
cargo run --release -p sp1-gpu-perf --bin replay_shards -- --config config.json --local-dir "$LOCAL_DIR"
```

---

Part of [SP1-GPU](https://github.com/succinctlabs/sp1/tree/dev/sp1-gpu), the GPU-accelerated prover for SP1.
