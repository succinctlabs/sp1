# sp1-gpu-perf

Performance benchmarks and testing utilities for SP1-GPU.

Provides benchmarking tools for measuring GPU prover performance, including end-to-end proving times and component-level metrics. This crate is used for development and optimization, not published to crates.io.

## Usage

### `node` — End-to-end benchmark

Runs the full proving pipeline for a program.

```bash
cargo run --release -p sp1-gpu-perf --bin node -- --program v6/fibonacci-200m --mode core
```

#### Writing shard records locally

The `node` binary honors two environment variables that cause it to write shard records and the verifying key to disk as it runs. This is the easiest way to capture inputs for `replay_shards`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SP1_RECORD_WRITE_DIR` | *(unset — disabled)* | Directory to write shard records to. When set, shard records are serialized to `<dir>/record_NNNN.bin`, the verifying key is written to `<dir>/vk.bin` on the first writeed shard, and the program ELF is written to `<dir>/program.bin`. The directory is created if it does not exist. |
| `RECORD_WRITE_FREQUENCY` | `5` | Only write every Nth shard record (shard index 0, N, 2N, ...). Set to `1` to write every shard. Has no effect unless `SP1_RECORD_WRITE_DIR` is also set. |

Example — write every shard record for fibonacci into `/tmp/shards/fib`:

```bash
SP1_RECORD_WRITE_DIR=/tmp/shards/fib RECORD_WRITE_FREQUENCY=1 \
    cargo run --release -p sp1-gpu-perf --bin node -- \
        --program v6/fibonacci-200m --mode core
```

### `replay_shards` — Replay shard records through the GPU prover

Re-proves previously written shard records through the GPU prover and reports per-shard timing. This is useful for benchmarking shard proving performance in isolation, and obtaining a mix of shard types across different programs.

```bash
cargo run --release -p sp1-gpu-perf --bin replay-shards -- \
    --config config.json --local-dir /tmp/shard-replay
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | *(required)* | Path to JSON config file (see schema below) |
| `--local-dir` | *(required)* | Local directory containing pre-written shard data, laid out as `<local-dir>/<program>/{vk.bin,program.bin,record_NNNN.bin}` (records under `input/<input>/` when the combo has an input) |
| `--num-shards-per-run` | `5` | Number of shards to replay per program/input combo |
| `--seed` | `42` | RNG seed for shard selection |

The config file is a JSON array of program entries:

```json
[
  {
    "program": "program_a",
    "inputs": ["input_0"]
  },
  {
    "program": "program_b",
    "inputs": []
  },
  {
    "program": "program_c",
    "inputs": ["input_0", "input_1" ]
  }
]
```

### `composed_workflow` — Write-then-replay in one shot

Drives `node` and `replay-shards` end-to-end against a persistent root directory, populating it with shard records and then replaying from it.

```bash
# First run: write records via `node`, then replay them.
cargo run --release -p sp1-gpu-perf --bin composed-workflow -- \
    --mode local --dir /tmp/shard-replay --config config.json

# Subsequent runs: skip the record write and reuse the records already in --dir.
cargo run --release -p sp1-gpu-perf --bin composed-workflow -- \
    --mode local-with-cache --dir /tmp/shard-replay --config config.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | *(required)* | `local` runs `node` for each combo (with `SP1_RECORD_WRITE_DIR` pointed at `--dir`) before replaying. `local-with-cache` skips the record write and assumes `--dir` already contains records. |
| `--dir` | *(required)* | Persistent root directory used for writing records to disk and replaying them. Created if missing; never deleted, so it can be reused across runs. |
| `--config` | *(required)* | Path to JSON config file (same schema as `replay-shards`) |
| `--k` | *(all)* | Forwarded to `replay-shards` as `--num-shards-per-run` |
| `--nsys-tracing` | `false` | If set, runs `replay-shards` under `nsys profile` |

---

Part of [SP1-GPU](https://github.com/succinctlabs/sp1/tree/dev/sp1-gpu), the GPU-accelerated prover for SP1.
