# sp1-gpu-perf

Performance benchmarks and testing utilities for SP1-GPU.

Provides benchmarking tools for measuring GPU prover performance, including end-to-end proving times and component-level metrics. This crate is used for development and optimization, not published to crates.io.

## Usage

### `node` — End-to-end benchmark

Runs the full proving pipeline for a program.

```bash
cargo run --release -p sp1-gpu-perf --bin node -- --program v6/fibonacci-200m --mode core
```

#### Dumping shard records locally

The `node` binary honors two environment variables that cause it to write shard records and the verifying key to disk as it runs. This is the supported way to capture inputs for `replay_shards` without going through S3.

| Variable | Default | Description |
|----------|---------|-------------|
| `SP1_DUMP_SHARD_DIR` | *(unset — disabled)* | Directory to write shard records to. When set, each emitted shard record is serialized to `<dir>/record_NNNN.bin`, and the verifying key is written to `<dir>/vk.bin` on the first dumped shard. The directory is created if it does not exist. |
| `RECORD_WRITE_FREQUENCY` | `5` | Only dump every Nth shard record (shard index 0, N, 2N, ...). Set to `1` to dump every shard. Has no effect unless `SP1_DUMP_SHARD_DIR` is also set. |

Example — dump every shard record for fibonacci into `/tmp/shards/fib`:

```bash
SP1_DUMP_SHARD_DIR=/tmp/shards/fib RECORD_WRITE_FREQUENCY=1 \
    cargo run --release -p sp1-gpu-perf --bin node -- \
        --program v6/fibonacci-200m --mode core
```

### `replay_shards` — Replay shard records through the GPU prover

Re-proves previously dumped shard records through the GPU prover and reports per-shard timing. This is useful for benchmarking shard proving performance in isolation, without re-executing programs or running the full proving pipeline.

```bash
cargo run --release -p sp1-gpu-perf --bin replay-shards -- \
    --config config.json --local-dir /tmp/shard-replay
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | *(required)* | Path to JSON config file (see schema below) |
| `--local-dir` | *(required)* | Local directory containing pre-dumped shard data, laid out as `<local-dir>/<program>/{vk.bin,program.bin,record_NNNN.bin}` (records under `input/<input>/` when the combo has an input) |
| `--num-shards-per-run` | `5` | Number of shards to replay per program/input combo |
| `--seed` | `42` | RNG seed for shard selection |

The config file is a JSON array of program entries:

```json
[
  {
    "program": "v6/fibonacci-200m",
    "inputs": []
  },
  {
    "program": "v6/dec4-failures/rsp",
    "inputs": ["23843375"]
  }
]
```

### `composed_workflow` — Dump-then-replay in one shot

Drives `node` and `replay-shards` end-to-end against a persistent root directory, populating it with shard records and then replaying from it. This replaces the previous `dump_shards` + `download_shards` flow: records stay on the local machine and never round-trip through S3.

```bash
# First run: dump records via `node`, then replay them.
cargo run --release -p sp1-gpu-perf --bin composed-workflow -- \
    --mode local --dir /tmp/shard-replay --config config.json

# Subsequent runs: skip the dump and reuse the records already in --dir.
cargo run --release -p sp1-gpu-perf --bin composed-workflow -- \
    --mode local-with-cache --dir /tmp/shard-replay --config config.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | *(required)* | `local` runs `node` for each combo (with `SP1_DUMP_SHARD_DIR` pointed at `--dir`) before replaying. `local-with-cache` skips the dump and assumes `--dir` already contains records. |
| `--dir` | *(required)* | Persistent root directory used for dumps and replay. Created if missing; never deleted, so it can be reused across runs. |
| `--config` | *(required)* | Path to JSON config file (same schema as `replay-shards`) |
| `--k` | *(all)* | Forwarded to `replay-shards` as `--num-shards-per-run` |
| `--nsys-tracing` | `false` | If set, runs `replay-shards` under `nsys profile` |

---

Part of [SP1-GPU](https://github.com/succinctlabs/sp1/tree/dev/sp1-gpu), the GPU-accelerated prover for SP1.
