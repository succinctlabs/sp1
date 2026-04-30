# SP1 Testing Suite

## Prerequisites

- [GitHub CLI](https://cli.github.com/)

## Run the testing suite

Set the workloads you want to run in the `workflow.sh` file. The workloads are keys in the
`sp1-testing-suite` s3 bucket.

```sh
CPU_WORKLOADS=("fibonacci-17k" "ssz-withdrawals")
CUDA_WORKLOADS=()
NETWORK_WORKLOADS=()
```

Run the workflow.

```sh
./workflow.sh
```

## Test the executor

Set the workloads you want to run in the `workflow_executor.sh` file. The workloads are keys in the
`sp1-testing-suite` s3 bucket.

```sh
SIMPLE_WORKLOADS=("fibonacci-17k" "ssz-withdrawals")
CHECKPOINT_WORKLOADS=()
TRACE_WORKLOADS=()
```

Run the workflow.

```sh
./workflow_executor.sh
```

## `run_s3.sh`

This script will run the `sp1-perf` binary on a workload in the `sp1-testing-suite` s3 bucket.

### Example Usage

The following command will run the `fibonacci-17k` workload and generate a proof using the CPU prover.

```sh
./run_s3.sh fibonacci-17k cpu
```

## `run_executor.sh`

This script will run the `sp1-perf-executor` binary on a workload in the `sp1-testing-suite` s3 bucket.

### `run_executor.sh` Example Usage

The following command will run the `fibonacci-17k` workload in checkpoint mode.

```sh
./run_executor.sh fibonacci-17k checkpoint
```

If you want, install [`cargo-flamegraph`](https://github.com/flamegraph-rs/flamegraph) and uncomment
these lines to generate flamegraphs for profiling executor performance.

```sh
cargo flamegraph --root --bin sp1-perf-executor --profile profiling --features bigint-rug \
    -c "record -e cycles -F 999 --call-graph dwarf" -- \
    --program program.bin \
    --stdin stdin.bin \
    --executor-mode $kind
```

If you're on Mac, it can be easier to use samply instead.

```sh
cd ../../

cargo build --bin sp1-perf-executor --profile profiling --features bigint-rug --

samply record ./target/profiling/sp1-perf-executor \
    --program crates/perf/program.bin \
    --stdin crates/perf/stdin.bin \
    --executor-mode $kind
```

## Interactive prover (`sp1-perf-prover`)

`sp1-perf-prover` is a REPL that initialises the prover client once and then loops on
user input, so you can submit many proof or execution requests in a single session
without paying the prover-init cost each time.

### Run

```sh
cargo run -p sp1-perf --bin sp1-perf-prover
```

A `.env` in the working directory (or any parent) is loaded automatically, so use it for
`SP1_PROVER`, `RUST_LOG`, `NETWORK_PRIVATE_KEY`, AWS credentials, etc.

The REPL has full readline editing — `↑`/`↓` for history, `Ctrl-R` for reverse search,
`Ctrl-A` / `Ctrl-E` / etc. History persists in `~/.sp1-perf-history` across sessions.

### Commands

```text
prove   --program <P> [--input <I>] [--mode <M>]
            Execute + setup + prove + verify; appends a row to data/measurements.csv.
            mode: core | compressed | groth16 | plonk (default: compressed)

execute --program <P> [--input <I>]
            Run only the executor; report cycles, gas, MHz, Mgas/s.

programs [<filter>]
            List benchmark programs in s3://sp1-testing-suite/, optionally filtered.

inputs  --program <P>
            List input files for a benchmark program.

help | h | ?       Show help.
quit | exit | q    Exit (Ctrl-D / Ctrl-C also work).
```

Program names follow the same convention as `sp1-gpu-perf node`:

- `local-<name>` — built-in ELF from `test-artifacts` (`fibonacci`, `sha2`, `keccak`).
- anything else — fetched via `aws s3 cp` from `s3://sp1-testing-suite/<program>/`.

### Examples

```text
sp1-perf> programs fib
sp1-perf> execute --program v6/fibonacci-200m
sp1-perf> prove   --program v6/fibonacci-200m --mode compressed
sp1-perf> prove   -p local-fibonacci -i 1000 -m core
sp1-perf> inputs  --program v6/rsp
sp1-perf> prove   --program v6/rsp --input 17106222 --mode groth16
```

### Caching and measurements

- Programs and inputs are cached in-memory by name (and by `(program, input)` for
  inputs) for the lifetime of the session, so repeating a request is free of S3
  round-trips.
- Each successful `prove` appends a row to `crates/perf/data/measurements.csv` with
  columns `timestamp,program,param,mode,cycles,gas,elf_bytes,execute_secs,setup_secs,
  prove_secs,khz,mgas_per_s`. The `data/` directory is gitignored.

## View the results of a testing suite run

Visit the [actions](https://github.com/succinctlabs/sp1/actions) tab on GitHub to view the results.

## Uploading new workloads

Take any existing binary that uses `sp1-sdk` and run it with `SP1_DUMP=1`. This will dump the
program and stdin to the current directory.

```sh
SP1_DUMP=1 cargo run --release
aws s3 cp program.bin s3://sp1-testing-suite/<workload>/program.bin
aws s3 cp stdin.bin s3://sp1-testing-suite/<workload>/stdin.bin
```
