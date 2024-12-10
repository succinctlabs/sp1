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

## View the results

Visit the [actions](https://github.com/succinctlabs/sp1/actions) tab on GitHub to view the results.

## Uploading new workloads

Take any existing binary that uses `sp1-sdk` and run it with `SP1_DUMP=1`. This will dump the
program and stdin to the current directory.

```sh
SP1_DUMP=1 cargo run --release
aws s3 cp program.bin s3://sp1-testing-suite/<workload>/program.bin
aws s3 cp stdin.bin s3://sp1-testing-suite/<workload>/stdin.bin
```
