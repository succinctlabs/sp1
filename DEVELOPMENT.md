# Development Guide

This is a guide with helpful information for developers who want to contribute to the SP1 project.

## Getting started

You can run the test suite in SP1 core by running the following command:

```bash
cd core
cargo test
```

**Debug Constraint Failure**

To debug constraint failures, you can use the `--features debug` feature alongside `--no-default-features` to eliminate the "perf" feature. For example:

```
RUST_LOG=info RUST_BACKTRACE=1 cargo test syscall::precompiles::edwards::ed_add::tests::test_ed_add_simple --release --features debug --no-default-features -- --nocapture
```

## Running a benchmark for core profiling

You can run a benchmark for core profiling by running the following commands:

For the Fibonacci program (shorter):
```bash
RUST_LOG=debug cargo test stark::machine::tests::test_fibonacci_prove --release -- --nocapture --ignored
```

For the Tendermint benchmark program (longer):
```bash
RUST_LOG=debug cargo test stark::machine::tests::test_tendermint_benchmark_prove --release -- --nocapture --ignored
```