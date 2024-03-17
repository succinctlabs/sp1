# Development Guide

This is a guide with helpful information for developers who want to contribute to the SP1 project.

## Getting started

You can run the test suite in SP1 core by running the following command:

```bash
cd core
cargo test
```


```
cargo test syscall::precompiles::edwards::ed_add::tests::test_ed_add_simple --release -- --nocapture
```
**Debug Constraint Failure**

```
RUS_LOG=info cargo test syscall::precompiles::edwards::ed_add::tests::test_ed_add_simple --release --features debug --no-default-features -- --nocapture
```

You need `--no-default-features` to make sure the "perf" feature is not enabled.
```
RUST_LOG=info RUST_BACKTRACE=1 cargo test syscall::precompiles::edwards::ed_add::tests::test_ed_add_simple --features debug --no-default-features --release -- --nocapture
```

RUST_LOG=info RUST_BACKTRACE=1 cargo test syscall::precompiles::edwards::ed_add::tests::test_ed_add_simple --no-default-features --release -- --nocapture