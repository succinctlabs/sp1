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

## Contributing to Docs

To build docs locally, run the following commands in the top-level directory:

```bash
cargo install mdbook  # Installs mdbook locally
mdbook serve  # Serves the docs locally
```
