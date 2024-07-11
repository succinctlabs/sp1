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

## Publishing

SP1 crates are hosted on [crates.io](https://crates.io/search?q=sp1). We use
[release-plz](https://release-plz.ieni.dev/) to automate the publication process, and it is configured
with [release-plz.toml](./release-plz.toml) and [.github/workflows/release-plz.yml](./.github/workflows/release-plz.yml).

With this configuration, when the `main` branch is pushed to, the following happens:

1. release-plz creates a pull request with the new versions, where it prepares the next release.
2. release-plz releases the unpublished packages.

In the case that this does not work, you can manually publish the crates by [installing
release-plz](https://release-plz.ieni.dev/docs/usage/installation) and preparing the crates with:

```bash
release-plz update
```

and then publishing the crates with:

```bash
release-plz release --git-token $GITHUB_TOKEN
```
