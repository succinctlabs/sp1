# Development Guide

This is a guide with helpful information for developers who want to contribute to the SP1 project.

## Getting started

You can run the test suite in SP1 core by running the following command:

```bash
cd core
cargo test
```

### Tips

We recommend you install the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) extension.

Note that if you use `cargo prove new` inside a monorepo, you will need to add the path to the Cargo.toml file to `rust-analyzer.linkedProjects` to get full IDE support.

**Debug Constraint Failure**

To debug constraint failures, you can use the `--features debug` feature. For example:

```
RUST_LOG=info RUST_BACKTRACE=1 cargo test syscall::precompiles::edwards::ed_add::tests::test_ed_add_simple --release --features debug -- --nocapture
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

With this configuration, when the `dev` branch is pushed to, the following should happen:

1. `release-plz` creates a pull request with the new version.
2. When we are ready to create a release, we merge the pull request.
3. After merging the pull request, `release-plz` publishes the packages.

After the release pull request has been merged to `dev`, only then should we merge `dev` into `main`
and create a GitHub release for the new version.

In the case that the automated publish does not work, you can manually do this by [installing
release-plz](https://release-plz.ieni.dev/docs/usage/installation) and preparing the crates with:

```bash
release-plz update
```

and then publishing the crates with:

```bash
release-plz release --git-token $GITHUB_TOKEN
```
