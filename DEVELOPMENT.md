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

SP1 crates are hosted on [crates.io](https://crates.io/search?q=sp1). This guide will walk you through the publication process.

The goal of this to to end up with a Github release and crate version that are referencing the same commit.

### Step 1: Update Cargo.toml versions

In each individual crate, update the version to the new version you want to publish.

For example, if the last version was `0.0.1`, and you want to publish `0.0.2`, you would replace
`version = "0.0.1"` with `version = "0.0.2"` each of the `Cargo.toml` files. You can do this all at
once using a find-and-replace tool, but be mindful of any other crates that might match the last version.

### Step 2: Create a release

Merge the `Cargo.toml` version changes into `dev`, and then into `main`, and then create a new release on GitHub as the new version.

### Step 3: Update Cargo.toml paths

To be able to publish the crates, you must change the relative paths in the `Cargo.toml` to the new version.

For example, if we have this `Cargo.toml` file:

```toml
sp1-core = { path = "../core" }
```

You would change it to this:

```toml
sp1-core = "0.0.2"
```

It may error that it doesn't exist yet, but that's okay.

You won't end up committing these changes, as it's best to leave them as relative paths for development.

### Step 4: Publish

To publish newer versions of these crates, you should use the [cargo-publish-workspace](https://crates.io/crates/cargo-publish-workspace-v2) tool:

```bash
cargo install cargo-publish-workspace-v2
```

If you don't have a [crates.io](https://crates.io) account, you should create one. Next, go to your [crates.io account tokens](https://crates.io/settings/tokens) and create a new token.

Then set it as your `CARGO_REGISTRY_TOKEN` environment variable:

```bash
export CARGO_REGISTRY_TOKEN=<your-token>
```

Then run the `cargo publish-workspace` command from the root of the repository:

```bash
cargo publish-workspace --target-version <version> --token $CARGO_REGISTRY_TOKEN --crate-prefix '' -- --allow-dirty
```

This will go through each of the crates and publish them. Each time you run it, it will go through and verify them, so you can be sure that they are all published correctly.
