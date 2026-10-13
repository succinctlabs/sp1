# Development Guide

This is a guide with helpful information for developers who want to contribute to the SP1 project.

## Getting started

To build SP1, you must install [Go](https://go.dev/doc/install). You can run the test suite in SP1 core by running the following command:

```bash
cd core
cargo test
```

### Code Formatting

Before submitting any changes, ensure your code is properly formatted by running:

```bash
cargo +nightly fmt --all
```

This is enforced by CI and your PR will fail if the code is not properly formatted.

### Building SP1 GPU server from source
This is useful for testing and development of unreleased or experimental versions.

sp1-gpu-server (for CUDA proving)
```sh
cargo install --locked --root "$HOME/.sp1" --path sp1-gpu/crates/server/
```

sp1 toolchain
```sh
cargo run -p sp1-cli -- prove install-toolchain
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

## PR workflow runners

The `PR` workflow uses the `ci-v3` RunsOn environment when the repository variable `SP1_CI_RUNS_ON_ENVIRONMENT` is empty.
Set this variable to `legacy` to select the existing runners for new ordinary jobs.
To select another RunsOn environment for ordinary PR, push, and merge-group jobs, set this variable to its environment name.
Prepare that environment before you set the variable.
The selected environment uses a `150gb:gp3:750mbps:4000iops` root volume.
GPU jobs keep their instance type and AMI.

The GitHub-hosted `Runner routing` job validates the selection before the nine RunsOn jobs can start.
An invalid environment name or volume fails that check.
The variable affects only this workflow.

Manual runs use their `runs_on_environment` and `runs_on_volume` inputs independently of the repository variable.
An empty manual environment input selects the legacy runners.

Clear `SP1_CI_RUNS_ON_ENVIRONMENT` to restore the `ci-v3` default for new ordinary runs.
This does not move jobs that already have runner labels or stop their instances.

Run `ruby .github/scripts/check-runner-routing.rb` to check the default, legacy, configured, and manual routes locally.

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
