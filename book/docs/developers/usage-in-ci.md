# Usage in CI

## Getting started

You may want to use SP1 in your [Github Actions](https://docs.github.com/en/actions) CI workflow.

You first need to have Rust installed, and you can use
[actions-rs/toolchain](https://github.com/actions-rs/toolchain) for this:

```yaml
- name: Install Rust Toolchain
  uses: actions-rs/toolchain@v1
  with:
    toolchain: 1.81.0
    profile: default
    override: true
    default: true
    components: llvm-tools, rustc-dev
```

And then you can install the SP1 toolchain:

```yaml
- name: Install SP1 toolchain
  run: |
    curl -L https://sp1.succinct.xyz | bash
    ~/.sp1/bin/sp1up 
    ~/.sp1/bin/cargo-prove prove --version
```

You might experience rate limiting from sp1up. Using a Github
[Personal Access Token (PAT)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) will help.

Try setting a GitHub Actions secret for your PAT, and then passing it into the `sp1up` command:

```yaml
- name: Install SP1 toolchain
  run: |
    curl -L https://sp1.succinct.xyz | bash
    ~/.sp1/bin/sp1up --token "${{ secrets.GH_PAT }}"
    ~/.sp1/bin/cargo-prove prove --version
```

Note: Installing via `sp1up` always installs the latest version, it's recommended to [use a release commit](https://github.com/succinctlabs/sp1/releases) via `sp1up -C <commit>`.

## Speeding up your CI workflow

### Caching

To speed up your CI workflow, you can cache the Rust toolchain and Succinct toolchain. See this example
from SP1's CI workflow, which caches the `~/.cargo` and parts of the `~/.sp1` directories.

```yaml
- name: rust-cache
  uses: actions/cache@v3
  with:
    path: |
      ~/.cargo/bin/
      ~/.cargo/registry/index/
      ~/.cargo/registry/cache/
      ~/.cargo/git/db/
      target/
      ~/.rustup/
      ~/.sp1/circuits/plonk/ # Cache these if you're generating plonk proofs with docker in CI.
      ~/.sp1/circuits/groth16/ # Cache these if you're generating groth16 proofs with docker in CI.
    key: rust-1.81.0-${{ hashFiles('**/Cargo.toml') }}
        restore-keys: rust-1.81.0-
```

### `runs-on` for bigger instances

Since SP1 is a fairly large repository, it might be useful to use [`runs-on`](https://github.com/runs-on/runs-on)
to specify a larger instance type.
