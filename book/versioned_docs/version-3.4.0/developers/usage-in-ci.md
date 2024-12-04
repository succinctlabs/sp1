# Usage in CI

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
